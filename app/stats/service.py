"""Оркестрация сбора статистики и аналитические запросы к истории."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from ..config import settings
from ..db import Database
from .collector import (NB, Aggregator, LogTailer, StubPoller, SystemPoller, merge_data, percentile)
from .parsing import CATEGORY_INFO, LAT_LABELS, GeoIP

log = logging.getLogger("nm.stats")


class StatsService:
    def __init__(self, db: Database, get_panel: Callable[[], Any], nginx_master: Callable[[], Any]) -> None:
        self.db = db
        self.get_panel = get_panel
        self.geoip = GeoIP()
        self.agg = Aggregator(db, get_panel, self.geoip)
        self.stub = StubPoller(settings.stub_status_port)
        self.system = SystemPoller(nginx_master, settings.log_dir)
        self.tailers = [
            LogTailer(settings.access_log, "access", db, self.agg.ingest_access),
            LogTailer(settings.error_log, "error", db, self.agg.ingest_errors),
            LogTailer(settings.stream_log, "stream", db, self.agg.ingest_stream),
        ]
        self.tasks: List[asyncio.Task] = []
        self.started = time.time()
        self.last_cleanup = 0.0
        self.last_sys_minute = int(time.time()) // 60 * 60

    def reload_geoip(self) -> None:
        p = self.get_panel()
        self.geoip.load(p.geoip_path, str(settings.geoip_dir))

    def start(self) -> None:
        self.reload_geoip()
        self.agg.load_hour_tops()
        loop = asyncio.get_running_loop()
        for t in self.tailers:
            self.tasks.append(loop.create_task(t.run(), name=f"tail-{t.name}"))
        self.tasks.append(loop.create_task(self.stub.run(), name="stub"))
        self.tasks.append(loop.create_task(self.system.run(), name="system"))
        self.tasks.append(loop.create_task(self._flusher(), name="flusher"))

    async def stop(self) -> None:
        for t in self.tasks:
            t.cancel()
        for t in self.tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await asyncio.to_thread(self.agg.flush, True)
        except Exception:
            log.exception("финальный сброс статистики")

    async def _flusher(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                await asyncio.to_thread(self.agg.flush)
                now = time.time()
                cur_min = int(now) // 60 * 60
                if cur_min > self.last_sys_minute:
                    await asyncio.to_thread(self._write_system_minute, self.last_sys_minute)
                    self.last_sys_minute = cur_min
                if now - self.last_cleanup > 3600:
                    self.last_cleanup = now
                    await asyncio.to_thread(self.cleanup)
            except Exception:
                log.exception("сброс статистики")

    def _write_system_minute(self, mts: int) -> None:
        avg = self.system.minute_avg(mts, mts + 60)
        if not avg:
            return
        stubs = [s for s in self.stub.samples if mts <= s["ts"] < mts + 60]

        def a(k):
            return sum(s[k] for s in stubs) / len(stubs) if stubs else None
        self.db.execute(
            "INSERT OR REPLACE INTO system_minute(ts,cpu,mem,swap,load1,load5,load15,disk,net_rx,net_tx,disk_r,disk_w,"
            "conn_active,conn_reading,conn_writing,conn_waiting,nginx_rss,nginx_cpu,nginx_workers,nginx_fds) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (mts, avg["cpu"], avg["mem"], avg["swap"], avg["load1"], avg["load5"], avg["load15"], avg["disk"],
             avg["net_rx"], avg["net_tx"], avg["disk_r"], avg["disk_w"], a("active"), a("reading"), a("writing"),
             a("waiting"), avg["nginx_rss"], avg["nginx_cpu"], avg["nginx_workers"], avg["nginx_fds"]))

    def cleanup(self) -> Dict[str, int]:
        p = self.get_panel()
        now = time.time()
        res = {}
        plan = [
            ("requests", "ts", now - p.requests_retention_hours * 3600),
            ("stats_minute", "ts", now - p.minute_retention_days * 86400),
            ("stats_hour", "ts", now - p.hour_retention_days * 86400),
            ("top_hour", "ts", now - p.top_retention_days * 86400),
            ("top_day", "ts", now - max(p.hour_retention_days, 30) * 86400),
            ("errors", "ts", now - p.errors_retention_days * 86400),
            ("system_minute", "ts", now - p.system_retention_days * 86400),
            ("stream_minute", "ts", now - p.minute_retention_days * 86400),
            ("health_minute", "ts", now - p.minute_retention_days * 86400),
            ("audit_log", "ts", now - 365 * 86400),
            ("events", "ts", now - 90 * 86400),
            ("alert_events", "ts", now - 180 * 86400),
            ("sessions", "expires_at", now),
        ]
        for table, col, cut in plan:
            with self.db.write_lock:
                cur = self.db.conn().execute(f"DELETE FROM {table} WHERE {col} < ?", (cut,))
                res[table] = cur.rowcount
        cnt = self.db.scalar("SELECT COUNT(*) FROM requests") or 0
        if cnt > p.requests_max_rows:
            extra = cnt - p.requests_max_rows
            with self.db.write_lock:
                self.db.conn().execute(
                    "DELETE FROM requests WHERE id IN (SELECT id FROM requests ORDER BY id LIMIT ?)", (extra,))
            res["requests_overflow"] = extra
        # незакрытые дневные топы (если сервис не работал на смене суток)
        last_day = int(now) // 86400 * 86400 - 86400
        if not self.db.scalar("SELECT 1 FROM top_day WHERE ts=? LIMIT 1", (last_day,)) and \
                self.db.scalar("SELECT 1 FROM top_hour WHERE ts>=? AND ts<? LIMIT 1", (last_day, last_day + 86400)):
            self.agg.rollup_day(last_day)
        if sum(res.values()) > 100000:
            with self.db.write_lock:
                self.db.conn().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return res

    # =====================================================================
    #  Снимок для дашборда/WebSocket
    # =====================================================================
    def snapshot(self) -> Dict[str, Any]:
        # последняя «полная» секунда: журнал nginx буферизуется до 1 с, плюс интервал чтения
        t = int(time.time()) - 3
        w1 = self.agg.window(1, "*", t + 1)
        w1["ts"] = t
        w10 = self.agg.window(10, "*", t + 1)
        w60 = self.agg.window(60, "*", t + 1)
        return {"ts": time.time(), "now": w1, "w10": w10, "w60": w60, "stub": self.stub.latest(),
                "system": self.system.latest(), "sites": self.agg.per_site_now(10)}

    def collector_info(self) -> Dict[str, Any]:
        return {"tailers": [t.info() for t in self.tailers], "parsed": self.agg.parsed,
                "parse_errors": self.agg.parse_errors, "stub": self.stub.latest(), "uptime": time.time() - self.started,
                "geoip": {"enabled": bool(self.geoip.reader), "path": self.geoip.path, "error": self.geoip.error},
                "pending_requests": len(self.agg.req_buffer), "open_minutes": len(self.agg.mins)}

    # =====================================================================
    #  История
    # =====================================================================
    def timeseries(self, start: float, end: float, site: str = "*", points: int = 240) -> Dict[str, Any]:
        span = max(60, end - start)
        table, base = ("stats_minute", 60) if span <= 48 * 3600 else ("stats_hour", 3600)
        step = max(base, int(span / points) // base * base or base)
        rows = self.db.query(f"SELECT * FROM {table} WHERE site=? AND ts>=? AND ts<? ORDER BY ts",
                             (site, int(start) // base * base, int(end)))
        buckets: Dict[int, Dict[str, Any]] = {}
        for r in rows:
            b = int(r["ts"]) // step * step
            cur = buckets.get(b)
            data = json.loads(r["data"] or "{}")
            if cur is None:
                buckets[b] = {**{k: r[k] for k in ("req", "bout", "bin", "s1", "s2", "s3", "s4", "s5", "rt_sum",
                                                    "rt_max", "urt_sum", "urt_n", "uniq")}, "data": data}
            else:
                for k in ("req", "bout", "bin", "s1", "s2", "s3", "s4", "s5", "rt_sum", "urt_sum", "urt_n", "uniq"):
                    cur[k] += r[k]
                cur["rt_max"] = max(cur["rt_max"], r["rt_max"])
                cur["data"] = merge_data(cur["data"], data)
        out: Dict[str, List] = {k: [] for k in ("ts", "req", "rps", "bout", "bin", "bps_out", "bps_in", "s1", "s2",
                                                 "s3", "s4", "s5", "rt_avg", "p50", "p90", "p95", "p99", "rt_max",
                                                 "urt_avg", "uniq", "hit_ratio", "bots", "errors", "err_pct")}
        t = int(start) // step * step
        while t < end:
            b = buckets.get(t)
            out["ts"].append(t)
            if not b:
                for k in list(out)[1:]:
                    out[k].append(0)
                t += step
                continue
            n = b["req"]
            d = b["data"]
            hist = d.get("hist") or [0] * NB
            cache = d.get("cache") or {}
            cacheable = sum(cache.values())
            out["req"].append(n)
            out["rps"].append(round(n / step, 3))
            out["bout"].append(b["bout"])
            out["bin"].append(b["bin"])
            out["bps_out"].append(round(b["bout"] * 8 / step, 1))
            out["bps_in"].append(round(b["bin"] * 8 / step, 1))
            for i in range(1, 6):
                out[f"s{i}"].append(b[f"s{i}"])
            out["rt_avg"].append(round(b["rt_sum"] / n * 1000, 1) if n else 0)
            for q, k in ((0.5, "p50"), (0.9, "p90"), (0.95, "p95"), (0.99, "p99")):
                out[k].append(round(percentile(hist, q) * 1000, 1))
            out["rt_max"].append(round(b["rt_max"] * 1000, 1))
            out["urt_avg"].append(round(b["urt_sum"] / b["urt_n"] * 1000, 1) if b["urt_n"] else 0)
            out["uniq"].append(b["uniq"])
            out["hit_ratio"].append(round(cache.get("HIT", 0) / cacheable * 100, 1) if cacheable else 0)
            out["bots"].append(d.get("bots", 0))
            out["errors"].append(sum((d.get("err") or {}).values()))
            out["err_pct"].append(round((b["s5"]) / n * 100, 2) if n else 0)
            t += step
        out["step"] = step  # type: ignore[assignment]
        out["source"] = table  # type: ignore[assignment]
        return out

    def summary(self, start: float, end: float, site: str = "*", exact_uniq: bool = True) -> Dict[str, Any]:
        span = end - start
        table = "stats_minute" if span <= 48 * 3600 else "stats_hour"
        base = 60 if table == "stats_minute" else 3600
        rows = self.db.query(f"SELECT * FROM {table} WHERE site=? AND ts>=? AND ts<?",
                             (site, int(start) // base * base, int(end)))
        t = {k: 0 for k in ("req", "bout", "bin", "s1", "s2", "s3", "s4", "s5", "urt_n", "uniq")}
        t.update(rt_sum=0.0, urt_sum=0.0)
        data: Dict[str, Any] = {}
        for r in rows:
            for k in t:
                t[k] += r[k]
            data = merge_data(data, json.loads(r["data"] or "{}"))
        # ещё не записанные в БД (открытые) минуты
        for mts, mb in list(self.agg.mins.items()):
            m = mb.get(site)
            if not m or not (start <= mts < end):
                continue
            t["req"] += m.req
            t["bout"] += m.bout
            t["bin"] += m.bin
            for i in range(1, 6):
                t[f"s{i}"] += m.s[i]
            t["rt_sum"] += m.rt_sum
            t["urt_sum"] += m.urt_sum
            t["urt_n"] += m.urt_n
            data = merge_data(data, m.data())
        res = self._summary_from(t, data, span, table)
        fallback = t["uniq"]
        if span >= 3600:
            fallback = self.db.scalar("SELECT SUM(uniq) FROM stats_hour WHERE site=? AND ts>=? AND ts<?",
                                      (site, int(start) // 3600 * 3600, int(end))) or fallback
        if exact_uniq:
            res["uniq"], res["uniq_exact"] = self.unique_ips(start, end, site, fallback)
        else:
            res["uniq"], res["uniq_exact"] = fallback, False
        return res

    def unique_ips(self, start: float, end: float, site: str, fallback: int):
        """Точное число уникальных IP по журналу запросов (если он хранится за этот период)."""
        p = self.get_panel()
        oldest = self.db.scalar("SELECT MIN(ts) FROM requests")
        if p.store_requests and p.requests_sample <= 1 and oldest and oldest <= start + 120:
            if site == "*":
                n = self.db.scalar("SELECT COUNT(DISTINCT ip) FROM requests WHERE ts>=? AND ts<?", (start, end))
            else:
                n = self.db.scalar("SELECT COUNT(DISTINCT ip) FROM requests WHERE site=? AND ts>=? AND ts<?",
                                   (site, start, end))
            return n or 0, True
        return fallback, False

    @staticmethod
    def _summary_from(t: Dict[str, Any], data: Dict[str, Any], span: float, source: str) -> Dict[str, Any]:
        n = t["req"]
        hist = data.get("hist") or [0] * NB
        cache = data.get("cache") or {}
        cacheable = sum(cache.values())
        err = data.get("err") or {}
        return {
            "source": source, "requests": n, "rps": n / span if span else 0, "bytes_out": t["bout"],
            "bytes_in": t["bin"], "status": {f"{i}xx": t[f"s{i}"] for i in range(1, 6)},
            "err5_pct": t["s5"] / n * 100 if n else 0, "err4_pct": t["s4"] / n * 100 if n else 0,
            "rt_avg": t["rt_sum"] / n * 1000 if n else 0,
            "p50": percentile(hist, 0.5) * 1000, "p90": percentile(hist, 0.9) * 1000,
            "p95": percentile(hist, 0.95) * 1000, "p99": percentile(hist, 0.99) * 1000,
            "urt_avg": t["urt_sum"] / t["urt_n"] * 1000 if t["urt_n"] else 0, "uniq": t["uniq"],
            "codes": data.get("codes", {}), "methods": data.get("methods", {}), "proto": data.get("proto", {}),
            "tls": data.get("tls", {}), "cache": cache,
            "hit_ratio": cache.get("HIT", 0) / cacheable * 100 if cacheable else 0,
            "hist": {"labels": LAT_LABELS, "values": hist},
            "bots": data.get("bots", 0), "slow": data.get("slow", 0), "static": data.get("static", 0),
            "errors": {k: {"count": v, **CATEGORY_INFO.get(k, CATEGORY_INFO["other"])} for k, v in
                       sorted(err.items(), key=lambda x: -x[1])},
            "upstream_status": data.get("ustatus", {}),
        }

    def tops(self, start: float, end: float, site: str, kind: str, limit: int = 50) -> List[Dict[str, Any]]:
        span = end - start
        # в памяти — поминутные топы последнего часа (если сервис работал весь этот период)
        if span <= 3600 + 60 and end >= time.time() - 120 and self.started <= start + 60:
            return self.agg.recent_tops(int(span // 60) or 1, site, kind, limit)
        table = "top_hour" if span <= self.get_panel().top_retention_days * 86400 else "top_day"
        base = 3600 if table == "top_hour" else 86400
        rows = self.db.query(
            f"SELECT key, SUM(cnt) c, SUM(bytes) b, SUM(extra) e FROM {table} WHERE site=? AND kind=? AND ts>=? "
            f"AND ts<? GROUP BY key ORDER BY c DESC LIMIT ?",
            (site, kind, int(start) // base * base, int(end), limit))
        out = []
        for r in rows:
            item = {"key": r["key"], "count": r["c"], "bytes": r["b"]}
            if kind == "slow":
                item["avg_ms"] = round(r["e"] / r["c"] * 1000, 1) if r["c"] else 0
            out.append(item)
        return out

    def compare_sites(self, start: float, end: float) -> List[Dict[str, Any]]:
        span = end - start
        table = "stats_minute" if span <= 48 * 3600 else "stats_hour"
        rows = self.db.query(
            f"SELECT site, SUM(req) req, SUM(bout) bout, SUM(s4) s4, SUM(s5) s5, SUM(rt_sum) rt_sum, "
            f"MAX(uniq) uniq FROM {table} WHERE ts>=? AND ts<? AND site != '*' GROUP BY site ORDER BY req DESC",
            (int(start), int(end)))
        for r in rows:
            n = r["req"]
            r["rt_avg"] = r["rt_sum"] / n * 1000 if n else 0
            r["err5_pct"] = r["s5"] / n * 100 if n else 0
        return rows

    def system_series(self, start: float, end: float) -> Dict[str, List]:
        span = end - start
        if span <= 1200:
            xs = [s for s in self.system.samples if s["ts"] >= start]
            stubs = {int(s["ts"]): s for s in self.stub.samples}
            out: Dict[str, List] = {k: [] for k in ("ts", "cpu", "mem", "load1", "disk", "net_rx", "net_tx", "disk_r",
                                                     "disk_w", "nginx_rss", "nginx_cpu", "conn_active",
                                                     "conn_reading", "conn_writing", "conn_waiting")}
            for s in xs:
                out["ts"].append(s["ts"])
                for k in ("cpu", "mem", "load1", "disk", "net_rx", "net_tx", "disk_r", "disk_w", "nginx_rss",
                          "nginx_cpu"):
                    out[k].append(round(s.get(k, 0), 2))
                st = stubs.get(int(s["ts"])) or stubs.get(int(s["ts"]) - 1) or {}
                for k in ("active", "reading", "writing", "waiting"):
                    out["conn_" + k].append(st.get(k, None))
            return out
        rows = self.db.query("SELECT * FROM system_minute WHERE ts>=? AND ts<? ORDER BY ts", (int(start), int(end)))
        step = max(60, int(span / 300) // 60 * 60)
        agg: Dict[int, List[dict]] = {}
        for r in rows:
            agg.setdefault(int(r["ts"]) // step * step, []).append(r)
        keys = ("cpu", "mem", "load1", "disk", "net_rx", "net_tx", "disk_r", "disk_w", "nginx_rss", "nginx_cpu",
                "conn_active", "conn_reading", "conn_writing", "conn_waiting")
        out = {k: [] for k in ("ts",) + keys}
        for t in sorted(agg):
            rs = agg[t]
            out["ts"].append(t)
            for k in keys:
                vals = [r[k] for r in rs if r[k] is not None]
                out[k].append(round(sum(vals) / len(vals), 2) if vals else None)
        return out

    def stream_series(self, start: float, end: float) -> Dict[str, Any]:
        rows = self.db.query("SELECT stream, SUM(sessions) sessions, SUM(bytes_in) bin, SUM(bytes_out) bout, "
                             "SUM(dur_sum) dur, SUM(errors) errors FROM stream_minute WHERE ts>=? AND ts<? "
                             "GROUP BY stream", (int(start), int(end)))
        series = self.db.query("SELECT ts, stream, sessions, bytes_in, bytes_out FROM stream_minute "
                               "WHERE ts>=? AND ts<? ORDER BY ts", (int(start), int(end)))
        return {"totals": rows, "series": series, "live": list(self.agg.stream_live)[-100:]}

    # ---------------------------------------------------------------------
    def search_requests(self, f: Dict[str, Any], limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        where, params = ["1=1"], []
        if f.get("start"):
            where.append("ts >= ?")
            params.append(float(f["start"]))
        if f.get("end"):
            where.append("ts < ?")
            params.append(float(f["end"]))
        if f.get("site") and f["site"] != "*":
            where.append("site = ?")
            params.append(str(f["site"]))
        if f.get("status"):
            st = str(f["status"])
            if st.endswith("xx") and st[0].isdigit():
                where.append("status >= ? AND status < ?")
                params += [int(st[0]) * 100, int(st[0]) * 100 + 100]
            elif st.isdigit():
                where.append("status = ?")
                params.append(int(st))
        if f.get("ip"):
            where.append("ip = ?")
            params.append(f["ip"])
        if f.get("method"):
            where.append("method = ?")
            params.append(f["method"].upper())
        if f.get("uri"):
            where.append("uri LIKE ?")
            params.append(f"%{f['uri']}%")
        if f.get("ua"):
            where.append("ua LIKE ?")
            params.append(f"%{f['ua']}%")
        if f.get("host"):
            where.append("host LIKE ?")
            params.append(f"%{f['host']}%")
        if f.get("min_rt"):
            where.append("rt >= ?")
            params.append(float(f["min_rt"]) / 1000)
        if f.get("upstream"):
            where.append("upstream LIKE ?")
            params.append(f"%{f['upstream']}%")
        if f.get("country"):
            where.append("country = ?")
            params.append(f["country"].upper())
        if f.get("rid"):
            where.append("rid = ?")
            params.append(f["rid"])
        w = " AND ".join(where)
        order = "rt DESC" if f.get("sort") == "rt" else "bytes DESC" if f.get("sort") == "bytes" else "id DESC"
        rows = self.db.query(f"SELECT * FROM requests WHERE {w} ORDER BY {order} LIMIT ? OFFSET ?",
                             params + [limit, offset])
        total = self.db.scalar(f"SELECT COUNT(*) FROM (SELECT 1 FROM requests WHERE {w} LIMIT 100000)", params)
        return {"items": rows, "total": total, "limit": limit, "offset": offset}

    def search_errors(self, f: Dict[str, Any], limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        where, params = ["1=1"], []
        if f.get("start"):
            where.append("ts >= ?")
            params.append(float(f["start"]))
        if f.get("end"):
            where.append("ts < ?")
            params.append(float(f["end"]))
        for k in ("level", "category", "site"):
            if f.get(k):
                where.append(f"{k} = ?")
                params.append(f[k])
        if f.get("q"):
            where.append("(message LIKE ? OR request LIKE ? OR client LIKE ? OR upstream LIKE ?)")
            params += [f"%{f['q']}%"] * 4
        w = " AND ".join(where)
        rows = self.db.query(f"SELECT * FROM errors WHERE {w} ORDER BY id DESC LIMIT ? OFFSET ?",
                             params + [limit, offset])
        total = self.db.scalar(f"SELECT COUNT(*) FROM errors WHERE {w}", params)
        cats = self.db.query(f"SELECT category, COUNT(*) n FROM errors WHERE {w} GROUP BY category ORDER BY n DESC",
                             params)
        for c in cats:
            c.update(CATEGORY_INFO.get(c["category"], CATEGORY_INFO["other"]))
        for r in rows:
            r["hint"] = CATEGORY_INFO.get(r["category"], {}).get("hint", "")
            r["title"] = CATEGORY_INFO.get(r["category"], {}).get("title", "")
        return {"items": rows, "total": total, "categories": cats}
