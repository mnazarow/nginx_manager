"""Сбор статистики в реальном времени.

Поток данных:
  nginx → nm-access.log (JSON) ─┐
  nginx → nm-error.log         ─┼→ LogTailer (чтение «хвоста», учёт ротации) → Aggregator
  nginx → nm-stream.log (JSON) ─┘
  stub_status (127.0.0.1:8089) → StubPoller ─┐
  psutil                        → SystemPoller ─┴→ кольцевые буферы (последние минуты)

Aggregator держит:
  * посекундные корзины за последние 10 минут (графики «реального времени», WebSocket);
  * поминутные агрегаты, которые через ~10 с после окончания минуты пишутся в stats_minute и
    сливаются в stats_hour;
  * топы (URI, IP, User-Agent, рефереры, страны, ошибки, медленные URI) — в памяти по минутам
    (последний час) и в БД по часам/дням;
  * кольцо последних запросов и ошибок для «живых» журналов.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import Counter, OrderedDict, deque
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from ..db import Database
from .parsing import (LAT_BOUNDS, GeoIP, bucket, classify_ua, parse_access, parse_error, parse_stream,
                      referer_domain)

log = logging.getLogger("nm.stats")

NB = len(LAT_BOUNDS) + 1
TOP_KINDS = ("uri", "ip", "ua", "referer", "browser", "os", "device", "country", "upstream", "e4xx", "e5xx",
             "slow", "host")


# =============================================================================
#  Чтение журналов
# =============================================================================
class LogTailer:
    def __init__(self, path: Path, name: str, db: Database, on_lines: Callable[[List[str]], None],
                 interval: float = 0.25) -> None:
        self.path = Path(path)
        self.name = name
        self.db = db
        self.on_lines = on_lines
        self.interval = interval
        self.f = None
        self.ino = None
        self.pos = 0
        self.partial = b""
        self.lines_total = 0
        self.errors = 0
        self.last_line_ts = 0.0
        self.status = "starting"
        self._last_save = 0.0

    def _open(self, from_start: bool) -> bool:
        try:
            f = open(self.path, "rb")
        except OSError:
            self.status = "файл не найден"
            return False
        st = os.fstat(f.fileno())
        saved = self.db.kv_get(f"tail:{self.name}") or {}
        if self.f is None and saved.get("ino") == st.st_ino and saved.get("pos", 0) <= st.st_size:
            pos = saved["pos"]
            # не «догоняем» слишком большой хвост после долгого простоя
            if st.st_size - pos > 200 * 1024 * 1024:
                pos = st.st_size
        else:
            pos = 0 if from_start else st.st_size
        if self.f:
            self.f.close()
        self.f, self.ino = f, st.st_ino
        self.f.seek(pos)
        self.pos = pos
        self.partial = b""
        self.status = "ok"
        return True

    def _read(self, budget: int = 1024 * 1024) -> bool:
        """Прочитать и обработать до budget байт. Возвращает True, если в файле, вероятно, есть ещё данные
        (вызывающий отдаёт управление циклу событий и продолжает — так WebSocket и API не «замирают»
        при всплесках трафика и дочитывании накопившегося журнала после перезапуска)."""
        if not self.f:
            return False
        chunk_total = 0
        while chunk_total < budget:
            data = self.f.read(256 * 1024)
            if not data:
                return False
            chunk_total += len(data)
            self.pos += len(data)
            data = self.partial + data
            *lines, self.partial = data.split(b"\n")
            if lines:
                decoded = [ln.decode("utf-8", "replace") for ln in lines]
                self.lines_total += len(decoded)
                self.last_line_ts = time.time()
                try:
                    self.on_lines(decoded)
                except Exception:  # pragma: no cover
                    self.errors += 1
                    log.exception("ошибка обработки строк журнала %s", self.name)
        return True

    async def run(self) -> None:
        first = True
        while True:
            try:
                if self.f is None:
                    if not self._open(from_start=not first):
                        await asyncio.sleep(2)
                        continue
                    first = False
                rounds = 0
                while self._read() and rounds < 64:  # не более ~64 МБ за проход, между порциями — другие задачи
                    rounds += 1
                    await asyncio.sleep(0)
                # ротация / усечение
                try:
                    st = os.stat(self.path)
                    if st.st_ino != self.ino:
                        while self._read():  # дочитать старый файл
                            await asyncio.sleep(0)
                        self.db.kv_set(f"tail:{self.name}", {})
                        self.f.close()
                        self.f = None
                        self._open(from_start=True)
                        continue
                    if st.st_size < self.pos:
                        self.f.seek(0)
                        self.pos = 0
                        self.partial = b""
                except FileNotFoundError:
                    self.status = "файл удалён (ожидание ротации)"
                now = time.time()
                if now - self._last_save > 5:
                    self._last_save = now
                    self.db.kv_set(f"tail:{self.name}", {"ino": self.ino, "pos": self.pos})
            except asyncio.CancelledError:
                if self.ino:
                    self.db.kv_set(f"tail:{self.name}", {"ino": self.ino, "pos": self.pos})
                raise
            except Exception:  # pragma: no cover
                self.errors += 1
                log.exception("ошибка чтения %s", self.path)
                await asyncio.sleep(2)
            await asyncio.sleep(self.interval)

    def info(self) -> Dict[str, Any]:
        size = 0
        try:
            size = os.path.getsize(self.path)
        except OSError:
            pass
        return {"name": self.name, "path": str(self.path), "status": self.status, "lines": self.lines_total,
                "errors": self.errors, "pos": self.pos, "size": size, "lag_bytes": max(0, size - self.pos),
                "last_line": self.last_line_ts}


# =============================================================================
#  Агрегаты
# =============================================================================
class Sec:
    __slots__ = ("req", "bout", "bin", "s", "rt_sum", "urt_sum", "urt_n", "hist", "hit")

    def __init__(self) -> None:
        self.req = self.bout = self.bin = self.urt_n = self.hit = 0
        self.s = [0] * 6
        self.rt_sum = self.urt_sum = 0.0
        self.hist = [0] * NB


class Minute:
    __slots__ = ("req", "bout", "bin", "s", "rt_sum", "rt_max", "urt_sum", "urt_n", "hist", "codes", "methods",
                 "proto", "tls", "cache", "err", "ips", "bots", "slow", "static", "tops", "top_bytes", "slow_sum",
                 "ustatus", "blk", "blkc")

    def __init__(self) -> None:
        self.req = self.bout = self.bin = self.urt_n = self.bots = self.slow = self.static = 0
        self.s = [0] * 6
        self.rt_sum = self.rt_max = self.urt_sum = 0.0
        self.hist = [0] * NB
        self.codes: Counter = Counter()
        self.methods: Counter = Counter()
        self.proto: Counter = Counter()
        self.tls: Counter = Counter()
        self.cache: Counter = Counter()
        self.err: Counter = Counter()
        self.ustatus: Counter = Counter()
        self.ips: set = set()
        self.tops: Dict[str, Counter] = {k: Counter() for k in TOP_KINDS}
        self.top_bytes: Dict[str, Counter] = {"uri": Counter(), "ip": Counter(), "host": Counter()}
        self.slow_sum: Counter = Counter()
        self.blk: Counter = Counter()  # отклонено блокировками: ban — по IP, geo — по странам
        self.blkc: Counter = Counter()  # коды ответов отклонённых блокировками (403, 444, 451…)

    def data(self) -> Dict[str, Any]:
        d = {"codes": dict(self.codes), "hist": self.hist, "methods": dict(self.methods),
             "proto": dict(self.proto), "tls": dict(self.tls), "cache": dict(self.cache), "err": dict(self.err),
             "bots": self.bots, "slow": self.slow, "static": self.static, "ustatus": dict(self.ustatus)}
        if self.blk:
            d["blk"] = dict(self.blk)
            d["blkc"] = dict(self.blkc)
        return d


class Totals:
    """Накопительные счётчики сайта с момента запуска панели (counter-метрики Prometheus)."""
    __slots__ = ("req", "s", "bin", "bout", "rt_sum", "hist", "cache", "banned", "geo")

    def __init__(self) -> None:
        self.req = self.bin = self.bout = self.banned = self.geo = 0
        self.s = [0] * 6
        self.rt_sum = 0.0
        self.hist = [0] * NB
        self.cache: Counter = Counter()

    def add(self, cls: int, bin_: int, bout: int, rt: float, hb: int, cache: str, banned: bool,
            geo: bool = False) -> None:
        self.req += 1
        self.s[cls] += 1
        self.bin += bin_
        self.bout += bout
        self.rt_sum += rt
        self.hist[hb] += 1
        if cache:
            self.cache[cache] += 1
        if banned:
            self.banned += 1
        elif geo:
            self.geo += 1


def merge_data(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict):
            d = dict(out.get(k) or {})
            for kk, vv in v.items():
                d[kk] = d.get(kk, 0) + vv
            out[k] = d
        elif isinstance(v, list):
            cur = out.get(k) or [0] * len(v)
            out[k] = [x + y for x, y in zip(cur + [0] * (len(v) - len(cur)), v)]
        elif isinstance(v, (int, float)):
            out[k] = out.get(k, 0) + v
    return out


def percentile(hist: List[int], q: float) -> float:
    """Перцентиль по гистограмме (линейная интерполяция внутри корзины), секунды."""
    total = sum(hist)
    if not total:
        return 0.0
    target = total * q
    acc = 0
    lo = 0.0
    for i, n in enumerate(hist):
        hi = LAT_BOUNDS[i] if i < len(LAT_BOUNDS) else LAT_BOUNDS[-1] * 2
        if acc + n >= target and n:
            return lo + (hi - lo) * ((target - acc) / n)
        acc += n
        lo = hi
    return LAT_BOUNDS[-1]


class Aggregator:
    def __init__(self, db: Database, get_settings: Callable[[], Any], geoip: GeoIP) -> None:
        self.db = db
        self.get_settings = get_settings
        self.geoip = geoip
        self.secs: "OrderedDict[int, Dict[str, Sec]]" = OrderedDict()
        self.mins: Dict[int, Dict[str, Minute]] = {}
        self.recent: Deque[Tuple[int, Dict[str, Minute]]] = deque(maxlen=75)  # последние ~час минут (для топов)
        self.hour_ips: Dict[str, set] = {}
        self.hour_tops: Dict[str, Dict[str, Counter]] = {}
        self.hour_top_bytes: Dict[str, Dict[str, Counter]] = {}
        self.hour_slow_sum: Dict[str, Counter] = {}
        self.cur_hour = 0
        self.live: Deque[Tuple[int, Dict[str, Any]]] = deque(maxlen=3000)
        self.live_seq = 0
        self.err_live: Deque[Tuple[int, Dict[str, Any]]] = deque(maxlen=1000)
        self.err_seq = 0
        self.req_buffer: List[tuple] = []
        self.err_buffer: List[tuple] = []
        self.stream_min: Dict[int, Dict[str, List[float]]] = {}
        self.stream_live: Deque[Dict[str, Any]] = deque(maxlen=500)
        self.parsed = self.parse_errors = 0
        self.sample_counter = 0
        self.domain_map: Dict[str, str] = {}
        self.stream_port_map: Dict[Tuple[int, str], str] = {}
        self.last_flush_hour_tops = 0.0
        self.passive_upstream: Counter = Counter()  # ошибки соединения к бэкендам из error.log
        self.detector = None  # BanDetector (раздел «Блокировки»), подключается ядром
        # накопительные счётчики с момента запуска (для /metrics в формате Prometheus)
        self.totals: Dict[str, Totals] = {}
        self.geo_hits: Counter = Counter()  # (сайт, страна) -> отклонено по странам с запуска панели

    # ------------------------------------------------------------------
    def _sec(self, ts: int) -> Optional[Dict[str, Sec]]:
        b = self.secs.get(ts)
        if b is None:
            now = int(time.time())
            if ts < now - 600 or ts > now + 5:
                return None
            b = self.secs[ts] = {}
            if len(self.secs) > 1:
                last = next(reversed(self.secs))
                if last != ts:  # вставка не по порядку (поздние строки) — переупорядочим
                    self.secs = OrderedDict(sorted(self.secs.items()))
            while self.secs and next(iter(self.secs)) < now - 600:
                self.secs.popitem(last=False)
        return b

    def ingest_access(self, lines: List[str]) -> None:
        ps = self.get_settings()
        slow_thr = ps.slow_request_ms / 1000.0
        for line in lines:
            r = parse_access(line)
            if r is None:
                if line.strip():
                    self.parse_errors += 1
                continue
            self.parsed += 1
            self._ingest(r, ps, slow_thr)

    def _ingest(self, r: Dict[str, Any], ps, slow_thr: float) -> None:
        ts = r["ts"]
        sec_ts, min_ts = int(ts), int(ts) // 60 * 60
        site = r["site"] if r["site"] not in ("", "-") else "-"
        status = r["status"]
        cls = min(status // 100, 5) if status >= 100 else 0
        rt = r["rt"]
        hb = bucket(rt)
        browser, os_, device, is_bot = classify_ua(r["ua"])
        country = self.geoip.country(r["ip"]) if ps.geoip_enabled and self.geoip.reader else ""
        r["country"] = country
        r["bot"] = is_bot
        keys = (site, "*") if site != "*" else ("*",)
        geo_blocked = r.get("geo_blocked", False) and not r["banned"]
        if geo_blocked:
            # уже отклонён правилом по странам — не нарушитель для автоблокировки
            self.geo_hits[(site, country or "--")] += 1
        elif self.detector is not None and site != "panel":
            self.detector.observe(r["ip"], ts, status, r["uri"], site, is_bot, r["banned"], country, r["host"])
        tot = self.totals.get(site)
        if tot is None:
            tot = self.totals[site] = Totals()
        tot.add(cls, r["bin"], r["bout"], rt, hb, r["cache"], r["banned"], geo_blocked)
        sb = self._sec(sec_ts)
        if sb is not None:
            for k in keys:
                s = sb.get(k)
                if s is None:
                    s = sb[k] = Sec()
                s.req += 1
                s.bout += r["bout"]
                s.bin += r["bin"]
                s.s[cls] += 1
                s.rt_sum += rt
                s.hist[hb] += 1
                if r["has_upstream"]:
                    s.urt_sum += r["urt"]
                    s.urt_n += 1
                if r["cache"] == "HIT":
                    s.hit += 1
        mb = self.mins.get(min_ts)
        if mb is None:
            mb = self.mins[min_ts] = {}
        ref = referer_domain(r["ref"], r["host"])
        for k in keys:
            m = mb.get(k)
            if m is None:
                m = mb[k] = Minute()
            m.req += 1
            m.bout += r["bout"]
            m.bin += r["bin"]
            m.s[cls] += 1
            m.rt_sum += rt
            if rt > m.rt_max:
                m.rt_max = rt
            m.hist[hb] += 1
            m.codes[str(status)] += 1
            m.methods[r["method"]] += 1
            m.proto[r["proto"] or "-"] += 1
            if r["tls"]:
                m.tls[r["tls"]] += 1
            if r["cache"]:
                m.cache[r["cache"]] += 1
            if r["has_upstream"]:
                m.urt_sum += r["urt"]
                m.urt_n += 1
                if r["ustatus"]:
                    m.ustatus[r["ustatus"].split(",")[-1].strip().split(":")[-1].strip()] += 1
            if len(m.ips) < 100000:
                m.ips.add(r["ip"])
            if is_bot:
                m.bots += 1
            if r["banned"]:
                m.blk["ban"] += 1
                m.blkc[str(status)] += 1
            elif geo_blocked:
                m.blk["geo"] += 1
                m.blkc[str(status)] += 1
            if r["static"]:
                m.static += 1
            t = m.tops
            t["uri"][r["path"]] += 1
            m.top_bytes["uri"][r["path"]] += r["bout"]
            t["ip"][r["ip"]] += 1
            m.top_bytes["ip"][r["ip"]] += r["bout"]
            t["host"][r["host"]] += 1
            m.top_bytes["host"][r["host"]] += r["bout"]
            t["ua"][r["ua"][:200]] += 1
            t["browser"][browser] += 1
            t["os"][os_] += 1
            t["device"][device] += 1
            if ref:
                t["referer"][ref] += 1
            if country:
                t["country"][country] += 1
            if r["upstream"]:
                t["upstream"][r["upstream"]] += 1
            if 400 <= status < 500:
                t["e4xx"][f"{status} {r['path']}"] += 1
            elif status >= 500:
                t["e5xx"][f"{status} {r['path']}"] += 1
            if rt >= slow_thr:
                m.slow += 1
                t["slow"][r["path"]] += 1
                m.slow_sum[r["path"]] += rt
        # «живой» журнал
        self.live_seq += 1
        item = {"seq": self.live_seq, "ts": ts, "site": site, "host": r["host"], "ip": r["ip"], "m": r["method"],
                "u": r["uri"][:500], "s": status, "b": r["bout"], "rt": round(rt, 4), "urt": round(r["urt"], 4),
                "up": r["upstream"], "us": r["ustatus"], "ref": r["ref"][:300], "ua": r["ua"][:300],
                "cache": r["cache"], "tls": r["tls"], "proto": r["proto"], "cc": country, "bot": is_bot,
                "rid": r["rid"]}
        self.live.append((self.live_seq, item))
        # журнал запросов в БД
        if ps.store_requests and not (ps.skip_static_in_log and r["static"]):
            self.sample_counter += 1
            if ps.requests_sample <= 1 or self.sample_counter % ps.requests_sample == 0:
                self.req_buffer.append((ts, site, r["host"][:200], r["ip"], r["method"], r["uri"][:2000], r["proto"],
                                        status, r["bout"], rt, r["urt"] if r["has_upstream"] else None,
                                        r["upstream"], r["ustatus"], r["ref"][:500], r["ua"][:500], r["cache"],
                                        r["tls"], country, r["rid"]))

    # ------------------------------------------------------------------
    def ingest_errors(self, lines: List[str]) -> None:
        for line in lines:
            e = parse_error(line)
            if not e:
                continue
            site = self.domain_map.get(e["server"]) or self.domain_map.get(e["host"]) or ""
            e["site"] = site
            mts = int(e["ts"]) // 60 * 60
            mb = self.mins.setdefault(mts, {})
            for k in ((site, "*") if site else ("*",)):
                m = mb.get(k)
                if m is None:
                    m = mb[k] = Minute()
                m.err[e["category"]] += 1
            if e["upstream"] and e["category"] in ("upstream_refused", "upstream_timeout", "upstream_unreachable",
                                                   "upstream_reset", "upstream_closed"):
                try:
                    from urllib.parse import urlsplit
                    u = urlsplit(e["upstream"])
                    self.passive_upstream[f"{u.hostname}:{u.port or 80}"] += 1
                except ValueError:
                    pass
            self.err_seq += 1
            self.err_live.append((self.err_seq, {"seq": self.err_seq, **e}))
            self.err_buffer.append((e["ts"], e["level"], e["category"], e["message"], e["client"], e["server"],
                                    site, e["request"][:1000], e["upstream"], e["host"]))

    def ingest_stream(self, lines: List[str]) -> None:
        for line in lines:
            r = parse_stream(line)
            if not r:
                continue
            sid = self.stream_port_map.get((r["port"], r["proto"].upper())) or \
                self.stream_port_map.get((r["port"], "TCP")) or f"port:{r['port']}"
            mts = int(r["ts"]) // 60 * 60
            mb = self.stream_min.setdefault(mts, {})
            row = mb.setdefault(sid, [0, 0, 0, 0.0, 0])
            row[0] += 1
            row[1] += r["bin"]
            row[2] += r["bout"]
            row[3] += r["dur"]
            if r["status"] != 200:
                row[4] += 1
            self.stream_live.append({**r, "stream": sid})

    # ------------------------------------------------------------------
    #  Сброс в БД
    # ------------------------------------------------------------------
    def flush(self, force: bool = False) -> None:
        now = time.time()
        if self.req_buffer:
            buf, self.req_buffer = self.req_buffer, []
            try:
                self.db.executemany(
                    "INSERT INTO requests(ts,site,host,ip,method,uri,proto,status,bytes,rt,urt,upstream,ustatus,"
                    "ref,ua,cache,tls,country,rid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", buf)
            except Exception:
                log.exception("запись журнала запросов")
        if self.err_buffer:
            buf, self.err_buffer = self.err_buffer, []
            try:
                self.db.executemany(
                    "INSERT INTO errors(ts,level,category,message,client,server,site,request,upstream,host) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)", buf)
            except Exception:
                log.exception("запись журнала ошибок")
        cutoff = int(now) // 60 * 60 - 60 if not force else int(now) + 60
        # минута закрывается через 60–120 с — запас на буферизацию журнала nginx
        for mts in sorted(k for k in self.mins if k <= cutoff - (0 if force else 0)):
            if not force and now < mts + 60 + 10:
                continue
            self._finalize_minute(mts, self.mins.pop(mts))
        for mts in sorted(k for k in self.stream_min if force or now >= k + 70):
            rows = self.stream_min.pop(mts)
            for sid, (n, bi, bo, dur, errs) in rows.items():
                self.db.execute(
                    "INSERT INTO stream_minute(ts,stream,sessions,bytes_in,bytes_out,dur_sum,errors) "
                    "VALUES(?,?,?,?,?,?,?) ON CONFLICT(ts,stream) DO UPDATE SET sessions=sessions+excluded.sessions,"
                    "bytes_in=bytes_in+excluded.bytes_in,bytes_out=bytes_out+excluded.bytes_out,"
                    "dur_sum=dur_sum+excluded.dur_sum,errors=errors+excluded.errors",
                    (mts, sid, n, bi, bo, dur, errs))
        if force or now - self.last_flush_hour_tops > 300:
            self.last_flush_hour_tops = now
            self._write_hour_tops()

    def _finalize_minute(self, mts: int, mb: Dict[str, Minute]) -> None:
        hour = mts // 3600 * 3600
        if hour != self.cur_hour:
            if self.cur_hour:
                self._write_hour_tops()
                self._rollup_day_if_needed(self.cur_hour, hour)
            self.cur_hour = hour
            self.hour_ips, self.hour_tops, self.hour_top_bytes, self.hour_slow_sum = {}, {}, {}, {}
        keep = self.get_settings().top_keep
        with self.db.transaction() as c:
            for site, m in mb.items():
                data = m.data()
                row = (mts, site, m.req, m.bout, m.bin, *m.s[1:6], m.rt_sum, m.rt_max, m.urt_sum, m.urt_n,
                       len(m.ips), json.dumps(data))
                old = c.execute("SELECT * FROM stats_minute WHERE ts=? AND site=?", (mts, site)).fetchone()
                if old:
                    row = self._merge_row(dict(old), row)
                c.execute("INSERT OR REPLACE INTO stats_minute(ts,site,req,bout,bin,s1,s2,s3,s4,s5,rt_sum,rt_max,"
                          "urt_sum,urt_n,uniq,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
                # часовой агрегат
                hs = self.hour_ips.setdefault(site, set())
                if len(hs) < 300000:
                    hs.update(m.ips)
                hrow = (hour, site, m.req, m.bout, m.bin, *m.s[1:6], m.rt_sum, m.rt_max, m.urt_sum, m.urt_n,
                        len(hs), json.dumps(data))
                hold = c.execute("SELECT * FROM stats_hour WHERE ts=? AND site=?", (hour, site)).fetchone()
                if hold:
                    hrow = self._merge_row(dict(hold), hrow, uniq_max=True)
                c.execute("INSERT OR REPLACE INTO stats_hour(ts,site,req,bout,bin,s1,s2,s3,s4,s5,rt_sum,rt_max,"
                          "urt_sum,urt_n,uniq,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", hrow)
                # топы часа в памяти (с ограничением размера)
                ht = self.hour_tops.setdefault(site, {k: Counter() for k in TOP_KINDS})
                hb = self.hour_top_bytes.setdefault(site, {"uri": Counter(), "ip": Counter(), "host": Counter()})
                hss = self.hour_slow_sum.setdefault(site, Counter())
                for kind, cnt in m.tops.items():
                    ht[kind].update(dict(cnt.most_common(keep * 5)))
                    if len(ht[kind]) > keep * 50:
                        ht[kind] = Counter(dict(ht[kind].most_common(keep * 10)))
                for kind, cnt in m.top_bytes.items():
                    hb[kind].update(dict(cnt.most_common(keep * 5)))
                    if len(hb[kind]) > keep * 50:
                        hb[kind] = Counter(dict(hb[kind].most_common(keep * 10)))
                hss.update(m.slow_sum)
                if len(hss) > keep * 50:
                    keys = {k for k, _ in ht["slow"].most_common(keep * 10)} if "slow" in ht else set()
                    self.hour_slow_sum[site] = Counter({k: v for k, v in hss.items() if k in keys})
        # компактная копия для «топов за последний час»: топы обрезаются, а байты и время медленных запросов
        # остаются только для оставшихся ключей — иначе на загруженных сайтах (тысячи уникальных IP и адресов
        # в минуту) 75 минут таких счётчиков занимают сотни мегабайт
        for m in mb.values():
            m.ips = set()
            for kind in m.tops:
                if len(m.tops[kind]) > keep * 3:
                    m.tops[kind] = Counter(dict(m.tops[kind].most_common(keep * 3)))
            for kind, cnt in m.top_bytes.items():
                if len(cnt) > keep * 3:
                    kept = m.tops.get(kind) or {}
                    m.top_bytes[kind] = Counter({k: cnt[k] for k in kept if k in cnt})
            if len(m.slow_sum) > keep * 3:
                kept = m.tops.get("slow") or {}
                m.slow_sum = Counter({k: m.slow_sum[k] for k in kept if k in m.slow_sum})
        self.recent.append((mts, mb))

    @staticmethod
    def _merge_row(old: Dict[str, Any], new: tuple, uniq_max: bool = False) -> tuple:
        ts, site, req, bout, bin_, s1, s2, s3, s4, s5, rt_sum, rt_max, urt_sum, urt_n, uniq, data = new
        merged = merge_data(json.loads(old.get("data") or "{}"), json.loads(data))
        return (ts, site, old["req"] + req, old["bout"] + bout, old["bin"] + bin_, old["s1"] + s1, old["s2"] + s2,
                old["s3"] + s3, old["s4"] + s4, old["s5"] + s5, old["rt_sum"] + rt_sum, max(old["rt_max"], rt_max),
                old["urt_sum"] + urt_sum, old["urt_n"] + urt_n,
                max(old["uniq"], uniq) if uniq_max else old["uniq"] + uniq, json.dumps(merged))

    def _write_hour_tops(self) -> None:
        if not self.cur_hour or not self.hour_tops:
            return
        keep = self.get_settings().top_keep
        rows = []
        for site, kinds in self.hour_tops.items():
            hb = self.hour_top_bytes.get(site, {})
            ss = self.hour_slow_sum.get(site, Counter())
            for kind, cnt in kinds.items():
                for key, n in cnt.most_common(keep):
                    rows.append((self.cur_hour, site, kind, key[:500], n, hb.get(kind, Counter()).get(key, 0),
                                 ss.get(key, 0.0) if kind == "slow" else 0.0))
        with self.db.transaction() as c:
            c.execute("DELETE FROM top_hour WHERE ts=?", (self.cur_hour,))
            c.executemany("INSERT OR REPLACE INTO top_hour(ts,site,kind,key,cnt,bytes,extra) VALUES(?,?,?,?,?,?,?)",
                          rows)

    def load_hour_tops(self) -> None:
        """После перезапуска — восстановить топы текущего часа из БД."""
        hour = int(time.time()) // 3600 * 3600
        self.cur_hour = hour
        for r in self.db.query("SELECT site,kind,key,cnt,bytes,extra FROM top_hour WHERE ts=?", (hour,)):
            ht = self.hour_tops.setdefault(r["site"], {k: Counter() for k in TOP_KINDS})
            if r["kind"] in ht:
                ht[r["kind"]][r["key"]] += r["cnt"]
            if r["kind"] in ("uri", "ip", "host"):
                self.hour_top_bytes.setdefault(r["site"], {"uri": Counter(), "ip": Counter(), "host": Counter()})[
                    r["kind"]][r["key"]] += r["bytes"]
            if r["kind"] == "slow":
                self.hour_slow_sum.setdefault(r["site"], Counter())[r["key"]] += r["extra"]

    def _rollup_day_if_needed(self, prev_hour: int, new_hour: int) -> None:
        prev_day, new_day = prev_hour // 86400, new_hour // 86400
        if prev_day == new_day:
            return
        self.rollup_day(prev_day * 86400)

    def rollup_day(self, day_ts: int) -> None:
        keep = self.get_settings().top_keep
        rows = self.db.query(
            "SELECT site,kind,key,SUM(cnt) c,SUM(bytes) b,SUM(extra) e FROM top_hour WHERE ts>=? AND ts<? "
            "GROUP BY site,kind,key", (day_ts, day_ts + 86400))
        groups: Dict[Tuple[str, str], List[dict]] = {}
        for r in rows:
            groups.setdefault((r["site"], r["kind"]), []).append(r)
        out = []
        for (site, kind), items in groups.items():
            items.sort(key=lambda x: -x["c"])
            for r in items[:keep]:
                out.append((day_ts, site, kind, r["key"], r["c"], r["b"], r["e"]))
        with self.db.transaction() as c:
            c.execute("DELETE FROM top_day WHERE ts=?", (day_ts,))
            c.executemany("INSERT INTO top_day(ts,site,kind,key,cnt,bytes,extra) VALUES(?,?,?,?,?,?,?)", out)

    # ------------------------------------------------------------------
    #  Срезы для API и WebSocket
    # ------------------------------------------------------------------
    def realtime(self, seconds: int = 300, site: str = "*") -> Dict[str, List]:
        now = int(time.time())
        out: Dict[str, List] = {k: [] for k in ("ts", "req", "bout", "bin", "s2", "s3", "s4", "s5", "rt_avg",
                                                 "p50", "p95", "p99", "urt_avg", "hit")}
        for ts in range(now - seconds, now):
            s = (self.secs.get(ts) or {}).get(site)
            out["ts"].append(ts)
            if not s:
                for k in list(out)[1:]:
                    out[k].append(0)
                continue
            out["req"].append(s.req)
            out["bout"].append(s.bout)
            out["bin"].append(s.bin)
            for i in (2, 3, 4, 5):
                out[f"s{i}"].append(s.s[i])
            out["rt_avg"].append(round(s.rt_sum / s.req * 1000, 1) if s.req else 0)
            out["p50"].append(round(percentile(s.hist, 0.5) * 1000, 1))
            out["p95"].append(round(percentile(s.hist, 0.95) * 1000, 1))
            out["p99"].append(round(percentile(s.hist, 0.99) * 1000, 1))
            out["urt_avg"].append(round(s.urt_sum / s.urt_n * 1000, 1) if s.urt_n else 0)
            out["hit"].append(s.hit)
        return out

    def window(self, seconds: int, site: str = "*", end: Optional[int] = None) -> Dict[str, Any]:
        """Сводка за последние N секунд (для KPI и оповещений)."""
        end = end or int(time.time())
        req = bout = bin_ = urt_n = 0
        s = [0] * 6
        rt_sum = urt_sum = 0.0
        hist = [0] * NB
        for ts in range(end - seconds, end):
            b = (self.secs.get(ts) or {}).get(site)
            if not b:
                continue
            req += b.req
            bout += b.bout
            bin_ += b.bin
            rt_sum += b.rt_sum
            urt_sum += b.urt_sum
            urt_n += b.urt_n
            for i in range(6):
                s[i] += b.s[i]
            for i in range(NB):
                hist[i] += b.hist[i]
        return {"seconds": seconds, "req": req, "rps": req / seconds if seconds else 0,
                "bout": bout, "bps_out": bout * 8 / seconds if seconds else 0,
                "bin": bin_, "bps_in": bin_ * 8 / seconds if seconds else 0,
                "s2": s[2], "s3": s[3], "s4": s[4], "s5": s[5],
                "err5_pct": s[5] / req * 100 if req else 0, "err4_pct": s[4] / req * 100 if req else 0,
                "rt_avg": rt_sum / req * 1000 if req else 0,
                "p50": percentile(hist, 0.5) * 1000, "p95": percentile(hist, 0.95) * 1000,
                "p99": percentile(hist, 0.99) * 1000, "urt_avg": urt_sum / urt_n * 1000 if urt_n else 0}

    def per_site_now(self, seconds: int = 10) -> Dict[str, Dict[str, float]]:
        end = int(time.time()) - 2
        res: Dict[str, Dict[str, float]] = {}
        for ts in range(end - seconds, end):
            for site, b in (self.secs.get(ts) or {}).items():
                r = res.setdefault(site, {"req": 0, "bout": 0, "s4": 0, "s5": 0, "rt_sum": 0.0})
                r["req"] += b.req
                r["bout"] += b.bout
                r["s4"] += b.s[4]
                r["s5"] += b.s[5]
                r["rt_sum"] += b.rt_sum
        for r in res.values():
            n = r["req"]
            r["rps"] = n / seconds
            r["bps"] = r["bout"] * 8 / seconds
            r["err5_pct"] = r["s5"] / n * 100 if n else 0
            r["rt_avg"] = r["rt_sum"] / n * 1000 if n else 0
        return res

    def recent_tops(self, minutes: int, site: str, kind: str, limit: int = 50) -> List[Dict[str, Any]]:
        cut = int(time.time()) - minutes * 60
        cnt: Counter = Counter()
        byt: Counter = Counter()
        slow: Counter = Counter()
        sources = [(mts, mb) for mts, mb in self.recent if mts >= cut] + \
                  [(mts, mb) for mts, mb in self.mins.items() if mts >= cut]
        for _mts, mb in sources:
            m = mb.get(site)
            if not m:
                continue
            cnt.update(m.tops.get(kind, {}))
            if kind in m.top_bytes:
                byt.update(m.top_bytes[kind])
            if kind == "slow":
                slow.update(m.slow_sum)
        out = []
        for key, n in cnt.most_common(limit):
            item = {"key": key, "count": n, "bytes": byt.get(key, 0)}
            if kind == "slow":
                item["avg_ms"] = round(slow.get(key, 0) / n * 1000, 1) if n else 0
            out.append(item)
        return out

    def recent_minutes_summary(self, minutes: int, site: str) -> Dict[str, Any]:
        cut = int(time.time()) - minutes * 60
        data: Dict[str, Any] = {}
        totals = {"req": 0, "bout": 0, "bin": 0, "s1": 0, "s2": 0, "s3": 0, "s4": 0, "s5": 0, "rt_sum": 0.0,
                  "urt_sum": 0.0, "urt_n": 0, "uniq": 0}
        ips: set = set()
        for mts, mb in list(self.recent) + list(self.mins.items()):
            if mts < cut:
                continue
            m = mb.get(site)
            if not m:
                continue
            data = merge_data(data, m.data())
            totals["req"] += m.req
            totals["bout"] += m.bout
            totals["bin"] += m.bin
            for i in range(1, 6):
                totals[f"s{i}"] += m.s[i]
            totals["rt_sum"] += m.rt_sum
            totals["urt_sum"] += m.urt_sum
            totals["urt_n"] += m.urt_n
            ips.update(m.ips)
        totals["uniq"] = len(ips)
        return {"totals": totals, "data": data}

    def live_since(self, seq: int, limit: int = 200) -> List[Dict[str, Any]]:
        if seq <= 0:
            return [x for _, x in list(self.live)[-limit:]]
        return [x for s, x in self.live if s > seq][-limit:]

    def errors_since(self, seq: int, limit: int = 100) -> List[Dict[str, Any]]:
        if seq <= 0:
            return [x for _, x in list(self.err_live)[-limit:]]
        return [x for s, x in self.err_live if s > seq][-limit:]


# =============================================================================
#  stub_status и системные метрики
# =============================================================================
class StubPoller:
    def __init__(self, port: int) -> None:
        self.port = port
        self.samples: Deque[Dict[str, float]] = deque(maxlen=900)
        self.last: Optional[Dict[str, float]] = None
        self.error = ""

    async def fetch(self) -> Optional[Dict[str, float]]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", self.port), 2)
            writer.write(b"GET /nm_status HTTP/1.0\r\nHost: nm_status\r\nUser-Agent: NginxManager\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), 2)
            writer.close()
            text = data.decode("ascii", "replace")
            body = text.split("\r\n\r\n", 1)[-1]
            lines = body.strip().splitlines()
            active = int(lines[0].split(":")[1])
            accepts, handled, requests = (int(x) for x in lines[2].split())
            parts = lines[3].split()
            self.error = ""
            return {"ts": time.time(), "active": active, "accepts": accepts, "handled": handled,
                    "requests": requests, "reading": int(parts[1]), "writing": int(parts[3]),
                    "waiting": int(parts[5])}
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
            return None

    async def run(self) -> None:
        while True:
            cur = await self.fetch()
            if cur:
                if self.last and cur["requests"] >= self.last["requests"]:
                    dt = max(0.001, cur["ts"] - self.last["ts"])
                    cur["rps"] = (cur["requests"] - self.last["requests"]) / dt
                    cur["cps"] = (cur["accepts"] - self.last["accepts"]) / dt
                    cur["dropped"] = (cur["accepts"] - cur["handled"])
                else:
                    cur["rps"] = cur["cps"] = 0.0
                    cur["dropped"] = 0
                self.last = cur
                self.samples.append(cur)
            await asyncio.sleep(1)

    def latest(self) -> Dict[str, Any]:
        if not self.samples or time.time() - self.samples[-1]["ts"] > 5:
            return {"ok": False, "error": self.error or "нет данных"}
        return {"ok": True, **self.samples[-1]}


class SystemPoller:
    def __init__(self, nginx_master: Callable[[], Any], log_dir: Path) -> None:
        self.nginx_master = nginx_master
        self.log_dir = log_dir
        self.samples: Deque[Dict[str, float]] = deque(maxlen=600)
        self._procs: Dict[int, Any] = {}
        self._net = None
        self._disk = None

    def sample(self) -> Dict[str, float]:
        import psutil
        now = time.time()
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        try:
            l1, l5, l15 = os.getloadavg()
        except OSError:
            l1 = l5 = l15 = 0.0
        du = psutil.disk_usage("/")
        try:
            dl = psutil.disk_usage(str(self.log_dir))
        except OSError:
            dl = du
        net = psutil.net_io_counters()
        try:
            disk = psutil.disk_io_counters()
        except Exception:
            disk = None
        s: Dict[str, float] = {"ts": now, "cpu": psutil.cpu_percent(None), "mem": vm.percent,
                               "mem_used": vm.total - vm.available, "mem_total": vm.total, "swap": sw.percent,
                               "load1": l1, "load5": l5, "load15": l15, "cpus": psutil.cpu_count() or 1,
                               "disk": du.percent, "disk_free": du.free, "disk_total": du.total,
                               "disk_log": dl.percent, "disk_log_free": dl.free}
        if self._net:
            dt = max(0.001, now - self._net[0])
            s["net_rx"] = (net.bytes_recv - self._net[1].bytes_recv) * 8 / dt
            s["net_tx"] = (net.bytes_sent - self._net[1].bytes_sent) * 8 / dt
        else:
            s["net_rx"] = s["net_tx"] = 0.0
        self._net = (now, net)
        if disk is not None:
            if self._disk:
                dt = max(0.001, now - self._disk[0])
                s["disk_r"] = (disk.read_bytes - self._disk[1].read_bytes) / dt
                s["disk_w"] = (disk.write_bytes - self._disk[1].write_bytes) / dt
            else:
                s["disk_r"] = s["disk_w"] = 0.0
            self._disk = (now, disk)
        # процессы nginx
        rss = cpu = 0.0
        fds = workers = 0
        m = self.nginx_master()
        if m:
            try:
                procs = [m] + m.children()
                workers = len(procs) - 1
                alive = set()
                for p in procs:
                    alive.add(p.pid)
                    pp = self._procs.get(p.pid)
                    if pp is None:
                        pp = self._procs[p.pid] = p
                        pp.cpu_percent(None)
                    try:
                        rss += pp.memory_info().rss
                        cpu += pp.cpu_percent(None)
                        fds += pp.num_fds()
                    except Exception:
                        pass
                for pid in list(self._procs):
                    if pid not in alive:
                        del self._procs[pid]
            except Exception:
                pass
        s.update(nginx_rss=rss, nginx_cpu=cpu, nginx_fds=fds, nginx_workers=workers)
        self.samples.append(s)
        return s

    async def run(self) -> None:
        import psutil
        psutil.cpu_percent(None)
        while True:
            try:
                await asyncio.to_thread(self.sample)
            except Exception:  # pragma: no cover
                log.exception("системные метрики")
            await asyncio.sleep(2)

    def latest(self) -> Dict[str, float]:
        return self.samples[-1] if self.samples else {}

    def minute_avg(self, start: float, end: float) -> Optional[Dict[str, float]]:
        xs = [s for s in self.samples if start <= s["ts"] < end]
        if not xs:
            return None
        keys = ("cpu", "mem", "swap", "load1", "load5", "load15", "disk", "net_rx", "net_tx", "disk_r", "disk_w",
                "nginx_rss", "nginx_cpu")
        out = {k: sum(x.get(k, 0) for x in xs) / len(xs) for k in keys}
        out["nginx_workers"] = xs[-1].get("nginx_workers", 0)
        out["nginx_fds"] = xs[-1].get("nginx_fds", 0)
        return out
