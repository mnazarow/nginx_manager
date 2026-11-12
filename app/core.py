"""Ядро приложения: связывает хранилище, nginx, статистику, проверки, оповещения и фоновые задачи."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import WebSocket

from .auth import AuthService
from .config import VERSION, settings
from .db import Database
from .models import AlertRule, GlobalSettings, PanelSettings
from .nginx.generator import State
from .nginx.manager import ApplyError, NginxManager
from .services.alerts import DEFAULT_RULES, AlertEngine
from .services.bans import BanService
from .services.insights import Analyzer
from .services.certs import CertificateService
from .services.diagnostics import Diagnostics
from .services.health import HealthChecker, Target
from .stats.service import StatsService
from .utils import hash_password

log = logging.getLogger("nm.core")


class WSClient:
    def __init__(self, ws: WebSocket, user: Dict[str, Any]) -> None:
        self.ws = ws
        self.user = user
        self.live = False
        self.live_filter: Dict[str, Any] = {}
        self.errors = False
        self.live_seq = 0
        self.err_seq = 0
        self.site = "*"


class App:
    def __init__(self) -> None:
        settings.ensure_dirs()
        self.db = Database(settings.db_path)
        self._panel: Optional[PanelSettings] = None
        self.nginx = NginxManager(self.db)
        self.auth = AuthService(self.db, self.panel)
        self.stats = StatsService(self.db, self.panel, self.nginx.master_process)
        self.health = HealthChecker(self.db, self.on_health_change)
        self.certs = CertificateService(self.db, self.panel)
        self.alerts = AlertEngine(self.db, self.metric, self.broadcast)
        self.diag = Diagnostics(self)
        self.bans = BanService(self)
        self.insights = Analyzer(self)
        self.stats.agg.detector = self.bans.detector
        self.clients: Set[WSClient] = set()
        self.tasks: List[asyncio.Task] = []
        self.started = time.time()
        self.revision = 0
        self._pending_cache: Tuple[int, float, Dict[str, Any]] = (-1, 0.0, {})
        self.nginx_restarts: List[float] = []
        self.bootstrap()

    # ------------------------------------------------------------------
    def panel(self) -> PanelSettings:
        if self._panel is None:
            self._panel = PanelSettings.model_validate(self.db.kv_get("panel_settings", {}))
        return self._panel

    def global_settings(self) -> GlobalSettings:
        return GlobalSettings.model_validate(self.db.kv_get("global_settings", {}))

    def save_panel(self, p: PanelSettings) -> None:
        self.db.kv_set("panel_settings", p.model_dump())
        self._panel = None
        self.touch()

    def touch(self) -> None:
        self.revision += 1

    def bootstrap(self) -> None:
        if self.db.kv_get("global_settings") is None:
            self.db.kv_set("global_settings", GlobalSettings().model_dump())
        if self.db.kv_get("panel_settings") is None:
            self.db.kv_set("panel_settings", PanelSettings().model_dump())
        if not self.db.kv_get("default_rules_created"):
            now = time.time()
            for r in DEFAULT_RULES:
                self.db.execute("INSERT INTO alert_rules(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                                (r.name, 1, json.dumps(r.model_dump(), ensure_ascii=False), now, now))
            self.db.kv_set("default_rules_created", True)

    def ensure_admin(self, username: str = "admin", password: Optional[str] = None) -> Optional[str]:
        if self.db.scalar("SELECT COUNT(*) FROM users"):
            return None
        import secrets
        pw = password or secrets.token_urlsafe(12)
        self.db.execute("INSERT INTO users(username,password_hash,role,created_at,must_change_password) "
                        "VALUES(?,?,?,?,?)", (username, hash_password(pw), "admin", time.time(),
                                              0 if password else 1))
        return pw

    # ------------------------------------------------------------------
    async def start(self) -> None:
        self.nginx.ensure_original_backup()
        self.refresh_runtime_maps()
        if not settings.disable_collector:
            self.stats.start()
        self.health.start()
        self.alerts.start()
        self.bans.start()
        loop = asyncio.get_running_loop()
        self.tasks += [loop.create_task(self.ticker(), name="ticker"),
                       loop.create_task(self.watchdog(), name="watchdog"),
                       loop.create_task(self.periodic(), name="periodic")]
        self.db.event("info", "panel", f"Nginx Manager {VERSION} запущен")

    async def stop(self) -> None:
        for t in self.tasks + [self.health.task, self.alerts.task, self.bans.task]:
            if t:
                t.cancel()
        await self.stats.stop()
        for c in list(self.clients):
            try:
                await c.ws.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    def last_applied_state(self) -> Optional[State]:
        last = self.nginx.last_applied()
        if not last:
            return None
        try:
            return State.from_json(json.loads(last["state"]))
        except Exception:
            log.exception("разбор последней применённой версии")
            return None

    def refresh_runtime_maps(self) -> None:
        state = self.last_applied_state() or self.nginx.load_state()
        dm: Dict[str, str] = {}
        for sid, s in state.sites:
            for d in s.domains:
                dm[d] = str(sid)
        if state.panel.panel_domain:
            dm[state.panel.panel_domain] = "panel"
        self.stats.agg.domain_map = dm
        spm: Dict[Tuple[int, str], str] = {}
        for sid, st in state.streams:
            for p in (["TCP", "UDP"] if st.protocol == "both" else [st.protocol.upper()]):
                spm[(st.listen_port, p)] = str(sid)
        self.stats.agg.stream_port_map = spm
        self.health.rebuild(state.sites, state.streams)

    def pending(self) -> Dict[str, Any]:
        rev, ts, cached = self._pending_cache
        if rev == self.revision and time.time() - ts < 30:
            return cached
        res = self.nginx.pending()
        self._pending_cache = (self.revision, time.time(), res)
        return res

    async def apply(self, username: str, comment: str = "", source: str = "user",
                    state: Optional[State] = None) -> Dict[str, Any]:
        res = await self.nginx.apply(state, username, comment, source)
        self.touch()
        self.refresh_runtime_maps()
        await self.broadcast({"type": "applied", "version": res["version"], "user": username, "source": source})
        return res

    async def apply_snapshot(self, reason: str, source: str) -> Optional[Dict[str, Any]]:
        """Переприменить последнюю применённую версию с актуальными сертификатами и переключениями бэкендов
        (неприменённые правки пользователя не затрагиваются)."""
        state = self.last_applied_state()
        if not state:
            return None
        fresh = self.nginx.load_state()
        state.certs = fresh.certs
        if self.panel().auto_apply_failover:
            state.overrides = self.health.disabled_by_failover()
        try:
            return await self.apply("system", reason, source, state)
        except ApplyError as e:
            self.db.event("error", source, f"Автоприменение не удалось: {e}", {"output": e.output[-2000:]})
            return None

    async def after_cert_issued(self, cid: int) -> None:
        state = self.last_applied_state()
        if not state:
            return
        uses = any(s.enabled and s.ssl.enabled and s.ssl.certificate_id == cid for _, s in state.sites) or \
            state.panel.panel_certificate_id == cid
        if uses:
            await self.apply_snapshot(f"Сертификат #{cid} выпущен/продлён", "certs")
        self.touch()

    async def on_health_change(self, t: Target, prev: str, new: str) -> None:
        lvl = "error" if new == "down" else "info"
        msg = f"Бэкенд {t.address}:{t.port} ({t.owner_name}) — {'НЕДОСТУПЕН' if new == 'down' else 'восстановлен'}"
        if t.last_error:
            msg += f": {t.last_error}"
        self.db.event(lvl, "health", msg, {"target": t.key})
        await self.broadcast({"type": "health", "key": t.key, "state": new, "message": msg})
        if t.check.auto_failover and t.owner.startswith("site:") and self.panel().auto_apply_failover:
            await self.apply_snapshot(f"Автопереключение: {msg}", "failover")

    # ------------------------------------------------------------------
    #  Метрики для оповещений
    # ------------------------------------------------------------------
    def metric(self, rule: AlertRule) -> Tuple[Optional[float], str]:
        m = rule.metric
        site = rule.site or "*"
        if m == "nginx_down":
            return (0.0 if self.nginx.is_running() else 1.0), ""
        if m == "config_error":
            ts, ok, out = self.nginx._last_test
            return (0.0 if ok else 1.0), out[-500:] if not ok else ""
        if m == "backend_down":
            down = [t for t in self.health.targets.values() if t.state == "down" and not t.backup and
                    (site == "*" or t.owner in (f"site:{site}", f"stream:{site}") or t.owner.startswith(f"loc:{site}:"))]
            return float(len(down)), "\n".join(f"{t.owner_name}: {t.address}:{t.port} — {t.last_error}" for t in down)
        if m == "cert_expiry":
            certs = [c for c in self.certs.list() if c["days_left"] is not None and c["used_by"]]
            if not certs:
                return None, ""
            c = min(certs, key=lambda x: x["days_left"])
            return round(c["days_left"], 1), f"Сертификат «{c['name']}» ({', '.join(c['domains'][:3])})"
        if m == "insights_crit":
            return float(self.insights.last["counts"].get("crit", 0)), "\n".join(
                f"{f['site_name']}: {f['title']} — {f['summary']}" for f in self.insights.last["findings"]
                if f["level"] == "crit")[:1500]
        if m == "autobans":
            n = self.db.scalar("SELECT COUNT(*) FROM events WHERE source='bans' AND ts>=? AND message LIKE "
                               "'Автоблокировка%'", (time.time() - rule.window,))
            return float(n or 0), ""
        sysm = self.stats.system.latest()
        if m == "cpu":
            return sysm.get("cpu"), ""
        if m == "memory":
            return sysm.get("mem"), ""
        if m == "disk":
            return max(sysm.get("disk", 0), sysm.get("disk_log", 0)), ""
        if m == "active_connections":
            st = self.stats.stub.latest()
            return (st.get("active") if st.get("ok") else None), ""
        if m in ("error_log_rate", "rate_limited"):
            since = time.time() - rule.window
            if m == "error_log_rate":
                n = self.db.scalar("SELECT COUNT(*) FROM errors WHERE ts>=? AND level IN ('error','crit','alert',"
                                   "'emerg')", (since,))
            else:
                n = self.db.scalar("SELECT COUNT(*) FROM errors WHERE ts>=? AND category IN ('limit_req',"
                                   "'limit_conn')", (since,))
            return (n or 0) / max(1, rule.window) * 60, ""
        w = self.stats.agg.window(rule.window, site)
        if m in ("error_5xx_rate", "error_4xx_rate", "latency_p95", "latency_avg") and w["req"] < rule.min_requests:
            return None, ""
        if m == "error_5xx_rate":
            top = self.stats.agg.recent_tops(max(1, rule.window // 60), site, "e5xx", 3)
            return w["err5_pct"], "\n".join(f"{t['key']} ×{t['count']}" for t in top)
        if m == "error_4xx_rate":
            return w["err4_pct"], ""
        if m == "latency_p95":
            return w["p95"], ""
        if m == "latency_avg":
            return w["rt_avg"], ""
        if m in ("rps_high", "rps_low"):
            return w["rps"], ""
        if m == "bandwidth_out":
            return w["bps_out"] / 1e6, ""
        return None, ""

    # ------------------------------------------------------------------
    #  WebSocket
    # ------------------------------------------------------------------
    async def broadcast(self, msg: Dict[str, Any]) -> None:
        data = json.dumps(msg, ensure_ascii=False, default=str)
        for c in list(self.clients):
            try:
                await asyncio.wait_for(c.ws.send_text(data), 5)
            except Exception:
                self.clients.discard(c)

    @staticmethod
    def _match(item: Dict[str, Any], f: Dict[str, Any]) -> bool:
        if f.get("site") and f["site"] != "*" and item["site"] != str(f["site"]):
            return False
        st = f.get("status")
        if st:
            s = str(item["s"])
            if st.endswith("xx"):
                if s[0] != st[0]:
                    return False
            elif s != st:
                return False
        if f.get("ip") and f["ip"] not in item["ip"]:
            return False
        if f.get("q"):
            q = f["q"].lower()
            if q not in item["u"].lower() and q not in item["host"].lower() and q not in item["ua"].lower():
                return False
        if f.get("min_rt") and item["rt"] * 1000 < float(f["min_rt"]):
            return False
        if f.get("hide_bots") and item.get("bot"):
            return False
        return True

    async def ticker(self) -> None:
        while True:
            await asyncio.sleep(1)
            if not self.clients:
                continue
            try:
                snap = self.stats.snapshot()
                snap["type"] = "tick"
                snap["nginx"] = {"running": self.nginx.is_running()}
                base = json.dumps(snap, ensure_ascii=False, default=str)
                for c in list(self.clients):
                    try:
                        await asyncio.wait_for(c.ws.send_text(base), 5)
                        if c.live:
                            items = self.stats.agg.live_since(c.live_seq, 500)
                            if items:
                                c.live_seq = items[-1]["seq"]
                                items = [x for x in items if self._match(x, c.live_filter)][-200:]
                                if items:
                                    await c.ws.send_text(json.dumps({"type": "requests", "items": items},
                                                                    ensure_ascii=False))
                        if c.errors:
                            errs = self.stats.agg.errors_since(c.err_seq, 200)
                            if errs:
                                c.err_seq = errs[-1]["seq"]
                                await c.ws.send_text(json.dumps({"type": "errors", "items": errs},
                                                                ensure_ascii=False, default=str))
                    except Exception:
                        self.clients.discard(c)
            except Exception:
                log.exception("ticker")

    # ------------------------------------------------------------------
    #  Фоновые задачи
    # ------------------------------------------------------------------
    async def watchdog(self) -> None:
        await asyncio.sleep(5)
        while True:
            try:
                running = await asyncio.to_thread(self.nginx.is_running)
                if not running and self.panel().auto_restart_nginx and self.nginx.last_applied():
                    now = time.time()
                    self.nginx_restarts = [t for t in self.nginx_restarts if now - t < 600]
                    if len(self.nginx_restarts) < 5:
                        self.nginx_restarts.append(now)
                        ok, out = await asyncio.to_thread(self.nginx.start)
                        self.db.event("warning" if ok else "error", "watchdog",
                                      "Nginx был остановлен — " + ("запущен автоматически" if ok else
                                                                   f"запустить не удалось: {out[-500:]}"))
                        await self.broadcast({"type": "watchdog", "ok": ok})
                    elif len(self.nginx_restarts) == 5:
                        self.nginx_restarts.append(now)
                        self.db.event("error", "watchdog", "Nginx падает повторно — автоперезапуск приостановлен на "
                                                           "10 минут. Запустите диагностику.")
                # периодически проверяем конфигурацию (для правила config_error)
                if time.time() - self.nginx._last_test[0] > 300:
                    await asyncio.to_thread(self.nginx.test_config)
            except Exception:
                log.exception("watchdog")
            await asyncio.sleep(10)

    def _insights_history(self, findings: List[Dict[str, Any]]) -> None:
        """Журнал появления и устранения проблем (уровни «проблема» и «внимание») — вкладка «История» анализа."""
        cur = {f["fid"]: f for f in findings if f["level"] in ("crit", "warn")}
        prev = getattr(self, "_ins_prev", None)
        self._ins_prev = cur
        if prev is None:  # первый проход после запуска — только запоминаем
            return
        for fid, f in cur.items():
            if fid not in prev:
                where = f"{f['site_name']}: " if f["site"] != "*" else ""
                self.db.event("error" if f["level"] == "crit" else "warning", "insights",
                              f"Обнаружено: {where}{f['title']} — {f['summary']}"[:500],
                              {"id": f["id"], "fid": fid, "level": f["level"], "site": f["site"]})
        for fid, f in prev.items():
            if fid not in cur:
                where = f"{f['site_name']}: " if f["site"] != "*" else ""
                dur = time.time() - (f.get("since") or time.time())
                self.db.event("info", "insights", f"Устранено: {where}{f['title']}"
                              + (f" (длилось ~{max(1, round(dur / 60))} мин)" if f.get("since") else ""),
                              {"id": f["id"], "fid": fid, "site": f["site"]})

    async def maybe_send_report(self) -> None:
        from .services import reports
        p = self.panel()
        key = reports.due(p)
        if not key or self.db.kv_get("last_report") == key:
            return
        self.db.kv_set("last_report", key)
        rep = await asyncio.to_thread(reports.build, self, p.report_period)
        res = await reports.send(self, rep, list(p.report_channels))
        ok = [r for r in res if r["ok"]]
        self.db.event("info" if ok else "error", "reports",
                      f"{rep['title']}: отправлен в {len(ok)} из {len(res)} каналов"
                      + ("" if len(ok) == len(res) else "; ошибки: " + "; ".join(
                          f"{r.get('name', r['id'])}: {r.get('error')}" for r in res if not r["ok"])))

    async def periodic(self) -> None:
        await asyncio.sleep(20)
        last_diag = last_cert = 0.0
        while True:
            now = time.time()
            p = self.panel()
            try:
                # встроенный анализ за последние 15 минут — для значка в меню и метрики оповещений
                res = await asyncio.to_thread(self.insights.evaluate, now - 900, now, "*")
                self.insights.last = {"counts": res["counts"], "findings": res["findings"][:50], "ts": now}
                self._insights_history(res["findings"])
            except Exception:
                log.exception("анализ метрик")
            try:
                if now - last_diag > p.diagnostics_interval:
                    last_diag = now
                    await self.diag.run_all()
                if now - last_cert > 6 * 3600:
                    last_cert = now
                    await asyncio.to_thread(self.certs.refresh_all)
                    await self.certs.auto_renew(after=self.after_cert_issued)
                lt = time.localtime(now)
                today = time.strftime("%Y-%m-%d", lt)
                await self.maybe_send_report()
                if lt.tm_hour == p.backup_hour and self.db.kv_get("last_auto_backup") != today:
                    self.db.kv_set("last_auto_backup", today)
                    from .services.backup import auto_backup
                    await asyncio.to_thread(auto_backup, self)
            except Exception:
                log.exception("периодические задачи")
            await asyncio.sleep(60)

    def state_summary(self, user: Dict[str, Any]) -> Dict[str, Any]:
        pend = self.pending()
        diag = self.db.kv_get("diagnostics_last", {}) or {}
        firing = [s for s in self.alerts.status().values() if s.get("state") == "firing"]
        return {"version": VERSION, "user": {"id": user["id"], "username": user["username"], "role": user["role"],
                                             "totp_enabled": bool(user["totp_enabled"]),
                                             "must_change_password": bool(user["must_change_password"])},
                "nginx": self.nginx.status(), "pending": pend, "diagnostics": diag, "alerts_firing": len(firing),
                "uptime": time.time() - self.started, "caps": {"stream": self.nginx.caps().stream_available,
                                                               "http3": self.nginx.caps().http3},
                "backends_down": sum(1 for t in self.health.targets.values() if t.state == "down"),
                "insights": self.insights.last["counts"]}
