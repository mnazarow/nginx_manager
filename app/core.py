"""Ядро приложения: связывает хранилище, nginx, статистику, проверки, оповещения и фоновые задачи."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
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
_UPSTREAM_RE = re.compile(r"^\s*upstream\s+nm_site_(\d+)\s*\{")
_FAILOVER_RE = re.compile(r"^\s*server\s+(\S+)\s.*\bdown;\s+#\s*выключен автопереключением")


def failover_in_files(files: Dict[str, str]) -> Dict[str, List[str]]:
    """Бэкенды, выключенные автопереключением в файлах конфигурации (по пометке генератора)."""
    out: Dict[str, List[str]] = {}
    for text in files.values():
        cur = None
        for ln in text.splitlines():
            m = _UPSTREAM_RE.match(ln)
            if m:
                cur = f"site:{m.group(1)}"
                continue
            m = _FAILOVER_RE.match(ln)
            if m and cur:
                out.setdefault(cur, []).append(m.group(1))
    return {k: sorted(v) for k, v in out.items()}


def effective_failover(state: State, overrides: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Что генератор реально выключит при таких overrides: только существующие и не выключенные вручную серверы,
    и ничего, если иначе не осталось бы ни одного основного (то же правило, что в Generator.upstream_block)."""
    out: Dict[str, List[str]] = {}
    for sid, s in state.sites:
        dis = set(overrides.get(f"site:{sid}") or [])
        if not dis or not s.enabled or s.type != "proxy":
            continue
        active = [b.key() for b in s.backends if not b.down and not b.backup]
        if all(k in dis for k in active):
            continue
        eff = sorted(b.key() for b in s.backends if b.key() in dis and not b.down)
        if eff:
            out[f"site:{sid}"] = eff
    return out


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
        from .services.peers import PeerSync
        self.peers = PeerSync(self)
        from .services.tgbot import TelegramActions
        self.tgbot = TelegramActions(self)
        self.insights = Analyzer(self)
        from .services.events import EventNotifier
        self.events = EventNotifier(self)
        self.stats.agg.detector = self.bans.detector
        from .protection.service import ProtectionService
        self.protection = ProtectionService(self)
        from .services.geoupdate import GeoUpdater
        self.geoupdate = GeoUpdater(self)
        from .services.access_links import GrantSync
        self.grants = GrantSync(self)
        self.stats.agg.protection = self.protection
        self.alerts.site_name = self._site_name
        self.clients: Set[WSClient] = set()
        self.tasks: List[asyncio.Task] = []
        self.started = time.time()
        self.revision = 0
        self._pending_cache: Tuple[int, float, Dict[str, Any]] = (-1, 0.0, {})
        self.nginx_restarts: List[float] = []
        self._reconcile_sig: Tuple[str, float] = ("", 0.0)
        self._expire_try: Tuple[int, int] = (0, 0)
        self.nginx.overrides_provider = self.failover_overrides
        self.bootstrap()
        self.migrate_trusted()

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

    # ------------------------------------------------------------------ доверенные адреса
    def trusted_entries(self) -> List[Any]:
        """Действующие доверенные записи: свои и полученные с других серверов."""
        from .services import trusted as TR
        return TR.effective(self.db, self.panel())

    def trusted(self) -> List[str]:
        """Доверенные адреса и подсети (раздел «Доверенные адреса» и полученные с других серверов)."""
        return [e.address for e in self.trusted_entries()]

    def migrate_trusted(self) -> None:
        """Однократно: «Никогда не блокировать» (блокировки IP) и «Доверенные IP» (защита) → «Доверенные адреса»."""
        if self.db.kv_get("trusted_migrated"):
            return
        from .models import IpEntry
        p = self.panel()
        prot = self.protection.settings()
        entries = list(p.trusted_ips)
        have = {e.address for e in entries}
        moved = 0
        for addr, note in [(a, "из «Блокировки IP → Никогда не блокировать»") for a in p.autoban_whitelist] + \
                [(a, "из «Защита от атак → Доверенные IP»") for a in prot.bypass_ips]:
            if addr not in have:
                entries.append(IpEntry(address=addr, comment=note))
                have.add(addr)
                moved += 1
        if p.autoban_whitelist or moved:
            self.save_panel(p.model_copy(update={"trusted_ips": entries, "autoban_whitelist": []}))
        if prot.bypass_ips:
            self.protection.save(prot.model_copy(update={"bypass_ips": []}))
        if moved:
            self.db.event("info", "panel", f"Доверенные адреса: перенесено {moved} из прежних списков исключений")
        self.db.kv_set("trusted_migrated", True)

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
        self.events.attach(loop)
        self.db.on_event = self.events.on_event
        self.tasks += [loop.create_task(self.ticker(), name="ticker"),
                       loop.create_task(self.watchdog(), name="watchdog"),
                       loop.create_task(self.periodic(), name="periodic"),
                       loop.create_task(self.protection.run(), name="protection"),
                       loop.create_task(self.peers.run(), name="peers"),
                       loop.create_task(self.tgbot.run(), name="tg-actions")]
        try:  # режим «Под атакой» мог закончиться, пока панель не работала
            await self.protection.sync_attack_file()
        except Exception:  # noqa: BLE001
            log.exception("защита: не удалось обновить файл режима «Под атакой»")
        try:  # доступ по ссылке мог истечь, пока панель не работала
            await self.grants.sync()
        except Exception:  # noqa: BLE001
            log.exception("не удалось обновить файл доступа по ссылкам")
        self.db.event("info", "panel", f"Nginx Manager {VERSION} запущен")

    async def stop(self) -> None:
        self.db.on_event = None
        try:
            self.protection.flush()
        except Exception:  # noqa: BLE001
            pass
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
        st = state or self.last_applied_state()
        if st is not None and any(s.ip_access.enabled and s.ip_access.lists for _, s in st.sites):
            from .utils import spawn
            spawn(self.lists_after_apply(), name="iplists")
        await self.broadcast({"type": "applied", "version": res["version"], "user": username, "source": source})
        return res

    async def lists_after_apply(self) -> None:
        """Новые списки адресов по ссылке скачиваются сразу после применения, а файл доступа — с новым составом
        сайтов (списки убранных сайтов перестают действовать)."""
        from .services import iplists
        try:
            state = self.last_applied_state()
            if state is not None:
                await asyncio.to_thread(iplists.refresh, self.db, state)
            await self.grants.sync()
        except Exception:  # noqa: BLE001
            log.exception("списки адресов: не удалось обновить после применения")

    def failover_overrides(self) -> Dict[str, List[str]]:
        """Бэкенды, которые сейчас нужно держать выключенными (проверки с автопереключением сочли их недоступными)."""
        return self.health.disabled_by_failover() if self.panel().auto_apply_failover else {}

    async def reconcile_failover(self) -> Optional[Dict[str, Any]]:
        """Сверка работающей конфигурации с результатами проверок. Расходятся они после применения из nmctl, отката
        в консоли, восстановления базы или перезапуска панели, пока бэкенд восстановился (переход unknown → up
        не вызывает переключения). При расхождении — переприменение последней версии с актуальным выключением."""
        if self.nginx.lock.locked():
            return None
        targets = [t for t in self.health.targets.values() if t.check.auto_failover and t.owner.startswith("site:")]
        if any(t.state == "unknown" for t in targets):
            return None  # ждём первых проверок после запуска
        last = self.nginx.last_applied()
        if not last:
            return None
        try:
            state = State.from_json(json.loads(last["state"]))
            have = failover_in_files(json.loads(last["files"]))
        except (ValueError, KeyError, TypeError):
            return None
        want = effective_failover(state, self.failover_overrides())
        if want == have:
            return None
        sig = json.dumps([last["id"], want, have], sort_keys=True)
        if self._reconcile_sig[0] == sig and time.time() - self._reconcile_sig[1] < 600:
            return None  # то же расхождение уже пытались устранить — не чаще раза в 10 минут
        self._reconcile_sig = (sig, time.time())
        log.info("сверка автопереключения: в конфигурации %s, по проверкам %s", have, want)
        return await self.apply_snapshot("Автопереключение: сверка выключенных бэкендов с результатами проверок",
                                         "failover")

    async def apply_snapshot(self, reason: str, source: str) -> Optional[Dict[str, Any]]:
        """Переприменить последнюю применённую версию с актуальными сертификатами и переключениями бэкендов
        (неприменённые правки пользователя не затрагиваются; выключение упавших бэкендов добавит NginxManager)."""
        state = self.last_applied_state()
        if not state:
            return None
        fresh = self.nginx.load_state()
        state.certs = fresh.certs
        # доверенные адреса — актуальные (полученные с других серверов, истёкшие временные)
        state.panel = state.panel.model_copy(update={"trusted_ips": fresh.panel.trusted_ips})
        try:
            return await self.apply("system", reason, source, state)
        except ApplyError:
            return None  # событие об ошибке записал NginxManager.apply

    async def expire_access(self) -> Optional[Dict[str, Any]]:
        """Временный доступ: убрать истёкшие записи из «Доступа по IP» сайтов и доверенных адресов; если работающая
        конфигурация их ещё содержит — переприменить последнюю применённую версию (неприменённые правки не трогаем:
        генератор пропускает истёкшие записи сам)."""
        now = time.time()
        gone: List[str] = []
        for r in self.db.query("SELECT id, name, data FROM sites"):
            d = json.loads(r["data"])
            ia = d.get("ip_access") or {}
            ents = ia.get("entries") or []
            keep = [e for e in ents if not e.get("expires") or e["expires"] > now]
            if len(keep) != len(ents):
                ia["entries"] = keep
                self.db.execute("UPDATE sites SET data=?, updated_at=? WHERE id=?",
                                (json.dumps(d, ensure_ascii=False), now, r["id"]))
                gone += [f"{e.get('address')} — сайт «{r['name']}»" for e in ents if e not in keep]
        p = self.panel()
        keep_t = [e for e in p.trusted_ips if e.active(now)]
        if len(keep_t) != len(p.trusted_ips):
            gone += [f"{e.address} — доверенные адреса" for e in p.trusted_ips if not e.active(now)]
            self.save_panel(p.model_copy(update={"trusted_ips": keep_t}))
            self.peers.mark()
        if gone:
            self.touch()
            self.db.event("info", "access", f"Истёк временный доступ: {', '.join(gone[:10])}"
                          + (f" и ещё {len(gone) - 10}" if len(gone) > 10 else ""))
        # доступ по ссылке: истёкшие адреса убираются из ip-grants.conf (без новой версии конфигурации); списки
        # адресов по ссылке скачиваются по своему расписанию
        state = self.last_applied_state()
        if state is not None:
            from .services import iplists
            changed, done = await asyncio.to_thread(iplists.refresh, self.db, state)
            for url, d in done.items():
                if not d.get("ok"):
                    self.db.event("warning", "access", f"Список адресов {url} не скачан: {d.get('error')} — "
                                                       "действуют адреса из последней удачной загрузки")
        await self.grants.sync()
        last = self.nginx.last_applied()
        if not last or self.nginx.lock.locked():
            return None
        try:
            st = json.loads(last["state"])
        except ValueError:
            return None
        applied_at = float(last["ts"])

        def stale(entries) -> bool:
            return any(e.get("expires") and applied_at < e["expires"] <= now for e in entries or [])
        need = stale((st.get("panel") or {}).get("trusted_ips")) or any(
            stale(((x.get("data") or {}).get("ip_access") or {}).get("entries")) for x in st.get("sites", []))
        if not need:
            return None
        if self._expire_try == (last["id"], int(now // 600)):
            return None  # эту версию уже пытались переприменить — не чаще раза в 10 минут
        self._expire_try = (last["id"], int(now // 600))
        return await self.apply_snapshot("Истёк временный доступ", "expire")

    async def after_cert_issued(self, cid: int) -> None:
        state = self.last_applied_state()
        if not state:
            return
        uses = any(s.enabled and s.ssl.enabled and s.ssl.certificate_id == cid for _, s in state.sites) or \
            state.panel.panel_certificate_id == cid
        if uses:
            await self.apply_snapshot(f"Сертификат #{cid} выпущен/продлён", "certs")
        self.touch()
        # сертификат переносился на другие серверы вместе с сайтами — отправить продлённый туда же
        await self._guard("отправка сертификата на другие серверы", asyncio.to_thread(self.peers.push_cert, cid))

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
            from .services.certs import lifetime_days
            certs = [c for c in self.certs.list() if c["days_left"] is not None and c["used_by"]]
            if not certs:
                return None, ""
            # короткие сертификаты (меньше 30 дней) в «днях до истечения» почти всегда ниже порога — учитываем их,
            # только когда продление явно не случилось (осталось меньше шестой части срока)
            urgent = [c for c in certs if lifetime_days(c) >= 30 or c["days_left"] < lifetime_days(c) / 6]
            if not urgent:
                return round(max(c["days_left"] for c in certs), 1), ""
            c = min(urgent, key=lambda x: x["days_left"])
            return round(c["days_left"], 1), f"Сертификат «{c['name']}» ({', '.join(c['domains'][:3])})"
        if m == "insights_crit":
            return float(self.insights.last["counts"].get("crit", 0)), "\n".join(
                f"{f['site_name']}: {f['title']} — {f['summary']}" for f in self.insights.last["findings"]
                if f["level"] == "crit")[:1500]
        if m in ("attacks_blocked", "under_attack", "vuln_attempts"):
            return self.protection.alert_metric(m, site, rule.window)
        if m == "ipaccess_denied":
            start = int((time.time() - rule.window) // 60) * 60
            q, args = "SELECT ip, SUM(n) AS n FROM ipdeny_minute WHERE ts>=?", [start]
            if site != "*":
                q += " AND site=?"
                args.append(str(site))
            by: Dict[str, int] = {r["ip"]: r["n"] for r in self.db.query(q + " GROUP BY ip", tuple(args))}
            for (ts, s_, ip), v in list(getattr(self.stats.agg, "ipdeny", {}).items()):  # ещё не записанные минуты
                if ts >= start and (site == "*" or s_ == str(site)):
                    by[ip] = by.get(ip, 0) + v[0]
            minutes = max(1.0, (time.time() - start) / 60)
            top = sorted(by.items(), key=lambda x: -x[1])[:5]
            return round(sum(by.values()) / minutes, 2), ", ".join(f"{ip}: {n}" for ip, n in top)
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

    def _silence_brief(self) -> Optional[Dict[str, Any]]:
        s = self.alerts.silence_for(None)
        if not s:
            now = time.time()
            s = self.db.one("SELECT * FROM silences WHERE starts_at<=? AND ends_at>? ORDER BY ends_at DESC LIMIT 1",
                            (now, now))
        return {"id": s["id"], "ends_at": s["ends_at"], "reason": s["reason"],
                "all": s["rule_ids"] in ("", "[]")} if s else None

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

    def _site_name(self, sid: str) -> str:
        from .services.metrics import site_names
        return site_names(self).get(str(sid), str(sid))

    async def refresh_geo(self, force: bool = False) -> None:
        """База GeoIP заменена на новую — перечитать её и пересобрать сети стран для nginx."""
        g = self.stats.geoip
        try:
            mt = os.path.getmtime(g.path) if g.path else 0.0
        except OSError:
            mt = 0.0
        a = self.stats.asn
        try:
            amt = os.path.getmtime(a.path) if a.path else 0.0
        except OSError:
            amt = 0.0
        changed = bool(g.path and mt and mt != getattr(g, "mtime", mt)) or bool(a.path and amt != a.mtime)
        if changed or not g.path or not a.path:  # обновлена база или могла появиться новая (автообновление)
            before = (g.path, a.path)
            self.stats.reload_geoip()
            if changed or (g.path, a.path) != before:
                self.db.event("info", "geoip", "Базы GeoIP перечитаны", {"country": g.path, "asn": a.path})
        g.mtime = os.path.getmtime(g.path) if g.path and os.path.exists(g.path) else mt
        async with self.nginx.lock:
            ares = await asyncio.to_thread(self.nginx.refresh_asn)
        if ares is not None and not ares[0]:
            self.db.event("error", "geoip", "Не удалось обновить сети провайдеров в nginx", {"output": ares[1][-2000:]})
        async with self.nginx.lock:
            res = await asyncio.to_thread(self.nginx.refresh_geo, force)
        if res is not None:
            ok, out = res
            st = self.nginx.geo_stats
            if ok:
                self.db.event("info", "geoip", f"Сети стран обновлены: {st.get('nets', 0)} сетей "
                              f"({', '.join(sorted(st.get('countries', {})))})", st)
            else:
                self.db.event("error", "geoip", "Не удалось обновить сети стран в nginx", {"output": out[-2000:]})

    async def periodic(self) -> None:
        await asyncio.sleep(20)
        last_diag = last_cert = last_geo = 0.0
        while True:
            now = time.time()
            try:
                p = self.panel()
            except Exception:
                log.exception("настройки панели")
                await asyncio.sleep(60)
                continue
            try:
                # встроенный анализ за последние 15 минут — для значка в меню и метрики оповещений
                res = await asyncio.to_thread(self.insights.evaluate, now - 900, now, "*")
                self.insights.last = {"counts": res["counts"], "findings": res["findings"][:50], "ts": now}
                self._insights_history(res["findings"])
            except Exception:
                log.exception("анализ метрик")
            # каждая задача — отдельно: сбой одной (например, диагностики) не откладывает продление сертификатов,
            # отчёты и резервные копии
            if now - last_diag > p.diagnostics_interval:
                last_diag = now
                await self._guard("диагностика", self.diag.run_all())
            if now - last_geo > 600:
                last_geo = now
                if p.geoip_auto_update:
                    await self._guard("обновление баз GeoIP", self.geoupdate.tick())
                await self._guard("сети стран GeoIP", self.refresh_geo())
            if now - last_cert > 3600:  # ежечасно: сертификаты внутренних центров живут и сутки
                last_cert = now
                await self._guard("проверка сертификатов", asyncio.to_thread(self.certs.refresh_all))
                await self._guard("продление сертификатов", self.certs.auto_renew(after=self.after_cert_issued))
            await self._guard("временный доступ", self.expire_access())
            await self._guard("регулярный отчёт", self.maybe_send_report())
            await self._guard("сверка автопереключения бэкендов", self.reconcile_failover())
            lt = time.localtime(now)
            today = time.strftime("%Y-%m-%d", lt)
            if lt.tm_hour == p.backup_hour and self.db.kv_get("last_auto_backup") != today:
                self.db.kv_set("last_auto_backup", today)
                from .services.backup import auto_backup
                await self._guard("автоматическая резервная копия", asyncio.to_thread(auto_backup, self))
            await asyncio.sleep(60)

    async def _guard(self, what: str, aw) -> None:
        """Выполнить фоновую задачу; ошибка — в журнал сервиса и в «События», цикл продолжается."""
        try:
            await aw
        except Exception as e:
            log.exception(what)
            try:
                self.db.event("error", "panel", f"Фоновая задача «{what}» завершилась ошибкой: {e}"[:500])
            except Exception:
                pass

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
                "insights": self.insights.last["counts"],
                "silence": self._silence_brief(), "peers": sum(1 for x in self.panel().peers if x.enabled)}
