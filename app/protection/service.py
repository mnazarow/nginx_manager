"""Служба защиты от атак: режим «Под атакой» (вручную и автоматически), списки угроз, журнал атак и счётчики,
самопроверка защиты сайта, оценка защищённости, сетевые настройки ядра."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
import urllib.request
from collections import Counter, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import settings
from ..models import ProtectionSettings, Site
from . import rules as W
from .nginx import challenge_ready, site_modes

log = logging.getLogger("nm.protection")

KINDS = {"waf": "Фильтр запросов", "custom": "Свои правила", "threat": "Списки угроз", "hotlink": "Хотлинкинг",
         "challenge": "Проверка браузера", "honeypot": "Ловушки", "ratelimit": "Ограничение частоты",
         "sni": "Host и SNI не совпадают"}
ACTIONS = {"blocked": "заблокировано", "detected": "записано", "challenged": "проверка браузера",
           "passed": "проверка пройдена", "banned": "IP заблокирован", "allowed": "пропущено"}
MAX_FEED_BYTES = 40 * 1024 * 1024
MAX_FEED_ENTRIES = 1_500_000


# =============================================================================
#  Списки угроз
# =============================================================================
def parse_feed(text: str) -> Tuple[List[str], int]:
    """Текст списка → нормализованные адреса и подсети (первое слово строки; комментарии # и ;)."""
    out, bad, seen = [], 0, set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        tok = line.split()[0].strip(",")
        if "-" in tok and "/" not in tok:  # диапазон «a-b» (DShield пишет начало и конец через пробел)
            tok = tok.split("-")[0]
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            # DShield: «начало конец маска» — берём начало и маску
            parts = line.split()
            try:
                net = ipaddress.ip_network(f"{parts[0]}/{parts[2]}", strict=False) if len(parts) >= 3 else None
            except (ValueError, IndexError):
                net = None
            if net is None:
                bad += 1
                continue
        if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 16):
            bad += 1  # слишком широкая сеть — вероятно, ошибка в списке
            continue
        s = str(net.network_address) if net.num_addresses == 1 else str(net)
        if s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= MAX_FEED_ENTRIES:
            break
    return out, bad


def fetch_feed(url: str, timeout: int = 60) -> str:
    if url.startswith("file://"):
        return Path(url[7:]).read_text(encoding="utf-8", errors="replace")
    req = urllib.request.Request(url, headers={"User-Agent": "NginxManager-ThreatFeeds/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — адрес задаёт администратор
        data = r.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("список больше 40 МБ")
    return data.decode("utf-8", errors="replace")


# =============================================================================
#  Самопроверка: «сырые» HTTP-запросы к nginx на этом сервере
# =============================================================================
def raw_request(host: str, port: int, tls: bool, sni: str, method: str, target: str, headers: Dict[str, str],
                timeout: float = 5.0) -> Tuple[Optional[int], Dict[str, str]]:
    """Отправить запрос как есть (без нормализации URL) и прочитать статус. None — соединение закрыто (444)."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=sni)
        lines = [f"{method} {target} HTTP/1.1", f"Host: {sni}", "Connection: close"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "surrogateescape"))
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        if not buf:
            return None, {}
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        first, *rest = head.split("\r\n")
        m = re.match(r"HTTP/\d(?:\.\d)? (\d{3})", first)
        hdrs = {}
        for ln in rest:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        return (int(m.group(1)) if m else None), hdrs
    except (ConnectionResetError, ssl.SSLError, socket.timeout, BrokenPipeError):
        return None, {}
    finally:
        try:
            s.close()
        except OSError:
            pass


def selftest_cases(level: int) -> List[Dict[str, Any]]:
    """Атаки для самопроверки: по одному примеру каждого правила (поле запроса или заголовок) + обычные запросы."""
    cases = []
    for r in W.RULES:
        if r.level > level or not r.examples:
            continue
        ex = r.examples[0]
        t = r.targets[0]
        case = {"rule": r.id, "cat": r.cat, "title": r.title, "method": "GET", "path": "/", "headers": {},
                "payload": ex, "field": W.TARGETS[t][1]}
        if t == "uri":
            if not ex.startswith("/"):
                continue
            case["path"] = ex
        elif t in ("ua", "ref", "cookie", "xff", "ctype", "xapi", "nextmw", "xmo"):
            hn = {"ua": "User-Agent", "ref": "Referer", "cookie": "Cookie", "xff": "X-Forwarded-For",
                  "ctype": "Content-Type", "xapi": "X-Api-Version", "nextmw": "X-Middleware-Subrequest",
                  "xmo": "X-HTTP-Method-Override"}[t]
            if not ex or "\r" in ex or "\n" in ex:
                continue
            case["headers"][hn] = ex
        elif t == "method":
            case["method"] = ex
        else:
            continue  # протокол/Transfer-Encoding — не проверяем, nginx сам отвечает на такие запросы
        cases.append(case)
    return cases


BENIGN_CASES = ["/", "/search?q=nginx+reverse+proxy", "/catalog?size=42&color=red", "/?q=O%27Reilly",
                "/blog/how-to-select-the-best-union-plan", "/api/v1/users/42?page=2", "/login?next=/account"]


# =============================================================================
#  Сетевые параметры ядра (защита от SYN-флуда и подмены адресов)
# =============================================================================
SYSCTL = [
    ("net.ipv4.tcp_syncookies", "1", "eq", "SYN cookies: ядро отвечает на SYN без выделения памяти — защита от SYN-флуда"),
    ("net.ipv4.tcp_max_syn_backlog", "8192", "ge", "Очередь полуоткрытых соединений"),
    ("net.core.somaxconn", "4096", "ge", "Очередь принятых соединений (nginx listen backlog)"),
    ("net.core.netdev_max_backlog", "16384", "ge", "Очередь пакетов сетевой карты при всплесках"),
    ("net.ipv4.tcp_synack_retries", "2", "le", "Меньше повторов SYN-ACK — быстрее освобождаются полуоткрытые"),
    ("net.ipv4.tcp_fin_timeout", "15", "le", "Быстрее закрывать соединения, брошенные клиентом"),
    ("net.ipv4.tcp_rfc1337", "1", "eq", "Защита от TIME-WAIT assassination (RFC 1337)"),
    ("net.ipv4.conf.all.rp_filter", "1", "in12", "Отбрасывать пакеты с подменённым адресом источника"),
    ("net.ipv4.conf.all.accept_redirects", "0", "eq", "Не принимать ICMP redirect (подмена маршрутов)"),
    ("net.ipv4.conf.all.send_redirects", "0", "eq", "Не отправлять ICMP redirect"),
    ("net.ipv4.conf.all.accept_source_route", "0", "eq", "Не принимать пакеты с маршрутом от источника"),
    ("net.ipv6.conf.all.accept_redirects", "0", "eq", "То же для IPv6"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "eq", "Не отвечать на широковещательный ping (Smurf)"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "eq", "Игнорировать поддельные ICMP-ошибки"),
    ("net.ipv4.conf.all.log_martians", "1", "eq", "Записывать в журнал ядра пакеты с невозможными адресами"),
]
SYSCTL_FILE = Path("/etc/sysctl.d/90-nginx-manager.conf")


def sysctl_read(name: str) -> Optional[str]:
    try:
        return Path("/proc/sys/" + name.replace(".", "/")).read_text().strip()
    except OSError:
        return None


def sysctl_ok(cur: Optional[str], want: str, how: str) -> Optional[bool]:
    if cur is None:
        return None
    try:
        c = int(cur.split()[0])
    except ValueError:
        return None
    w = int(want)
    return {"eq": c == w, "ge": c >= w, "le": c <= w, "in12": c in (1, 2)}[how]


def sysctl_report() -> List[Dict[str, Any]]:
    out = []
    for name, want, how, title in SYSCTL:
        cur = sysctl_read(name)
        out.append({"name": name, "current": cur, "recommended": want, "rule": how, "title": title,
                    "ok": sysctl_ok(cur, want, how)})
    return out


# =============================================================================
#  Служба
# =============================================================================
class ProtectionService:
    FLUSH_SEC = 60

    def __init__(self, app) -> None:
        self.app = app
        self.db = app.db
        self._settings: Optional[ProtectionSettings] = None
        self.counts: Counter = Counter()          # (минута, сайт, вид, правило, действие) → число
        self.minute_rows = 0
        self.minute_start = 0
        self.pending_rows: List[tuple] = []
        self.ip_hits: Dict[str, deque] = {}        # IP → время срабатываний фильтра (для автоблокировки)
        self.flagged: Dict[str, float] = {}
        self.recent: deque = deque(maxlen=200)     # последние события для живой ленты
        self.challenge_stats: Counter = Counter()  # served/passed/failed
        self.totals: Counter = Counter()           # (сайт, вид, действие) → число с запуска (для /metrics)
        self._lock: Optional[asyncio.Lock] = None
        self.feed_task_running = False

    # ------------------------------------------------------------------ настройки
    def settings(self) -> ProtectionSettings:
        if self._settings is None:
            self._settings = ProtectionSettings.model_validate(self.db.kv_get("protection_settings", {}))
        return self._settings

    def save(self, p: ProtectionSettings) -> None:
        self.db.kv_set("protection_settings", p.model_dump())
        self._settings = None
        self.app.touch()

    # ------------------------------------------------------------------ режим «Под атакой»
    def attack_state(self) -> Dict[str, Any]:
        st = self.db.kv_get("attack_mode", {}) or {}
        st.setdefault("global", None)
        st.setdefault("sites", {})
        return st

    def active_attack(self, now: Optional[float] = None) -> Tuple[bool, List[str]]:
        now = now or time.time()
        st = self.attack_state()
        g = st.get("global")
        glob = bool(g) and (g.get("until") is None or g["until"] > now)
        sites = [k for k, v in st["sites"].items() if v and (v.get("until") is None or v["until"] > now)]
        return glob, sites

    def render_attack_file(self) -> str:
        glob, sites = self.active_attack()
        lines = ["# Nginx Manager: режим «Под атакой» (c — проверять браузер). Меняется панелью.",
                 f'default "{"c" if glob else ""}";']
        for sid in sorted(sites, key=lambda x: int(x) if x.isdigit() else 0):
            lines.append(f'"{sid}" "c";')
        return "\n".join(lines) + "\n"

    async def sync_attack_file(self) -> Tuple[bool, str]:
        mgr = self.app.nginx
        async with mgr.lock:
            return await asyncio.to_thread(mgr.write_side_file, settings.attack_file, self.render_attack_file())

    async def set_attack(self, site: Optional[int], on: bool, minutes: Optional[int] = None, user: str = "system",
                         auto: bool = False, reason: str = "") -> Dict[str, Any]:
        st = self.attack_state()
        key = None if site is None else str(site)
        entry = {"since": time.time(), "until": time.time() + minutes * 60 if minutes else None, "by": user,
                 "auto": auto, "reason": reason} if on else None
        if key is None:
            st["global"] = entry
        elif entry:
            st["sites"][key] = entry
        else:
            st["sites"].pop(key, None)
        self.db.kv_set("attack_mode", st)
        ok, out = await self.sync_attack_file()
        who = "автоматически" if auto else user
        name = "всех сайтов" if key is None else f"сайта «{self.site_name(key)}»"
        if on:
            dur = f" на {minutes} мин" if minutes else ""
            self.db.event("warning", "protection", f"Режим «Под атакой» включён для {name}{dur} ({who})"
                          + (f": {reason}" if reason else ""), {"site": key, "auto": auto})
        else:
            self.db.event("info", "protection", f"Режим «Под атакой» выключен для {name} ({who})", {"site": key})
        return {"ok": ok, "output": out[-1000:] if not ok else "", "state": self.attack_state()}

    def alert_metric(self, m: str, site: str, window: int) -> Tuple[Optional[float], str]:
        """Значение метрик оповещений attacks_blocked (в минуту за окно) и under_attack (1/0)."""
        now = time.time()
        if m == "under_attack":
            glob, sites = self.active_attack(now)
            on = glob or (bool(sites) if site == "*" else str(site) in sites)
            return (1.0 if on else 0.0), ("для всех сайтов" if glob else
                                          ", ".join(self.site_name(x) for x in sites) if on else "")
        start = int((now - window) // 60) * 60
        q = "SELECT kind, SUM(n) AS n FROM attack_minute WHERE ts>=? AND action='blocked'"
        args: list = [start]
        if site != "*":
            q += " AND site=?"
            args.append(str(site))
        rows = self.db.query(q + " GROUP BY kind ORDER BY n DESC", tuple(args))
        pend = Counter()
        for (ts, s, kind, _rule, act), n in self.counts.items():
            if ts >= start and act == "blocked" and (site == "*" or s == str(site)):
                pend[kind] += n
        by = Counter({r["kind"]: r["n"] or 0 for r in rows}) + pend
        total = sum(by.values())
        minutes = max(1.0, (now - start) / 60)
        return round(total / minutes, 2), ", ".join(f"{k}: {v}" for k, v in by.most_common(5))

    def site_name(self, sid: str) -> str:
        r = self.db.one("SELECT name FROM sites WHERE id=?", (int(sid),)) if str(sid).isdigit() else None
        return r["name"] if r else str(sid)

    async def auto_attack_tick(self, now: Optional[float] = None) -> List[str]:
        """Раз в минуту: включить «Под атакой» для сайта при всплеске нагрузки, выключить после затишья."""
        p = self.settings()
        now = now or time.time()
        st = self.attack_state()
        changed: List[str] = []
        # истёкшие ручные и автоматические режимы
        for key, v in list(st["sites"].items()):
            if v and v.get("until") and v["until"] <= now:
                if v.get("auto") and self.site_rps(key, now) >= p.auto_rps:
                    continue  # нагрузка ещё высокая — держим
                await self.set_attack(int(key), False, user="система", auto=bool(v.get("auto")))
                changed.append(key)
        g = st.get("global")
        if g and g.get("until") and g["until"] <= now:
            await self.set_attack(None, False, user="система", auto=bool(g.get("auto")))
        if not p.auto_attack:
            return changed
        _, active = self.active_attack(now)
        for sid, s in self.app.nginx.load_state().sites:
            if not s.enabled or not s.protection.enabled or s.protection.challenge != "auto" or str(sid) in active:
                continue
            rps = self.site_rps(str(sid), now)
            if rps < p.auto_rps:
                continue
            base = self.site_baseline(str(sid), now)
            if rps < p.auto_factor * max(base, 0.1):
                continue
            await self.set_attack(sid, True, p.auto_minutes, auto=True,
                                  reason=f"{rps:.0f} запросов/с при обычных {base:.1f}")
            changed.append(str(sid))
        return changed

    def site_rps(self, sid: str, now: float) -> float:
        m = int(now // 60) * 60 - 60
        r = self.db.scalar("SELECT COALESCE(SUM(req),0) FROM stats_minute WHERE site=? AND ts>=? AND ts<?",
                           (sid, m - 60, m + 60)) or 0
        return r / 120.0

    def site_baseline(self, sid: str, now: float) -> float:
        r = self.db.one("SELECT COALESCE(SUM(req),0) AS n, COUNT(*) AS m FROM stats_minute WHERE site=? AND ts>=? "
                        "AND ts<?", (sid, now - 86400, now - 900))
        return (r["n"] / 60.0 / max(r["m"], 1)) if r else 0.0

    # ------------------------------------------------------------------ списки угроз
    def feed_dir(self) -> Path:
        d = settings.data_dir / "threats"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def feed_status(self) -> Dict[str, Any]:
        return self.db.kv_get("threat_status", {}) or {}

    def render_threats(self) -> Tuple[str, int]:
        p = self.settings()
        lines = ["# Nginx Manager: списки угроз (раздел «Защита»). Файл обновляется панелью."]
        seen, total = set(), 0
        for f in p.threat_feeds:
            if not f.enabled:
                continue
            path = self.feed_dir() / f"{f.id}.txt"
            if not path.exists():
                continue
            for net in path.read_text().split():
                if net in seen:
                    continue
                seen.add(net)
                lines.append(f'{net} "{f.id}:{f.action}";')
                total += 1
        return "\n".join(lines) + "\n", total

    async def update_feeds(self, force: bool = False, only: Optional[str] = None) -> Dict[str, Any]:
        p = self.settings()
        status = self.feed_status()
        now = time.time()
        results = {}
        for f in p.threat_feeds:
            if not f.enabled or (only and f.id != only):
                continue
            st = status.get(f.id, {})
            if not force and st.get("updated") and now - st["updated"] < p.threat_update_hours * 3600 and st.get("ok"):
                continue
            try:
                text = await asyncio.to_thread(fetch_feed, f.url)
                nets, bad = parse_feed(text)
                if not nets:
                    raise ValueError("в списке не найдено ни одного адреса")
                (self.feed_dir() / f"{f.id}.txt").write_text("\n".join(nets) + "\n")
                status[f.id] = {"ok": True, "count": len(nets), "skipped": bad, "updated": now, "error": ""}
            except Exception as e:  # noqa: BLE001 — сеть, формат, файл: ошибка показывается у списка
                prev = status.get(f.id, {})
                status[f.id] = {**prev, "ok": False, "error": str(e)[:300], "tried": now}
                self.db.event("warning", "protection", f"Список угроз «{f.name}» не обновлён: {e}")
            results[f.id] = status[f.id]
        self.db.kv_set("threat_status", status)
        content, total = self.render_threats()
        mgr = self.app.nginx
        async with mgr.lock:
            ok, out = await asyncio.to_thread(mgr.write_side_file, settings.threats_file, content)
        if not ok:
            self.db.event("error", "protection", "Не удалось подключить списки угроз к nginx", {"output": out[-1500:]})
        return {"ok": ok, "total": total, "feeds": results, "output": "" if ok else out[-1500:]}

    # ------------------------------------------------------------------ журнал атак (из сборщика статистики)
    def observe(self, r: Dict[str, Any], site: str, country: str, ts: float) -> None:
        """Строка журнала доступа → счётчики и журнал атак. Вызывается сборщиком для каждой строки."""
        wa = r.get("wa") or ""
        wf = r.get("wf") or ""
        ch = r.get("ch") or ""
        status = r.get("status", 0)
        uri = r.get("uri") or ""
        test = "nm_selftest=" in uri
        events = []
        if wf and wa and wa[0] not in "ax":
            act = {"block": "blocked", "drop": "blocked", "detect": "detected", "log": "detected",
                   "challenge": "challenged"}.get(wa)
            if act:
                kind = wf.split("/", 1)[0]
                kind = kind if kind in ("custom", "threat", "hotlink") else "waf"
                events.append((kind, wf, act))
        if ch in ("c", "c0"):
            events.append(("challenge", "challenge", "challenged"))
            self.challenge_stats["served"] += 1
        elif ch == "c1":
            self.challenge_stats["passed"] += 1
        if status == 421:
            events.append(("sni", "sni", "blocked"))
        if status == 429 and not r.get("ustatus"):
            events.append(("ratelimit", "limit_req", "blocked"))
        ip = r.get("ip") or ""
        if site not in ("-", "panel", "") and self._honeypot(site, uri):
            events.append(("honeypot", "honeypot", "banned"))
        for kind, rule, act in events:
            self._count(ts, site, kind, rule, act, test)
            self._row(ts, site, ip, country, kind, rule, act, r, test)
            if not test and kind == "waf" and act in ("blocked", "detected"):
                self._autoban(ip, ts, rule, uri, country, r.get("host") or "")
            if not test and kind == "honeypot":
                self._honeypot_ban(ip, ts, uri, country, r.get("host") or "")

    def _honeypot(self, site: str, uri: str) -> bool:
        p = self.settings()
        if not p.honeypot_paths:
            return False
        sp = self.site_prot().get(site)
        if not sp or not sp.enabled or not sp.honeypot:
            return False
        path = uri.split("?", 1)[0].lower()
        for h in p.honeypot_paths:
            if h.startswith("~"):
                if re.search(h[1:], path):
                    return True
            elif path.startswith(h.lower()):
                return True
        return False

    _site_prot_cache: Tuple[int, Dict[str, Any]] = (-1, {})

    def site_prot(self) -> Dict[str, Any]:
        rev = self.app.revision
        if self._site_prot_cache[0] != rev:
            out = {}
            for row in self.db.query("SELECT id, data FROM sites"):
                try:
                    out[str(row["id"])] = Site.model_validate(json.loads(row["data"])).protection
                except Exception:  # noqa: BLE001
                    continue
            self._site_prot_cache = (rev, out)
        return self._site_prot_cache[1]

    def _count(self, ts, site, kind, rule, act, test) -> None:
        if test:
            return
        self.counts[(int(ts // 60) * 60, site, kind, rule, act)] += 1
        self.totals[(site, kind, act)] += 1

    def _row(self, ts, site, ip, country, kind, rule, act, r, test) -> None:
        m = int(ts // 60)
        if m != self.minute_start:
            self.minute_start, self.minute_rows = m, 0
        self.minute_rows += 1
        if self.minute_rows > self.settings().log_per_minute and not test:
            return
        row = (ts, site, ip, country, kind, rule, act, (r.get("method") or "")[:10], (r.get("uri") or "")[:500],
               (r.get("ua") or "")[:300], int(r.get("status") or 0), (r.get("rid") or "")[:40],
               (r.get("host") or "")[:200], 1 if test else 0)
        self.pending_rows.append(row)
        self.recent.append({"ts": ts, "site": site, "ip": ip, "country": country, "kind": kind, "rule": rule,
                            "action": act, "method": row[7], "uri": row[8][:200], "status": row[10], "test": test})

    def _autoban(self, ip: str, ts: float, rule: str, uri: str, country: str, host: str) -> None:
        p = self.settings()
        if not p.autoban_waf or not ip or not self.app.panel().autoban_enabled:
            return
        window = self.app.panel().autoban_window
        q = self.ip_hits.get(ip)
        if q is None:
            if len(self.ip_hits) > 100_000:
                self.ip_hits.clear()
            q = self.ip_hits[ip] = deque(maxlen=max(p.autoban_waf, 1))
        q.append(ts)
        if len(q) >= p.autoban_waf and ts - q[0] <= window:
            last = self.flagged.get(ip)
            if last and ts - last < window:
                return
            self.flagged[ip] = ts
            det = getattr(getattr(self.app, "bans", None), "detector", None)
            if det is not None:
                info = {"ip": ip, "rule": "waf", "title": "Атаки (фильтр запросов)", "count": len(q),
                        "window": window, "ts": ts, "sample": uri[:300], "host": host[:200], "country": country,
                        "requests": len(q), "e4xx": 0, "e401": 0, "scan": len(q), "default": 0, "waf_rule": rule}
                det.candidates.append(info)
                det.suspicious[ip] = info

    def _honeypot_ban(self, ip: str, ts: float, uri: str, country: str, host: str) -> None:
        det = getattr(getattr(self.app, "bans", None), "detector", None)
        if det is None or not ip or (self.flagged.get("hp:" + ip, 0) > ts - 60):
            return
        self.flagged["hp:" + ip] = ts
        info = {"ip": ip, "rule": "honeypot", "title": "Ловушка для сканеров", "count": 1, "window": 60, "ts": ts,
                "sample": uri[:300], "host": host[:200], "country": country, "requests": 1, "e4xx": 0, "e401": 0,
                "scan": 1, "default": 0, "ban_minutes": self.settings().honeypot_minutes, "force": True}
        det.candidates.append(info)
        det.suspicious[ip] = info

    def flush(self) -> int:
        """Записать накопленное в базу (вызывается раз в несколько секунд)."""
        rows, self.pending_rows = self.pending_rows, []
        counts, self.counts = self.counts, Counter()
        if rows:
            self.db.executemany("INSERT INTO attack_log(ts,site,ip,country,kind,rule,action,method,uri,ua,status,rid,"
                                "host,test) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        if counts:
            self.db.executemany("INSERT INTO attack_minute(ts,site,kind,rule,action,n) VALUES(?,?,?,?,?,?) "
                                "ON CONFLICT(ts,site,kind,rule,action) DO UPDATE SET n=n+excluded.n",
                                [(*k, n) for k, n in counts.items()])
        return len(rows)

    def cleanup(self) -> None:
        cut = time.time() - self.settings().log_days * 86400
        self.db.execute("DELETE FROM attack_log WHERE ts<?", (cut,))
        self.db.execute("DELETE FROM attack_minute WHERE ts<?", (cut,))

    # ------------------------------------------------------------------ отчёты
    def overview(self, hours: int = 24, site: str = "") -> Dict[str, Any]:
        now = time.time()
        since = now - hours * 3600
        cond, args = "ts>=?", [since]
        if site:
            cond += " AND site=?"
            args.append(site)
        tot = {r["action"]: r["n"] for r in self.db.query(
            f"SELECT action, SUM(n) AS n FROM attack_minute WHERE {cond} GROUP BY action", args)}
        by_kind = self.db.query(f"SELECT kind, action, SUM(n) AS n FROM attack_minute WHERE {cond} "
                                "GROUP BY kind, action ORDER BY n DESC", args)
        rules = self.db.query(f"SELECT kind, rule, action, SUM(n) AS n FROM attack_minute WHERE {cond} "
                              "GROUP BY kind, rule, action ORDER BY n DESC LIMIT 25", args)
        sites = self.db.query(f"SELECT site, SUM(n) AS n FROM attack_minute WHERE {cond} AND action IN "
                              "('blocked','detected','challenged','banned') GROUP BY site ORDER BY n DESC LIMIT 15", args)
        lcond = cond + " AND test=0"
        ips = self.db.query(f"SELECT ip, country, COUNT(*) AS n, MAX(ts) AS last, "
                            f"GROUP_CONCAT(DISTINCT kind) AS kinds FROM attack_log WHERE {lcond} "
                            "GROUP BY ip ORDER BY n DESC LIMIT 20", args)
        countries = self.db.query(f"SELECT country, COUNT(*) AS n FROM attack_log WHERE {lcond} AND country!='' "
                                  "GROUP BY country ORDER BY n DESC LIMIT 15", args)
        uris = self.db.query(f"SELECT uri, COUNT(*) AS n FROM attack_log WHERE {lcond} GROUP BY uri "
                             "ORDER BY n DESC LIMIT 15", args)
        step = 300 if hours <= 6 else 1800 if hours <= 48 else 3 * 3600
        buckets = self.db.query(f"SELECT (ts/{step})*{step} AS b, kind, SUM(n) AS n FROM attack_minute WHERE {cond} "
                                "AND action IN ('blocked','detected','challenged','banned') GROUP BY b, kind ORDER BY b",
                                args)
        names = {str(r["id"]): r["name"] for r in self.db.query("SELECT id, name FROM sites")}
        for r in sites:
            r["name"] = names.get(r["site"], r["site"])
        for r in rules:
            r["title"] = self.rule_title(r["kind"], r["rule"])
        glob, active = self.active_attack()
        return {"hours": hours, "since": since, "totals": tot, "by_kind": by_kind, "rules": rules, "sites": sites,
                "ips": ips, "countries": countries, "uris": uris, "step": step, "series": buckets,
                "attack": {"global": glob, "sites": active, "state": self.attack_state()},
                "challenge": dict(self.challenge_stats), "kinds": KINDS, "actions": ACTIONS}

    def rule_title(self, kind: str, rule: str) -> str:
        if kind == "waf" and "/" in rule:
            r = W.RULE_BY_ID.get(rule.split("/", 1)[1])
            return f"{W.CATEGORIES.get(r.cat, {}).get('title', r.cat)}: {r.title}" if r else rule
        if kind == "custom":
            rid = rule.split("/", 1)[-1]
            for cr in self.settings().custom_rules:
                if cr.id == rid:
                    return f"Своё правило: {cr.name}"
            return rule
        if kind == "threat":
            fid = rule.split("/", 1)[-1].split(":")[0]
            for f in self.settings().threat_feeds:
                if f.id == fid:
                    return f"Список угроз: {f.name}"
            return rule
        return KINDS.get(kind, kind)

    def events(self, limit: int = 200, before: Optional[float] = None, site: str = "", ip: str = "",
               kind: str = "", action: str = "", q: str = "", rid: str = "", test: Optional[bool] = False
               ) -> List[Dict[str, Any]]:
        cond, args = ["1=1"], []
        for col, v in (("site", site), ("ip", ip), ("kind", kind), ("action", action), ("rid", rid)):
            if v:
                cond.append(f"{col}=?")
                args.append(v)
        if before:
            cond.append("ts<?")
            args.append(before)
        if q:
            cond.append("(uri LIKE ? OR ua LIKE ? OR rule LIKE ? OR host LIKE ?)")
            args += [f"%{q}%"] * 4
        if test is not None:
            cond.append("test=?")
            args.append(1 if test else 0)
        rows = self.db.query(f"SELECT * FROM attack_log WHERE {' AND '.join(cond)} ORDER BY ts DESC LIMIT ?",
                             args + [min(limit, 2000)])
        for r in rows:
            r["title"] = self.rule_title(r["kind"], r["rule"])
        return rows

    # ------------------------------------------------------------------ самопроверка
    async def selftest(self, sid: int) -> Dict[str, Any]:
        state = self.app.nginx.load_state()
        site = dict(state.sites).get(sid)
        if site is None:
            raise ValueError("Сайт не найден")
        if not site.enabled:
            raise ValueError("Сайт выключен — его нет в конфигурации nginx")
        if self.app.pending().get("pending"):
            note = "Есть неприменённые изменения: проверяется работающая конфигурация nginx."
        else:
            note = ""
        tls = bool(site.ssl.enabled and site.ssl.certificate_id)
        port = site.https_port if tls else site.http_port
        host = site.listen_ip.strip("[]") if site.listen_ip else "127.0.0.1"
        domain = site.main_domain if hasattr(site, "main_domain") else site.domains[0]
        if domain.startswith("*.") or domain.startswith("~"):
            domain = "selftest" + domain[1:] if domain.startswith("*.") else site.domains[0]
        p = self.settings()
        modes = site_modes(p, site.protection)
        token = os.urandom(4).hex()
        cases = selftest_cases(p.waf_level)
        results = []

        def run(case, n):
            # пробелы, кавычки и # недопустимы в строке запроса HTTP — их кодирует любой клиент, кодируем и мы
            path = case["path"].replace(" ", "%20").replace('"', "%22").replace("#", "%23")
            sep = "&" if "?" in path else "?"
            target = f"{path}{sep}nm_selftest={token}{n}"
            hdrs = dict(case["headers"])
            hdrs.setdefault("User-Agent", "Mozilla/5.0 (NginxManager-SelfTest)")
            t0 = time.time()
            try:
                st, h = raw_request(host, port, tls, domain, case["method"], target, hdrs)
                err = ""
            except OSError as e:
                st, h, err = None, {}, str(e)
            return st, h, err, round((time.time() - t0) * 1000)

        for n, case in enumerate(cases):
            st, h, err, ms = await asyncio.to_thread(run, case, n)
            disabled = case["rule"] in site.protection.waf_disabled_rules or case["rule"] in p.waf_disabled_rules
            mode = "off" if disabled else modes.get(case["cat"], "off")
            # 400 и 405 — запрос отклонил сам nginx (путь выше корня после нормализации, метод TRACE и т. п.)
            blocked = st in (400, 403, 405, 444) or (st is None and not err)
            results.append({**{k: case[k] for k in ("rule", "cat", "title", "method", "field")},
                            "payload": case["payload"][:160], "mode": mode, "status": st, "blocked": blocked,
                            "error": err, "ms": ms, "n": n})
        benign = []
        for n, path in enumerate(BENIGN_CASES):
            case = {"path": path, "headers": {}, "method": "GET"}
            st, h, err, ms = await asyncio.to_thread(run, case, 1000 + n)
            benign.append({"path": path, "status": st, "blocked": st in (403, 444) or st is None, "error": err})
        # «запись в журнал» видна только в журнале атак: ждём, пока сборщик дочитает журнал nginx
        await asyncio.sleep(3)
        self.flush()
        logged = {r["uri"] for r in self.db.query("SELECT uri FROM attack_log WHERE test=1 AND uri LIKE ?",
                                                  (f"%nm_selftest={token}%",))}
        for r in results:
            mark = f"nm_selftest={token}{r['n']}"
            r["logged"] = any(u.endswith(mark) or (mark + "&") in u for u in logged)
            if r["mode"] == "block":
                r["ok"] = r["blocked"]
            elif r["mode"] == "detect":
                r["ok"] = r["logged"] and not r["blocked"]
            else:
                r["ok"] = True
        summary = {
            "total": len(results), "block_expected": sum(r["mode"] == "block" for r in results),
            "blocked": sum(r["mode"] == "block" and r["blocked"] for r in results),
            "detect_expected": sum(r["mode"] == "detect" for r in results),
            "detected": sum(r["mode"] == "detect" and r["logged"] for r in results),
            "off": sum(r["mode"] == "off" for r in results),
            "failed": sum(not r["ok"] for r in results),
            "false_positives": sum(b["blocked"] for b in benign),
        }
        res = {"site": sid, "name": site.name, "target": f"{'https' if tls else 'http'}://{domain}:{port}",
               "ts": time.time(), "summary": summary, "results": results, "benign": benign, "note": note}
        self.db.kv_set(f"selftest_{sid}", {k: v for k, v in res.items() if k != "results"} | {"failed": [
            r for r in results if not r["ok"]][:50]})
        return res

    # ------------------------------------------------------------------ оценка защищённости
    def score(self, sid: int, site: Site) -> Dict[str, Any]:
        p = self.settings()
        g = self.app.global_settings()
        panel = self.app.panel()
        sp = site.protection
        modes = site_modes(p, sp)
        sec = site.security
        https = site.ssl.enabled
        core = ("sqli", "xss", "traversal", "rce", "php", "java", "files", "scanners", "cve", "webshells")
        blocked_core = sum(modes.get(c) == "block" for c in core)
        detect_core = sum(modes.get(c) == "detect" for c in core)
        caps = self.app.nginx.caps()
        checks = [
            ("https", "Сайт работает по HTTPS", 10, https, "ssl", "Подключите сертификат на вкладке «SSL / HTTPS»"),
            ("redirect", "HTTP перенаправляется на HTTPS", 4, https and site.ssl.force_https, "ssl",
             "Включите «Перенаправлять HTTP на HTTPS»"),
            ("hsts", "HSTS (браузер не откроет сайт по HTTP)", 4, https and site.ssl.hsts, "ssl", "Включите HSTS"),
            ("tls", "Только TLS 1.2 и 1.3", 4, https and "TLSv1 " not in (site.ssl.protocols or g.ssl_protocols) + " "
             and "TLSv1.1" not in (site.ssl.protocols or g.ssl_protocols), "ssl", "Уберите TLSv1 и TLSv1.1"),
            ("waf", "Фильтр запросов блокирует основные атаки", 15, blocked_core >= 8, "protection",
             "Включите режим «Как в общих настройках» и блокировку категорий в «Защита → Фильтр запросов»"
             if detect_core < 8 else "Фильтр в режиме записи — переведите в блокировку после проверки журнала"),
            ("waf_detect", "Фильтр запросов хотя бы записывает атаки", 5, blocked_core + detect_core >= 8,
             "protection", "Включите фильтр запросов"),
            ("challenge", "Проверка браузера доступна для «Под атакой»", 5,
             sp.enabled and sp.challenge != "off" and challenge_ready(caps), "protection",
             "Режим «В режиме «Под атакой»» на вкладке «Защита от атак» (нужен модуль secure_link в nginx)"),
            ("rate", "Ограничение частоты запросов с IP", 8, sec.rate_limit, "security",
             "Включите ограничение частоты на вкладке «Безопасность»"),
            ("conn", "Ограничение соединений с IP", 4, sec.conn_limit > 0, "security",
             "Задайте «Макс. соединений с одного IP» (например, 50)"),
            ("login", "Защита форм входа от перебора", 4, sp.enabled and sp.login_protection, "protection",
             "Включите защиту форм входа, если на сайте есть вход"),
            ("headers", "Заголовки безопасности", 5, sec.security_headers, "security", "Включите заголовки безопасности"),
            ("csp", "Content-Security-Policy", 3, sec.security_headers and bool(sec.csp) and not sec.csp_report_only,
             "security", "Задайте CSP (сначала в режиме Report-Only)"),
            ("hidden", "Скрытые файлы (.git, .env) закрыты", 4, sec.block_hidden_files, "security",
             "Включите блокировку скрытых файлов"),
            ("strip", "Опасные заголовки запроса удаляются", 3, sp.enabled and sp.strip_headers or site.type != "proxy",
             "protection", "Включите «Удалять опасные заголовки запроса»"),
            ("sni", "Host и SNI сверяются", 2, not https or sp.enabled and sp.sni_check, "protection",
             "Включите проверку соответствия Host и SNI"),
            ("threats", "Подключены списки угроз", 4, sp.enabled and sp.threats and any(
                f.enabled for f in p.threat_feeds), "protection",
             "Подключите Spamhaus DROP и FireHOL level 1 в «Защита → Списки угроз»"),
            ("autoban", "Автоблокировка нарушителей", 5, panel.autoban_enabled, "panel-bans",
             "Включите автоблокировку в «Настройки панели → Блокировки IP»"),
            ("honeypot", "Ловушки для сканеров", 2, sp.enabled and sp.honeypot and bool(p.honeypot_paths),
             "protection", "Включите ловушки"),
            ("tokens", "Версия nginx скрыта (server_tokens off)", 3, not g.server_tokens, "global",
             "«Настройки nginx» → server_tokens: выключить"),
            ("slow", "Таймауты против медленных атак (Slowloris)", 3, _dur(g.client_header_timeout) <= 20
             and _dur(g.client_body_timeout) <= 30, "global",
             "client_header_timeout ≤ 15s, client_body_timeout ≤ 30s в «Настройки nginx»"),
            ("body", "Ограничен размер тела запроса", 2, bool(site.performance.client_max_body_size
                                                              or g.client_max_body_size), "performance",
             "Задайте client_max_body_size"),
        ]
        total = sum(w for _, _, w, *_ in checks)
        got = sum(w for _, _, w, ok, *_ in checks if ok)
        pct = round(got * 100 / total) if total else 0
        grade = "A" if pct >= 90 else "B" if pct >= 80 else "C" if pct >= 65 else "D" if pct >= 50 else "F"
        return {"site": sid, "name": site.name, "score": pct, "grade": grade,
                "checks": [{"id": i, "title": t, "weight": w, "ok": bool(ok), "tab": tab, "hint": hint}
                           for i, t, w, ok, tab, hint in checks]}

    # ------------------------------------------------------------------ фоновые задачи
    async def run(self) -> None:
        last_min = last_feeds = last_clean = 0.0
        while True:
            try:
                await asyncio.sleep(5)
                await asyncio.to_thread(self.flush)
                now = time.time()
                if now - last_min >= 60:
                    last_min = now
                    await self.auto_attack_tick(now)
                if now - last_feeds >= 600:
                    last_feeds = now
                    if any(f.enabled for f in self.settings().threat_feeds):
                        await self.update_feeds()
                if now - last_clean >= 3600:
                    last_clean = now
                    await asyncio.to_thread(self.cleanup)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — фоновая задача не должна останавливаться
                log.exception("защита: ошибка фоновой задачи")


def _dur(v: str) -> float:
    v = (v or "").strip()
    m = re.match(r"^(\d+)(ms|s|m|h)?$", v)
    if not m:
        return 60.0
    n = int(m.group(1))
    return {"ms": n / 1000, "s": n, None: n, "m": n * 60, "h": n * 3600}[m.group(2)]
