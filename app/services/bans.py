"""Блокировка IP-адресов: ручные блокировки и автоматические (аналог fail2ban на данных журнала доступа).

Как это работает:
  * Список заблокированных адресов и подсетей хранится в таблице bans и выгружается в файл
    /etc/nginx/nginx-manager/bans.conf, который подключён в `geo $nm_banned { … }` на уровне http.
    Каждый server-блок сайтов начинается с `if ($nm_banned) { return 444; }` — запрос отклоняется
    до выбора location, до проксирования и до проверки пароля.
  * Файл меняется без создания версии конфигурации: запись → nginx -t → reload (не чаще раза в
    несколько секунд, изменения копятся пачкой). Неприменённые правки сайтов это не затрагивает.
  * Детектор (BanDetector) смотрит на каждую строку журнала доступа и считает по каждому IP в окне
    фиксированной длины: зондирование уязвимостей, ответы 4xx, неудачные авторизации (401), обращения
    к серверу по умолчанию (по IP / к чужим доменам) и общее число запросов. Превышение порога —
    «подозрительный IP»; при включённой автоблокировке он блокируется на заданное время, повторные
    нарушители — на всё больший срок.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from collections import Counter, OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("nm.bans")

# Запросы, которые обычный посетитель не делает: служебные файлы, известные пути сканеров уязвимостей,
# обход каталогов, SQL-инъекции, XSS, Log4Shell. Проверяется «сырой» $request_uri в нижнем регистре.
SCAN_PATTERNS = [
    r"/\.(?:env|git(?:/|$)|svn|hg/|htaccess|htpasswd|aws/|ssh/|docker|ds_store|bash_history|npmrc|vscode/|idea/)",
    r"/(?:wp-config\.php|phpinfo\.php|info\.php|config\.php\.bak|web\.config|server-status|\.well-known/\.\.)",
    r"/(?:phpmyadmin|pma|myadmin|adminer|mysqladmin|dbadmin)(?:/|\.php|$)",
    r"/(?:cgi-bin/|vendor/phpunit|boaform|hnap1|solr/admin|actuator/|jmx-console|manager/html|owa/auth|"
    r"autodiscover/autodiscover\.xml|remote/fgt_lang|_ignition/|telescope/requests|debug/default/view)",
    r"/etc/(?:passwd|shadow)|/proc/self/|\.\./|\.\.%2f|%2e%2e(?:/|%2f)",
    r"union(?:\s|%20|\+|/\*\*/)+(?:all(?:\s|%20|\+)+)?select|information_schema|sleep\(\s*\d|benchmark\(|"
    r"waitfor(?:\s|%20)+delay",
    r"<script|%3cscript|javascript:|\$\{jndi:|%24%7bjndi",
    r"/[^?]*\.(?:sql|bak|swp|old)(?:\?|$)",
]
SCAN_RE = re.compile("|".join(f"(?:{p})" for p in SCAN_PATTERNS))

RULE_TITLES = {
    "scan": "Поиск уязвимостей",
    "e4xx": "Много ошибок 4xx",
    "auth": "Подбор пароля (401)",
    "default": "Обращения по IP / к чужим доменам",
    "flood": "Слишком много запросов",
    "manual": "Вручную",
}

ALWAYS_TRUSTED = ["127.0.0.0/8", "::1/128"]
MAX_ESCALATED_MINUTES = 30 * 24 * 60


def normalize_net(value: str) -> str:
    """IP → «1.2.3.4», подсеть → «10.0.0.0/8» (хост-биты обнуляются). Бросает ValueError."""
    v = (value or "").strip()
    if not v:
        raise ValueError("пустой адрес")
    if "/" in v:
        net = ipaddress.ip_network(v, strict=False)
        if net.num_addresses == 1:
            return str(net.network_address)
        if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 16):
            raise ValueError(f"{v}: слишком широкая подсеть")
        return str(net)
    return str(ipaddress.ip_address(v))


def in_any(ip: str, nets: List[Any]) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("/")[0])
    except ValueError:
        return False
    for n in nets:
        try:
            if a in (n if isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                     else ipaddress.ip_network(n, strict=False)):
                return True
        except (ValueError, TypeError):
            continue
    return False


# =============================================================================
#  Детектор (вызывается из сборщика статистики на каждую строку журнала)
# =============================================================================
class BanDetector:
    MAX_IPS = 200_000

    def __init__(self, get_settings: Callable[[], Any]) -> None:
        self.get_settings = get_settings
        # ip -> [начало окна, запросов, 4xx, 401, зондов, к серверу по умолчанию, последний «плохой» URI]
        self.win: Dict[str, list] = {}
        self.flagged: Dict[str, float] = {}
        self.candidates: List[Dict[str, Any]] = []
        self.suspicious: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.blocked_hits: Counter = Counter()
        self.blocked_total = 0
        self.seen = 0

    def observe(self, ip: str, ts: float, status: int, uri: str, site: str, is_bot: bool, banned: bool,
                country: str = "", host: str = "") -> None:
        if banned:
            self.blocked_hits[ip] += 1
            self.blocked_total += 1
            return
        ps = self.get_settings()
        window = ps.autoban_window
        self.seen += 1
        w = self.win.get(ip)
        if w is None or ts - w[0] > window:
            if len(self.win) >= self.MAX_IPS:
                self._purge(ts, window)
            w = self.win[ip] = [ts, 0, 0, 0, 0, 0, ""]
        w[1] += 1
        if 400 <= status < 500 or status == 444:
            w[2] += 1
            if status == 401:
                w[3] += 1
        low = uri.lower()
        if SCAN_RE.search(low):
            w[4] += 1
            w[6] = uri[:300]
        if site == "-":
            w[5] += 1
        rule = None
        if ps.autoban_scan and w[4] >= ps.autoban_scan:
            rule, count = "scan", w[4]
        elif ps.autoban_auth and w[3] >= ps.autoban_auth:
            rule, count = "auth", w[3]
        elif ps.autoban_default_host and w[5] >= ps.autoban_default_host:
            rule, count = "default", w[5]
        elif ps.autoban_4xx and w[2] >= ps.autoban_4xx:
            rule, count = "e4xx", w[2]
        elif ps.autoban_requests and w[1] >= ps.autoban_requests:
            rule, count = "flood", w[1]
        if rule is None:
            return
        if is_bot and ps.autoban_ignore_bots and rule in ("e4xx", "flood"):
            return
        last = self.flagged.get(ip)
        if last and ts - last < window:
            return
        self.flagged[ip] = ts
        info = {"ip": ip, "rule": rule, "title": RULE_TITLES[rule], "count": count, "window": window, "ts": ts,
                "requests": w[1], "e4xx": w[2], "e401": w[3], "scan": w[4], "default": w[5],
                "sample": w[6] or uri[:300], "host": host[:200], "country": country}
        self.candidates.append(info)
        self.suspicious[ip] = info
        self.suspicious.move_to_end(ip)
        while len(self.suspicious) > 500:
            self.suspicious.popitem(last=False)

    def _purge(self, now: float, window: int) -> None:
        old = [k for k, v in self.win.items() if now - v[0] > window]
        for k in old:
            del self.win[k]
        if len(self.win) >= self.MAX_IPS:  # всё свежее — сбрасываем половину самых старых
            for k in sorted(self.win, key=lambda x: self.win[x][0])[: self.MAX_IPS // 2]:
                del self.win[k]
        self.flagged = {k: v for k, v in self.flagged.items() if now - v < window}

    def take(self) -> List[Dict[str, Any]]:
        c, self.candidates = self.candidates, []
        return c

    def top_offenders(self, limit: int = 20) -> List[Dict[str, Any]]:
        """IP с наибольшим числом «плохих» запросов в текущем окне (ещё не достигшие порога)."""
        now = time.time()
        window = self.get_settings().autoban_window
        rows = [(ip, w) for ip, w in self.win.items() if now - w[0] <= window and (w[4] or w[3] or w[2] >= 10)]
        rows.sort(key=lambda x: (x[1][4] * 20 + x[1][3] * 5 + x[1][2]), reverse=True)
        return [{"ip": ip, "requests": w[1], "e4xx": w[2], "e401": w[3], "scan": w[4], "default": w[5],
                 "sample": w[6]} for ip, w in rows[:limit]]


# =============================================================================
#  Сервис блокировок
# =============================================================================
class BanService:
    SYNC_MIN_INTERVAL = 5.0

    def __init__(self, app) -> None:
        self.app = app
        self.db = app.db
        self.detector = BanDetector(app.panel)
        self.dirty = True  # при старте сверим файл с базой
        self.last_sync = 0.0
        self.last_error = ""
        self.last_sync_ok: Optional[float] = None
        self.task: Optional[asyncio.Task] = None
        self._sync_lock: Optional[asyncio.Lock] = None  # создаётся в цикле событий (Python 3.9)

    # ------------------------------------------------------------------ данные
    def active(self) -> List[Dict[str, Any]]:
        now = time.time()
        rows = self.db.query("SELECT * FROM bans WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at DESC",
                             (now,))
        for r in rows:
            r["remaining"] = None if r["expires_at"] is None else max(0, r["expires_at"] - now)
            r["hits"] += self.detector.blocked_hits.get(r["net"], 0)
            r["rule_title"] = RULE_TITLES.get(r["rule"] or r["source"], r["rule"])
            r["details"] = json.loads(r["details"]) if r.get("details") else None
        return rows

    def trusted_nets(self) -> List[str]:
        p = self.app.panel()
        return ALWAYS_TRUSTED + list(p.autoban_whitelist) + list(p.panel_allow)

    def offense_count(self, ip: str) -> int:
        r = self.db.one("SELECT count, last_at FROM ban_offenses WHERE ip=?", (ip,))
        if not r or time.time() - r["last_at"] > 30 * 86400:  # «прощаем» через 30 дней
            return 0
        return r["count"]

    def add(self, net: str, minutes: Optional[int], reason: str = "", source: str = "manual", username: str = "",
            rule: str = "", details: Optional[Dict[str, Any]] = None, country: str = "") -> Dict[str, Any]:
        """Заблокировать адрес/подсеть. minutes=None — бессрочно. Повторная блокировка обновляет срок."""
        n = normalize_net(net)
        now = time.time()
        expires = None if minutes is None else now + max(1, int(minutes)) * 60
        existing = self.db.one("SELECT * FROM bans WHERE net=?", (n,))
        det = json.dumps(details, ensure_ascii=False, default=str) if details else None
        if existing:
            self.db.execute("UPDATE bans SET reason=?, source=?, rule=?, username=?, created_at=?, expires_at=?, "
                            "offenses=offenses+1, details=COALESCE(?, details), country=COALESCE(NULLIF(?, ''), "
                            "country) WHERE net=?", (reason, source, rule, username, now, expires, det, country, n))
        else:
            self.db.execute("INSERT INTO bans(net, reason, source, rule, username, created_at, expires_at, details, "
                            "country) VALUES(?,?,?,?,?,?,?,?,?)",
                            (n, reason, source, rule, username, now, expires, det, country))
        self.dirty = True
        self.app.touch()
        return {"net": n, "expires_at": expires}

    def remove(self, ban_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.one("SELECT * FROM bans WHERE id=?", (ban_id,))
        if row:
            self.db.execute("DELETE FROM bans WHERE id=?", (ban_id,))
            self.detector.flagged.pop(row["net"], None)
            self.detector.win.pop(row["net"], None)
            self.dirty = True
            self.app.touch()
        return row

    def expire(self) -> int:
        now = time.time()
        rows = self.db.query("SELECT net, hits FROM bans WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))
        if rows:
            self.db.execute("DELETE FROM bans WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))
            for r in rows:
                self.detector.blocked_hits.pop(r["net"], None)
            self.dirty = True
            self.app.touch()
        return len(rows)

    def persist_hits(self) -> None:
        hits = self.detector.blocked_hits
        if not hits:
            return
        now = time.time()
        items = list(hits.items())
        hits.clear()
        self.db.executemany("UPDATE bans SET hits=hits+?, last_hit=? WHERE net=?", [(n, now, ip) for ip, n in items])

    def render_file(self) -> str:
        nets = [r["net"] for r in self.db.query(
            "SELECT net FROM bans WHERE expires_at IS NULL OR expires_at > ? ORDER BY net", (time.time(),))]
        head = ["# Nginx Manager: заблокированные IP (раздел «Блокировки»). Файл перезаписывается панелью.",
                f"# Записей: {len(nets)}, обновлён {time.strftime('%Y-%m-%d %H:%M:%S')}"]
        return "\n".join(head + [f"{n} 1;" for n in nets]) + "\n"

    def stats(self) -> Dict[str, Any]:
        now = time.time()
        active = self.db.scalar("SELECT COUNT(*) FROM bans WHERE expires_at IS NULL OR expires_at > ?", (now,)) or 0
        auto = self.db.scalar("SELECT COUNT(*) FROM bans WHERE source='auto' AND (expires_at IS NULL OR "
                              "expires_at > ?)", (now,)) or 0
        auto_day = self.db.scalar("SELECT COUNT(*) FROM events WHERE source='bans' AND ts>=? AND message LIKE "
                                  "'Автоблокировка%'", (now - 86400,)) or 0
        hits = (self.db.scalar("SELECT SUM(hits) FROM bans") or 0) + sum(self.detector.blocked_hits.values())
        return {"active": active, "auto": auto, "manual": active - auto, "auto_24h": auto_day,
                "blocked_since_start": self.detector.blocked_total, "blocked_total": hits,
                "suspicious": len(self.detector.suspicious), "last_error": self.last_error,
                "last_sync": self.last_sync_ok, "pending": self.dirty}

    # ------------------------------------------------------------------ автоблокировка
    def process_candidates(self) -> List[Dict[str, Any]]:
        p = self.app.panel()
        banned = []
        cands = self.detector.take()
        if not cands or not p.autoban_enabled:
            return banned
        trusted = [ipaddress.ip_network(x, strict=False) for x in self.trusted_nets()]
        active = {r["net"] for r in self.db.query("SELECT net FROM bans WHERE expires_at IS NULL OR expires_at > ?",
                                                  (time.time(),))}
        for c in cands:
            ip = c["ip"]
            if ip in active or in_any(ip, trusted):
                continue
            try:
                n = normalize_net(ip)
            except ValueError:
                continue
            prev = self.offense_count(n)
            minutes = p.autoban_minutes
            if p.autoban_escalate and prev:
                minutes = min(MAX_ESCALATED_MINUTES, minutes * (4 ** prev))
            self.db.execute("INSERT INTO ban_offenses(ip, count, last_at) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE "
                            "SET count=?, last_at=excluded.last_at", (n, prev + 1, time.time(), prev + 1))
            reason = f"{c['title']}: {c['count']} за {c['window'] // 60 or 1} мин"
            self.add(n, minutes, reason, "auto", "system", c["rule"], c, c.get("country", ""))
            active.add(n)
            c["minutes"] = minutes
            c["net"] = n
            banned.append(c)
            dur = fmt_minutes(minutes)
            self.db.event("warning", "bans", f"Автоблокировка {n} на {dur}: {reason}"
                          + (f" (повторно, {prev + 1}-й раз)" if prev else ""),
                          {"ip": n, "rule": c["rule"], "sample": c.get("sample"), "host": c.get("host")})
        return banned

    # ------------------------------------------------------------------ синхронизация с nginx
    async def sync(self, force: bool = False) -> Tuple[bool, str]:
        if not (self.dirty or force):
            return True, ""
        if self._sync_lock is None:
            self._sync_lock = asyncio.Lock()
        async with self._sync_lock:
            if time.time() - self.last_sync < self.SYNC_MIN_INTERVAL and not force:
                return True, "отложено"
            self.last_sync = time.time()
            self.dirty = False
            content = self.render_file()
            mgr = self.app.nginx
            async with mgr.lock:
                ok, out = await asyncio.to_thread(mgr.write_bans, content)
            if ok:
                self.last_error = ""
                self.last_sync_ok = time.time()
            else:
                self.last_error = out[-1000:]
                self.dirty = True
                self.db.event("error", "bans", "Не удалось обновить список блокировок в nginx", {"output": out[-2000:]})
            return ok, out

    async def run(self) -> None:
        last_expire = last_hits = 0.0
        while True:
            try:
                now = time.time()
                banned = self.process_candidates()
                if banned:
                    await self.app.broadcast({"type": "bans", "items": [
                        {"ip": b["net"], "rule": b["rule"], "minutes": b["minutes"]} for b in banned]})
                if now - last_expire > 15:
                    last_expire = now
                    self.expire()
                if now - last_hits > 60:
                    last_hits = now
                    self.persist_hits()
                if self.dirty:
                    await self.sync()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("блокировки")
            await asyncio.sleep(2)

    def start(self) -> None:
        self.task = asyncio.get_running_loop().create_task(self.run(), name="bans")


def fmt_minutes(m: Optional[int]) -> str:
    if m is None:
        return "бессрочно"
    if m % (24 * 60) == 0:
        d = m // (24 * 60)
        return f"{d} сут."
    if m % 60 == 0:
        return f"{m // 60} ч"
    return f"{m} мин"
