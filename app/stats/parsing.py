"""Разбор строк журналов nginx: access (JSON), stream (JSON), error (текст)."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

# Границы корзин гистограммы времени ответа, секунды (последняя корзина — «больше 10 с»)
LAT_BOUNDS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
LAT_LABELS = ["≤5мс", "≤10мс", "≤25мс", "≤50мс", "≤100мс", "≤250мс", "≤500мс", "≤1с", "≤2.5с", "≤5с", "≤10с", ">10с"]
STATIC_RE = re.compile(r"\.(css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm|mp3)(\?|$)", re.I)


def _f(v: Any) -> float:
    """Числа nginx: '-', '0.012', '0.010, 0.004 : 0.002' (несколько бэкендов) → сумма."""
    if not v or v == "-":
        return 0.0
    try:
        return float(v)
    except ValueError:
        total = 0.0
        for part in re.split(r"[,:]\s*", v):
            part = part.strip()
            if part and part != "-":
                try:
                    total += float(part)
                except ValueError:
                    pass
        return total


def _i(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def bucket(rt: float) -> int:
    for i, b in enumerate(LAT_BOUNDS):
        if rt <= b:
            return i
    return len(LAT_BOUNDS)


def parse_access(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        d = json.loads(line)
    except ValueError:
        return None
    uri = d.get("u", "")
    path = uri.split("?", 1)[0]
    ua_addr = d.get("ua", "")
    upstream = ua_addr.split(",")[-1].strip() if ua_addr and ua_addr != "-" else ""
    tls = d.get("tls", "")
    return {
        "ts": _f(d.get("t")) or time.time(),
        "site": d.get("site") or "-",
        "host": d.get("host", ""),
        "ip": d.get("ip", ""),
        "method": d.get("m", "")[:16],
        "uri": uri[:2000],
        "path": path[:500],
        "proto": d.get("p", ""),
        "status": _i(d.get("s")),
        "bout": _i(d.get("bs")),
        "bin": _i(d.get("rl")),
        "rt": _f(d.get("rt")),
        "upstream": upstream,
        "ustatus": d.get("us", "") if d.get("us") != "-" else "",
        "urt": _f(d.get("urt")),
        "uct": _f(d.get("uct")),
        "uht": _f(d.get("uht")),
        "has_upstream": bool(upstream),
        "ref": d.get("ref", "")[:500],
        "ua": d.get("agent", "")[:500],
        "cache": d.get("cache", "") if d.get("cache") not in ("-", None) else "",
        "scheme": d.get("sch", ""),
        "tls": tls if tls != "-" else "",
        "rid": d.get("rid", ""),
        "static": bool(STATIC_RE.search(path)),
        "banned": d.get("bn") == "1",
        "geo_blocked": d.get("gb") == "1",
    }


def parse_stream(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        d = json.loads(line)
    except ValueError:
        return None
    return {"ts": _f(d.get("t")) or time.time(), "ip": d.get("ip", ""), "proto": d.get("proto", "TCP"),
            "port": _i(d.get("port")), "status": _i(d.get("s")), "bout": _i(d.get("bs")),
            "bin": _i(d.get("br")), "dur": _f(d.get("dur")), "upstream": d.get("ua", ""),
            "uct": _f(d.get("uct"))}


# ---------------------------------------------------------------------------
#  Журнал ошибок
# ---------------------------------------------------------------------------
ERR_LINE_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): (?:\*(\d+) )?(.*)$")
ERR_FIELDS = {k: re.compile(p) for k, p in {
    "client": r", client: ([^,]+)",
    "server": r", server: ([^,]*)",
    "request": r", request: \"((?:[^\"\\\\]|\\\\.)*)\"",
    "upstream": r", upstream: \"([^\"]*)\"",
    "host": r", host: \"([^\"]*)\"",
}.items()}

# (id, шаблон, заголовок, уровень, рекомендация)
ERROR_CATEGORIES = [
    ("upstream_timeout", r"upstream timed out", "Бэкенд не ответил вовремя", "error",
     "Бэкенд обрабатывает запрос дольше proxy_read_timeout. Проверьте нагрузку и медленные запросы приложения "
     "(журнал → фильтр по времени ответа). Для длительных операций увеличьте «Таймаут чтения» сайта или локации."),
    ("upstream_refused", r"Connection refused\) while connecting to upstream|connect\(\) failed \(111",
     "Бэкенд отклоняет соединения", "error",
     "Приложение не запущено или слушает другой порт/адрес. Проверьте сервис на бэкенде и порт в настройках сайта. "
     "Страница «Бэкенды» покажет, какой именно сервер недоступен."),
    ("upstream_unreachable", r"No route to host|Network is unreachable|Host is unreachable",
     "Бэкенд недоступен по сети", "error",
     "Нет маршрута до сервера бэкенда: проверьте сеть, VPN, firewall на бэкенде и правильность IP."),
    ("upstream_reset", r"Connection reset by peer\) while (reading response header from|sending request to) upstream",
     "Бэкенд сбросил соединение", "error",
     "Приложение аварийно закрыло соединение (падение воркера, лимиты, keepalive-несовместимость). Если ошибка "
     "массовая — попробуйте уменьшить keepalive до 0 и проверьте журналы приложения."),
    ("upstream_closed", r"upstream prematurely closed connection", "Бэкенд закрыл соединение до ответа", "error",
     "Приложение завершило соединение раньше времени — смотрите его журналы (часто это падение/таймаут PHP-FPM, "
     "gunicorn, node)."),
    ("upstream_disabled", r"upstream server temporarily disabled", "Бэкенд временно исключён (max_fails)", "warn",
     "Nginx исключил сервер из балансировки на fail_timeout после max_fails неудачных попыток. Это следствие "
     "других ошибок (отказ соединения, таймаут) — устраните их причину."),
    ("no_live_upstreams", r"no live upstreams", "Нет доступных бэкендов", "crit",
     "Все серверы группы помечены недоступными (max_fails). Восстановите бэкенды или добавьте резервный (backup)."),
    ("host_not_found", r"could not be resolved|host not found", "Ошибка DNS", "error",
     "Не удаётся разрешить имя. Укажите resolver в глобальных настройках или используйте IP-адреса."),
    ("upstream_big_header", r"upstream sent too big header", "Слишком большой заголовок ответа бэкенда", "error",
     "Увеличьте proxy_buffer_size (например, 32k) в настройках сайта (Проксирование → дополнительно) "
     "или глобально. Причина — большие cookie или заголовки приложения."),
    ("body_too_large", r"client intended to send too large body", "Слишком большое тело запроса (413)", "warn",
     "Клиент загружает файл больше client_max_body_size. Увеличьте «Макс. размер тела запроса» сайта, если это "
     "легитимная загрузка."),
    ("buffered_to_file", r"buffered to a temporary file", "Ответ буферизуется на диск", "warn",
     "Ответы бэкенда не помещаются в proxy_buffers. Это работает, но медленнее. Увеличьте proxy_buffers "
     "(например, 32 16k) или выключите буферизацию для крупных скачиваний."),
    ("limit_req", r"limiting requests", "Сработал лимит частоты запросов", "warn",
     "Клиент превысил rate limit. Если это легитимные пользователи — увеличьте rate/burst в разделе «Безопасность»."),
    ("limit_conn", r"limiting connections", "Сработал лимит соединений", "warn",
     "Клиент превысил лимит одновременных соединений. Увеличьте значение, если это прокси/NAT многих пользователей."),
    ("ssl_handshake", r"SSL_do_handshake\(\) failed.*while SSL handshaking(?! to upstream)|SSL_read\(\) failed|"
                      r"ssl_.*failed.*client|no \"ssl_certificate\"|SSL: error:.*(wrong version|unsupported protocol|"
                      r"no shared cipher|bad key share|version too low)", "Ошибка TLS-рукопожатия клиента", "info",
     "Обычно это сканеры или устаревшие клиенты. Массовые ошибки после смены профиля TLS — признак слишком "
     "строгих настроек (профиль Modern)."),
    ("upstream_ssl", r"while SSL handshaking to upstream|upstream SSL certificate", "Ошибка TLS к бэкенду", "error",
     "Не удаётся установить TLS с https-бэкендом. Проверьте протокол бэкенда, SNI и проверку сертификата."),
    ("worker_connections", r"worker_connections are not enough", "Не хватает worker_connections", "crit",
     "Увеличьте worker_connections в глобальных настройках (и worker_rlimit_nofile ≥ 2× значения)."),
    ("too_many_files", r"Too many open files", "Исчерпан лимит открытых файлов", "crit",
     "Увеличьте worker_rlimit_nofile в глобальных настройках и LimitNOFILE в systemd-юните nginx."),
    ("permission_denied", r"\(13: Permission denied\)", "Нет прав доступа", "error",
     "Процесс nginx не может открыть файл или подключиться. Проверьте права на каталоги, а на RHEL — SELinux "
     "(setsebool -P httpd_can_network_connect 1). Диагностика предложит исправление."),
    ("file_not_found", r"\(2: No such file or directory\)", "Файл не найден", "info",
     "Запрошен несуществующий файл (статика, favicon.ico и т.п.). Обычно не требует действий."),
    ("access_forbidden", r"access forbidden by rule", "Доступ запрещён правилом", "info",
     "Сработали списки доступа allow/deny. Если блокируются нужные клиенты — проверьте «Безопасность»."),
    ("auth_failed", r"was not found in|password mismatch|no user/password", "Ошибка Basic Auth", "warn",
     "Неверный логин/пароль. Много ошибок с одного IP — возможный перебор паролей: добавьте IP в чёрный список "
     "или ограничьте частоту."),
    ("client_closed", r"client prematurely closed|client closed connection|epoll_wait\(\) reported that client",
     "Клиент закрыл соединение", "info",
     "Пользователь закрыл страницу до ответа (код 499 в журнале). Массово — признак медленного бэкенда."),
    ("bind_failed", r"bind\(\) to .* failed", "Порт занят", "crit",
     "Другой процесс занимает порт. Диагностика → «Порты» покажет, какой."),
    ("config", r"\[emerg\]|emerg", "Ошибка конфигурации", "crit", "Проверьте последнюю применённую версию конфигурации."),
]
_CAT_RES = [(cid, re.compile(p, re.I), title, lvl, hint) for cid, p, title, lvl, hint in ERROR_CATEGORIES]
CATEGORY_INFO = {cid: {"title": title, "level": lvl, "hint": hint} for cid, _, title, lvl, hint in ERROR_CATEGORIES}
CATEGORY_INFO["other"] = {"title": "Прочее", "level": "info", "hint": "Сообщения, не попавшие в известные категории. Откройте записи ниже: текст сообщения обычно прямо указывает причину; при повторении проверьте раздел «Диагностика»."}


def categorize(msg: str) -> str:
    for cid, rx, _t, _l, _h in _CAT_RES:
        if rx.search(msg):
            return cid
    return "other"


def parse_error(line: str) -> Optional[Dict[str, Any]]:
    m = ERR_LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    date, level, _pid, _tid, _cid, rest = m.groups()
    try:
        ts = datetime.strptime(date, "%Y/%m/%d %H:%M:%S").timestamp()
    except ValueError:
        ts = time.time()
    fields = {}
    for k, rx in ERR_FIELDS.items():
        fm = rx.search(rest)
        fields[k] = fm.group(1) if fm else ""
    msg = rest.split(", client: ", 1)[0] if ", client: " in rest else rest
    return {"ts": ts, "level": level, "message": msg[:2000], "category": categorize(rest), **fields}


# ---------------------------------------------------------------------------
#  User-Agent
# ---------------------------------------------------------------------------
BOT_RE = re.compile(r"bot|crawl|spider|slurp|curl|wget|python|httpclient|go-http|java/|okhttp|libwww|scrapy|"
                    r"headless|phantom|scan|nmap|masscan|zgrab|nuclei|nikto|sqlmap|feedfetcher|monitor|uptime|"
                    r"pingdom|axios|node-fetch|postman|insomnia|healthcheck|facebookexternalhit|preview", re.I)


@lru_cache(maxsize=20000)
def classify_ua(ua: str) -> Tuple[str, str, str, bool]:
    """Возвращает (браузер, ОС, устройство, это_бот)."""
    if not ua or ua == "-":
        return ("Пусто", "Неизвестно", "Неизвестно", True)
    u = ua.lower()
    is_bot = bool(BOT_RE.search(u))
    if "googlebot" in u:
        b = "Googlebot"
    elif "yandexbot" in u or "yandex.com/bots" in u:
        b = "YandexBot"
    elif "bingbot" in u:
        b = "Bingbot"
    elif is_bot:
        m = re.match(r"([a-z0-9_.\-]+)[/ ]", u)
        b = (m.group(1) if m else "Бот")[:24]
        if b in ("mozilla",):
            m2 = re.search(r"compatible; ([a-z0-9_.\-]+)", u)
            b = (m2.group(1) if m2 else "Бот")[:24]
    elif "yabrowser" in u:
        b = "Яндекс.Браузер"
    elif "edg/" in u or "edge/" in u:
        b = "Edge"
    elif "opr/" in u or "opera" in u:
        b = "Opera"
    elif "samsungbrowser" in u:
        b = "Samsung Internet"
    elif "firefox/" in u or "fxios" in u:
        b = "Firefox"
    elif "chrome/" in u or "crios" in u:
        b = "Chrome"
    elif "safari/" in u:
        b = "Safari"
    elif "msie" in u or "trident/" in u:
        b = "Internet Explorer"
    else:
        b = "Другой"
    if "android" in u:
        os_ = "Android"
    elif "iphone" in u or "ipad" in u or "ios" in u:
        os_ = "iOS"
    elif "windows" in u:
        os_ = "Windows"
    elif "mac os x" in u or "macintosh" in u:
        os_ = "macOS"
    elif "cros" in u:
        os_ = "ChromeOS"
    elif "linux" in u:
        os_ = "Linux"
    else:
        os_ = "Другая"
    if is_bot:
        dev = "Бот"
    elif "ipad" in u or "tablet" in u or ("android" in u and "mobile" not in u):
        dev = "Планшет"
    elif "mobi" in u or "iphone" in u:
        dev = "Мобильный"
    else:
        dev = "Компьютер"
    return (b, os_, dev, is_bot)


def referer_domain(ref: str, host: str) -> str:
    if not ref or ref == "-":
        return ""
    try:
        h = urlsplit(ref).hostname or ""
    except ValueError:
        return ""
    if not h or h == host:
        return ""
    return h[:200]


class GeoIP:
    """Необязательное определение страны (maxminddb + GeoLite2/DB-IP Country)."""

    def __init__(self) -> None:
        self.reader = None
        self.path = ""
        self.error = ""
        self.mtime = 0.0  # время изменения загруженной базы (обновление базы перечитывается)

    def load(self, path: str, fallback_dir: str) -> None:
        import os
        from ..services.geoblock import candidates
        cands = candidates(path, fallback_dir)
        try:
            import maxminddb  # type: ignore
        except ImportError:
            self.error = "не установлен пакет maxminddb"
            return
        for c in cands:
            if c and os.path.exists(c):
                try:
                    self.reader = maxminddb.open_database(c)
                    self.path = c
                    self.mtime = os.path.getmtime(c)
                    self.error = ""
                    self._lookup.cache_clear()
                    return
                except Exception as e:  # pragma: no cover
                    self.error = str(e)
        if not self.error:
            self.error = "база GeoIP не найдена"

    @lru_cache(maxsize=50000)
    def _lookup(self, ip: str) -> str:
        if not self.reader:
            return ""
        try:
            r = self.reader.get(ip)
            if r:
                c = r.get("country") or r.get("registered_country") or {}
                return c.get("iso_code", "") or ""
        except Exception:
            pass
        return ""

    def country(self, ip: str) -> str:
        return self._lookup(ip) if self.reader else ""
