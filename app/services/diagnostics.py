"""Автоматическая диагностика: десятки проверок с объяснением и рекомендациями,
а также автоматические исправления для типовых проблем."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import time
import urllib.request
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

import psutil

from ..config import settings
from ..models import CLOUDFLARE_IPS
from ..stats.parsing import CATEGORY_INFO
from ..utils import has_systemd, run, which

log = logging.getLogger("nm.diag")

OK, WARN, FAIL, INFO, SKIP = "ok", "warn", "fail", "info", "skip"


def R(id: str, group: str, title: str, status: str, message: str = "", details: Any = None,
      hint: str = "", fix: Optional[str] = None, fix_label: str = "", fix_args: Optional[dict] = None) -> Dict[str, Any]:
    return {"id": id, "group": group, "title": title, "status": status, "message": message, "details": details,
            "hint": hint, "fix": fix, "fix_label": fix_label, "fix_args": fix_args or {}}


COMPACT_AFTER = 12  # однотипных строк одного состояния в группе, после которых остальные сворачиваются
_ST_WORD = {OK: "в порядке", INFO: "к сведению", SKIP: "пропущено", WARN: "предупреждения", FAIL: "ошибки"}


def compact(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Сотни однотипных строк (DNS доменов, серверы бэкендов) — в одну сводную строку с подробностями.

    Проблемные строки (ошибки, предупреждения) остаются по отдельности первые COMPACT_AFTER — у них есть
    подсказки и кнопки исправления; исправные сворачиваются целиком. Счётчики сводки не меняются."""
    def family(r):
        return (r["group"], re.split(r"[_:|]", r["id"], maxsplit=1)[0], r["status"])
    counts: Dict[tuple, int] = {}
    for r in results:
        counts[family(r)] = counts.get(family(r), 0) + 1
    out: List[Dict[str, Any]] = []
    folded: Dict[tuple, Dict[str, Any]] = {}
    seen: Dict[tuple, int] = {}
    for r in results:
        k = family(r)
        if counts[k] <= COMPACT_AFTER:
            out.append(r)
            continue
        seen[k] = seen.get(k, 0) + 1
        keep = COMPACT_AFTER - 1 if r["status"] in (FAIL, WARN) else 0
        if seen[k] <= keep:
            out.append(r)
            continue
        row = folded.get(k)
        if row is None:
            rest = counts[k] - keep
            row = R(f"{k[1]}_{r['status']}_more", r["group"],
                    ("Ещё " if keep else "") + f"{rest} {plural(rest, 'проверка', 'проверки', 'проверок')}",
                    r["status"], _ST_WORD.get(r["status"], ""), details=[],
                    hint=r["hint"] if r["status"] in (FAIL, WARN) else "")
            row["folded"] = rest
            row["_msgs"] = set()
            folded[k] = row
            out.append(row)
        row["details"].append(f"{r['title']} — {r['message']}")
        row["_msgs"].add(r["message"])
    for row in folded.values():
        msgs = row.pop("_msgs")
        if len(msgs) == 1:  # у всех одинаковое сообщение (например, «Домен не разрешается») — его и показываем
            row["message"] = next(iter(msgs))
        row["details"] = "\n".join(row["details"])
    return out


NGINX_PORT_TYPES = ("http_port_t", "http_cache_port_t")  # порты, на которых nginx (httpd_t) может слушать


def selinux_port_types(semanage_out: str) -> Dict[tuple, str]:
    """Вывод `semanage port -l` → {(протокол, порт): тип}. Диапазоны «10001-10010» разворачиваются."""
    out: Dict[tuple, str] = {}
    for line in semanage_out.splitlines():
        m = re.match(r"^(\S+_t)\s+(tcp|udp|sctp|dccp)\s+(.+)$", line.strip())
        if not m:
            continue
        typ, proto, ports = m.groups()
        for part in ports.split(","):
            part = part.strip()
            if re.fullmatch(r"\d+-\d+", part):
                a, b = (int(x) for x in part.split("-"))
                if b - a <= 70000:
                    for p in range(a, b + 1):
                        out.setdefault((proto, p), typ)
            elif part.isdigit():
                out.setdefault((proto, int(part)), typ)
    return out


def selinux_port_problems(needed: List[tuple], types: Dict[tuple, str]) -> List[Dict[str, Any]]:
    """Какие порты nginx не сможет занять: [(протокол, порт, кто)] → список проблем с текущим типом метки."""
    out = []
    for proto, port, who in needed:
        typ = types.get((proto, port))
        if typ in NGINX_PORT_TYPES:
            continue
        out.append({"proto": proto, "port": port, "who": who, "type": typ})
    return out


def plural(n: int, one: str, few: str, many: str) -> str:
    n = abs(n) % 100
    if 10 < n < 20:
        return many
    n %= 10
    return one if n == 1 else few if 2 <= n <= 4 else many


class Diagnostics:
    def __init__(self, app) -> None:
        self.app = app
        self.last: Dict[str, Any] = {"ts": 0, "results": [], "summary": {}}
        self.running = False
        self._ext_ip_cache = (0.0, [])

    # ------------------------------------------------------------------
    async def run_all(self) -> Dict[str, Any]:
        if self.running:
            return self.last
        self.running = True
        t0 = time.time()
        try:
            checks: List[Callable[[], Awaitable[List[Dict[str, Any]]]]] = [
                self.c_nginx, self.c_config, self.c_ports, self.c_network, self.c_dns, self.c_backends,
                self.c_certs, self.c_firewall, self.c_selinux, self.c_system, self.c_limits, self.c_logs,
                self.c_errors, self.c_traffic, self.c_security, self.c_time, self.c_backups,
            ]
            results: List[Dict[str, Any]] = []
            outs = await asyncio.gather(*(asyncio.wait_for(c(), 60) for c in checks), return_exceptions=True)
            for c, out in zip(checks, outs):
                if isinstance(out, Exception):
                    results.append(R(c.__name__, "Диагностика", f"Проверка {c.__name__}", WARN,
                                     f"Проверка завершилась с ошибкой: {type(out).__name__}: {out}"))
                else:
                    results.extend(out)
            summary = {s: sum(1 for r in results if r["status"] == s) for s in (OK, WARN, FAIL, INFO, SKIP)}
            self.last = {"ts": time.time(), "duration": round(time.time() - t0, 2), "results": compact(results),
                         "summary": summary, "total": len(results)}
            self.app.db.kv_set("diagnostics_last", {"ts": self.last["ts"], "summary": summary})
            return self.last
        finally:
            self.running = False

    # ------------------------------------------------------------------
    async def c_nginx(self) -> List[Dict[str, Any]]:
        g = "Nginx"
        mgr = self.app.nginx
        res = []
        if not Path(mgr.binary).exists():
            return [R("nginx_installed", g, "Nginx установлен", FAIL, f"Не найден исполняемый файл {mgr.binary}",
                      hint="Установите nginx: apt install nginx (Debian/Ubuntu) или dnf install nginx (RHEL). "
                           "Скрипт install.sh делает это автоматически.")]
        info = await asyncio.to_thread(mgr.info)
        res.append(R("nginx_installed", g, "Nginx установлен", OK, f"{info['version_full']} ({info['openssl']})",
                     details={"binary": info["binary"], "modules": info["modules"]}))
        ver = tuple(int(x) for x in info["version"].split("."))
        if ver < (1, 18, 0):
            res.append(R("nginx_version", g, "Версия nginx", WARN, f"Версия {info['version']} устарела",
                         hint="Рекомендуется nginx ≥ 1.20 (лучше mainline/stable с nginx.org): исправления "
                              "безопасности, ssl_reject_handshake, директива http2."))
        else:
            res.append(R("nginx_version", g, "Версия nginx", OK, info["version"]))
        missing = [m for m in ("http_ssl", "http_v2", "http_stub_status", "http_realip") if m not in info["modules"]]
        if missing:
            res.append(R("nginx_modules", g, "Необходимые модули", WARN, "Нет модулей: " + ", ".join(missing),
                         hint="Без stub_status не будет статистики соединений, без http_v2 — HTTP/2, без realip — "
                              "определения IP за CDN. Установите сборку nginx с этими модулями."))
        else:
            res.append(R("nginx_modules", g, "Необходимые модули", OK, "ssl, http_v2, stub_status, realip"))
        streams_used = any(s.enabled for _, s in mgr.load_state().streams)
        if not info["stream"]:
            res.append(R("nginx_stream", g, "Модуль stream (TCP/UDP)", FAIL if streams_used else INFO,
                         "Модуль stream недоступен",
                         hint="Установите libnginx-mod-stream (Debian/Ubuntu) или nginx-mod-stream (RHEL), затем "
                              "примените конфигурацию.", fix="install_stream" if streams_used else None,
                         fix_label="Установить модуль"))
        else:
            res.append(R("nginx_stream", g, "Модуль stream (TCP/UDP)", OK, "доступен"))
        st = await asyncio.to_thread(mgr.status)
        if st["running"]:
            res.append(R("nginx_running", g, "Nginx запущен", OK,
                         f"PID {st.get('pid')}, воркеров: {st.get('workers')}, работает {fmt_dur(st.get('uptime', 0))}"))
            if st.get("workers", 0) == 0:
                res.append(R("nginx_workers", g, "Рабочие процессы", FAIL, "Нет воркеров",
                             fix="restart_nginx", fix_label="Перезапустить nginx"))
        else:
            res.append(R("nginx_running", g, "Nginx запущен", FAIL, "Процесс nginx не найден",
                         hint="Смотрите журнал: journalctl -u nginx -n 50. Частые причины: занят порт, ошибка "
                              "конфигурации, нет сертификата.", fix="start_nginx", fix_label="Запустить nginx"))
        if has_systemd():
            code, _ = await asyncio.to_thread(run, ["systemctl", "is-enabled", "--quiet", "nginx"])
            if code != 0:
                res.append(R("nginx_enabled", g, "Автозапуск nginx", WARN, "nginx не добавлен в автозагрузку",
                             fix="enable_nginx", fix_label="Включить автозапуск"))
            else:
                res.append(R("nginx_enabled", g, "Автозапуск nginx", OK, "включён"))
        return res

    async def c_config(self) -> List[Dict[str, Any]]:
        g = "Конфигурация"
        mgr = self.app.nginx
        res = []
        ok, out = await asyncio.to_thread(mgr.test_config)
        warns = [ln for ln in out.splitlines() if "[warn]" in ln]
        if ok:
            res.append(R("config_test", g, "Проверка nginx -t", WARN if warns else OK,
                         "Конфигурация корректна" + (f", предупреждений: {len(warns)}" if warns else ""),
                         details=out.strip() or None,
                         hint="\n".join(filter(None, (mgr_explain(w) for w in warns)))))
        else:
            res.append(R("config_test", g, "Проверка nginx -t", FAIL, "Ошибка в конфигурации", details=out,
                         hint=mgr_explain(out), fix="reapply", fix_label="Применить последнюю рабочую версию"))
        if not mgr.is_managed():
            res.append(R("config_managed", g, "nginx.conf под управлением панели", FAIL,
                         f"{settings.nginx_conf} не содержит метки Nginx Manager — его перезаписал пакетный "
                         f"менеджер или администратор", fix="reapply", fix_label="Применить конфигурацию",
                         hint="Обычно происходит после обновления пакета nginx с заменой конфигурации. "
                              "Исходный файл сохранён в nginx.conf.nm-orig."))
        else:
            res.append(R("config_managed", g, "nginx.conf под управлением панели", OK, str(settings.nginx_conf)))
        pend = await asyncio.to_thread(mgr.pending)
        if pend.get("error"):
            res.append(R("config_pending", g, "Неприменённые изменения", FAIL, pend["error"],
                         hint="Исправьте настройки, указанные в сообщении."))
        elif pend.get("pending"):
            res.append(R("config_pending", g, "Неприменённые изменения", INFO,
                         f"Изменено файлов: {len(pend['changed'])}", details=pend["changed"],
                         hint="Нажмите «Применить» в верхней панели.", fix="reapply", fix_label="Применить"))
        else:
            res.append(R("config_pending", g, "Неприменённые изменения", OK, "Конфигурация актуальна"))
        user = mgr.load_state().glob.user or mgr.caps().default_user
        bad = await asyncio.to_thread(mgr.unreadable_paths, user)
        if bad:
            res.append(R("config_perms", g, "Права доступа воркеров nginx", FAIL,
                         f"Пользователь {user} не может прочитать {len(bad)} путь(ей)", details=bad,
                         hint="Страницы ошибок, Basic Auth или проверки Let's Encrypt не будут работать "
                              "(в журнале ошибок — «Permission denied»). Частая причина — umask 077 при запуске.",
                         fix="fix_perms", fix_label="Исправить права"))
        else:
            res.append(R("config_perms", g, "Права доступа воркеров nginx", OK,
                         f"{user} читает страницы, ACME и файлы паролей"))
        # блокировки IP: файл подключён в живой конфигурации и принят nginx
        bans = getattr(self.app, "bans", None)
        if bans is not None:
            base = settings.live_dir / "http.d" / "00-base.conf"
            included = base.exists() and "nm_banned" in base.read_text(errors="replace")
            st = bans.stats()
            if st["last_error"]:
                res.append(R("bans_sync", g, "Список блокировок IP", FAIL, "nginx не принял файл блокировок",
                             details=st["last_error"][-800:], fix="bans_sync", fix_label="Повторить",
                             hint="Список сохранён в панели и будет отправлен повторно. Проверьте вывод nginx -t."))
            elif st["active"] and not included:
                res.append(R("bans_sync", g, "Список блокировок IP", WARN,
                             f"Активных блокировок: {st['active']}, но действующая конфигурация их ещё не учитывает",
                             hint="Конфигурация создана версией панели без блокировок — примените её заново.",
                             fix="reapply", fix_label="Применить конфигурацию"))
            else:
                res.append(R("bans_sync", g, "Список блокировок IP", OK,
                             f"активных: {st['active']} (автоматических {st['auto']})" if st["active"]
                             else "блокировок нет" + ("" if included else " (подключится при следующем применении)")))
        # доступ по странам
        st_geo = mgr.load_state()
        geo_sites = [s.name for _, s in st_geo.sites if s.enabled and s.security.geo_mode != "off"]
        if geo_sites:
            gs = mgr.geo_status()
            need = {c for _, s in st_geo.sites if s.enabled and s.security.geo_mode != "off"
                    for c in s.security.geo_countries}
            if not gs["db"]:
                geoip = self.app.stats.geoip
                res.append(R("geo_block", g, "Доступ по странам", FAIL,
                             f"Правила заданы у сайтов ({', '.join(geo_sites[:5])}), но базы GeoIP нет — "
                             "ограничения не действуют",
                             details=geoip.error or "база не найдена",
                             hint="Установите пакет maxminddb (sudo ./update.sh --with-geoip), положите "
                                  "GeoLite2-Country.mmdb или dbip-country-lite.mmdb в /var/lib/nginx-manager/geoip/ "
                                  "и примените конфигурацию. Подробно — глава 17 документации."))
            elif not need <= set(gs["countries"]):
                res.append(R("geo_block", g, "Доступ по странам", WARN,
                             "Не все страны из правил подключены к nginx: " + ", ".join(sorted(need - set(gs["countries"]))),
                             hint="Сети стран собираются при применении конфигурации — примените её.",
                             fix="reapply", fix_label="Применить конфигурацию"))
            else:
                res.append(R("geo_block", g, "Доступ по странам", OK,
                             f"сайтов с правилами: {len(geo_sites)}, стран: {len(need)}, сетей: {gs['nets']}"))
        live = settings.live_dir
        if not live.exists():
            res.append(R("config_live", g, "Каталог конфигурации", FAIL, f"{live} отсутствует",
                         fix="reapply", fix_label="Применить конфигурацию"))
        # дубли доменов
        state = mgr.load_state()
        seen: Dict[tuple, str] = {}
        dups = []
        for sid, s in state.sites:
            if not s.enabled:
                continue
            for d in s.domains:
                for port in ([s.http_port] + ([s.https_port] if s.ssl.enabled else [])):
                    k = (d, port, s.listen_ip)
                    if k in seen and seen[k] != s.name:
                        dups.append(f"{d}:{port} — «{seen[k]}» и «{s.name}»")
                    seen[k] = s.name
        if dups:
            res.append(R("config_dup_domains", g, "Уникальность доменов", WARN, f"Конфликтов: {len(dups)}",
                         details=dups, hint="Один домен на одном порту может обслуживать только один сайт — nginx "
                                            "выберет первый. Удалите дубли."))
        else:
            res.append(R("config_dup_domains", g, "Уникальность доменов", OK, "Конфликтов нет"))
        longest = max((len(d) for _, s in state.sites for d in s.domains), default=0)
        if longest > state.glob.server_names_hash_bucket_size - 20:
            res.append(R("config_hash", g, "server_names_hash_bucket_size", WARN,
                         f"Длинные доменные имена ({longest} симв.) при bucket_size "
                         f"{state.glob.server_names_hash_bucket_size}",
                         fix="hash_bucket", fix_label="Увеличить до 256"))
        return res

    async def c_ports(self) -> List[Dict[str, Any]]:
        g = "Сеть"
        state = self.app.nginx.load_state()
        need: Dict[tuple, str] = {("tcp", 80): "HTTP", ("tcp", 443): "HTTPS"}
        for _, s in state.sites:
            if s.enabled:
                need[("tcp", s.http_port)] = f"HTTP ({s.name})"
                if s.ssl.enabled:
                    need[("tcp", s.https_port)] = f"HTTPS ({s.name})"
        for _, s in state.streams:
            if s.enabled:
                for p in (["tcp", "udp"] if s.protocol == "both" else [s.protocol]):
                    need[(p, s.listen_port)] = f"{p.upper()} поток «{s.name}»"
        need[("tcp", settings.stub_status_port)] = "stub_status (127.0.0.1)"
        listeners: Dict[tuple, List[str]] = {}

        def collect():
            for c in psutil.net_connections(kind="inet"):
                if c.laddr and ((c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN) or
                                c.type == socket.SOCK_DGRAM):
                    proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                    name = "?"
                    try:
                        name = psutil.Process(c.pid).name() if c.pid else "?"
                    except psutil.Error:
                        pass
                    listeners.setdefault((proto, c.laddr.port), []).append(name)
        await asyncio.to_thread(collect)
        res = []
        nginx_up = self.app.nginx.is_running()
        for (proto, port), what in sorted(need.items(), key=lambda x: x[0][1]):
            owners = sorted(set(listeners.get((proto, port), [])))
            others = [o for o in owners if o != "nginx"]
            if "nginx" in owners and not others:
                res.append(R(f"port_{proto}_{port}", g, f"Порт {port}/{proto}", OK, f"{what}: слушает nginx"))
            elif others:
                res.append(R(f"port_{proto}_{port}", g, f"Порт {port}/{proto}", FAIL,
                             f"{what}: занят процессом {', '.join(others)}",
                             hint=f"Остановите/отключите {', '.join(others)} или смените порт. Например: "
                                  f"systemctl disable --now apache2 (httpd)."))
            elif nginx_up:
                res.append(R(f"port_{proto}_{port}", g, f"Порт {port}/{proto}", WARN, f"{what}: никто не слушает",
                             hint="Возможно, конфигурация не применена.", fix="reapply", fix_label="Применить"))
        if (("tcp", settings.bind_port)) in listeners and settings.bind_host in ("0.0.0.0", "::"):
            res.append(R("panel_port", g, f"Порт панели {settings.bind_port}", INFO,
                         "Панель доступна на всех интерфейсах — откройте порт только для доверенных IP или "
                         "используйте домен панели с HTTPS"))
        return res

    async def external_ips(self) -> List[str]:
        panel = self.app.panel()
        if panel.external_ip:
            return [panel.external_ip]
        if time.time() - self._ext_ip_cache[0] < 600 and self._ext_ip_cache[1]:
            return self._ext_ip_cache[1]
        ips = set()
        for _iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    try:
                        ip = ipaddress.ip_address(a.address.split("%")[0])
                    except ValueError:
                        continue
                    if ip.is_global:
                        ips.add(str(ip))
        if panel.ip_detect_url:
            def fetch():
                try:
                    with urllib.request.urlopen(panel.ip_detect_url, timeout=5) as r:
                        return r.read(100).decode().strip()
                except Exception:
                    return ""
            ext = await asyncio.to_thread(fetch)
            try:
                ipaddress.ip_address(ext)
                ips.add(ext)
            except ValueError:
                pass
        res = sorted(ips)
        self._ext_ip_cache = (time.time(), res)
        return res

    async def c_network(self) -> List[Dict[str, Any]]:
        g = "Сеть"
        res = []
        ips = await self.external_ips()
        local = set()
        for _iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    local.add(a.address.split("%")[0])
        if ips:
            nat = [ip for ip in ips if ip not in local]
            res.append(R("external_ip", g, "Внешний IP-адрес", OK, ", ".join(ips),
                         hint="Сервер за NAT: внешний IP не назначен на интерфейс. Убедитесь, что порты 80/443 "
                              "проброшены на этот сервер." if nat else ""))
        else:
            res.append(R("external_ip", g, "Внешний IP-адрес", WARN, "Не удалось определить",
                         hint="Укажите внешний IP вручную в «Настройки панели → Сеть»."))
        has6 = self.app.nginx.caps().ipv6
        res.append(R("ipv6", g, "IPv6", INFO if not has6 else OK, "доступен" if has6 else "отключён в системе",
                     hint="" if has6 else "listen [::] не добавляется (режим IPv6 = авто)."))
        return res

    async def c_dns(self) -> List[Dict[str, Any]]:
        g = "DNS"
        state = self.app.nginx.load_state()
        ips = set(await self.external_ips())
        cf = [ipaddress.ip_network(n) for n in CLOUDFLARE_IPS]
        res = []

        def resolve(d):
            try:
                return sorted({ai[4][0] for ai in socket.getaddrinfo(d, None)})
            except (socket.gaierror, UnicodeError, OSError):
                return None
        domains = []
        for sid, s in state.sites:
            if s.enabled:
                for d in s.domains:
                    if not d.startswith(("~", "*", ".")) and d != "_" and not d.endswith(".*"):
                        domains.append((s.name, d))
        if state.panel.panel_domain:
            domains.append(("Панель", state.panel.panel_domain))
        limit = 2000
        if len(domains) > limit:
            res.append(R("dns_limit", g, "Проверка DNS", INFO, f"Проверены первые {limit} доменов из {len(domains)}"))
            domains = domains[:limit]
        sem = asyncio.Semaphore(32)

        async def lookup(d: str):
            async with sem:
                return await asyncio.to_thread(resolve, d)
        tasks = [asyncio.ensure_future(lookup(d)) for _, d in domains]
        if tasks:
            await asyncio.wait(tasks, timeout=40)  # общий бюджет проверки DNS, чтобы не упереться в лимит в 60 с
        late = [d for (_, d), t in zip(domains, tasks) if not t.done()]
        for t in tasks:
            if not t.done():
                t.cancel()
        if late:
            res.append(R("dns_timeout", g, "Проверка DNS", WARN, f"Не успели проверить {len(late)} доменов за 40 с",
                         details="\n".join(late[:500]), hint="DNS-сервер отвечает медленно. Проверьте /etc/resolv.conf."))
        resolved = [t.result() if t.done() and not t.cancelled() else False for t in tasks]
        for (name, d), addrs in zip(domains, resolved):
            if addrs is False:
                continue
            if addrs is None:
                res.append(R(f"dns_{d}", g, d, FAIL, "Домен не разрешается (NXDOMAIN)", details={"site": name},
                             hint="Создайте A-запись (и AAAA для IPv6) у регистратора/DNS-провайдера, указывающую "
                                  f"на {', '.join(sorted(ips)) or 'внешний IP сервера'}. Let's Encrypt не выпустит "
                                  "сертификат, пока домен не разрешается."))
                continue
            if not ips:
                res.append(R(f"dns_{d}", g, d, INFO, ", ".join(addrs), details={"site": name}))
                continue
            via_cf = any(ipaddress.ip_address(a) in n for a in addrs for n in cf if
                         ipaddress.ip_address(a).version == n.version)
            if set(addrs) & ips:
                res.append(R(f"dns_{d}", g, d, OK, f"→ {', '.join(addrs)}", details={"site": name}))
            elif via_cf:
                res.append(R(f"dns_{d}", g, d, INFO, f"→ {', '.join(addrs)} (Cloudflare proxy)",
                             details={"site": name},
                             hint="Домен проксируется Cloudflare. Включите «Реальный IP клиента» с диапазонами "
                                  "Cloudflare, чтобы видеть реальные IP посетителей."))
            elif any(ipaddress.ip_address(a).is_private or ipaddress.ip_address(a).is_loopback for a in addrs):
                res.append(R(f"dns_{d}", g, d, INFO, f"→ {', '.join(addrs)} (локальный адрес)",
                             details={"site": name}))
            else:
                res.append(R(f"dns_{d}", g, d, WARN, f"→ {', '.join(addrs)}, а внешний IP сервера "
                                                     f"{', '.join(sorted(ips))}", details={"site": name},
                             hint="Домен указывает на другой сервер. Если это не CDN/балансировщик — исправьте "
                                  "A-запись. Изменения DNS распространяются до TTL (обычно до часа)."))
        if not domains:
            res.append(R("dns_none", g, "Домены", SKIP, "Нет сайтов с доменами"))
        return res

    async def c_backends(self) -> List[Dict[str, Any]]:
        g = "Бэкенды"
        res = []
        targets = await self.app.health.check_now()
        for t in targets:
            name = f"{t['owner_name']} → {t['address']}:{t['port']}"
            if t["state"] == "up":
                res.append(R(f"be_{t['key']}", g, name, OK, f"доступен, {t['latency_ms']} мс"
                             + (f", HTTP {t['status']}" if t["status"] else "")))
            elif t["state"] == "down" or t["error"]:
                hint = backend_hint(t["error"])
                res.append(R(f"be_{t['key']}", g, name, WARN if t["backup"] else FAIL,
                             t["error"] or "недоступен", hint=hint))
            else:
                res.append(R(f"be_{t['key']}", g, name, INFO, t["state"]))
        passive = self.app.stats.agg.passive_upstream
        if passive:
            top = passive.most_common(5)
            res.append(R("be_passive", g, "Ошибки соединения из журнала nginx", WARN,
                         "; ".join(f"{k}: {v}" for k, v in top),
                         hint="Nginx фиксировал ошибки подключения к этим бэкендам с момента запуска панели."))
        if not targets:
            res.append(R("be_none", g, "Бэкенды", SKIP, "Нет бэкендов для проверки"))
        return res

    async def c_certs(self) -> List[Dict[str, Any]]:
        g = "SSL"
        res = []
        await asyncio.to_thread(self.app.certs.refresh_all)
        certs = self.app.certs.list()
        state = self.app.nginx.load_state()
        from .certs import domain_covered, expiry_level, fmt_left
        for c in certs:
            name = f"Сертификат «{c['name']}»"
            if c["status"] == "pending":
                res.append(R(f"cert_{c['id']}", g, name, INFO, "выпускается..."))
                continue
            if c["status"] in ("error", "missing"):
                res.append(R(f"cert_{c['id']}", g, name, FAIL, c["last_error"] or c["status"],
                             fix="renew_cert" if c["type"] == "letsencrypt" else None,
                             fix_label="Выпустить заново", fix_args={"id": c["id"]}))
                continue
            days = c["days_left"]
            if days is None:
                res.append(R(f"cert_{c['id']}", g, name, WARN, "Не удалось определить срок действия"))
            elif days < 0:
                res.append(R(f"cert_{c['id']}", g, name, FAIL, "Срок действия истёк",
                             fix="renew_cert", fix_label="Продлить", fix_args={"id": c["id"]}))
            elif expiry_level(c) == "crit":
                res.append(R(f"cert_{c['id']}", g, name, FAIL, f"Истекает через {fmt_left(days)}",
                             fix="renew_cert", fix_label="Продлить", fix_args={"id": c["id"]}))
            elif expiry_level(c) == "warn":
                res.append(R(f"cert_{c['id']}", g, name, WARN, f"Истекает через {fmt_left(days)}",
                             fix="renew_cert", fix_label="Продлить", fix_args={"id": c["id"]},
                             hint="ACME-сертификаты продлеваются автоматически (за 30 дней, короткие — за треть "
                                  "срока). Если не продлился — смотрите ошибку на странице «Сертификаты»."))
            else:
                res.append(R(f"cert_{c['id']}", g, name, OK, f"Действителен ещё {days:.0f} дн. "
                                                            f"({', '.join(c['domains'][:4])})"))
            if c["data"].get("self_signed"):
                res.append(R(f"cert_ss_{c['id']}", g, name, INFO, "Самоподписанный: браузеры покажут предупреждение"))
        for sid, s in state.sites:
            if not (s.enabled and s.ssl.enabled):
                continue
            c = next((x for x in certs if x["id"] == s.ssl.certificate_id), None)
            if not c:
                res.append(R(f"cert_site_{sid}", g, f"HTTPS сайта «{s.name}»", FAIL, "Сертификат не найден"))
                continue
            plain = [d for d in s.domains if not d.startswith(("~", "."))]
            missing = [d for d in plain if not domain_covered(d, c["domains"])]
            if missing:
                res.append(R(f"cert_site_{sid}", g, f"HTTPS сайта «{s.name}»", WARN,
                             f"Сертификат не покрывает: {', '.join(missing)}",
                             hint="Выпустите сертификат, включающий все домены сайта, иначе браузеры покажут ошибку."))
        dns_used = self.app.certs.dns_accounts_usage()
        if any(c["type"] == "letsencrypt" for c in certs):
            if not self.app.certs.certbot():
                res.append(R("certbot", g, "certbot", FAIL, "Не установлен", fix="install_certbot",
                             fix_label="Установить certbot"))
            elif (cb := await asyncio.to_thread(run, [self.app.certs.certbot() or "certbot", "--version"], 60))[0] != 0:
                out = cb[1]
                res.append(R("certbot", g, "certbot", FAIL, "Установлен, но не запускается — сертификаты не продлеваются",
                             hint="Ошибка: " + ([ln.strip() for ln in out.strip().splitlines()
                                                 if ln.strip(" ^~")] or ["—"])[-1][:300] +
                                  ". Частая причина — certbot из пакета запускается не тем Python (после замены "
                                  "python3 через update-alternatives или pip). Переустановите: apt install --reinstall "
                                  "certbot python3-certbot (dnf reinstall certbot)."))
            else:
                active = await asyncio.to_thread(self.app.certs.certbot_timer_active)
                res.append(R("certbot", g, "Автопродление certbot", OK if active else INFO,
                             "таймер certbot активен" if active else
                             "системный таймер не найден — продлением занимается Nginx Manager (ежедневно)"))
        if dns_used and self.app.certs.certbot():
            from . import acme
            plugins = await asyncio.to_thread(acme.installed_plugins, True)
            for aid, names in dns_used.items():
                acc = self.app.certs.dns_account(aid)
                if not acc:
                    res.append(R(f"dns_account_{aid}", g, "Учётная запись DNS", FAIL,
                                 f"Удалена, но по ней продлеваются: {', '.join(names[:5])}",
                                 hint="Выпустите эти сертификаты заново с другой учётной записью DNS."))
                    continue
                if acc.provider == "hook" or plugins is None:
                    continue
                auth = acme.PLUGINS[acc.provider]["auth"]
                if auth not in plugins:
                    res.append(R(f"dns_plugin_{acc.provider}", g, f"Плагин certbot {auth}", FAIL,
                                 f"Не установлен — не продлятся: {', '.join(names[:5])}",
                                 fix="install_dns_plugin", fix_label="Установить плагин",
                                 fix_args={"provider": acc.provider}))
        panel = self.app.panel()
        if panel.acme_ca == "custom" and not panel.acme_directory:
            res.append(R("acme_directory", g, "Центр сертификации", WARN, "Выбран свой ACME-сервер, но адрес не указан",
                         hint="Настройки панели → «Сертификаты (ACME)» → «Адрес каталога ACME»."))
        elif panel.acme_ca in ("zerossl", "google") and not (panel.acme_eab_kid and panel.acme_eab_hmac):
            res.append(R("acme_eab", g, "Центр сертификации", WARN, "Не указан ключ EAB — новые сертификаты не выпустятся",
                         hint="Получите Key ID и HMAC-ключ в личном кабинете центра сертификации и укажите их в "
                              "настройках панели."))
        webroot = settings.acme_webroot / ".well-known" / "acme-challenge"
        if not webroot.is_dir():
            res.append(R("acme_webroot", g, "Каталог ACME", FAIL, f"{webroot} не существует", fix="fix_webroot",
                         fix_label="Создать"))
        else:
            mode = webroot.stat().st_mode & 0o777
            if not mode & 0o005:
                res.append(R("acme_webroot", g, "Каталог ACME", FAIL, "Нет прав чтения для nginx",
                             fix="fix_webroot", fix_label="Исправить права"))
            else:
                res.append(R("acme_webroot", g, "Каталог ACME", OK, str(settings.acme_webroot)))
        if not certs:
            res.append(R("cert_none", g, "Сертификаты", SKIP, "Нет сертификатов"))
        return res

    async def c_firewall(self) -> List[Dict[str, Any]]:
        g = "Firewall"
        res = []
        ports = {80, 443} | {s.listen_port for _, s in self.app.nginx.load_state().streams if s.enabled}
        if which("ufw"):
            code, out = await asyncio.to_thread(run, ["ufw", "status"])
            if "Status: active" in out:
                closed = [p for p in sorted(ports) if not re.search(rf"^{p}(/tcp|/udp)?\s+(ALLOW|LIMIT)", out, re.M)
                          and not ("Nginx Full" in out and p in (80, 443))]
                if closed:
                    res.append(R("fw_ufw", g, "UFW", WARN, f"Порты не разрешены: {', '.join(map(str, closed))}",
                                 fix="fw_open", fix_label="Открыть порты", fix_args={"ports": closed}))
                else:
                    res.append(R("fw_ufw", g, "UFW", OK, "необходимые порты открыты"))
            else:
                res.append(R("fw_ufw", g, "UFW", INFO, "неактивен"))
        if which("firewall-cmd"):
            code, state = await asyncio.to_thread(run, ["firewall-cmd", "--state"])
            if "running" in state:
                _, services = await asyncio.to_thread(run, ["firewall-cmd", "--list-services"])
                _, plist = await asyncio.to_thread(run, ["firewall-cmd", "--list-ports"])
                closed = []
                for p in sorted(ports):
                    svc = {80: "http", 443: "https"}.get(p)
                    if (svc and svc in services.split()) or re.search(rf"\b{p}/(tcp|udp)\b", plist):
                        continue
                    closed.append(p)
                if closed:
                    res.append(R("fw_firewalld", g, "firewalld", WARN,
                                 f"Порты не разрешены: {', '.join(map(str, closed))}",
                                 fix="fw_open", fix_label="Открыть порты", fix_args={"ports": closed}))
                else:
                    res.append(R("fw_firewalld", g, "firewalld", OK, "необходимые порты открыты"))
        if not res:
            if which("iptables"):
                code, out = await asyncio.to_thread(run, ["iptables", "-S", "INPUT"])
                if code == 0 and "-P INPUT DROP" in out:
                    res.append(R("fw_iptables", g, "iptables", INFO, "Политика INPUT = DROP — проверьте, что 80/443 "
                                                                      "разрешены", details=out[:3000]))
                else:
                    res.append(R("fw_iptables", g, "iptables", OK, "блокирующей политики не обнаружено"))
            else:
                res.append(R("fw_none", g, "Firewall", INFO, "Локальный firewall не обнаружен. Проверьте правила "
                                                             "облачного провайдера (security groups)."))
        return res

    async def c_selinux(self) -> List[Dict[str, Any]]:
        g = "SELinux"
        if not which("getenforce"):
            return []
        _, mode = await asyncio.to_thread(run, ["getenforce"])
        mode = mode.strip()
        if mode != "Enforcing":
            return [R("selinux", g, "SELinux", INFO, mode)]
        res = [R("selinux", g, "SELinux", INFO, "Enforcing")]
        _, out = await asyncio.to_thread(run, ["getsebool", "httpd_can_network_connect"])
        if "--> on" in out:
            res.append(R("selinux_net", g, "httpd_can_network_connect", OK, "on"))
        else:
            res.append(R("selinux_net", g, "httpd_can_network_connect", FAIL,
                         "off — nginx не может подключаться к бэкендам (502, Permission denied)",
                         fix="selinux_net", fix_label="Разрешить (setsebool -P)"))
        # порты: nginx может слушать только порты с меткой http_port_t / http_cache_port_t
        if which("semanage"):
            state = self.app.nginx.load_state()
            needed = [("tcp", settings.stub_status_port, "stub_status панели")]
            for _, s in state.sites:
                if s.enabled:
                    needed.append(("tcp", s.http_port, f"сайт «{s.name}»"))
                    if s.ssl.enabled:
                        needed.append(("tcp", s.https_port, f"сайт «{s.name}» (HTTPS)"))
                        if s.ssl.http3:
                            needed.append(("udp", s.https_port, f"сайт «{s.name}» (HTTP/3)"))
            for _, st in state.streams:
                if st.enabled:
                    for proto in (("tcp", "udp") if st.protocol == "both" else (st.protocol,)):
                        needed.append((proto, st.listen_port, f"поток «{st.name}»"))
            needed = list({(p, n): (p, n, w) for p, n, w in needed}.values())
            code, out = await asyncio.to_thread(run, ["semanage", "port", "-l"], 60)
            probs = selinux_port_problems(needed, selinux_port_types(out)) if code == 0 else []
            for pr in probs:
                if pr["type"] is None:
                    res.append(R(f"selinux_port_{pr['proto']}_{pr['port']}", g,
                                 f"Порт {pr['port']}/{pr['proto']}", FAIL,
                                 f"{pr['who']}: у порта нет метки http_port_t — nginx не сможет его занять "
                                 "(bind() … Permission denied при перезагрузке)",
                                 fix="selinux_port", fix_label="Разрешить порт для nginx",
                                 fix_args={"proto": pr["proto"], "port": pr["port"]}))
                else:
                    res.append(R(f"selinux_port_{pr['proto']}_{pr['port']}", g,
                                 f"Порт {pr['port']}/{pr['proto']}", FAIL,
                                 f"{pr['who']}: порт помечен как {pr['type']} — nginx не сможет его занять",
                                 hint=f"Порт закреплён за другой службой. Если её нет на этом сервере, выполните: "
                                      f"semanage port -m -t http_port_t -p {pr['proto']} {pr['port']} "
                                      f"(изменит метку для всех программ). Или выберите другой порт."))
            if code == 0 and not probs:
                res.append(R("selinux_ports", g, "Порты nginx", OK, f"меток достаточно ({len(needed)} портов)"))
        return res

    async def c_system(self) -> List[Dict[str, Any]]:
        g = "Система"
        res = []
        s = self.app.stats.system.latest() or await asyncio.to_thread(self.app.stats.system.sample)
        cpus = s.get("cpus", 1)
        load = s.get("load5", 0)
        res.append(R("sys_load", g, "Нагрузка CPU", WARN if load > cpus * 1.5 else OK,
                     f"load average {s.get('load1', 0):.2f} / {load:.2f} / {s.get('load15', 0):.2f} "
                     f"на {cpus} ядрах, CPU {s.get('cpu', 0):.0f}%"))
        mem = s.get("mem", 0)
        res.append(R("sys_mem", g, "Память", FAIL if mem > 95 else WARN if mem > 85 else OK,
                     f"используется {mem:.0f}%"))
        for key, label, path in (("disk", "Диск /", "/"), ("disk_log", "Диск журналов", str(settings.log_dir))):
            v = s.get(key, 0)
            free = s.get(key + "_free" if key == "disk_log" else "disk_free", 0)
            res.append(R(f"sys_{key}", g, label, FAIL if v > 95 else WARN if v > 85 else OK,
                         f"заполнен на {v:.0f}%, свободно {free / 1024 ** 3:.1f} ГБ ({path})",
                         hint="Уменьшите сроки хранения в «Настройки → Статистика», проверьте ротацию журналов "
                              "(logrotate) и кэш nginx." if v > 85 else ""))
        try:
            st = os.statvfs(str(settings.data_dir))
            if st.f_files and st.f_ffree / st.f_files < 0.05:
                res.append(R("sys_inodes", g, "Inode", FAIL, "свободных inode < 5%"))
        except OSError:
            pass
        db_size = sum(f.stat().st_size for f in settings.data_dir.glob("nginx-manager.db*") if f.exists())
        res.append(R("sys_db", g, "База данных панели", WARN if db_size > 5 * 1024 ** 3 else OK,
                     f"{db_size / 1024 ** 2:.0f} МБ"))
        return res

    async def c_limits(self) -> List[Dict[str, Any]]:
        g = "Производительность"
        res = []
        state = self.app.nginx.load_state()
        gl = state.glob
        m = self.app.nginx.master_process()
        if m:
            try:
                txt = Path(f"/proc/{m.pid}/limits").read_text()
                mm = re.search(r"Max open files\s+(\d+)\s+(\d+)", txt)
                soft = int(mm.group(1)) if mm else 0
                ch = m.children()
                wsoft = soft
                if ch:
                    t2 = Path(f"/proc/{ch[0].pid}/limits").read_text()
                    wm = re.search(r"Max open files\s+(\d+)", t2)
                    wsoft = int(wm.group(1)) if wm else soft
                need = gl.worker_connections * 2
                if wsoft < need:
                    res.append(R("lim_nofile", g, "Лимит открытых файлов воркера", WARN,
                                 f"{wsoft} < 2 × worker_connections ({need})",
                                 hint="Увеличьте worker_rlimit_nofile в глобальных настройках."))
                else:
                    res.append(R("lim_nofile", g, "Лимит открытых файлов воркера", OK, str(wsoft)))
            except (OSError, AttributeError, psutil.Error):
                pass
        stub = self.app.stats.stub.latest()
        if stub.get("ok"):
            workers = len(m.children()) if m else 1
            cap = max(1, workers) * gl.worker_connections
            used = stub["active"] / cap * 100
            res.append(R("lim_conns", g, "Использование соединений", WARN if used > 70 else OK,
                         f"{stub['active']} из ~{cap} ({used:.1f}%)",
                         hint="Увеличьте worker_connections." if used > 70 else ""))
            if stub.get("dropped", 0) > 0:
                res.append(R("lim_dropped", g, "Отброшенные соединения", WARN,
                             f"accepts − handled = {stub['dropped']}",
                             hint="Nginx отбрасывал соединения из-за лимитов — увеличьте worker_connections."))
        else:
            res.append(R("stub_status", g, "stub_status", FAIL, stub.get("error", "нет данных"),
                         hint="Без stub_status нет данных об активных соединениях. Примените конфигурацию.",
                         fix="reapply", fix_label="Применить"))
        try:
            somax = int(Path("/proc/sys/net/core/somaxconn").read_text())
            res.append(R("sysctl_somaxconn", g, "net.core.somaxconn", INFO if somax < 1024 else OK, str(somax),
                         hint="Для высокой нагрузки: sysctl -w net.core.somaxconn=4096" if somax < 1024 else ""))
        except (OSError, ValueError):
            pass
        return res

    async def c_logs(self) -> List[Dict[str, Any]]:
        g = "Журналы и статистика"
        res = []
        info = self.app.stats.collector_info()
        for t in info["tailers"]:
            label = {"access": "Журнал запросов", "error": "Журнал ошибок", "stream": "Журнал TCP/UDP"}[t["name"]]
            if t["status"] != "ok":
                st = INFO if t["name"] == "stream" else WARN
                res.append(R(f"log_{t['name']}", g, label, st, f"{t['path']}: {t['status']}",
                             hint="Файл появится после применения конфигурации и первых запросов."))
            elif t["lag_bytes"] > 50 * 1024 * 1024:
                res.append(R(f"log_{t['name']}", g, label, WARN, f"отставание обработки {t['lag_bytes'] // 1024 ** 2} МБ"))
            else:
                res.append(R(f"log_{t['name']}", g, label, OK,
                             f"{t['path']} ({t['size'] / 1024 ** 2:.1f} МБ)" +
                             (f", обработано строк: {t['lines']}" if t["lines"] >= 0 else "")))
        if info["parse_errors"] > 0 and info["parse_errors"] > info["parsed"] * 0.01:
            res.append(R("log_parse", g, "Разбор журнала", WARN, f"Ошибок разбора: {info['parse_errors']}",
                         hint="В nm-access.log пишет кто-то кроме панели или изменён формат. Примените конфигурацию."))
        lr = Path("/etc/logrotate.d/nginx-manager")
        res.append(R("logrotate", g, "Ротация журналов", OK if lr.exists() else WARN,
                     str(lr) if lr.exists() else "конфигурация logrotate не найдена",
                     hint="" if lr.exists() else "Журналы будут расти бесконечно. Переустановите (install.sh) "
                                                 "или создайте /etc/logrotate.d/nginx-manager.",
                     fix=None if lr.exists() else "logrotate", fix_label="Создать"))
        geo = info["geoip"]
        res.append(R("geoip", g, "GeoIP (страны)", OK if geo["enabled"] else INFO,
                     geo["path"] if geo["enabled"] else geo["error"],
                     hint="" if geo["enabled"] else "Скачайте GeoLite2-Country.mmdb (MaxMind, бесплатная регистрация) "
                                                    "или dbip-country-lite.mmdb (DB-IP) в /var/lib/nginx-manager/geoip/ "
                                                    "и установите пакет maxminddb в venv панели."))
        return res

    async def c_errors(self) -> List[Dict[str, Any]]:
        g = "Анализ ошибок nginx"
        since = time.time() - 3600
        rows = self.app.db.query("SELECT category, COUNT(*) n, MAX(message) sample FROM errors WHERE ts>=? "
                                 "GROUP BY category ORDER BY n DESC", (since,))
        res = []
        for r in rows:
            info = CATEGORY_INFO.get(r["category"], CATEGORY_INFO["other"])
            lvl = info["level"]
            st = FAIL if lvl == "crit" else WARN if lvl == "error" and r["n"] > 10 else INFO
            res.append(R(f"err_{r['category']}", g, info["title"], st, f"{r['n']} за последний час",
                         details=r["sample"], hint=info["hint"]))
        if not rows:
            res.append(R("err_none", g, "Ошибки nginx за час", OK, "Ошибок нет"))
        return res

    async def c_traffic(self) -> List[Dict[str, Any]]:
        g = "Трафик"
        res = []
        state = self.app.nginx.load_state()
        names = {str(sid): s.name for sid, s in state.sites}
        rows = self.app.stats.compare_sites(time.time() - 900, time.time())
        for r in rows:
            name = names.get(r["site"], r["site"])
            if r["req"] >= 30 and r["err5_pct"] >= 5:
                top = self.app.stats.tops(time.time() - 900, time.time(), r["site"], "e5xx", 3)
                res.append(R(f"tr_5xx_{r['site']}", g, f"Ошибки 5xx: {name}", FAIL if r["err5_pct"] > 20 else WARN,
                             f"{r['err5_pct']:.1f}% ответов 5xx за 15 минут ({r['s5']} из {r['req']})",
                             details=[f"{t['key']} — {t['count']}" for t in top],
                             hint="502 — бэкенд недоступен/упал; 504 — не успел ответить; 500/503 — ошибка "
                                  "приложения. Смотрите «Журнал ошибок» и «Бэкенды»."))
            if r["req"] >= 30 and r["rt_avg"] > 2000:
                res.append(R(f"tr_slow_{r['site']}", g, f"Медленные ответы: {name}", WARN,
                             f"среднее время ответа {r['rt_avg']:.0f} мс",
                             hint="Включите кэширование, проверьте нагрузку на бэкенд и медленные URI на странице "
                                  "«Аналитика»."))
        if not res:
            res.append(R("tr_ok", g, "Ошибки и время ответа", OK, "Аномалий за 15 минут не обнаружено"))
        return res

    async def c_security(self) -> List[Dict[str, Any]]:
        g = "Безопасность"
        res = []
        users = self.app.db.query("SELECT username, role, totp_enabled, must_change_password FROM users WHERE "
                                  "disabled=0")
        weak = [u["username"] for u in users if u["must_change_password"]]
        if weak:
            res.append(R("sec_default_pw", g, "Пароли по умолчанию", WARN,
                         f"Пользователи с временным паролем: {', '.join(weak)}", hint="Смените пароль в профиле."))
        admins_no2fa = [u["username"] for u in users if u["role"] == "admin" and not u["totp_enabled"]]
        if admins_no2fa:
            res.append(R("sec_2fa", g, "Двухфакторная аутентификация", INFO,
                         f"Без 2FA: {', '.join(admins_no2fa)}", hint="Включите 2FA в профиле пользователя."))
        panel = self.app.panel()
        if settings.bind_host in ("0.0.0.0", "::") and not settings.tls_cert and not panel.panel_allow:
            res.append(R("sec_exposed", g, "Доступ к панели", WARN,
                         f"Панель доступна по HTTP на порту {settings.bind_port} со всех адресов",
                         hint="Варианты: задайте домен панели с HTTPS (Настройки → Сеть), ограничьте доступ по IP, "
                              "или привяжите панель к 127.0.0.1 и используйте SSH-туннель."))
        else:
            res.append(R("sec_exposed", g, "Доступ к панели", OK, "ограничен"))
        state = self.app.nginx.load_state()
        if state.glob.server_tokens:
            res.append(R("sec_tokens", g, "server_tokens", INFO, "Версия nginx видна в ответах"))
        if state.glob.ssl_preset == "old":
            res.append(R("sec_tls", g, "Профиль TLS", WARN, "Включены устаревшие TLS 1.0/1.1"))
        nohttps = [s.name for _, s in state.sites if s.enabled and not s.ssl.enabled and s.type != "redirect"]
        if nohttps:
            res.append(R("sec_nohttps", g, "Сайты без HTTPS", INFO, ", ".join(nohttps[:10]),
                         hint="Выпустите бесплатный сертификат Let's Encrypt на странице «Сертификаты»."))
        basic_nohttps = [s.name for _, s in state.sites if s.enabled and s.security.basic_auth and not s.ssl.enabled]
        if basic_nohttps:
            res.append(R("sec_basic_http", g, "Basic Auth без HTTPS", WARN, ", ".join(basic_nohttps),
                         hint="Пароли передаются открытым текстом."))
        return res

    async def c_backups(self) -> List[Dict[str, Any]]:
        g = "Резервные копии"
        res: List[Dict[str, Any]] = []
        now = time.time()
        autos = sorted(settings.backups_dir.glob("nginx-manager-*-auto.db"), key=lambda x: x.stat().st_mtime)
        if autos:
            age = (now - autos[-1].stat().st_mtime) / 3600
            res.append(R("backup_auto", g, "Ежедневная копия", OK if age < 36 else WARN,
                         f"последняя {age:.0f} ч назад ({autos[-1].name})" if age < 36 else
                         f"последняя {age / 24:.0f} дн. назад — ежедневное копирование не выполняется",
                         hint="" if age < 36 else "Смотрите «События» (источник «Сервис панели»): фоновая задача "
                                                   "копирования завершается ошибкой, или сервис не работал в час копирования."))
        elif now - self.app.started > 36 * 3600:
            res.append(R("backup_auto", g, "Ежедневная копия", WARN, "ни одной автоматической копии",
                         hint="Проверьте «Час ежедневного резервного копирования» и журнал «События»."))
        p = self.app.panel()
        if p.s3_enabled:
            last = self.app.db.kv_get("offsite_last") or {}
            if not last:
                res.append(R("backup_s3", g, f"Хранилище {p.s3_bucket}", INFO,
                             "выгрузок ещё не было — первая будет с ежедневной копией",
                             hint="Проверьте доступ кнопкой «Проверить хранилище» на странице «Копии и импорт»."))
            elif not last.get("ok"):
                res.append(R("backup_s3", g, f"Хранилище {p.s3_bucket}", FAIL,
                             f"последняя выгрузка не удалась: {last.get('error', '')[:200]}",
                             hint="Копии остаются только на этом сервере. Проверьте ключи, бакет, регион и сеть "
                                  "(«Проверить хранилище»)."))
            else:
                age = (now - last.get("ts", 0)) / 3600
                res.append(R("backup_s3", g, f"Хранилище {p.s3_bucket}", OK if age < 50 else WARN,
                             f"последняя выгрузка {age:.0f} ч назад" if age < 50 else
                             f"последняя выгрузка {age / 24:.0f} дн. назад"))
            if not p.s3_encrypt_password:
                res.append(R("backup_s3_enc", g, "Шифрование копий в хранилище", INFO, "выключено",
                             hint="В копиях есть секреты (токены каналов и DNS, ключи сертификатов, хеши паролей). "
                                  "Задайте пароль шифрования, если хранилищем пользуется кто-то ещё."))
        return res

    async def c_time(self) -> List[Dict[str, Any]]:
        g = "Система"
        if not which("timedatectl"):
            return []
        code, out = await asyncio.to_thread(run, ["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        if code != 0:
            return []
        synced = out.strip() == "yes"
        return [R("time_sync", g, "Синхронизация времени (NTP)", OK if synced else WARN,
                  "синхронизировано" if synced else "не синхронизировано",
                  hint="" if synced else "Неверное время ломает проверку сертификатов и статистику. "
                                         "Включите: timedatectl set-ntp true",
                  fix=None if synced else "ntp", fix_label="Включить NTP")]

    # ------------------------------------------------------------------
    #  Исправления
    # ------------------------------------------------------------------
    async def fix(self, action: str, args: Dict[str, Any], username: str) -> Dict[str, Any]:
        mgr = self.app.nginx
        if action == "start_nginx":
            ok, out = await asyncio.to_thread(mgr.start)
            return {"ok": ok, "output": out}
        if action == "restart_nginx":
            ok, out = await asyncio.to_thread(mgr.restart)
            return {"ok": ok, "output": out}
        if action == "enable_nginx":
            code, out = await asyncio.to_thread(run, ["systemctl", "enable", "nginx"])
            return {"ok": code == 0, "output": out}
        if action == "reapply":
            res = await self.app.apply(username, "Применено из диагностики")
            return {"ok": True, "output": f"Версия {res['version']}"}
        if action == "hash_bucket":
            g = self.app.global_settings()
            g.server_names_hash_bucket_size = 256
            self.app.db.kv_set("global_settings", g.model_dump())
            res = await self.app.apply(username, "server_names_hash_bucket_size=256")
            return {"ok": True, "output": f"Версия {res['version']}"}
        if action == "fw_open":
            ports = [int(p) for p in args.get("ports", [80, 443])]
            outs = []
            if which("ufw"):
                for p in ports:
                    outs.append((await asyncio.to_thread(run, ["ufw", "allow", str(p)]))[1])
            if which("firewall-cmd"):
                for p in ports:
                    outs.append((await asyncio.to_thread(run, ["firewall-cmd", "--permanent", f"--add-port={p}/tcp"]))[1])
                outs.append((await asyncio.to_thread(run, ["firewall-cmd", "--reload"]))[1])
            return {"ok": True, "output": "\n".join(outs)}
        if action == "selinux_port":
            proto = str(args.get("proto", "tcp"))
            port = int(args.get("port", 0))
            if proto not in ("tcp", "udp") or not 1 <= port <= 65535:
                return {"ok": False, "output": "некорректный порт"}
            code, out = await asyncio.to_thread(run, ["semanage", "port", "-a", "-t", "http_port_t", "-p", proto,
                                                      str(port)], 120)
            return {"ok": code == 0, "output": out or f"порт {port}/{proto} помечен как http_port_t"}
        if action == "selinux_net":
            code, out = await asyncio.to_thread(run, ["setsebool", "-P", "httpd_can_network_connect", "1"], 120)
            return {"ok": code == 0, "output": out}
        if action == "renew_cert":
            await self.app.certs.renew(int(args["id"]), after=self.app.after_cert_issued)
            return {"ok": True, "output": "Продление запущено — следите за статусом на странице «Сертификаты»"}
        if action == "bans_sync":
            ok, out = await self.app.bans.sync(force=True)
            return {"ok": ok, "output": out}
        if action == "fix_perms":
            user = mgr.load_state().glob.user or mgr.caps().default_user
            fixed = await asyncio.to_thread(mgr.fix_permissions, user)
            return {"ok": True, "output": f"Исправлено путей: {len(fixed)}\n" + "\n".join(fixed[:50])}
        if action == "fix_webroot":
            settings.ensure_dirs()
            return {"ok": True, "output": "Каталог создан, права исправлены"}
        if action == "install_certbot":
            return await self._pkg_install(["certbot"])
        if action == "install_dns_plugin":
            from . import acme
            provider = str((args or {}).get("provider", ""))
            if provider not in acme.PLUGINS or provider == "hook":
                raise ValueError("Неизвестный DNS-провайдер")
            cmd = acme.install_command(provider)
            if not cmd:
                return {"ok": False, "output": "Пакетный менеджер не найден — установите плагин вручную: "
                                               + acme.PLUGINS[provider]["pkg"]}
            code, out = await asyncio.to_thread(run, cmd, 600, None)
            acme.installed_plugins(refresh=True)
            hint = ""
            if code != 0 and which("dnf"):
                hint = "\nНа RHEL-системах плагины есть в EPEL: dnf install epel-release"
            return {"ok": code == 0, "output": out[-4000:] + hint}
        if action == "install_stream":
            if which("apt-get"):
                return await self._pkg_install(["libnginx-mod-stream"])
            return await self._pkg_install(["nginx-mod-stream"])
        if action == "logrotate":
            from ..utils import atomic_write
            atomic_write("/etc/logrotate.d/nginx-manager", LOGROTATE)
            return {"ok": True, "output": "Создан /etc/logrotate.d/nginx-manager"}
        if action == "ntp":
            code, out = await asyncio.to_thread(run, ["timedatectl", "set-ntp", "true"])
            return {"ok": code == 0, "output": out}
        raise ValueError(f"Неизвестное действие: {action}")

    async def _pkg_install(self, pkgs: List[str]) -> Dict[str, Any]:
        if which("apt-get"):
            cmd = ["apt-get", "install", "-y", *pkgs]
        elif which("dnf"):
            cmd = ["dnf", "install", "-y", *pkgs]
        elif which("yum"):
            cmd = ["yum", "install", "-y", *pkgs]
        else:
            return {"ok": False, "output": "Пакетный менеджер не найден"}
        code, out = await asyncio.to_thread(run, cmd, 600, None)
        self.app.nginx.caps(refresh=True)
        return {"ok": code == 0, "output": out[-4000:]}


LOGROTATE = """/var/log/nginx/nm-*.log {
    daily
    rotate 14
    maxsize 500M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid) 2>/dev/null || true
    endscript
}
"""


def mgr_explain(text: str) -> str:
    from ..nginx.manager import explain_nginx_error
    hints = []
    for ln in text.splitlines():
        h = explain_nginx_error(ln)
        if h and h not in hints:
            hints.append(h)
    return "\n".join(hints)


def backend_hint(err: str) -> str:
    e = (err or "").lower()
    if "отклонено" in e or "refused" in e:
        return "Порт закрыт: приложение не запущено или слушает другой адрес (например, только 127.0.0.1 на " \
               "другом сервере). Проверьте: ss -tlnp на бэкенде."
    if "таймаут" in e or "timed out" in e:
        return "Нет ответа: firewall на бэкенде отбрасывает пакеты, неверный IP или приложение зависло."
    if "no route" in e or "unreachable" in e:
        return "Нет маршрута до бэкенда — проверьте сеть/VPN и IP-адрес."
    if e.startswith("http "):
        return "Бэкенд отвечает, но код ответа не входит в ожидаемые. Проверьте путь проверки (health check)."
    if "name or service not known" in e or "nodename" in e:
        return "Имя хоста бэкенда не разрешается через DNS."
    return ""


def fmt_dur(sec: float) -> str:
    sec = int(sec or 0)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, _ = divmod(sec, 60)
    return (f"{d} д " if d else "") + f"{h} ч {m} мин"
