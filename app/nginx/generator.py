"""Генератор конфигурации nginx из моделей панели.

Результат рендера — словарь {относительный_путь: содержимое}:
    nginx.conf                       главный файл (копируется в /etc/nginx/nginx.conf)
    http.d/00-base.conf              log_format, map, зоны кэша, общие параметры
    http.d/10-default.conf           сервер по умолчанию, stub_status, домен панели
    sites/site-<id>.conf             по файлу на сайт (upstream + server-блоки)
    stream.d/00-base.conf            log_format для TCP/UDP
    streams/stream-<id>.conf         по файлу на поток
    auth/site-<id>.htpasswd          пользователи Basic Auth
    pages/*.html                     страницы ошибок и обслуживания
"""
from __future__ import annotations

import html
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from ..models import (TLS_PRESETS, Backend, GlobalSettings, Location, PanelSettings, Site, Stream)
from ..validators import quote, quote_if_needed, quote_multiline

MARKER = "# NGINX-MANAGER: managed file — изменения вручную будут перезаписаны"
STATIC_EXT = "css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|pdf|zip|gz"
HEALTH_UA = "NginxManager-HealthCheck"


@dataclass
class NginxCaps:
    """Возможности установленного nginx (определяются по `nginx -V`)."""
    version: Tuple[int, int, int] = (1, 24, 0)
    modules: set = field(default_factory=set)
    stream_available: bool = True
    stream_load: str = ""            # строка load_module, если модуль не подключён системой
    module_includes: List[str] = field(default_factory=list)
    mime_types: str = "/etc/nginx/mime.types"
    pid_path: str = "/run/nginx.pid"
    default_user: str = "www-data"
    ipv6: bool = True
    ca_bundle: str = "/etc/ssl/certs/ca-certificates.crt"

    @property
    def http2_directive(self) -> bool:
        return self.version >= (1, 25, 1)

    @property
    def reject_handshake(self) -> bool:
        return self.version >= (1, 19, 4)

    @property
    def http3(self) -> bool:
        return "http_v3" in self.modules


@dataclass
class CertInfo:
    id: int
    cert_path: str
    key_path: str
    ok: bool = True


@dataclass
class State:
    sites: List[Tuple[int, Site]]
    streams: List[Tuple[int, Stream]]
    glob: GlobalSettings
    panel: PanelSettings
    certs: Dict[int, CertInfo]
    overrides: Dict[str, List[str]] = field(default_factory=dict)  # "site:12" -> ["10.0.0.1:80"] отключённые

    def to_json(self) -> dict:
        return {
            "sites": [{"id": i, "data": s.model_dump()} for i, s in self.sites],
            "streams": [{"id": i, "data": s.model_dump()} for i, s in self.streams],
            "global": self.glob.model_dump(),
            "panel": self.panel.model_dump(),
            "certs": {str(k): {"id": v.id, "cert_path": v.cert_path, "key_path": v.key_path, "ok": v.ok}
                      for k, v in self.certs.items()},
        }

    @classmethod
    def from_json(cls, d: dict) -> "State":
        return cls(
            sites=[(x["id"], Site.model_validate(x["data"])) for x in d.get("sites", [])],
            streams=[(x["id"], Stream.model_validate(x["data"])) for x in d.get("streams", [])],
            glob=GlobalSettings.model_validate(d.get("global", {})),
            panel=PanelSettings.model_validate(d.get("panel", {})),
            certs={int(k): CertInfo(**v) for k, v in d.get("certs", {}).items()},
        )


@dataclass
class Paths:
    include_root: str        # куда смотрят include (staging-каталог версии или live)
    live_root: str           # стабильный путь (симлинк live) для htpasswd/страниц
    acme_webroot: str
    log_dir: str
    cache_dir: str
    stub_status_port: int
    panel_port: int
    data_dir: str


class ConfigError(Exception):
    def __init__(self, message: str, site_id: Optional[int] = None):
        super().__init__(message)
        self.site_id = site_id


class Conf:
    def __init__(self) -> None:
        self.lines: List[str] = []
        self.ind = 0

    def line(self, s: str = "") -> None:
        self.lines.append(("    " * self.ind + s) if s else "")

    def d(self, *parts) -> None:
        self.line(" ".join(str(p) for p in parts if p is not None and p != "") + ";")

    def comment(self, s: str) -> None:
        for ln in s.splitlines():
            self.line("# " + ln)

    def raw(self, text: str) -> None:
        for ln in (text or "").splitlines():
            self.line(ln.rstrip())

    @contextmanager
    def block(self, header: str) -> Iterator[None]:
        self.line(header + " {")
        self.ind += 1
        yield
        self.ind -= 1
        self.line("}")

    def text(self) -> str:
        return "\n".join(self.lines).rstrip() + "\n"


def onoff(b: bool) -> str:
    return "on" if b else "off"


def slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:40] or "site"


# =============================================================================
class Generator:
    def __init__(self, state: State, caps: NginxCaps, paths: Paths) -> None:
        self.st = state
        self.g = state.glob
        self.caps = caps
        self.p = paths
        self.files: Dict[str, str] = {}
        self.warnings: List[str] = []
        self._quic_ports: set = set()
        # порты, где хотя бы один сайт использует http2 (для nginx < 1.25.1 параметр listen общий на порт)
        self._h2_ports = {s.https_port for _, s in state.sites
                          if s.enabled and s.ssl.enabled and s.ssl.http2 and state.glob.http2_global}
        if state.panel.panel_domain:
            self._h2_ports.add(443)

    # ------------------------------------------------------------------
    @property
    def ipv6(self) -> bool:
        return self.g.ipv6 == "on" or (self.g.ipv6 == "auto" and self.caps.ipv6)

    def access_log_line(self) -> str:
        opts = ""
        if self.g.access_log_buffer:
            opts = f" buffer={self.g.access_log_buffer}"
            if self.g.access_log_flush:
                opts += f" flush={self.g.access_log_flush}"
        cond = " if=$nm_loggable" if self.g.log_ignore_status else ""
        return f"access_log {self.p.log_dir}/nm-access.log nm_json{opts}{cond}"

    def stream_enabled_any(self) -> bool:
        return any(s.enabled for _, s in self.st.streams)

    # ------------------------------------------------------------------
    def render(self) -> Dict[str, str]:
        self.files["http.d/00-base.conf"] = self.render_http_base()
        self.files["http.d/10-default.conf"] = self.render_default()
        for sid, site in self.st.sites:
            if not site.enabled:
                continue
            try:
                self.files[f"sites/site-{sid}-{slug(site.name)}.conf"] = self.render_site(sid, site)
            except ConfigError as e:
                e.site_id = sid
                raise
        if self.caps.stream_available:
            self.files["stream.d/00-base.conf"] = self.render_stream_base()
            for sid, s in self.st.streams:
                if s.enabled:
                    self.files[f"streams/stream-{sid}-{slug(s.name)}.conf"] = self.render_stream(sid, s)
        elif self.stream_enabled_any():
            raise ConfigError("Включены TCP/UDP-потоки, но модуль stream в nginx недоступен. "
                              "Установите пакет libnginx-mod-stream (Debian/Ubuntu) или nginx-mod-stream (RHEL).")
        self.render_pages()
        self.files["nginx.conf"] = self.render_main()
        # пустые каталоги не создаются — добавим заглушки для include
        for d in ("sites", "streams", "auth", "pages"):
            if not any(k.startswith(d + "/") for k in self.files):
                self.files[f"{d}/.keep"] = ""
        return self.files

    # ------------------------------------------------------------------
    def render_main(self) -> str:
        g, c = self.g, Conf()
        c.line(MARKER)
        c.line("# Главный файл конфигурации. Сгенерирован Nginx Manager.")
        c.line()
        c.d("user", g.user or self.caps.default_user)
        c.d("worker_processes", g.worker_processes)
        c.d("worker_rlimit_nofile", g.worker_rlimit_nofile)
        c.d("pid", self.caps.pid_path)
        c.d("error_log", f"{self.p.log_dir}/nm-error.log", g.error_log_level)
        c.d("pcre_jit", "on")
        for inc in self.caps.module_includes:
            c.d("include", inc)
        if self.caps.stream_load:
            c.d("load_module", self.caps.stream_load)
        if g.custom_main.strip():
            c.comment("Свои директивы (main)")
            c.raw(g.custom_main)
        c.line()
        with c.block("events"):
            c.d("worker_connections", g.worker_connections)
            c.d("multi_accept", onoff(g.multi_accept))
            if g.custom_events.strip():
                c.raw(g.custom_events)
        c.line()
        with c.block("http"):
            c.d("include", self.caps.mime_types)
            c.d("default_type", "application/octet-stream")
            c.d("include", f"{self.p.include_root}/http.d/*.conf")
            c.d("include", f"{self.p.include_root}/sites/*.conf")
            if g.include_conf_d:
                c.d("include", "/etc/nginx/conf.d/*.conf")
            if g.include_sites_enabled:
                c.d("include", "/etc/nginx/sites-enabled/*")
        if self.caps.stream_available:
            c.line()
            with c.block("stream"):
                c.d("include", f"{self.p.include_root}/stream.d/*.conf")
                c.d("include", f"{self.p.include_root}/streams/*.conf")
        return c.text()

    # ------------------------------------------------------------------
    def render_http_base(self) -> str:
        g, c = self.g, Conf()
        c.line(MARKER)
        c.comment("Общие параметры уровня http")
        c.line()
        c.raw(LOG_FORMAT_HTTP)
        c.line()
        c.d(self.access_log_line())
        c.line()
        with c.block("map $http_upgrade $connection_upgrade"):
            c.d("default", "upgrade")
            c.d("''", "''")
        with c.block("map $http_user_agent $nm_loggable"):
            c.d("default", "1")
            c.d(f"~{HEALTH_UA}", "0")
        with c.block("map $request_uri $nm_static"):
            c.d("default", "0")
            c.d(f"~*\\.({STATIC_EXT})(\\?|$)", "1")
        c.line()
        c.d("sendfile", onoff(g.sendfile))
        c.d("tcp_nopush", onoff(g.tcp_nopush))
        c.d("tcp_nodelay", onoff(g.tcp_nodelay))
        c.d("keepalive_timeout", g.keepalive_timeout or "65s")
        c.d("keepalive_requests", g.keepalive_requests)
        c.d("server_tokens", onoff(g.server_tokens))
        c.d("server_names_hash_bucket_size", g.server_names_hash_bucket_size)
        c.d("server_names_hash_max_size", g.server_names_hash_max_size)
        c.d("types_hash_max_size", g.types_hash_max_size)
        c.d("client_max_body_size", g.client_max_body_size or "1m")
        c.d("client_body_buffer_size", g.client_body_buffer_size or "128k")
        c.d("client_header_buffer_size", g.client_header_buffer_size or "1k")
        c.d("large_client_header_buffers", g.large_client_header_buffers)
        c.d("client_body_timeout", g.client_body_timeout or "60s")
        c.d("client_header_timeout", g.client_header_timeout or "60s")
        c.d("send_timeout", g.send_timeout or "60s")
        c.d("reset_timedout_connection", onoff(g.reset_timedout_connection))
        if g.open_file_cache:
            c.d("open_file_cache", "max=10000 inactive=60s")
            c.d("open_file_cache_valid", "120s")
            c.d("open_file_cache_min_uses", "2")
            c.d("open_file_cache_errors", "on")
        c.line()
        c.comment("Сжатие")
        c.d("gzip", onoff(g.gzip))
        if g.gzip:
            c.d("gzip_comp_level", g.gzip_level)
            c.d("gzip_min_length", g.gzip_min_length)
            c.d("gzip_vary", "on")
            c.d("gzip_proxied", "any" if g.gzip_proxied else "off")
            types = [t for t in g.gzip_types if t != "text/html"]
            if types:
                c.d("gzip_types", " ".join(types))
        c.line()
        c.comment("TLS")
        protocols, ciphers = (g.ssl_protocols, g.ssl_ciphers) if g.ssl_preset == "custom" else TLS_PRESETS[g.ssl_preset]
        c.d("ssl_protocols", protocols)
        if ciphers:
            c.d("ssl_ciphers", ciphers)
        c.d("ssl_prefer_server_ciphers", onoff(g.ssl_prefer_server_ciphers))
        c.d("ssl_session_cache", f"shared:NM_SSL:{g.ssl_session_cache or '50m'}")
        c.d("ssl_session_timeout", g.ssl_session_timeout or "1d")
        c.d("ssl_session_tickets", onoff(g.ssl_session_tickets))
        if g.ssl_dhparam:
            c.d("ssl_dhparam", f"{self.p.data_dir}/certs/dhparam.pem")
        if g.resolver:
            c.d("resolver", " ".join(g.resolver), f"valid={g.resolver_valid or '300s'}",
                "" if self.ipv6 else "ipv6=off")
            c.d("resolver_timeout", "5s")
        c.line()
        c.comment("Параметры проксирования по умолчанию")
        c.d("proxy_connect_timeout", g.proxy_connect_timeout or "5s")
        c.d("proxy_read_timeout", g.proxy_read_timeout or "60s")
        c.d("proxy_send_timeout", g.proxy_send_timeout or "60s")
        c.d("proxy_buffer_size", g.proxy_buffer_size or "16k")
        c.d("proxy_buffers", g.proxy_buffers)
        c.d("proxy_busy_buffers_size", g.proxy_busy_buffers_size or "32k")
        c.d("proxy_headers_hash_max_size", 1024)
        c.d("proxy_headers_hash_bucket_size", 128)
        if g.real_ip_enabled and g.real_ip_from:
            c.line()
            c.comment("Реальный IP клиента")
            for net in g.real_ip_from:
                c.d("set_real_ip_from", net)
            c.d("real_ip_header", g.real_ip_header)
            c.d("real_ip_recursive", onoff(g.real_ip_recursive))
        if g.cache_zones:
            c.line()
            c.comment("Зоны кэша")
            for z in g.cache_zones:
                c.d("proxy_cache_path", f"{self.p.cache_dir}/{z.name}", f"levels={z.levels}",
                    f"keys_zone=nm_{z.name}:{z.keys_zone_size}", f"max_size={z.max_size}",
                    f"inactive={z.inactive}", "use_temp_path=off")
        if g.custom_http.strip():
            c.line()
            c.comment("Свои директивы (http)")
            c.raw(g.custom_http)
        return c.text()

    # ------------------------------------------------------------------
    def listen(self, c: Conf, ip: str, port: int, ssl: bool = False, default: bool = False,
               http2_old: bool = False, quic: bool = False) -> None:
        opts = []
        if ssl:
            opts.append("ssl")
        if ssl and not self.caps.http2_directive and port in self._h2_ports:
            opts.append("http2")
        if self.g.proxy_protocol and not quic:
            opts.append("proxy_protocol")
        if default:
            opts.append("default_server")
        addrs = [f"{ip}:{port}" if ip else str(port)]
        if self.ipv6 and not ip:
            addrs.append(f"[::]:{port}")
        for a in addrs:
            if quic:
                first = (a, port) not in self._quic_ports
                self._quic_ports.add((a, port))
                c.d("listen", a, "quic", "reuseport" if first else "", "default_server" if default else "")
            else:
                c.d("listen", a, *opts)

    def acme_location(self, c: Conf) -> None:
        with c.block("location ^~ /.well-known/acme-challenge/"):
            c.d("root", self.p.acme_webroot)
            c.d("default_type", "text/plain")
            c.d("try_files", "$uri", "=404")
            c.d("access_log", "off")

    def render_default(self) -> str:
        g, c = self.g, Conf()
        c.line(MARKER)
        c.comment("Сервер по умолчанию: запросы с неизвестным Host, проверки Let's Encrypt")
        sites = [s for _, s in self.st.sites if s.enabled]
        http_ports = sorted({s.http_port for s in sites} | {80})
        https_ports = sorted({s.https_port for s in sites if s.ssl.enabled} | {443})
        taken_http = {s.http_port for s in sites if s.default_server and not s.listen_ip}
        taken_https = {s.https_port for s in sites if s.default_server and s.ssl.enabled and not s.listen_ip}
        for port_set, kind in ((taken_http, "http_port"), (taken_https, "https_port")):
            for port in port_set:
                owners = [s.name for s in sites if s.default_server and not s.listen_ip
                          and getattr(s, kind) == port and (kind == "http_port" or s.ssl.enabled)]
                if len(owners) > 1:
                    raise ConfigError(f"Несколько сайтов отмечены «сервер по умолчанию» для порта {port}: "
                                      + ", ".join(owners))
        with c.block("server"):
            for port in http_ports:
                self.listen(c, "", port, default=port not in taken_http)
            c.d("server_name", "_")
            c.d("set", "$nm_site", '"-"')
            self.acme_location(c)
            with c.block("location /"):
                self.default_action(c)
        if self.caps.reject_handshake:
            c.line()
            with c.block("server"):
                for port in https_ports:
                    self.listen(c, "", port, ssl=True, default=port not in taken_https)
                c.d("server_name", "_")
                c.d("set", "$nm_site", '"-"')
                c.d("ssl_reject_handshake", "on")
        c.line()
        c.comment("Внутренний статус для сбора метрик (только localhost)")
        with c.block("server"):
            c.d("listen", f"127.0.0.1:{self.p.stub_status_port}")
            c.d("server_name", "nm_status")
            c.d("access_log", "off")
            with c.block("location = /nm_status"):
                c.d("stub_status")
                c.d("allow", "127.0.0.1")
                c.d("deny", "all")
            with c.block("location /"):
                c.d("return", 404)
        panel = self.st.panel
        if panel.panel_domain:
            c.line()
            c.comment("Веб-панель Nginx Manager")
            cert = self.st.certs.get(panel.panel_certificate_id or -1)
            upstream = f"http://127.0.0.1:{self.p.panel_port}"
            if cert and cert.ok:
                with c.block("server"):
                    self.listen(c, "", 80)
                    c.d("server_name", panel.panel_domain)
                    c.d("set", "$nm_site", '"panel"')
                    self.acme_location(c)
                    with c.block("location /"):
                        c.d("return", 301, "https://$host$request_uri")
            with c.block("server"):
                if cert and cert.ok:
                    self.listen(c, "", 443, ssl=True, http2_old=not self.caps.http2_directive)
                    if self.caps.http2_directive:
                        c.d("http2", "on")
                    c.d("ssl_certificate", cert.cert_path)
                    c.d("ssl_certificate_key", cert.key_path)
                else:
                    self.listen(c, "", 80)
                    self.acme_location(c)
                c.d("server_name", panel.panel_domain)
                c.d("set", "$nm_site", '"panel"')
                c.d("client_max_body_size", "50m")
                for ip in panel.panel_allow:
                    c.d("allow", ip)
                if panel.panel_allow:
                    c.d("deny", "all")
                with c.block("location /"):
                    c.d("proxy_pass", upstream)
                    c.d("proxy_http_version", "1.1")
                    c.d("proxy_set_header", "Host", "$host")
                    c.d("proxy_set_header", "X-Real-IP", "$remote_addr")
                    c.d("proxy_set_header", "X-Forwarded-For", "$proxy_add_x_forwarded_for")
                    c.d("proxy_set_header", "X-Forwarded-Proto", "$scheme")
                    c.d("proxy_set_header", "Upgrade", "$http_upgrade")
                    c.d("proxy_set_header", "Connection", "$connection_upgrade")
                    c.d("proxy_read_timeout", "3600s")
                    c.d("proxy_buffering", "off")
        return c.text()

    def default_action(self, c: Conf) -> None:
        g = self.g
        if g.default_action == "close":
            c.d("return", 444)
        elif g.default_action == "404":
            c.d("return", 404)
        elif g.default_action == "redirect":
            c.d("return", 302, g.default_redirect)
        else:
            c.d("default_type", "text/html")
            c.d("charset", "utf-8")
            body = (f"<!doctype html><meta charset=utf-8><title>{html.escape(g.default_page_title)}</title>"
                    f"<body style='font-family:sans-serif;text-align:center;padding-top:15vh;color:#555'>"
                    f"<h1>{html.escape(g.default_page_title)}</h1></body>")
            c.d("return", 200, quote(body))

    # ------------------------------------------------------------------
    def upstream_block(self, c: Conf, name: str, backends: List[Backend], balancing: str,
                       hash_key: str = "", consistent: bool = False, keepalive: int = 0,
                       keepalive_timeout: str = "", keepalive_requests: int = 0,
                       disabled: Optional[List[str]] = None, stream: bool = False) -> None:
        disabled = set(disabled or [])
        active = [b for b in backends if not b.down and not b.backup]
        # авто-переключение: не выключаем все основные серверы сразу
        if disabled and all(b.key() in disabled for b in active):
            disabled = set()
        with c.block(f"upstream {name}"):
            if balancing == "least_conn":
                c.d("least_conn")
            elif balancing == "ip_hash" and not stream:
                c.d("ip_hash")
            elif balancing == "hash":
                c.d("hash", hash_key or ("$remote_addr" if stream else "$request_uri"),
                    "consistent" if consistent else "")
            elif balancing == "random":
                c.d("random")
            elif balancing == "random_two":
                c.d("random", "two", "least_conn")
            if not stream:
                c.d("zone", f"{name} 256k")
            else:
                c.d("zone", f"{name} 64k")
            for b in backends:
                addr = b.address if b.address.startswith("unix:") else f"{b.address}:{b.port or 80}"
                opts = []
                if b.weight != 1:
                    opts.append(f"weight={b.weight}")
                opts.append(f"max_fails={b.max_fails}")
                opts.append(f"fail_timeout={b.fail_timeout}")
                if b.max_conns:
                    opts.append(f"max_conns={b.max_conns}")
                if b.backup:
                    opts.append("backup")
                if b.down or b.key() in disabled:
                    opts.append("down")
                line = "server " + addr + " " + " ".join(opts) + ";"
                if b.key() in disabled and not b.down:
                    line += "  # выключен автопереключением (health check)"
                elif b.comment:
                    line += "  # " + b.comment.replace("\n", " ")
                c.line(line)
            if keepalive and not stream:
                c.d("keepalive", keepalive)
                if keepalive_timeout:
                    c.d("keepalive_timeout", keepalive_timeout)
                if keepalive_requests:
                    c.d("keepalive_requests", keepalive_requests)

    # ------------------------------------------------------------------
    def render_site(self, sid: int, s: Site) -> str:
        c = Conf()
        c.line(MARKER)
        c.comment(f"Сайт #{sid}: {s.name}")
        c.comment("Домены: " + ", ".join(s.domains))
        c.line()
        up = f"nm_site_{sid}"
        if s.type == "proxy" and s.backends:
            self.upstream_block(c, up, s.backends, s.balancing, s.hash_key, s.hash_consistent, s.keepalive,
                                s.keepalive_timeout, s.keepalive_requests, self.st.overrides.get(f"site:{sid}"))
            c.line()
        for i, loc in enumerate(s.locations):
            if loc.enabled and loc.action == "proxy" and not loc.use_site_backends:
                self.upstream_block(c, f"{up}_l{i}", loc.backends, loc.balancing, keepalive=16)
                c.line()
        if s.security.rate_limit:
            c.d("limit_req_zone", s.security.rate_key, f"zone=nm_rl_{sid}:10m", f"rate={s.security.rate}")
        for i, loc in enumerate(s.locations):
            if loc.enabled and loc.rate_limit == "custom":
                c.d("limit_req_zone", "$binary_remote_addr", f"zone=nm_rl_{sid}_l{i}:10m", f"rate={loc.rate}")
        if s.security.conn_limit:
            c.d("limit_conn_zone", "$binary_remote_addr", f"zone=nm_cl_{sid}:10m")
        if s.maintenance.enabled:
            with c.block(f"geo $nm_maint_{sid}"):
                c.d("default", 1)
                for ip in s.maintenance.allow:
                    c.d(ip, 0)
        if s.performance.static_expires and s.type == "proxy":
            with c.block(f"map $nm_static $nm_exp_{sid}"):
                c.d("default", "off")
                c.d("1", s.performance.static_expires)
        if s.type == "proxy" and s.cache.bypass_cookie_pattern and (
                s.cache.enabled or any(l.enabled and l.cache == "on" for l in s.locations)):
            with c.block(f"map $http_cookie $nm_nocache_{sid}"):
                c.d("default", 0)
                c.d(quote("~*(" + s.cache.bypass_cookie_pattern + ")"), 1)
        if s.custom_http.strip():
            c.comment("Свои директивы уровня http")
            c.raw(s.custom_http)
        c.line()

        cert = None
        if s.ssl.enabled:
            cert = self.st.certs.get(s.ssl.certificate_id or -1)
            if not cert:
                raise ConfigError(f"Сайт «{s.name}»: выбранный сертификат не найден", sid)
            if not cert.ok:
                self.warnings.append(f"Сайт «{s.name}»: сертификат не выпущен — HTTPS отключён до выпуска")
                cert = None

        if cert and s.ssl.force_https:
            # HTTP-блок только для перенаправления и ACME
            with c.block("server"):
                self.listen(c, s.listen_ip, s.http_port, default=s.default_server)
                c.d("server_name", " ".join(s.domains))
                c.d("set", "$nm_site", f'"{sid}"')
                if not s.performance.access_log:
                    c.d("access_log", "off")
                self.acme_location(c)
                with c.block("location /"):
                    port = "" if s.https_port == 443 else f":{s.https_port}"
                    c.d("return", s.ssl.redirect_code, f"https://$host{port}$request_uri")
            c.line()
            self.server_block(c, sid, s, cert, http=False, https=True)
        elif cert:
            self.server_block(c, sid, s, cert, http=True, https=True)
        else:
            self.server_block(c, sid, s, None, http=True, https=False)
        return c.text()

    # ------------------------------------------------------------------
    def server_block(self, c: Conf, sid: int, s: Site, cert, http: bool, https: bool) -> None:
        sec = s.security
        with c.block("server"):
            if http:
                self.listen(c, s.listen_ip, s.http_port, default=s.default_server)
            if https:
                use_h2 = s.ssl.http2 and self.g.http2_global
                self.listen(c, s.listen_ip, s.https_port, ssl=True, default=s.default_server,
                            http2_old=use_h2 and not self.caps.http2_directive)
                if s.ssl.http3 and self.caps.http3:
                    self.listen(c, s.listen_ip, s.https_port, quic=True, default=s.default_server)
                elif s.ssl.http3:
                    self.warnings.append(f"Сайт «{s.name}»: HTTP/3 не поддерживается установленным nginx")
                if use_h2 and self.caps.http2_directive:
                    c.d("http2", "on")
                if s.ssl.http3 and self.caps.http3:
                    c.d("http3", "on")
            c.d("server_name", " ".join(s.domains))
            c.d("set", "$nm_site", f'"{sid}"')
            c.line()
            if https:
                c.d("ssl_certificate", cert.cert_path)
                c.d("ssl_certificate_key", cert.key_path)
                if s.ssl.protocols:
                    c.d("ssl_protocols", s.ssl.protocols)
                if s.ssl.ocsp_stapling:
                    c.d("ssl_stapling", "on")
                    c.d("ssl_stapling_verify", "on")
                c.line()
            # журнал
            if not s.performance.access_log:
                c.d("access_log", "off")
            elif not s.performance.log_static:
                c.d("access_log", f"{self.p.log_dir}/nm-access.log", "nm_json",
                    "if=$nm_log_dynamic_" + str(sid))
                # дополнительная переменная: логировать только нестатические запросы
            # производительность
            p = s.performance
            if p.client_max_body_size:
                c.d("client_max_body_size", p.client_max_body_size)
            if p.limit_rate:
                c.d("limit_rate", p.limit_rate)
            if p.limit_rate_after:
                c.d("limit_rate_after", p.limit_rate_after)
            if p.keepalive_timeout:
                c.d("keepalive_timeout", p.keepalive_timeout)
            if p.gzip != "inherit":
                c.d("gzip", p.gzip)
            # безопасность
            if sec.conn_limit:
                c.d("limit_conn", f"nm_cl_{sid}", sec.conn_limit)
                c.d("limit_conn_status", 429)
            if sec.rate_limit or any(l.enabled and l.rate_limit == "custom" for l in s.locations):
                c.d("limit_req_status", sec.limit_status)
            self.access_rules(c, sec.access_mode == "allowlist" and sec.allow or [], sec.deny)
            if sec.basic_auth and sec.basic_auth_users:
                c.d("auth_basic", quote(sec.basic_auth_realm or "Restricted"))
                c.d("auth_basic_user_file", f"{self.p.live_root}/auth/site-{sid}.htpasswd")
                if sec.satisfy_any and sec.access_mode == "allowlist" and sec.allow:
                    c.d("satisfy", "any")
                self.files[f"auth/site-{sid}.htpasswd"] = "".join(
                    f"{u.username}:{u.password_hash}\n" for u in sec.basic_auth_users if u.password_hash)
            if sec.allowed_methods:
                methods = sorted(set(sec.allowed_methods) | ({"HEAD"} if "GET" in sec.allowed_methods else set()))
                with c.block(f"if ($request_method !~ ^({'|'.join(methods)})$)"):
                    c.d("return", 405)
            if sec.block_bad_bots and sec.bad_bots:
                pattern = "|".join(re.escape(b).replace("\\ ", " ") for b in sec.bad_bots)
                with c.block(f'if ($http_user_agent ~* {quote("(" + pattern + ")")})'):
                    c.d("return", 403)
            if sec.block_exploits:
                for pat in EXPLOIT_PATTERNS:
                    with c.block(f"if ($query_string ~* {quote(pat)})"):
                        c.d("return", 403)
            if s.canonical_redirect and len(s.domains) > 1:
                main = s.main_domain
                with c.block(f'if ($host != "{main}")'):
                    port = ""
                    if https and s.https_port != 443:
                        port = f":{s.https_port}"
                    elif not https and s.http_port != 80:
                        port = f":{s.http_port}"
                    c.d("return", 301, f"$scheme://{main}{port}$request_uri")
            # заголовки ответа
            for h in self.response_headers(s, https):
                c.d("add_header", h.name, quote(h.value), "always" if h.always else "")
            if s.type == "proxy":
                for h in s.proxy.hide_headers:
                    c.d("proxy_hide_header", h)
            # обслуживание
            if s.maintenance.enabled:
                c.line()
                c.comment("Режим обслуживания")
                with c.block(f"if ($nm_maint_{sid})"):
                    c.d("return", 503)
            # страницы ошибок
            codes = list(s.error_pages.codes) if s.error_pages.enabled else []
            if s.maintenance.enabled and 503 not in codes:
                codes.append(503)
            if codes:
                c.line()
                c.comment("Страницы ошибок (именованные локации не повторяют проверки уровня server)")
                for code in sorted(codes):
                    c.d("error_page", code, f"@nm_err_{code}")
                for code in sorted(codes):
                    page = f"maintenance-{sid}.html" if (code == 503 and s.maintenance.enabled) \
                        else f"error-{code}.html"
                    with c.block(f"location @nm_err_{code}"):
                        c.d("root", f"{self.p.live_root}/pages")
                        c.d("allow", "all")
                        c.d("auth_basic", "off")
                        c.d("rewrite", "^", f"/{page}", "break")
                        if code == 503 and s.maintenance.enabled:
                            c.d("add_header", "Retry-After", s.maintenance.retry_after, "always")
                        c.d("add_header", "Cache-Control", '"no-store"', "always")
            c.line()
            if http:
                self.acme_location(c)
            if sec.block_hidden_files:
                with c.block("location ~ /\\.(?!well-known)"):
                    c.d("return", 404)
            # локации пользователя
            has_root = False
            for i, loc in enumerate(s.locations):
                if not loc.enabled:
                    continue
                if loc.path == "/" and loc.match in ("prefix", "prefix_priority"):
                    has_root = True
                self.location(c, sid, s, i, loc, https)
            if not has_root:
                self.main_location(c, sid, s, https)
            if s.custom_server.strip():
                c.line()
                c.comment("Свои директивы")
                c.raw(s.custom_server)
        if not s.performance.log_static and s.performance.access_log:
            # переменная для условного журнала: 0 для статики
            c.line()
            with c.block(f"map $nm_static $nm_log_dynamic_{sid}"):
                c.d("default", 1)
                c.d("1", 0)

    def access_rules(self, c: Conf, allow: List[str], deny: List[str]) -> None:
        for ip in deny:
            c.d("deny", ip)
        for ip in allow:
            c.d("allow", ip)
        if allow:
            c.d("deny", "all")

    def response_headers(self, s: Site, https: bool) -> List:
        from ..models import Header
        out = []
        sec = s.security
        if sec.security_headers:
            out.append(Header(name="X-Content-Type-Options", value="nosniff"))
            if sec.x_frame_options != "off":
                out.append(Header(name="X-Frame-Options", value=sec.x_frame_options))
            if sec.referrer_policy != "off":
                out.append(Header(name="Referrer-Policy", value=sec.referrer_policy))
            if sec.permissions_policy:
                out.append(Header(name="Permissions-Policy", value=sec.permissions_policy))
            if sec.csp:
                out.append(Header(name="Content-Security-Policy-Report-Only" if sec.csp_report_only
                                  else "Content-Security-Policy", value=sec.csp))
        if https and s.ssl.hsts:
            v = f"max-age={s.ssl.hsts_max_age}"
            if s.ssl.hsts_subdomains:
                v += "; includeSubDomains"
            if s.ssl.hsts_preload:
                v += "; preload"
            out.append(Header(name="Strict-Transport-Security", value=v))
        if https and s.ssl.http3 and self.caps.http3:
            out.append(Header(name="Alt-Svc", value=f'h3=":{s.https_port}"; ma=86400'))
        if s.type == "proxy" and s.cache.enabled and s.cache.status_header:
            out.append(Header(name="X-Cache-Status", value="$upstream_cache_status"))
        out.extend(s.headers)
        return out

    # ------------------------------------------------------------------
    def proxy_directives(self, c: Conf, sid: int, s: Site, upstream: str, scheme: str,
                         proxy_path: str = "", websocket: Optional[bool] = None, read_timeout: str = "",
                         buffering: Optional[bool] = None, cache_mode: str = "inherit", cache_valid: str = "",
                         extra_headers: Optional[list] = None, backends: Optional[List[Backend]] = None) -> None:
        px = s.proxy
        c.d("proxy_pass", f"{scheme}://{upstream}{proxy_path}")
        c.d("proxy_http_version", px.http_version)
        ws = px.websocket if websocket is None else websocket
        backends = backends or s.backends
        if px.host_header == "client":
            host = "$host"
        elif px.host_header == "custom" and px.custom_host:
            host = px.custom_host
        else:
            b = backends[0] if backends else None
            host = b.address if b else "$host"
            if b and b.port and b.port not in (80, 443) and not b.address.startswith("unix:"):
                host += f":{b.port}"
        c.d("proxy_set_header", "Host", host)
        if px.pass_real_ip:
            c.d("proxy_set_header", "X-Real-IP", "$remote_addr")
            c.d("proxy_set_header", "X-Forwarded-For", "$proxy_add_x_forwarded_for")
            c.d("proxy_set_header", "X-Forwarded-Proto", "$scheme")
            c.d("proxy_set_header", "X-Forwarded-Host", "$host")
            c.d("proxy_set_header", "X-Forwarded-Port", "$server_port")
        if px.pass_request_id:
            c.d("proxy_set_header", "X-Request-ID", "$request_id")
        if ws:
            c.d("proxy_set_header", "Upgrade", "$http_upgrade")
            c.d("proxy_set_header", "Connection", "$connection_upgrade")
        else:
            c.d("proxy_set_header", "Connection", '""')
        for h in s.proxy_headers + (extra_headers or []):
            c.d("proxy_set_header", h.name, quote(h.value))
        c.d("proxy_connect_timeout", px.connect_timeout or self.g.proxy_connect_timeout)
        c.d("proxy_read_timeout", read_timeout or px.read_timeout or self.g.proxy_read_timeout)
        c.d("proxy_send_timeout", px.send_timeout or self.g.proxy_send_timeout)
        buf = px.buffering if buffering is None else buffering
        if not buf:
            c.d("proxy_buffering", "off")
        if not px.request_buffering:
            c.d("proxy_request_buffering", "off")
        if px.buffer_size:
            c.d("proxy_buffer_size", px.buffer_size)
        if px.buffers:
            c.d("proxy_buffers", px.buffers)
        if px.busy_buffers_size:
            c.d("proxy_busy_buffers_size", px.busy_buffers_size)
        nu = [x for x in px.next_upstream if x != "off"] or ["off"]
        if "off" in px.next_upstream:
            nu = ["off"]
        c.d("proxy_next_upstream", " ".join(nu))
        if px.next_upstream_tries:
            c.d("proxy_next_upstream_tries", px.next_upstream_tries)
        if px.next_upstream_timeout:
            c.d("proxy_next_upstream_timeout", px.next_upstream_timeout)
        if px.intercept_errors:
            c.d("proxy_intercept_errors", "on")
        if px.redirect == "off":
            c.d("proxy_redirect", "off")
        if scheme == "https":
            c.d("proxy_ssl_server_name", onoff(px.ssl_server_name))
            if px.ssl_server_name:
                c.d("proxy_ssl_name", host if not host.startswith("[") else "$host")
            c.d("proxy_ssl_verify", onoff(px.ssl_verify))
            if px.ssl_verify:
                c.d("proxy_ssl_trusted_certificate", self.caps.ca_bundle)
            c.d("proxy_ssl_session_reuse", "on")
        # кэш
        cache = s.cache
        use_cache = (cache.enabled and cache_mode != "off") or cache_mode == "on"
        if use_cache:
            zone = cache.zone if any(z.name == cache.zone for z in self.g.cache_zones) else None
            if not zone and self.g.cache_zones:
                zone = self.g.cache_zones[0].name
            if not zone:
                raise ConfigError(f"Сайт «{s.name}»: для кэша нужна хотя бы одна зона в глобальных настройках", sid)
            c.d("proxy_cache", f"nm_{zone}")
            c.d("proxy_cache_key", quote(cache.key))
            valid = [cache_valid] if cache_valid else cache.valid
            for v in valid:
                c.d("proxy_cache_valid", v)
            bypass = [f"$cookie_{x}" for x in cache.bypass_cookies]
            if cache.bypass_cookie_pattern:
                bypass.append(f"$nm_nocache_{sid}")
            if cache.bypass_authorization:
                bypass.append("$http_authorization")
            if cache.bypass_arg:
                bypass.append(f"$arg_{cache.bypass_arg}")
            if bypass:
                c.d("proxy_cache_bypass", " ".join(bypass))
                c.d("proxy_no_cache", " ".join(bypass))
            if cache.methods:
                c.d("proxy_cache_methods", " ".join(cache.methods))
            if cache.min_uses > 1:
                c.d("proxy_cache_min_uses", cache.min_uses)
            if cache.use_stale:
                c.d("proxy_cache_use_stale", " ".join(cache.use_stale))
            c.d("proxy_cache_background_update", onoff(cache.background_update))
            c.d("proxy_cache_lock", onoff(cache.lock))
            if cache.ignore_headers:
                c.d("proxy_ignore_headers", " ".join(cache.ignore_headers))

    def site_rate_limit(self, c: Conf, sid: int, s: Site) -> None:
        sec = s.security
        if sec.rate_limit:
            c.d("limit_req", f"zone=nm_rl_{sid}", f"burst={sec.burst}", "nodelay" if sec.nodelay else "")

    def main_location(self, c: Conf, sid: int, s: Site, https: bool) -> None:
        c.line()
        with c.block("location /"):
            self.site_rate_limit(c, sid, s)
            if s.performance.static_expires and s.type == "proxy":
                c.d("expires", f"$nm_exp_{sid}")
            if s.type == "proxy":
                self.proxy_directives(c, sid, s, f"nm_site_{sid}", s.backend_scheme)
            elif s.type == "redirect":
                r = s.redirect
                target = r.url.rstrip("/") + "$request_uri" if r.preserve_path else r.url
                c.d("return", r.code, target)
            elif s.type == "static":
                st = s.static
                c.d("root", st.root)
                c.d("index", st.index)
                c.d("try_files", "$uri", "$uri/", "/index.html" if st.spa else "=404")
                if st.autoindex:
                    c.d("autoindex", "on")
                if st.expires:
                    c.d("expires", st.expires)
            if s.custom_location.strip():
                c.comment("Свои директивы")
                c.raw(s.custom_location)

    def location(self, c: Conf, sid: int, s: Site, i: int, loc: Location, https: bool) -> None:
        mod = {"prefix": "", "exact": "= ", "prefix_priority": "^~ ", "regex": "~ ", "regex_ci": "~* "}[loc.match]
        path = quote(loc.path) if loc.match in ("regex", "regex_ci") else quote_if_needed(loc.path)
        c.line()
        with c.block(f"location {mod}{path}"):
            if loc.allow:
                for ip in loc.allow:
                    c.d("allow", ip)
                c.d("deny", "all")
            if loc.rate_limit == "custom":
                c.d("limit_req", f"zone=nm_rl_{sid}_l{i}", f"burst={loc.burst}", "nodelay")
            elif loc.rate_limit == "inherit":
                self.site_rate_limit(c, sid, s)
            if loc.basic_auth == "off":
                c.d("auth_basic", "off")
            elif loc.basic_auth == "on" and s.security.basic_auth_users:
                c.d("auth_basic", quote(s.security.basic_auth_realm or "Restricted"))
                c.d("auth_basic_user_file", f"{self.p.live_root}/auth/site-{sid}.htpasswd")
                self.files[f"auth/site-{sid}.htpasswd"] = "".join(
                    f"{u.username}:{u.password_hash}\n" for u in s.security.basic_auth_users if u.password_hash)
            if loc.client_max_body_size:
                c.d("client_max_body_size", loc.client_max_body_size)
            if loc.headers:
                for h in self.response_headers(s, https) + loc.headers:
                    c.d("add_header", h.name, quote(h.value), "always" if h.always else "")
            if loc.action == "proxy":
                if loc.use_site_backends:
                    if s.type != "proxy" or not s.backends:
                        raise ConfigError(f"Локация {loc.path}: у сайта нет бэкендов — выберите свои", sid)
                    up, scheme, bks = f"nm_site_{sid}", s.backend_scheme, s.backends
                else:
                    up, scheme, bks = f"nm_site_{sid}_l{i}", loc.backend_scheme, loc.backends
                self.proxy_directives(c, sid, s, up, scheme, loc.proxy_path, loc.websocket, loc.read_timeout,
                                      loc.buffering, loc.cache, loc.cache_valid, loc.proxy_headers, bks)
            elif loc.action == "redirect":
                c.d("return", loc.redirect_code, loc.redirect_url)
            elif loc.action == "return":
                if loc.return_type:
                    c.d("default_type", loc.return_type)
                c.d("return", loc.return_code, quote_multiline(loc.return_body) if loc.return_body else "")
            elif loc.action == "static":
                root = loc.static_root.rstrip("/")
                if loc.match in ("prefix", "prefix_priority") and loc.path.endswith("/"):
                    c.d("alias", root + "/")
                else:
                    c.d("root", root)
                c.d("try_files", "$uri", "=404")
                if loc.static_expires:
                    c.d("expires", loc.static_expires)
            elif loc.action == "deny":
                c.d("return", 403)
            if loc.custom.strip():
                c.comment("Свои директивы")
                c.raw(loc.custom)

    # ------------------------------------------------------------------
    def render_stream_base(self) -> str:
        c = Conf()
        c.line(MARKER)
        c.raw(LOG_FORMAT_STREAM)
        if self.g.custom_stream.strip():
            c.comment("Свои директивы (stream)")
            c.raw(self.g.custom_stream)
        return c.text()

    def render_stream(self, sid: int, s: Stream) -> str:
        c = Conf()
        c.line(MARKER)
        c.comment(f"Поток #{sid}: {s.name} ({s.protocol.upper()} :{s.listen_port})")
        up = f"nm_stream_{sid}"
        self.upstream_block(c, up, s.backends, s.balancing, s.hash_key, True,
                            disabled=self.st.overrides.get(f"stream:{sid}"), stream=True)
        if s.conn_limit:
            c.d("limit_conn_zone", "$binary_remote_addr", f"zone=nm_scl_{sid}:10m")
        c.line()
        with c.block("server"):
            protos = ["tcp", "udp"] if s.protocol == "both" else [s.protocol]
            for proto in protos:
                addrs = [f"{s.listen_ip}:{s.listen_port}" if s.listen_ip else str(s.listen_port)]
                if s.ipv6 and self.ipv6 and not s.listen_ip:
                    addrs.append(f"[::]:{s.listen_port}")
                for a in addrs:
                    c.d("listen", a, "udp" if proto == "udp" else "")
            c.d("proxy_pass", up)
            c.d("proxy_connect_timeout", s.connect_timeout)
            c.d("proxy_timeout", s.timeout)
            if s.proxy_protocol:
                c.d("proxy_protocol", "on")
            if s.udp_responses and s.protocol in ("udp", "both"):
                c.d("proxy_responses", s.udp_responses)
            if s.conn_limit:
                c.d("limit_conn", f"nm_scl_{sid}", s.conn_limit)
            self.access_rules(c, s.allow, s.deny)
            c.d("access_log", f"{self.p.log_dir}/nm-stream.log", "nm_stream")
        return c.text()

    # ------------------------------------------------------------------
    def render_pages(self) -> None:
        for code, (title, text) in ERROR_PAGES.items():
            self.files[f"pages/error-{code}.html"] = page_html(code, title, text)
        for sid, s in self.st.sites:
            if s.enabled and s.maintenance.enabled:
                self.files[f"pages/maintenance-{sid}.html"] = page_html(
                    503, s.maintenance.title, s.maintenance.message, maintenance=True)


LOG_FORMAT_HTTP = r"""log_format nm_json escape=json '{'
    '"t":"$msec","site":"$nm_site","host":"$host","ip":"$remote_addr",'
    '"m":"$request_method","u":"$request_uri","p":"$server_protocol","s":"$status",'
    '"b":"$body_bytes_sent","bs":"$bytes_sent","rl":"$request_length","rt":"$request_time",'
    '"ua":"$upstream_addr","us":"$upstream_status","urt":"$upstream_response_time",'
    '"uct":"$upstream_connect_time","uht":"$upstream_header_time",'
    '"ref":"$http_referer","agent":"$http_user_agent","cache":"$upstream_cache_status",'
    '"sch":"$scheme","tls":"$ssl_protocol","rid":"$request_id","cr":"$connection_requests"'
    '}';"""

LOG_FORMAT_STREAM = r"""log_format nm_stream escape=json '{'
    '"t":"$msec","ip":"$remote_addr","proto":"$protocol","port":"$server_port","s":"$status",'
    '"bs":"$bytes_sent","br":"$bytes_received","dur":"$session_time","ua":"$upstream_addr",'
    '"uct":"$upstream_connect_time"'
    '}';"""

EXPLOIT_PATTERNS = [
    r"(union(\s|%20|\+|/\*.*\*/)+(all(\s|%20|\+)+)?select)",
    r"(<|%3C)\s*script",
    r"(\.\./|\.\.%2f|%2e%2e/|%2e%2e%2f)",
    r"(etc/passwd|proc/self/environ|boot\.ini)",
    r"(base64_decode|eval\(|GLOBALS(=|\[|%[0-9A-Z]{0,2}))",
    r"(sleep\(\s*\d+\s*\)|benchmark\(|waitfor\s+delay)",
]

ERROR_PAGES = {
    400: ("Некорректный запрос", "Сервер не смог обработать запрос."),
    401: ("Требуется авторизация", "Для доступа к странице необходимо войти."),
    403: ("Доступ запрещён", "У вас нет прав для просмотра этой страницы."),
    404: ("Страница не найдена", "Запрошенная страница не существует или была перемещена."),
    405: ("Метод не поддерживается", "Этот метод запроса не разрешён."),
    429: ("Слишком много запросов", "Пожалуйста, подождите немного и повторите попытку."),
    500: ("Внутренняя ошибка сервера", "Что-то пошло не так. Мы уже разбираемся."),
    502: ("Сервис временно недоступен", "Сервер приложения не отвечает. Попробуйте обновить страницу через минуту."),
    503: ("Сервис временно недоступен", "Сервер перегружен или на обслуживании. Попробуйте позже."),
    504: ("Превышено время ожидания", "Сервер приложения не успел ответить. Попробуйте обновить страницу."),
}


def page_html(code: int, title: str, text: str, maintenance: bool = False) -> str:
    t, m = html.escape(title), html.escape(text).replace("\n", "<br>")
    icon = "🛠" if maintenance else str(code)
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{t}</title><meta name="robots" content="noindex">
<style>
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f4f6fa;color:#1f2937}}
.box{{text-align:center;padding:48px 32px;max-width:560px}}
.code{{font-size:72px;font-weight:700;color:#3b6fd8;letter-spacing:-2px;margin-bottom:8px}}
h1{{font-size:24px;margin:0 0 12px}} p{{color:#6b7280;line-height:1.6;margin:0}}
@media (prefers-color-scheme:dark){{body{{background:#111827;color:#e5e7eb}}p{{color:#9ca3af}}}}
</style></head><body><div class="box"><div class="code">{icon}</div><h1>{t}</h1><p>{m}</p></div></body></html>
"""
