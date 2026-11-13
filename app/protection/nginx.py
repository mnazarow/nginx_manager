"""Конфигурация nginx для защиты от атак.

Уровень http (файл http.d/05-protection.conf):
  * карты фильтра запросов: по одной на пару «категория × поле» (map $request_uri $nm_w_sqli_uri …) — значение
    «категория/правило» при совпадении; карты вычисляются лениво и только там, где их спрашивают;
  * geo доверенных адресов, geo списков угроз (файл обновляет панель без версии конфигурации), карта режима
    «Под атакой» по сайтам (тоже отдельный файл), проверка пропуска браузера (secure_link по cookie);
  * карты исключений путей, путей входа, хотлинкинга и своих правил.
Уровень server каждого сайта: цепочка `if/set`, которая вычисляет действие ($nm_wchk) и при необходимости
отвечает 403/444 или отправляет на проверку браузера. Порядок: доверенные → «пропустить» из своих правил →
категории «запись» → категории «блокировка» → списки угроз → свои правила → отключённые правила сайта.
В журнал доступа пишутся поля wf (сработавшее правило), wa (итоговое действие) и ch (проверка браузера).
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..models import CustomRule, ProtectionSettings, Site
from . import rules as W

CHALLENGE_PREFIX = "/.nm-challenge"
FIELD_VARS = {"uri": "$request_uri", "path": "$uri", "args": "$args", "ua": "$http_user_agent",
              "referer": "$http_referer", "cookie": "$http_cookie", "host": "$host", "method": "$request_method"}


def q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def path_key(p: str) -> str:
    """Путь из настроек → ключ карты: «/api/» → префикс, «~выражение» → регулярное выражение как есть."""
    if p.startswith("~"):
        return W.nginx_quote("~" + p[1:])
    return W.nginx_quote("~^" + re.escape(p))


def site_modes(prot: ProtectionSettings, sp) -> Dict[str, str]:
    """Итоговый режим каждой категории для сайта."""
    out = {}
    for cat in W.CATEGORIES:
        m = prot.mode(cat)
        if not sp.enabled or sp.waf == "off":
            m = "off"
        elif sp.waf == "detect" and m == "block":
            m = "detect"
        elif sp.waf == "custom":
            o = sp.waf_overrides.get(cat, "inherit")
            if o != "inherit":
                m = o if prot.waf_enabled else "off"
        out[cat] = m
    return out


def challenge_ready(caps) -> bool:
    return "http_secure_link" in caps.modules


class ProtectionConf:
    def __init__(self, state, paths, caps) -> None:
        self.st = state
        self.prot: ProtectionSettings = state.protection
        self.p = paths
        self.caps = caps
        self.sites: List[Tuple[int, Site]] = [(i, s) for i, s in state.sites if s.enabled]
        self.maps = W.maps(self.prot.waf_level, self.prot.waf_disabled_rules)
        self.warnings: List[str] = []

    # ------------------------------------------------------------------ http
    def used_cats(self) -> set:
        used = set()
        for sid, s in self.sites:
            for cat, m in site_modes(self.prot, s.protection).items():
                if m != "off":
                    used.add(cat)
        return used

    def custom_rules(self, sid: Optional[int] = None) -> List[CustomRule]:
        return [r for r in self.prot.custom_rules if r.enabled and (sid is None or not r.sites or sid in r.sites)]

    def feeds_on(self) -> bool:
        return bool(self.p.threats_file) and any(f.enabled for f in self.prot.threat_feeds)

    def http_conf(self) -> str:
        out: List[str] = ["# Nginx Manager: защита от атак (раздел «Защита»). Файл генерируется панелью.", ""]
        a = out.append
        a("uninitialized_variable_warn off;")
        used = self.used_cats()
        a("")
        a("# --- фильтр запросов: карта на каждую пару «категория × поле»; значение — «категория/правило»")
        for (cat, target), rules in sorted(self.maps.items()):
            if cat not in used:
                continue
            var = W.TARGETS[target][0]
            src = var if "|" not in var else q(var)
            a(f"map {src} {W.map_name(cat, target)} {{")
            a('    default "";')
            for r in rules:
                if r.flags == "=":
                    key = W.nginx_quote(r.pattern)
                else:
                    key = W.nginx_quote(r.flags + r.pattern)
                a(f"    {key} {q(cat + '/' + r.id)};")
            a("}")
        a("")
        a("# --- доверенные адреса (без проверок защиты на всех сайтах)")
        a("geo $nm_trusted {")
        a("    default 0;")
        for ip in self.prot.bypass_ips:
            a(f"    {ip} 1;")
        a("}")
        for sid, s in self.sites:
            if s.protection.enabled and s.protection.bypass_ips:
                a(f"geo $nm_trusted_{sid} {{")
                a("    default 0;")
                for ip in s.protection.bypass_ips:
                    a(f"    {ip} 1;")
                a("}")
        a("")
        a("# --- списки угроз: «список:действие»; файл обновляется панелью по расписанию")
        a("geo $nm_threat {")
        a('    default "";')
        if self.feeds_on():
            a(f"    include {self.p.threats_file};")
        a("}")
        a("map $nm_threat $nm_threat_act {")
        a('    default "";')
        a('    "~:block$" "block";')
        a('    "~:challenge$" "challenge";')
        a('    "~:detect$" "detect";')
        a("}")
        a("")
        a("# --- соответствие SNI и Host (421 при несовпадении)")
        a('map "$ssl_server_name|$host" $nm_sni_bad {')
        a("    default 1;")
        a('    "~^\\|" 0;')
        a('    "~*^([^|]+)\\|\\1$" 0;')
        a("}")
        if challenge_ready(self.caps) and self.p.challenge_secret:
            a("")
            a("# --- проверка браузера: пропуск — cookie nm_pass (md5 от срока, IP и секрета), выдаёт панель")
            a("secure_link $cookie_nm_pass,$cookie_nm_pass_e;")
            ip = "$remote_addr" if self.prot.challenge_bind_ip else ""
            a(f"secure_link_md5 {q('$cookie_nm_pass_e' + ip + ' ' + self.p.challenge_secret)};")
            a("limit_req_zone $binary_remote_addr zone=nm_chal:10m rate=5r/s;")
            a("# режим «Под атакой»: c — проверять (файл меняется кнопкой и автоматикой без версии конфигурации)")
            a("map $nm_site $nm_chal_auto {")
            if self.p.attack_file:
                a(f"    include {self.p.attack_file};")
            else:
                a('    default "";')
            a("}")
        elif any(s.protection.enabled and s.protection.challenge != "off" for _, s in self.sites):
            if not challenge_ready(self.caps):
                self.warnings.append("Проверка браузера недоступна: в nginx нет модуля secure_link "
                                     "(--with-http_secure_link_module)")
        a("")
        a("# --- свои правила")
        for r in self.custom_rules():
            self.custom_rule_map(out, r)
        a("")
        a("# --- исключения путей, пути входа, хотлинкинг (по сайтам)")
        for sid, s in self.sites:
            sp = s.protection
            if not sp.enabled:
                continue
            if sp.waf_exclude_paths:
                a(f"map $uri $nm_wx_{sid} {{")
                a('    default "";')
                for pth in sp.waf_exclude_paths:
                    a(f"    {path_key(pth)} \"x\";")
                a("}")
            if sp.challenge != "off":
                a(f"map $uri $nm_cx_{sid} {{")
                a('    default "";')
                for pth in [CHALLENGE_PREFIX + "/", "/.well-known/acme-challenge/"] + \
                        list(self.prot.challenge_exempt_paths) + list(sp.challenge_exclude_paths):
                    a(f"    {path_key(pth)} \"x\";")
                a("}")
            if sp.login_protection and sp.login_paths:
                a(f"map $uri $nm_login_{sid} {{")
                a('    default "";')
                for pth in sp.login_paths:
                    a(f"    {path_key(pth)} $binary_remote_addr;")
                a("}")
                a(f"limit_req_zone $nm_login_{sid} zone=nm_login_{sid}:10m rate={sp.login_rate};")
            if sp.hotlink and sp.hotlink_ext:
                a(f"map $uri $nm_hl_{sid} {{")
                a('    default "";')
                ext_re = "~*\\.(?:" + "|".join(sp.hotlink_ext) + ")$"
                a(f"    {W.nginx_quote(ext_re)} \"1\";")
                a("}")
        return "\n".join(out) + "\n"

    def custom_rule_map(self, out: List[str], r: CustomRule) -> None:
        a = out.append
        neg = r.op in ("not_contains", "not_regex", "not_in")
        hit, miss = ('""', '"1"') if neg else ('"1"', '""')
        if r.field == "ip":
            a(f"geo $nm_cr_{r.id} {{")
            a(f"    default {miss};")
            for net in r.value.split():
                a(f"    {net} {hit};")
            a("}")
            return
        var = f"$http_{r.header.lower().replace('-', '_')}" if r.field == "header" else FIELD_VARS[r.field]
        v = r.value
        if r.op in ("contains", "not_contains"):
            key = W.nginx_quote("~*" + re.escape(v))
        elif r.op == "prefix":
            key = W.nginx_quote("~*^" + re.escape(v))
        elif r.op == "equals":
            key = q(v)
        else:
            key = W.nginx_quote("~*" + v)
        a(f"map {var} $nm_cr_{r.id} {{")
        a(f"    default {miss};")
        a(f"    {key} {hit};")
        a("}")

    # ------------------------------------------------------------------ server
    def server(self, c, sid: int, s: Site, https: bool) -> None:
        """Проверки уровня server: вызывается сразу после блокировок IP и доступа по странам."""
        sp = s.protection
        c.line()
        c.comment("Защита от атак (раздел «Защита»): итог — в $nm_wchk, поля wf/wa/ch журнала доступа")
        c.d("set", "$nm_waf", '""')
        c.d("set", "$nm_wact", '""')
        c.d("set", "$nm_chk", '""')
        if not sp.enabled:
            c.d("set", "$nm_wchk", '""')
            return
        c.d("set", "$nm_pa", '""')
        with c.block("if ($nm_trusted)"):
            c.d("set", "$nm_pa", '"a"')
        if sp.bypass_ips:
            with c.block(f"if ($nm_trusted_{sid})"):
                c.d("set", "$nm_pa", '"a"')
        rules = self.custom_rules(sid)
        for r in rules:
            if r.action == "allow":
                with c.block(f"if ($nm_cr_{r.id})"):
                    c.d("set", "$nm_pa", '"a"')
                    c.d("set", "$nm_waf", q(f"custom/{r.id}"))
                    c.d("set", "$nm_wact", '"allow"')
        modes = site_modes(self.prot, sp)

        # Каждое следующее совпадение перезаписывает предыдущее, поэтому проверки идут от слабого действия к
        # строгому: запись → проверка браузера → блокировка. Свои правила одного уровня — снизу вверх по списку,
        # чтобы при нескольких совпадениях действовало правило, стоящее в списке выше.
        def custom(actions):
            for r in reversed(rules):
                if r.action in actions:
                    with c.block(f"if ($nm_cr_{r.id})"):
                        c.d("set", "$nm_waf", q(f"custom/{r.id}"))
                        c.d("set", "$nm_wact", q(r.action))

        if sp.threats and self.feeds_on():
            with c.block('if ($nm_threat_act = "detect")'):
                c.d("set", "$nm_waf", '"threat/$nm_threat"')
                c.d("set", "$nm_wact", '"detect"')
        for want in ("detect", "block"):
            if want == "block":
                custom(("log",))
                custom(("challenge",))
            for (cat, target) in sorted(self.maps):
                if modes.get(cat) != want:
                    continue
                var = W.map_name(cat, target)
                with c.block(f"if ({var})"):
                    c.d("set", "$nm_waf", var)
                    c.d("set", "$nm_wact", f'"{want}"')
        if sp.hotlink and sp.hotlink_ext:
            c.d("valid_referers", "none", "blocked", "server_names", *sp.hotlink_allow)
            c.d("set", "$nm_hl", f'"$nm_hl_{sid}$invalid_referer"')
            with c.block('if ($nm_hl = "11")'):
                c.d("set", "$nm_waf", '"hotlink/hotlink"')
                c.d("set", "$nm_wact", '"block"')
        if sp.threats and self.feeds_on():
            with c.block('if ($nm_threat_act = "block")'):
                c.d("set", "$nm_waf", '"threat/$nm_threat"')
                c.d("set", "$nm_wact", '"block"')
        custom(("block", "drop"))
        if sp.waf_disabled_rules:
            pat = "^[a-z_]+/(?:" + "|".join(re.escape(x) for x in sp.waf_disabled_rules) + ")$"
            with c.block(f"if ($nm_waf ~ {W.nginx_quote(pat)})"):
                c.d("set", "$nm_wact", '"off"')
        wx = f"$nm_wx_{sid}" if sp.waf_exclude_paths else ""
        c.d("set", "$nm_wchk", f'"$nm_pa{wx}$nm_wact"')
        with c.block('if ($nm_wchk = "block")'):
            c.d("return", self.prot.block_status)
        with c.block('if ($nm_wchk = "drop")'):
            c.d("return", 444)
        if https and sp.sni_check:
            with c.block("if ($nm_sni_bad)"):
                c.d("return", 421)
        if sp.challenge != "off" and challenge_ready(self.caps) and self.p.challenge_secret:
            c.d("set", "$nm_chs", '"c"' if sp.challenge == "on" else "$nm_chal_auto")
            if sp.threats and self.feeds_on():
                with c.block('if ($nm_threat_act = "challenge")'):
                    c.d("set", "$nm_chs", '"c"')
            if any(r.action == "challenge" for r in rules):
                with c.block('if ($nm_wchk = "challenge")'):
                    c.d("set", "$nm_chs", '"c"')
            c.d("set", "$nm_chk", f'"$nm_pa$nm_cx_{sid}$nm_chs$secure_link"')
            with c.block('if ($nm_chk ~ "^c0?$")'):
                c.d("rewrite", "^", CHALLENGE_PREFIX, "last")

    def locations(self, c, sid: int, s: Site) -> None:
        """Служебные location: страница проверки браузера, приём решения, страница блокировки."""
        sp = s.protection
        if not sp.enabled:
            return
        if sp.challenge != "off" and challenge_ready(self.caps) and self.p.challenge_secret:
            host = f"[{self.p.panel_host}]" if ":" in self.p.panel_host else self.p.panel_host
            panel = f"{self.p.panel_scheme}://{host}:{self.p.panel_port}"
            for loc, target, internal in ((f"= {CHALLENGE_PREFIX}", "/challenge/page", True),
                                          (f"= {CHALLENGE_PREFIX}/verify", "/challenge/verify", False)):
                c.line()
                with c.block(f"location {loc}"):
                    if internal:
                        c.d("internal")
                        c.d("proxy_method", "GET")
                        c.d("proxy_pass_request_body", "off")
                        c.d("proxy_set_header", "Content-Length", '""')
                    else:
                        c.d("limit_req", "zone=nm_chal", "burst=10", "nodelay")
                        c.d("client_max_body_size", "4k")
                    c.d("proxy_pass", panel + target)
                    c.d("proxy_set_header", "Host", "$host")
                    c.d("proxy_set_header", "X-Real-IP", "$remote_addr")
                    c.d("proxy_set_header", "X-Forwarded-For", "$remote_addr")
                    c.d("proxy_set_header", "X-Forwarded-Proto", "$scheme")
                    c.d("proxy_set_header", "X-NM-Site", "$nm_site")
                    c.d("proxy_set_header", "X-NM-Original", "$request_uri")
                    c.d("proxy_set_header", "X-NM-Key", q(self.p.challenge_key))
                    c.d("proxy_set_header", "Cookie", '""')
                    if self.p.panel_scheme == "https":
                        c.d("proxy_ssl_verify", "off")
                    c.d("proxy_connect_timeout", "5s")
                    c.d("proxy_read_timeout", "15s")
                    c.d("proxy_intercept_errors", "off")
                    c.d("auth_basic", "off")
                    c.d("allow", "all")
        if self.prot.block_status == 403 and not (s.error_pages.enabled and 403 in s.error_pages.codes):
            c.line()
            c.d("error_page", 403, "@nm_blocked")
            with c.block("location @nm_blocked"):
                c.d("root", f"{self.p.live_root}/pages")
                c.d("rewrite", "^", "/blocked.html", "break")
                c.d("ssi", "on")
                c.d("default_type", "text/html")
                c.d("allow", "all")
                c.d("auth_basic", "off")
                c.d("add_header", "Cache-Control", '"no-store"', "always")

    def login_limit(self, c, sid: int, s: Site) -> None:
        sp = s.protection
        if sp.enabled and sp.login_protection and sp.login_paths:
            c.d("limit_req", f"zone=nm_login_{sid}", f"burst={sp.login_burst}" if sp.login_burst else "", "nodelay")

    def strip_headers(self, c, s: Site) -> None:
        if s.protection.enabled and s.protection.strip_headers:
            for h in ("Proxy", "X-Original-URL", "X-Rewrite-URL", "X-Middleware-Subrequest", "X-HTTP-Method-Override",
                      "X-Method-Override"):
                c.d("proxy_set_header", h, '""')


BLOCKED_PAGE = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Доступ запрещён</title>
<style>body{font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f4f4f1;color:#1f1f1c;
margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}main{max-width:560px;margin:24px;
background:#fff;border:1px solid #e1e0d9;border-radius:12px;padding:32px}h1{font-size:22px;margin:0 0 12px}
p{margin:0 0 12px;color:#45443f}dl{display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:13px;
margin:20px 0 0;padding:14px 16px;background:#f3f3f0;border-radius:8px}dt{color:#6b6963}dd{margin:0;
font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
@media (prefers-color-scheme:dark){body{background:#141413;color:#ecebe4}main{background:#1a1a19;border-color:#2f2f2c}
p{color:#c3c2b7}dl{background:#222220}dt{color:#9a988f}}</style></head>
<body><main><h1>Доступ запрещён</h1>
<p>Система защиты сайта отклонила этот запрос: он похож на атаку или пришёл с адреса, доступ с которого
ограничен.</p><p>Если вы считаете это ошибкой, сообщите администратору сайта номер запроса — по нему можно найти
причину и разрешить доступ.</p>
<dl><dt>Номер запроса</dt><dd><!--# echo var="request_id" default="—" --></dd>
<dt>Ваш IP</dt><dd><!--# echo var="remote_addr" default="—" --></dd>
<dt>Время (UTC)</dt><dd><!--# config timefmt="%Y-%m-%d %H:%M:%S" --><!--# echo var="date_gmt" default="—" --></dd>
</dl></main></body></html>
"""
