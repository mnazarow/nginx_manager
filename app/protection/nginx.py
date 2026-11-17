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

Дополнительно: проверка поисковых роботов по официальным диапазонам адресов (geo $nm_vbot и карта
User-Agent → заявленный робот, оба файла обновляет панель), правила ограничения частоты (limit_req_zone на
правило, ключ — IP, если запрос подходит под правило), ModSecurity v3 + OWASP CRS (файлы modsec/*.conf версии
конфигурации; номер транзакции «сайт-доверенный-request_id» связывает журнал аудита с журналом доступа).
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..models import CustomRule, ProtectionSettings, RateRule, Site
from . import rules as W

CHALLENGE_PREFIX = "/.nm-challenge"
LINK_PREFIX = "/.nm-access"  # ссылки временного доступа раздела сайта «Доступ по IP» (страница панели)
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


# Каталоги OWASP CRS в пакетах дистрибутивов и при ручной установке
CRS_DIRS = ["/usr/share/modsecurity-crs", "/usr/share/owasp-modsecurity-crs", "/usr/share/mod_modsecurity_crs",
            "/usr/share/coreruleset", "/etc/nginx/modsec/coreruleset", "/usr/local/owasp-modsecurity-crs",
            "/opt/coreruleset"]


def find_crs(prefer: str = "") -> Tuple[str, str]:
    """(каталог правил CRS, версия «335»/«4100») или ("", ""). prefer — выпуск, скачанный панелью с GitHub."""
    from pathlib import Path
    for d in ([prefer] if prefer else []) + CRS_DIRS:
        rules = Path(d) / "rules"
        init = rules / "REQUEST-901-INITIALIZATION.conf"
        if init.is_file():
            try:
                m = re.search(r"ver\.(\d+)\.(\d+)\.(\d+)", init.read_text(errors="replace")[:20000])
            except OSError:
                continue
            return str(rules), "".join(m.groups()) if m else "335"
    return "", ""


def crs_label(crs_dir: str) -> str:
    """Версия CRS для показа: «3.3.5», «4.30.0» ('' — каталог не найден)."""
    from pathlib import Path
    if not crs_dir:
        return ""
    try:
        m = re.search(r"ver\.(\d+\.\d+\.\d+)", (Path(crs_dir) / "REQUEST-901-INITIALIZATION.conf")
                      .read_text(errors="replace")[:20000])
    except OSError:
        return ""
    return m.group(1) if m else ""


def modsec_ready(caps) -> bool:
    return bool(getattr(caps, "modsecurity", False))


# Внутренний код отказа защиты: error_page превращает его в 403 со страницей «Доступ запрещён»
BLOCK_CODE = 418

# Номера служебных правил Nginx Manager в ModSecurity (вне диапазонов CRS 900000–999999)
MODSEC_ID_BASE = 4190000


class ProtectionConf:
    def __init__(self, state, paths, caps) -> None:
        self.st = state
        self.prot: ProtectionSettings = state.protection
        self.p = paths
        self.caps = caps
        self.sites: List[Tuple[int, Site]] = [(i, s) for i, s in state.sites if s.enabled]
        self.maps = W.maps(self.prot.waf_level, self.prot.waf_disabled_rules)
        self.warnings: List[str] = []
        self.crs_dir, self.crs_ver = (getattr(paths, "crs_dir", ""), getattr(paths, "crs_version", ""))
        if any(r.enabled and r.field == "country" for r in self.prot.custom_rules) and not self.p.geo_file:
            self.warnings.append("Свои правила по стране не действуют: нет базы GeoIP (раздел «Настройки панели → "
                                 "GeoIP»)")
        if any(r.enabled and r.field == "asn" for r in self.prot.custom_rules) and not self.asn_ready():
            self.warnings.append("Свои правила по сети провайдера не действуют: нет базы ASN (включите «Скачивать и "
                                 "обновлять бесплатные базы DB-IP Lite» в настройках панели)")
        if self.prot.modsec_enabled and not self.modsec_on():
            self.warnings.append("Глубокая проверка (ModSecurity) не действует: " + (
                "в nginx нет модуля ModSecurity (пакет libnginx-mod-http-modsecurity)" if not modsec_ready(caps)
                else "не найден OWASP CRS (пакет modsecurity-crs)"))

    # ------------------------------------------------------------------ http
    def used_cats(self) -> set:
        used = set()
        for sid, s in self.sites:
            for cat, m in site_modes(self.prot, s.protection).items():
                if m != "off":
                    used.add(cat)
        return used

    def asn_ready(self) -> bool:
        return bool(getattr(self.p, "asn_file", ""))

    def custom_rules(self, sid: Optional[int] = None) -> List[CustomRule]:
        return [r for r in self.prot.custom_rules if r.enabled and (sid is None or not r.sites or sid in r.sites)
                and (r.field != "country" or self.p.geo_file) and (r.field != "asn" or self.asn_ready())]

    def asn_rules(self) -> List[CustomRule]:
        return [r for r in self.custom_rules() if r.field == "asn"]

    def country_rules(self) -> List[CustomRule]:
        return [r for r in self.custom_rules() if r.field == "country"]

    def rate_rules(self, sid: Optional[int] = None) -> List[RateRule]:
        return [r for r in self.prot.rate_rules if r.enabled and (sid is None or not r.sites or sid in r.sites)]

    def bots_on(self) -> bool:
        p = self.prot
        return bool(getattr(self.p, "bots_file", "")) and any(b.enabled for b in p.verified_bots) and \
            (p.fake_bot_action != "off" or p.verified_skip_challenge)

    def vuln_on(self) -> bool:
        return bool(getattr(self.p, "vuln_file", "")) and self.prot.vulndb_enabled and self.prot.mode("vuln") != "off"

    def modsec_on(self) -> bool:
        return self.prot.modsec_enabled and modsec_ready(self.caps) and bool(self.crs_dir)

    def modsec_site(self, s: Site) -> str:
        """Итоговый режим ModSecurity сайта: off / detect / block."""
        if not self.modsec_on() or not s.protection.enabled or s.protection.modsec == "off":
            return "off"
        return "detect" if s.protection.modsec == "detect" else self.prot.modsec_mode

    def feeds_on(self) -> bool:
        intel = bool(self.prot.abuseipdb_key and self.prot.abuseipdb_blacklist) or \
            bool(self.prot.crowdsec_url and self.prot.crowdsec_key)
        return bool(self.p.threats_file) and (any(f.enabled for f in self.prot.threat_feeds) or intel)

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
        a("# --- доверенные адреса (раздел «Доверенные адреса»): без проверок защиты и ограничений частоты")
        a("geo $nm_trusted {")
        a("    default 0;")
        seen = set()
        for ip in [e.address for e in getattr(self.st.panel, "trusted_ips", []) if e.active()] + \
                list(self.prot.bypass_ips):
            if ip not in seen:
                seen.add(ip)
                a(f"    {ip} 1;")
        a("}")
        a("map $nm_trusted $nm_limit_key {")
        a("    default $binary_remote_addr;")
        a('    1 "";')
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
        a("# --- проверка роботов: заявленный в User-Agent робот и его официальные адреса (файлы обновляет панель)")
        a("geo $nm_vbot {")
        a('    default "";')
        if self.bots_on():
            a(f"    include {self.p.bots_file};")
        a("}")
        a("map $http_user_agent $nm_bot_claim {")
        a('    default "";')
        if self.bots_on():
            a(f"    include {self.p.bots_ua_file};")
        a("}")
        a('map "$nm_bot_claim:$nm_vbot" $nm_fakebot {')
        a("    default 0;")
        a('    "~^([a-z0-9]+):(?!\\1$)" 1;')
        a("}")
        a('map "$nm_bot_claim:$nm_vbot" $nm_vbot_ok {')
        a("    default 0;")
        a('    "~^([a-z0-9]+):\\1$" 1;')
        a("}")
        if self.vuln_on():
            from .vulndb import PAYLOAD_RE
            a("")
            a("# --- пути эксплойтов известных уязвимостей (CISA KEV, nuclei-templates; файл обновляет панель):")
            a("# «CVE:a» — опасен сам путь, «CVE:p» — нужен ещё признак атаки в параметрах")
            a("map $uri $nm_vuln_raw {")
            a('    default "";')
            a(f"    include {self.p.vuln_file};")
            a("}")
            a("map $args $nm_vuln_pl {")
            a("    default 0;")
            a(f"    {W.nginx_quote('~*' + PAYLOAD_RE)} 1;")
            a("}")
            a('map "$nm_vuln_raw:$nm_vuln_pl" $nm_vuln {')
            a('    default "";')
            a('    "~^(?<c>CVE-[0-9]+-[0-9]+):a:" $c;')
            a('    "~^(?<c>CVE-[0-9]+-[0-9]+):p:1$" $c;')
            a("}")
        a("")
        a("# --- правила ограничения частоты: ключ — IP, если запрос подходит под правило")
        a('map "$request_method:$uri" $nm_rlid {')
        a('    default "";')
        for r in self.rate_rules():
            a(f"    {self.rate_key(r)} {q(r.id)};")
        a("}")
        for r in self.rate_rules():
            a(f'map "$request_method:$uri" $nm_rrk_{r.id} {{')
            a('    default "";')
            a(f"    {self.rate_key(r)} $binary_remote_addr;")
            a("}")
            a(f"limit_req_zone $nm_rrk_{r.id} zone=nm_rr_{r.id}:10m rate={r.rate};")
        if self.modsec_on():
            a("")
            a("# --- глубокая проверка: ModSecurity v3 + OWASP CRS (правила — modsec/main.conf этой версии)")
            a(f"modsecurity_rules_file {self.p.include_root}/modsec/main.conf;")
            a('modsecurity_transaction_id "$nm_site-$nm_pa-$request_id";')
        a("")
        if self.asn_rules():
            a("# --- сети провайдеров (ASN) из своих правил; файл собирает панель из базы ASN")
            a("geo $nm_asn {")
            a("    default 0;")
            a(f"    include {self.p.asn_file};")
            a("}")
        a("# --- свои правила")
        for r in self.custom_rules():
            self.custom_rule_map(out, r)
        a("")
        a("# --- исключения путей, пути входа, хотлинкинг (по сайтам)")
        for sid, s in self.sites:
            sp = s.protection
            if not sp.enabled:
                continue
            if self.waf_excluded(s):
                a(f"map $uri $nm_wx_{sid} {{")
                a('    default "";')
                # страница ссылки временного доступа: только проверка кода в панели (с ограничением частоты)
                for pth in list(sp.waf_exclude_paths) + ([LINK_PREFIX + "/"] if s.ip_access.enabled else []):
                    a(f"    {path_key(pth)} \"x\";")
                a("}")
            if sp.challenge != "off":
                a(f"map $uri $nm_cx_{sid} {{")
                a('    default "";')
                for pth in [CHALLENGE_PREFIX + "/", "/.well-known/acme-challenge/"] + \
                        ([LINK_PREFIX + "/"] if s.ip_access.enabled else []) + \
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
        if r.field == "asn":
            a(f"map $nm_asn $nm_cr_{r.id} {{")
            a(f"    default {miss};")
            for n in r.value.split():
                a(f"    {n} {hit};")
            a("}")
            return
        if r.field == "country":
            a(f"map $nm_cc $nm_cr_{r.id} {{")
            a(f"    default {miss};")
            for cc in r.value.split():
                a(f"    {cc} {hit};")
            a("}")
            return
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

    @staticmethod
    def rate_key(r: RateRule) -> str:
        meth = "(?:" + "|".join(r.methods) + ")" if r.methods else "[A-Z]+"
        if r.path.startswith("~"):
            rx = r.path[1:]
            pathre = rx[1:] if rx.startswith("^") else ".*" + rx
        else:
            pathre = re.escape(r.path)
        return W.nginx_quote(f"~^{meth}:{pathre}")

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

        fb = self.prot.fake_bot_action if self.bots_on() else "off"

        def fakebot(level):
            if fb == level:
                with c.block("if ($nm_fakebot)"):
                    c.d("set", "$nm_waf", '"fakebot/$nm_bot_claim"')
                    c.d("set", "$nm_wact", q(level))

        if sp.threats and self.feeds_on():
            with c.block('if ($nm_threat_act = "detect")'):
                c.d("set", "$nm_waf", '"threat/$nm_threat"')
                c.d("set", "$nm_wact", '"detect"')
        fakebot("detect")
        for want in ("detect", "block"):
            if want == "block":
                custom(("log",))
                custom(("challenge",))
                fakebot("challenge")
            for (cat, target) in sorted(self.maps):
                if modes.get(cat) != want:
                    continue
                var = W.map_name(cat, target)
                with c.block(f"if ({var})"):
                    c.d("set", "$nm_waf", var)
                    c.d("set", "$nm_wact", f'"{want}"')
            if self.vuln_on() and modes.get("vuln") == want:
                with c.block('if ($nm_vuln)'):
                    c.d("set", "$nm_waf", '"vuln/$nm_vuln"')
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
        fakebot("block")
        custom(("block", "drop"))
        if sp.waf_disabled_rules:
            pat = "^[a-z_]+/(?:" + "|".join(re.escape(x) for x in sp.waf_disabled_rules) + ")$"
            with c.block(f"if ($nm_waf ~ {W.nginx_quote(pat)})"):
                c.d("set", "$nm_wact", '"off"')
        wx = f"$nm_wx_{sid}" if self.waf_excluded(s) else ""
        c.d("set", "$nm_wchk", f'"$nm_pa{wx}$nm_wact"')
        with c.block('if ($nm_wchk = "block")'):
            c.d("return", self.deny_code(s, self.prot.block_status))
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
            if any(r.action == "challenge" for r in rules) or fb == "challenge":
                with c.block('if ($nm_wchk = "challenge")'):
                    c.d("set", "$nm_chs", '"c"')
            if self.bots_on() and self.prot.verified_skip_challenge:
                with c.block("if ($nm_vbot_ok)"):
                    c.d("set", "$nm_chs", '""')
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
                    # без X-Forwarded-For: uvicorn подставил бы адрес посетителя вместо адреса nginx, и панель
                    # отказала бы (страница проверки принимается только от nginx); адрес посетителя — в X-Real-IP
                    c.d("proxy_set_header", "X-Forwarded-For", '""')
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
        if self.block_page(s):
            c.line()
            c.d("error_page", BLOCK_CODE, "=403", "@nm_blocked")
            # Страница отдаётся директивой return (а не файлом): статический файл на POST дал бы 405, а
            # именованная location не перезапускает проверки уровня server, как внутреннее перенаправление на URI.
            with c.block("location @nm_blocked"):
                c.d("default_type", '"text/html; charset=utf-8"')
                c.d("allow", "all")
                c.d("auth_basic", "off")
                c.d("add_header", "Cache-Control", '"no-store"', "always")
                c.d("return", 403, blocked_body())

    @staticmethod
    def waf_excluded(s: Site) -> bool:
        return bool(s.protection.waf_exclude_paths) or s.ip_access.enabled

    def block_page(self, s: Site) -> bool:
        """Страница «Доступ запрещён» в этом server: защита включена, ответ 403, своей страницы 403 у сайта нет."""
        return s.protection.enabled and self.prot.block_status == 403 and \
            not (s.error_pages.enabled and 403 in s.error_pages.codes)

    def deny_code(self, s: Site, code: int) -> int:
        """Код для return при отказе: 403 → внутренний 418, который error_page превращает в 403 со страницей.
        Ответы 403 бэкенда и ModSecurity не перехватываются: внутреннее перенаправление ModSecurity
        потеряло бы данные транзакции, и журнал аудита остался бы без записи."""
        return BLOCK_CODE if code == 403 and self.block_page(s) else code

    def login_limit(self, c, sid: int, s: Site) -> None:
        """limit_req защиты входа и правил ограничения частоты — в каждой location сайта (директивы limit_req
        не наследуются, если в location есть свои)."""
        sp = s.protection
        if sp.enabled and sp.login_protection and sp.login_paths:
            c.d("limit_req", f"zone=nm_login_{sid}", f"burst={sp.login_burst}" if sp.login_burst else "", "nodelay")
        if sp.enabled:
            for r in self.rate_rules(sid):
                c.d("limit_req", f"zone=nm_rr_{r.id}", f"burst={r.burst}" if r.burst else "", "nodelay")

    def has_limits(self, sid: int, s: Site) -> bool:
        sp = s.protection
        return sp.enabled and ((sp.login_protection and bool(sp.login_paths)) or bool(self.rate_rules(sid)))

    def modsec_server(self, c, sid: int, s: Site) -> None:
        if not self.modsec_on():
            return
        c.d("modsecurity", "on" if self.modsec_site(s) != "off" else "off")

    # ------------------------------------------------------------------ ModSecurity
    def modsec_files(self) -> Dict[str, str]:
        if not self.modsec_on():
            return {}
        p = self.prot
        root = f"{self.p.include_root}/modsec"
        v4 = self.crs_ver[:1] >= "4" and len(self.crs_ver) >= 3
        main = [
            "# Nginx Manager: ModSecurity v3 + OWASP CRS. Файл генерируется панелью (раздел «Защита от атак»).",
            f"SecRuleEngine {'On' if p.modsec_mode == 'block' else 'DetectionOnly'}",
            "SecRequestBodyAccess On",
            f"SecRequestBodyLimit {p.modsec_body_limit_kb * 1024}",
            f"SecRequestBodyNoFilesLimit {min(p.modsec_body_limit_kb * 1024, 1048576)}",
            "SecRequestBodyLimitAction ProcessPartial",
            'SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\\+|/)|text/)xml" '
            '"id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"',
            'SecRule REQUEST_HEADERS:Content-Type "^application/json" '
            '"id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"',
            'SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,'
            "msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2\"",
            "SecResponseBodyAccess Off",
            "SecTmpDir /tmp/",
            "SecDataDir /tmp/",
            "SecArgumentSeparator &",
            "SecCookieFormat 0",
            "SecStatusEngine Off",
            "SecAuditEngine RelevantOnly",
            'SecAuditLogRelevantStatus "^$"',
            "SecAuditLogParts ABHZ",
            "SecAuditLogType Serial",
            "SecAuditLogFormat JSON",
            f"SecAuditLog {self.p.log_dir}/nm-modsec-audit.log",
            f"Include {root}/crs-setup.conf",
            f"Include {root}/before.conf",
            f"Include {self.crs_dir}/*.conf",
            f"Include {root}/after.conf",
        ]
        pl = "blocking_paranoia_level" if v4 else "paranoia_level"
        setup = [
            "# Настройки OWASP CRS (вместо crs-setup.conf дистрибутива)",
            'SecDefaultAction "phase:1,log,auditlog,pass"',
            'SecDefaultAction "phase:2,log,auditlog,pass"',
            f'SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.{pl}={p.modsec_paranoia}"',
            f'SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold='
            f'{p.modsec_threshold},setvar:tx.outbound_anomaly_score_threshold=4"',
        ]
        if p.modsec_apps and not v4:
            setup.append('SecAction "id:900130,phase:1,nolog,pass,t:none,'
                         + ",".join(f"setvar:tx.crs_exclusions_{a}=1" for a in p.modsec_apps) + '"')
        elif p.modsec_apps:
            self.warnings.append("CRS 4: исключения для приложений подключаются плагинами CRS, а не настройкой панели")
        setup.append(f'SecAction "id:900990,phase:1,nolog,pass,t:none,setvar:tx.crs_setup_version={self.crs_ver}"')
        before = ["# Исключения по сайтам: номер транзакции «сайт-доверенный-request_id» (modsecurity_transaction_id)"]
        rid = MODSEC_ID_BASE
        before.append(f'SecRule UNIQUE_ID "@rx ^[^-]*-a-" "id:{rid},phase:1,pass,nolog,ctl:ruleEngine=Off"')
        before.append(f'SecRule REQUEST_URI "@contains nm_selftest=" "id:{rid + 1},phase:1,pass,nolog,'
                      'ctl:auditEngine=On"')
        rid += 10
        for sid, st in self.sites:
            mode = self.modsec_site(st)
            if mode == "off":
                continue
            sp = st.protection
            if mode == "detect" and p.modsec_mode == "block":
                before.append(f'SecRule UNIQUE_ID "@beginsWith {sid}-" "id:{rid},phase:1,pass,nolog,'
                              'ctl:ruleEngine=DetectionOnly"')
                rid += 1
            if sp.modsec_disabled_ids:
                ctl = ",".join(f"ctl:ruleRemoveById={i}" for i in sp.modsec_disabled_ids)
                before.append(f'SecRule UNIQUE_ID "@beginsWith {sid}-" "id:{rid},phase:1,pass,nolog,{ctl}"')
                rid += 1
            for pth in sp.modsec_exclude_paths:
                op = f'@rx {pth[1:]}' if pth.startswith("~") else f"@beginsWith {pth}"
                before.append(f'SecRule UNIQUE_ID "@beginsWith {sid}-" "id:{rid},phase:1,pass,nolog,chain"')
                before.append(f'    SecRule REQUEST_FILENAME "{op}" "ctl:ruleEngine=Off"')
                rid += 1
        after = ["# Правила CRS, отключённые на всех сайтах"]
        if p.modsec_disabled_ids:
            after.append("SecRuleRemoveById " + " ".join(str(i) for i in p.modsec_disabled_ids))
        return {"modsec/main.conf": "\n".join(main) + "\n", "modsec/crs-setup.conf": "\n".join(setup) + "\n",
                "modsec/before.conf": "\n".join(before) + "\n", "modsec/after.conf": "\n".join(after) + "\n"}

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
<dl><dt>Номер запроса</dt><dd>$request_id</dd>
<dt>Ваш IP</dt><dd>$remote_addr</dd>
<dt>Время</dt><dd>$time_iso8601</dd>
</dl></main></body></html>
"""


def blocked_body() -> str:
    """Страница «Доступ запрещён» одной строкой в одинарных кавычках nginx; переменные подставляет nginx."""
    body = " ".join(line.strip() for line in BLOCKED_PAGE.splitlines() if line.strip())
    return "'" + body.replace("\\", "\\\\").replace("'", "\\'") + "'"
