"""Технологии сайтов: что работает за nginx (CMS, фреймворки, серверы приложений, панели) и их уязвимости.

Раз в сутки (и по кнопке) панель запрашивает главную страницу каждого сайта прямо у бэкенда — без фильтров защиты
и проверки браузера — и сопоставляет заголовки ответа, cookie и HTML с сигнатурами по образцу Wappalyzer и
WhatWeb. Найденные продукты дополняют список «Ваши продукты»: новые эксплуатируемые уязвимости в них — событие
и подсказка анализа, а на вкладке «Уязвимости» видны уязвимости, относящиеся к вашим сайтам.
"""
from __future__ import annotations

import http.client
import re
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Tech:
    id: str
    name: str
    cat: str
    keywords: Tuple[str, ...]         # слова для поиска уязвимостей по «производитель продукт» в базе
    headers: Tuple[Tuple[str, str], ...] = ()   # (заголовок, регулярное выражение; группа 1 — версия)
    cookies: Tuple[str, ...] = ()               # регулярные выражения имён cookie
    html: Tuple[str, ...] = ()                  # регулярные выражения по HTML (группа 1 — версия)
    meta: str = ""                              # регулярное выражение по <meta name="generator">
    implies: Tuple[str, ...] = field(default=())
    ver: str = ""                               # версия по HTML, если продукт найден (группа 1)


def T(name: str) -> str:
    """Регулярное выражение «название в заголовке страницы»."""
    return rf"<title>\s*(?:[^<]{{0,60}}[-|–—:·]\s*)?(?:Atlassian\s+|Oracle\s+)?{name}\b[^<]{{0,50}}</title>"


CATS = {"cms": "CMS и сайты", "shop": "Интернет-магазины", "framework": "Фреймворки", "server": "Веб-серверы",
        "lang": "Языки и платформы", "app": "Приложения и панели", "js": "JavaScript"}

TECHS: List[Tech] = [
    # CMS
    Tech("wordpress", "WordPress", "cms", ("wordpress",), html=(r"/wp-(?:content|includes)/", r"wp-emoji-release"),
         meta=r"WordPress ?([\d.]+)?", implies=("php",)),
    Tech("drupal", "Drupal", "cms", ("drupal",), headers=(("x-generator", r"Drupal ?(\d+)?"), ("x-drupal-cache", "")),
         html=(r"/sites/(?:default|all)/(?:files|themes|modules)/", r"Drupal\.settings", r"data-drupal-"),
         meta=r"Drupal ?(\d+)?", implies=("php",)),
    Tech("joomla", "Joomla", "cms", ("joomla",), html=(r"/media/(?:jui|system)/js/", r"/components/com_"),
         meta=r"Joomla!? ?([\d.]+)?", implies=("php",)),
    Tech("bitrix", "1С-Битрикс", "cms", ("bitrix",), headers=(("x-powered-cms", r"Bitrix"),),
         cookies=(r"^BITRIX_SM_",), html=(r"/bitrix/(?:js|templates|cache)/",), implies=("php",)),
    Tech("modx", "MODX", "cms", ("modx",), html=(r"/assets/components/",), meta=r"MODX", implies=("php",)),
    Tech("typo3", "TYPO3", "cms", ("typo3",), html=(r"/typo3(?:conf|temp)/",), meta=r"TYPO3 CMS ?([\d.]+)?"),
    Tech("ghost", "Ghost", "cms", ("ghost",), meta=r"Ghost ?([\d.]+)?"),
    Tech("craft", "Craft CMS", "cms", ("craft cms", "craftcms"), headers=(("x-powered-by", r"Craft CMS"),),
         cookies=(r"^CraftSessionId",)),
    Tech("dle", "DataLife Engine", "cms", ("datalife",), html=(r"/engine/classes/",), meta=r"DataLife Engine"),
    # магазины
    Tech("magento", "Magento / Adobe Commerce", "shop", ("magento", "adobe commerce"),
         html=(r"Mage\.Cookies", r"/static/version\d+/frontend/", r"mage/cookies"), cookies=(r"^X-Magento",),
         implies=("php",)),
    Tech("woocommerce", "WooCommerce", "shop", ("woocommerce",), html=(r"/wp-content/plugins/woocommerce/",)),
    Tech("prestashop", "PrestaShop", "shop", ("prestashop",), html=(r"var prestashop\b",), meta=r"PrestaShop",
         cookies=(r"^PrestaShop-",)),
    Tech("opencart", "OpenCart", "shop", ("opencart",), html=(r"catalog/view/theme/",), cookies=(r"^OCSESSID$",)),
    Tech("shopify", "Shopify", "shop", ("shopify",), headers=(("x-shopid", ""),), html=(r"cdn\.shopify\.com",)),
    # фреймворки
    Tech("laravel", "Laravel", "framework", ("laravel",), cookies=(r"^laravel_session$",), implies=("php",)),
    Tech("symfony", "Symfony", "framework", ("symfony",), headers=(("x-debug-token", ""),), cookies=(r"^sf_redirect",)),
    Tech("django", "Django", "framework", ("django",), cookies=(r"^csrftoken$", r"^django_language$"),
         html=(r"csrfmiddlewaretoken",), implies=("python",)),
    Tech("flask", "Flask", "framework", ("flask",), headers=(("server", r"Werkzeug/([\d.]+)"),), implies=("python",)),
    Tech("rails", "Ruby on Rails", "framework", ("rails",), headers=(("x-runtime", r"^[\d.]+$"),),
         cookies=(r"^_[a-z0-9_]+_session$",), html=(r'name="csrf-param" content="authenticity_token"',)),
    Tech("express", "Express", "framework", ("express",), headers=(("x-powered-by", r"^Express"),),
         implies=("nodejs",)),
    Tech("nextjs", "Next.js", "framework", ("next.js", "nextjs"), headers=(("x-powered-by", r"Next\.js ?([\d.]+)?"),),
         html=(r"__NEXT_DATA__", r"/_next/static/"), implies=("nodejs",)),
    Tech("nuxt", "Nuxt", "framework", ("nuxt",), html=(r"__NUXT__", r"/_nuxt/"), implies=("nodejs",)),
    Tech("spring", "Spring Boot", "framework", ("spring boot", "spring framework"),
         html=(r"Whitelabel Error Page",), implies=("java",)),
    Tech("aspnet", "ASP.NET", "framework", (".net", "asp.net"),
         headers=(("x-aspnet-version", r"([\d.]+)"), ("x-aspnetmvc-version", r"([\d.]+)"),
                  ("x-powered-by", r"ASP\.NET")), cookies=(r"^ASP\.NET_SessionId$", r"^\.AspNetCore\.")),
    # языки и платформы
    Tech("php", "PHP", "lang", ("php group php", "php php"), headers=(("x-powered-by", r"PHP/([\d.]+)"),),
         cookies=(r"^PHPSESSID$",)),
    Tech("python", "Python", "lang", ("python",), headers=(("server", r"Python/([\d.]+)"),)),
    Tech("nodejs", "Node.js", "lang", ("node.js", "nodejs"), headers=(("x-powered-by", r"^Node"),)),
    Tech("java", "Java", "lang", ("oracle java",), cookies=(r"^JSESSIONID$",)),
    # серверы
    Tech("apache", "Apache HTTP Server", "server", ("apache http server", "apache httpd"),
         headers=(("server", r"Apache(?:/([\d.]+))?(?! ?Tomcat|-Coyote)"),)),
    Tech("tomcat", "Apache Tomcat", "server", ("tomcat",), headers=(("server", r"Apache-Coyote|Tomcat"),),
         html=(r"Apache Tomcat/([\d.]+)",), implies=("java",)),
    Tech("iis", "Microsoft IIS", "server", ("internet information services", " iis"),
         headers=(("server", r"Microsoft-IIS/([\d.]+)"),)),
    Tech("nginx-backend", "nginx (бэкенд)", "server", ("nginx",), headers=(("server", r"^nginx(?:/([\d.]+))?"),)),
    Tech("openresty", "OpenResty", "server", ("openresty",), headers=(("server", r"openresty(?:/([\d.]+))?"),)),
    Tech("caddy", "Caddy", "server", ("caddy",), headers=(("server", r"^Caddy"),)),
    Tech("gunicorn", "Gunicorn", "server", ("gunicorn",), headers=(("server", r"gunicorn(?:/([\d.]+))?"),),
         implies=("python",)),
    Tech("uvicorn", "Uvicorn", "server", ("uvicorn",), headers=(("server", r"^uvicorn"),), implies=("python",)),
    Tech("jetty", "Eclipse Jetty", "server", ("jetty",), headers=(("server", r"Jetty\(([\d.]+)"),), implies=("java",)),
    Tech("weblogic", "Oracle WebLogic", "server", ("weblogic",), html=(T("WebLogic"), r"Oracle WebLogic Server")),
    # приложения и панели
    Tech("confluence", "Atlassian Confluence", "app", ("confluence",),
         headers=(("x-confluence-request-time", ""),), html=(T("Confluence"), r'<meta name="confluence-'), ver=r'ajs-version-number" content="([\d.]+)'),
    Tech("jira", "Atlassian Jira", "app", ("jira",), headers=(("x-arequestid", ""),),
         cookies=(r"^atlassian\.xsrf\.token$",), html=(r'name="application-name" content="JIRA"', T("Jira")),
         ver=r'ajs-version-number" content="([\d.]+)'),
    Tech("bitbucket", "Atlassian Bitbucket", "app", ("bitbucket",), html=(T("Bitbucket"),)),
    Tech("gitlab", "GitLab", "app", ("gitlab",), cookies=(r"^_gitlab_session$",), html=(r"gon\.gitlab_url", T("GitLab"))),
    Tech("gitea", "Gitea / Forgejo", "app", ("gitea", "forgejo"), cookies=(r"^i_like_gitea$",),
         html=(r"Powered by Gitea", r"forgejo")),
    Tech("jenkins", "Jenkins", "app", ("jenkins",), headers=(("x-jenkins", r"([\d.]+)"), ("x-hudson", ""))),
    Tech("grafana", "Grafana", "app", ("grafana",), html=(r"grafanaBootData", r"public/build/grafana")),
    Tech("kibana", "Kibana", "app", ("kibana",), headers=(("kbn-name", ""), ("kbn-version", r"([\d.]+)"))),
    Tech("nextcloud", "Nextcloud", "app", ("nextcloud",), html=(T("Nextcloud"),), cookies=(r"^nc_sameSiteCookie",)),
    Tech("owncloud", "ownCloud", "app", ("owncloud",), html=(T("ownCloud"),)),
    Tech("roundcube", "Roundcube Webmail", "app", ("roundcube",), html=(r"rcmail\.set_env", T("Roundcube")),
         cookies=(r"^roundcube_sessid$",)),
    Tech("zimbra", "Zimbra", "app", ("zimbra",), html=(T("Zimbra"),), cookies=(r"^ZM_TEST$",)),
    Tech("exchange", "Microsoft Exchange / OWA", "app", ("exchange server",),
         headers=(("x-owa-version", r"([\d.]+)"),), html=(r"/owa/auth/",)),
    Tech("sharepoint", "Microsoft SharePoint", "app", ("sharepoint",),
         headers=(("microsoftsharepointteamservices", r"([\d.]+)"),)),
    Tech("phpmyadmin", "phpMyAdmin", "app", ("phpmyadmin",), html=(r"phpMyAdmin",), cookies=(r"^phpMyAdmin$",)),
    Tech("keycloak", "Keycloak", "app", ("keycloak",), html=(T("Keycloak"), r"/resources/[^/]+/login/keycloak"), cookies=(r"^KC_RESTART$", r"^AUTH_SESSION")),
    Tech("minio", "MinIO", "app", ("minio",), headers=(("server", r"^MinIO"),)),
    Tech("geoserver", "GeoServer", "app", ("geoserver",), html=(T("GeoServer"),)),
    Tech("moodle", "Moodle", "app", ("moodle",), cookies=(r"^MoodleSession",), html=(r"M\.cfg = \{",)),
    Tech("mattermost", "Mattermost", "app", ("mattermost",), html=(T("Mattermost"),)),
    Tech("rocketchat", "Rocket.Chat", "app", ("rocket.chat",), html=(T(r"Rocket\.Chat"),)),
    Tech("sonarqube", "SonarQube", "app", ("sonarqube",), html=(T("SonarQube"),)),
    Tech("zabbix", "Zabbix", "app", ("zabbix",), html=(T("Zabbix"),), cookies=(r"^zbx_session",)),
    Tech("wazuh", "Wazuh", "app", ("wazuh",), html=(T("Wazuh"),)),
    Tech("ivanti", "Ivanti", "app", ("ivanti",), html=(T("Ivanti"),)),
    Tech("citrix", "Citrix NetScaler / ADC", "app", ("netscaler", "citrix"), html=(r"/vpn/index\.html", r"/logon/LogonPoint/"),
         cookies=(r"^NSC_",)),
    Tech("fortinet", "Fortinet FortiGate / FortiWeb", "app", ("fortinet", "fortios"), html=(r"ftnt-fortinet-grid", T("Forti(?:Gate|Web|Mail)"))),
    Tech("vmware", "VMware vCenter / ESXi", "app", ("vmware",), html=(T("VMware"), T("vSphere"))),
    # JavaScript
    Tech("jquery", "jQuery", "js", ("jquery",), html=(r"jquery[.-]?([\d.]+)?(?:\.min)?\.js",)),
    Tech("angularjs", "AngularJS", "js", ("angularjs",), html=(r"angular(?:\.min)?\.js", r"ng-app=")),
]
TECH_BY_ID = {t.id: t for t in TECHS}
MAX_BODY = 400_000


def detect(headers: List[Tuple[str, str]], body: str) -> List[Dict[str, Any]]:
    """Технологии по ответу: [{id, name, cat, version, evidence}] (с подразумеваемыми: WordPress → PHP)."""
    hmap: Dict[str, List[str]] = {}
    for k, v in headers:
        hmap.setdefault(k.lower(), []).append(v)
    cookies = []
    for v in hmap.get("set-cookie", []):
        name = v.split("=", 1)[0].strip()
        if name:
            cookies.append(name)
    low = body[:MAX_BODY]
    gens = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', low, re.I) + \
        re.findall(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', low, re.I)
    found: Dict[str, Dict[str, Any]] = {}

    def add(t: Tech, version: str, evidence: str) -> None:
        cur = found.get(t.id)
        if cur and (cur["version"] or not version):
            return
        found[t.id] = {"id": t.id, "name": t.name, "cat": t.cat, "version": version or "", "evidence": evidence}

    for t in TECHS:
        for hname, rx in t.headers:
            for v in hmap.get(hname, []):
                m = re.search(rx, v, re.I) if rx else True
                if m:
                    ver = m.group(1) if rx and m.re.groups and m.group(1) else ""
                    add(t, ver or "", f"заголовок {hname}: {v[:80]}")
        for rx in t.cookies:
            for c in cookies:
                if re.search(rx, c, re.I):
                    add(t, "", f"cookie {c}")
        if t.meta:
            for g in gens:
                m = re.search(t.meta, g, re.I)
                if m:
                    add(t, (m.group(1) or "") if m.re.groups else "", f"generator: {g[:80]}")
        for rx in t.html:
            m = re.search(rx, low, re.I)
            if m:
                add(t, (m.group(1) or "") if m.re.groups and m.group(1) else "", "страница: " + m.group(0)[:60])
                break
    for tid, f in found.items():
        t = TECH_BY_ID[tid]
        if t.ver and not f["version"]:
            m = re.search(t.ver, low, re.I)
            if m:
                f["version"] = m.group(1)
    for tid in list(found):
        for imp in TECH_BY_ID[tid].implies:
            if imp not in found:
                t = TECH_BY_ID[imp]
                found[imp] = {"id": t.id, "name": t.name, "cat": t.cat, "version": "",
                              "evidence": f"следует из {TECH_BY_ID[tid].name}"}
    order = list(CATS)
    return sorted(found.values(), key=lambda x: (order.index(x["cat"]), x["name"]))


def fetch(scheme: str, address: str, port: int, host: str, path: str = "/", timeout: float = 8.0,
          redirects: int = 3) -> Tuple[int, List[Tuple[str, str]], str]:
    """GET к бэкенду с заголовком Host сайта; переходы по перенаправлениям в пределах того же сайта."""
    for _ in range(redirects + 1):
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(address, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(address, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"Host": host, "Accept": "text/html,*/*;q=0.8",
                                               "User-Agent": "Mozilla/5.0 (compatible; NginxManager-Inventory/1.0)",
                                               "Accept-Encoding": "identity"})
            r = conn.getresponse()
            body = r.read(MAX_BODY).decode("utf-8", "replace")
            hdrs = r.getheaders()
            loc = r.getheader("location") or ""
            if r.status in (301, 302, 303, 307, 308) and loc:
                u = urllib.parse.urlparse(loc)
                if (not u.netloc or u.hostname == host) and (u.path or "/") != path:
                    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                    continue
            return r.status, hdrs, body
        finally:
            conn.close()
    return 0, [], ""


def site_target(site) -> Optional[Tuple[str, str, int, str]]:
    """(схема, адрес, порт, Host) первого бэкенда сайта-прокси; None — сайт без HTTP-бэкенда."""
    if getattr(site, "type", "proxy") != "proxy" or not site.backends:
        return None
    b = site.backends[0]
    if str(b.address).startswith("unix:"):
        return None
    scheme = getattr(site, "backend_scheme", "http") or "http"
    port = b.port or (443 if scheme == "https" else 80)
    host = site.main_domain if hasattr(site, "main_domain") else site.domains[0]
    return scheme, b.address.strip("[]"), port, host or "localhost"


def scan_site(site) -> Dict[str, Any]:
    t = site_target(site)
    if not t:
        return {"ts": time.time(), "tech": [], "error": "", "skipped": "сайт без HTTP-бэкенда"}
    try:
        status, hdrs, body = fetch(*t)
        return {"ts": time.time(), "status": status, "tech": detect(hdrs, body), "error": "",
                "target": f"{t[0]}://{t[1]}:{t[2]} (Host: {t[3]})"}
    except Exception as e:  # noqa: BLE001
        return {"ts": time.time(), "tech": [], "error": str(e)[:200], "target": f"{t[0]}://{t[1]}:{t[2]}"}


def keywords(tech_ids: List[str]) -> List[str]:
    out: List[str] = []
    for tid in tech_ids:
        t = TECH_BY_ID.get(tid)
        if t and t.cat not in ("js",):
            for k in t.keywords:
                if k not in out:
                    out.append(k)
    return out
