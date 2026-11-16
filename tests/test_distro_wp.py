"""Сборки дистрибутивов (Ubuntu OSV/OpenVEX, Debian OSV), плагины и темы WordPress (Wordfence, nuclei),
команды боту Telegram."""
from __future__ import annotations

import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.protection import distro as D
from app.protection import vulndb as V
from app.protection import wordpress as WP
from tests.test_protection import free_port

OSV_APACHE = {"id": "UBUNTU-CVE-2024-38475", "affected": [
    {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "apache2"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.52-1ubuntu4.10"}]}],
     "versions": ["2.4.52-1ubuntu4.7", "2.4.52-1ubuntu4.8", "2.4.52-1ubuntu4.9"]},
    {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "apache2"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.58-1ubuntu8.2"}]}],
     "versions": ["2.4.58-1ubuntu7", "2.4.58-1ubuntu8", "2.4.58-1ubuntu8.1"]}]}
VEX_PHP = {"statements": [
    {"status": "not_affected", "justification": "vulnerable_code_not_present", "products": [
        {"@id": "pkg:deb/ubuntu/php8.1@8.1.2-1ubuntu2.18?arch=source&distro=jammy"},
        {"@id": "pkg:deb/ubuntu/libapache2-mod-php8.1@8.1.2-1ubuntu2.18?arch=amd64&distro=jammy"}]},
    {"status": "not_affected", "justification": "component_not_present", "products": [
        {"@id": "pkg:deb/ubuntu/php8.3@8.3.6-0ubuntu0.24.04.1?arch=source&distro=noble"}]}]}
DEBIAN_OSV = {"id": "DEBIAN-CVE-2024-38475", "affected": [
    {"package": {"ecosystem": "Debian:12", "name": "apache2"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.61-1~deb12u1"}]}],
     "versions": ["2.4.57-2", "2.4.59-1~deb12u1"]}]}


@pytest.fixture()
def app(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    return App()


# =============================================================================
#  Дистрибутивы
# =============================================================================
def test_deb_version_compare():
    c = D.deb_vcmp
    assert c("2.4.52-1ubuntu4.9", "2.4.52-1ubuntu4.10") < 0 and c("1.0~rc1", "1.0") < 0 and c("1:1.0", "2.0") > 0
    assert c("8.1.2-1ubuntu2.14", "8.1.2-1ubuntu2.18") < 0 and c("1.0", "1.0") == 0 and c("1.0a", "1.0") > 0
    assert c("2.4.62-1~deb12u1", "2.4.62-1~deb12u2") < 0 and c("1.0-1", "1.0-1~bpo1") > 0
    assert D.upstream("1:2.4.52+dfsg-1ubuntu4.10") == "2.4.52"


def test_distro_from_headers():
    assert D.distro_of("PHP/8.1.2-1ubuntu2.14") == ("ubuntu", "8.1.2-1ubuntu2.14")
    assert D.distro_of("Apache/2.4.52 (Ubuntu)") == ("ubuntu", "")
    assert D.distro_of("PHP/8.2.7-1~deb12u1") == ("debian", "8.2.7-1~deb12u1")
    assert D.distro_of("nginx/1.22.1 (Debian)") == ("debian", "")
    assert D.distro_of("Apache/2.4.37 (Rocky Linux) OpenSSL/1.1.1k")[0] == "rhel"
    assert D.distro_of("PHP/8.2.28") == ("", "")
    from app.protection.fingerprint import detect
    tech = {t["id"]: t for t in detect([("Server", "Apache/2.4.52 (Ubuntu)"),
                                        ("X-Powered-By", "PHP/8.1.2-1ubuntu2.14")], "")}
    assert tech["apache"]["distro"] == "ubuntu" and tech["apache"]["pkgver"] == ""
    assert tech["php"]["version"] == "8.1.2" and tech["php"]["pkgver"] == "8.1.2-1ubuntu2.14"


def test_distro_verdict():
    osv = D.parse_osv(json.dumps(OSV_APACHE).encode())
    data = {"osv": osv, "vex": []}
    v = D.verdict(data, ["apache2"], "2.4.52", "")
    assert v["state"] == "depends" and v["fixed"] == "2.4.52-1ubuntu4.10" and v["release"] == "Ubuntu 22.04"
    assert "dpkg -l apache2" in D.describe(v) and D.affected_from(v, True) is None
    assert D.verdict(data, ["apache2"], "2.4.52", "2.4.52-1ubuntu4.9")["state"] == "affected"
    assert D.verdict(data, ["apache2"], "2.4.52", "2.4.52-1ubuntu4.10")["state"] == "fixed"
    assert D.verdict(data, ["apache2"], "2.4.52", "2.4.52-1ubuntu4.12")["state"] == "fixed"
    assert D.verdict(data, ["apache2"], "2.4.62", "") is None  # не та версия — данных нет, вывод по основной
    assert D.verdict(data, ["nginx"], "2.4.52", "") is None
    vex = D.parse_vex(json.dumps(VEX_PHP).encode())
    assert [x["pkg"] for x in vex] == ["php8.1", "php8.3"]  # только исходные пакеты
    v = D.verdict({"osv": [], "vex": vex}, D.packages("php", "8.1.2"), "8.1.2", "")
    assert v["state"] == "not_affected" and v["release"] == "Ubuntu 22.04" and "уязвимого кода нет" in D.describe(v)
    deb = D.parse_osv(json.dumps(DEBIAN_OSV).encode())
    assert D.verdict({"osv": deb}, ["apache2"], "2.4.59", "2.4.59-1~deb12u1")["state"] == "affected"
    assert D.verdict({"osv": deb}, ["apache2"], "2.4.62", "2.4.62-1~deb12u2") is None  # другая основная версия
    assert D.urls("ubuntu", "CVE-2024-38475")["osv"][0].endswith("/osv/cve/2024/UBUNTU-CVE-2024-38475.json")
    assert D.urls("debian", "CVE-2024-38475")["osv"] == ["https://api.osv.dev/v1/vulns/DEBIAN-CVE-2024-38475"]


def test_installed_affected_with_distro(app, monkeypatch):
    """Apache 2.4.52 (Ubuntu): по основной версии уязвим, по данным Ubuntu — «проверьте пакет»; RHEL — «возможно»."""
    db = app.protection.vulndb
    app.db.execute("INSERT INTO vulns(cve,name,vendor,product,kev,kev_added,cvss,ranges,updated) "
                   "VALUES(?,?,?,?,1,'2025-05-01',9.8,?,0)",
                   ("CVE-2024-38475", "Apache mod_rewrite", "Apache", "HTTP Server",
                    json.dumps([{"product": "Apache Software Foundation Apache HTTP Server", "v": "2.4.0",
                                 "lte": "2.4.59"}])))
    app.db.kv_set("site_tech", {"1": {"ts": time.time(), "name": "Сайт", "tech": [
        {"id": "apache", "name": "Apache HTTP Server", "cat": "server", "version": "2.4.52", "evidence": "x",
         "distro": "ubuntu", "pkgver": ""}]},
        "2": {"ts": time.time(), "name": "Старый", "tech": [
            {"id": "apache", "name": "Apache HTTP Server", "cat": "server", "version": "2.4.37", "evidence": "x",
             "distro": "rhel", "pkgver": ""}]}})
    urls = []

    def fake(url, **kw):
        urls.append(url)
        if "osv/cve" in url:
            return json.dumps(OSV_APACHE).encode()
        raise V.urllib.error.HTTPError(url, 404, "nf", {}, None)
    monkeypatch.setattr(V, "fetch_bytes", fake)
    res = db.update_distro()
    assert res["fetched"] == 1 and any("UBUNTU-CVE-2024-38475" in u for u in urls)
    t = db.tech()["1"]["tech"][0]
    assert db.installed_affected(t) == []
    may = db.installed_affected(t, maybe=True)
    assert may and "2.4.52-1ubuntu4.10" in may[0]["note"]
    rh = db.tech()["2"]["tech"][0]
    assert db.installed_affected(rh) == [] and "rpm -q --changelog" in db.installed_affected(rh, maybe=True)[0]["note"]
    card = db.get("CVE-2024-38475")
    assert {x["site"]: x["affected"] for x in card["on_sites"]} == {"1": None, "2": None}
    # с версией пакета — однозначный ответ
    app.db.kv_set("site_tech", {"1": {"ts": time.time(), "name": "Сайт", "tech": [
        {**t, "pkgver": "2.4.52-1ubuntu4.9"}]}})
    assert [a["cve"] for a in db.installed_affected(db.tech()["1"]["tech"][0])] == ["CVE-2024-38475"]
    # учёт дистрибутивов выключен — вывод по основной версии
    app.protection.save(app.protection.settings().model_copy(update={"vulndb_distro": False}))
    assert len(db.installed_affected(t)) == 1


# =============================================================================
#  WordPress
# =============================================================================
FEED = {
    "a1": {"id": "a1", "title": "Contact Form 7 <= 5.3.1 - Unrestricted File Upload", "informational": False,
           "software": [{"type": "plugin", "name": "Contact Form 7", "slug": "contact-form-7",
                         "affected_versions": {"* - 5.3.1": {"from_version": "*", "from_inclusive": True,
                                                             "to_version": "5.3.1", "to_inclusive": True}},
                         "patched": True, "patched_versions": ["5.3.2"]}],
           "cve": "CVE-2020-35489", "cvss": {"score": 10.0, "vector": "CVSS:3.1/…", "rating": "Critical"},
           "published": "2020-12-17T00:00:00+00:00"},
    "a2": {"id": "a2", "title": "Astra theme XSS", "informational": False,
           "software": [{"type": "theme", "name": "Astra", "slug": "astra",
                         "affected_versions": {"4.0.0 - 4.6.4": {"from_version": "4.0.0", "from_inclusive": True,
                                                                 "to_version": "4.6.4", "to_inclusive": False}},
                         "patched": True, "patched_versions": ["4.6.4"]}], "cve": None, "cvss": {"score": 6.4}},
    "a3": {"id": "a3", "title": "Closed plugin", "informational": True, "software": [], "cve": None},
}


def test_wordpress_detect_and_feed():
    html = ('<link href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.3.1">'
            '<script src="/wp-content/plugins/elementor/assets/frontend.min.js?ver=6.4.2"></script>'
            '<link href="https://blog.test/wp-content/themes/astra/style.min.css?ver=4.6.4">')
    wp = WP.detect(html, "6.4.2")
    assert [(x["slug"], x["version"]) for x in wp["plugins"]] == [("contact-form-7", "5.3.1"), ("elementor", "")]
    assert wp["themes"][0]["slug"] == "astra" and wp["themes"][0]["version"] == "4.6.4"
    assert WP.readme_version("=== CF7 ===\nStable tag: 5.8.1\n") == "5.8.1"
    for payload in (json.dumps(FEED), json.dumps(list(FEED.values())), "\n".join(json.dumps(v) for v in FEED.values())):
        rows = list(WP.feed_rows(WP.iter_feed(io.BytesIO(payload.encode()), chunk=17)))
        assert [(r[1], r[2]) for r in rows] == [("contact-form-7", "plugin"), ("astra", "theme")]
    assert WP.in_ranges("5.3.1", [["*", True, "5.3.1", True]]) is True
    assert WP.in_ranges("5.3.2", [["*", True, "5.3.1", True]]) is False
    assert WP.in_ranges("4.6.4", [["4.0.0", True, "4.6.4", False]]) is False
    assert WP.in_ranges("", [["*", True, "*", True]]) is None
    assert WP.ranges_from_title("WordPress File Manager 6.0-6.8 - Remote Code Execution") == [["6.0", True, "6.8", True]]
    assert WP.ranges_from_title("WordPress Events Calendar <1.4.5 - XSS") == [["*", True, "1.4.5", False]]
    assert WP.ranges_from_title("WordPress Plugin Forminator 1.24.6 - Arbitrary File Upload") == []
    assert WP.slug_from_template("path:\n  - '{{BaseURL}}/wp-content/plugins/wp-file-manager/lib/php/connector.php'"
                                 ) == "plugin:wp-file-manager"


def test_wordfence_and_nuclei_plugins(app, monkeypatch):
    port = free_port()
    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            seen["auth"] = self.headers.get("Authorization")
            seen["path"] = self.path
            data = json.dumps(FEED).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setitem(WP.WORDFENCE_URLS, "production",
                            f"http://127.0.0.1:{port}/api/intelligence/v3/vulnerabilities/production")
        db = app.protection.vulndb
        assert db._wordfence("wf-key") == 2
        assert seen["auth"] == "Bearer wf-key" and seen["path"].endswith("/v3/vulnerabilities/production")
        # уязвимость с публичным эксплойтом из шаблона nuclei: slug из пути, версии — из записи CVE
        app.db.execute("INSERT INTO vulns(cve,name,kev,cvss,wp,ranges,template,updated) VALUES(?,?,?,?,?,?,?,0)",
                       ("CVE-2023-4596", "WordPress Plugin Forminator 1.24.6 - Arbitrary File Upload", 0, 9.8,
                        "plugin:forminator", json.dumps([{"product": "wpmudev Forminator", "v": "0",
                                                          "lte": "1.24.6"}]), "http/cves/2023/CVE-2023-4596.yaml"))
        app.db.execute("INSERT INTO vulns(cve,name,kev,cvss,wp,ranges,template,updated) VALUES(?,?,?,?,?,?,?,0)",
                       ("CVE-2020-35489", "WordPress Contact Form 7 - File Upload", 0, 10.0, "plugin:contact-form-7",
                        "[]", "http/cves/2020/CVE-2020-35489.yaml"))
        app.db.execute("INSERT INTO vulns(cve,name,kev,cvss,wp,ranges,template,updated) VALUES(?,?,?,?,?,?,?,0)",
                       ("CVE-2020-25213", "WordPress File Manager 6.0-6.8 - Remote Code Execution", 1, 9.8,
                        "plugin:wp-file-manager", json.dumps([{"product": "", "v": "n/a"}]),
                        "http/cves/2020/CVE-2020-25213.yaml"))
        assert db.wp_vulns_for("plugin", "wp-file-manager", "6.8")[0]["affected"] is True
        assert db.wp_vulns_for("plugin", "wp-file-manager", "6.9")[0]["affected"] is False
        site_wp = {"plugins": [{"slug": "contact-form-7", "version": "5.3.1", "evidence": "x"},
                               {"slug": "forminator", "version": "1.24.6", "evidence": "y"},
                               {"slug": "elementor", "version": "", "evidence": "z"}],
                   "themes": [{"slug": "astra", "version": "4.6.3", "evidence": "w"}]}
        app.db.kv_set("site_tech", {"1": {"ts": time.time(), "name": "Блог", "tech": [
            {"id": "wordpress", "name": "WordPress", "cat": "cms", "version": "6.4.2", "evidence": "g"}],
            "wp": site_wp}})
        res = {f"{w['type']}:{w['slug']}": w for w in db.tech_vulns()[0]["wp"]}
        cf7 = res["plugin:contact-form-7"]
        assert cf7["name"] == "Contact Form 7" and cf7["affected_n"] == 1
        assert cf7["affected"][0]["exploit"] is True and cf7["affected"][0]["patched"] == "5.3.2"
        assert res["plugin:forminator"]["affected_n"] == 1 and res["theme:astra"]["affected_n"] == 1
        assert res["plugin:elementor"]["known"] == 0
        assert db.wp_vulns_for("plugin", "contact-form-7", "5.3.2")[0]["affected"] is False
        assert db.wp_vulns_for("plugin", "contact-form-7", "")[0]["affected"] is None
        found = [x for x in app.protection.analytics.insights() if x[0] == "wp_vulnerable"]
        assert {x[6] for x in found} == {"1:plugin:contact-form-7", "1:plugin:forminator", "1:theme:astra"}
        assert next(x for x in found if x[6] == "1:plugin:contact-form-7")[1] == "crit"
        card = db.get("CVE-2023-4596")
        assert card["on_sites"] == [{"site": "1", "name": "Блог", "tech": "плагин forminator", "version": "1.24.6",
                                     "note": "", "affected": True}]
        # шаблоны уязвимостей WordPress загружаются, только если WordPress есть на сайтах
        assert {r["cve"] for r in db.wp_candidates()} == {"CVE-2023-4596", "CVE-2020-35489", "CVE-2020-25213"}
        app.db.kv_set("site_tech", {})
        assert db.wp_candidates() == []
    finally:
        srv.shutdown()


# =============================================================================
#  Telegram: команды
# =============================================================================
def test_telegram_commands(app):
    from app.models import AlertChannel
    ch = AlertChannel(name="TG", type="telegram", telegram_token="1:x", telegram_chat_id="-1007",
                      telegram_actions=True, telegram_admins=["@boss"])
    bot = app.tgbot

    def msg(text, chat="-1007", user=None):
        return {"message_id": 5, "text": text, "chat": {"id": int(chat)}, "from": user or {"id": 1, "username": "boss"}}
    assert bot.command(ch, msg("привет")) is None
    assert bot.command(ch, msg("/weather")) is None
    assert bot.command(ch, msg("/status", chat="-999")) is None
    assert bot.command(ch, msg("/status", user={"id": 2, "username": "x"}))[0].startswith("Нет прав")
    text, _ = bot.command(ch, msg("/help@nm_bot"))
    assert "/ban" in text and "/status" in text
    text, _ = bot.command(ch, msg("/status"))
    assert "nginx:" in text and "Атак за час: 0" in text and "Заблокированных адресов: 0" in text
    assert bot.command(ch, msg("/ban"))[0].startswith("Укажите адрес")
    assert bot.command(ch, msg("/ban 203.0.113.9 x"))[0].startswith("Срок")
    assert bot.command(ch, msg("/ban 203.0.113.9 6"))[0] == "203.0.113.9 заблокирован на 6 ч"
    row = app.db.one("SELECT * FROM bans WHERE net='203.0.113.9'")
    assert row and row["username"] == "telegram:@boss" and 6 * 3600 - 60 < row["expires_at"] - time.time() <= 6 * 3600
    text, kb = bot.command(ch, msg("/ip 203.0.113.9"))
    assert "Заблокирован" in text and kb["inline_keyboard"][0][0]["text"] == "Разблокировать"
    assert bot.command(ch, msg("/unban 203.0.113.9"))[0] == "203.0.113.9 разблокирован"
    assert bot.command(ch, msg("/top"))[0] == "За последний час атак не было"
