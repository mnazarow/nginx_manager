"""Защита 2.3: технологии сайтов, сети провайдеров (ASN), обмен данными об угрозах (AbuseIPDB, CrowdSec), раздел
«Безопасность» в отчёте, автообновление баз GeoIP, несколько серверов (общие блокировки и настройки защиты)."""
from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from app.protection import fingerprint as FP
from app.protection import intel as I
from app.services import asn as A
from tests.test_protection import free_port

AB_KEY = "a" * 40


class Mock(BaseHTTPRequestHandler):
    """AbuseIPDB, CrowdSec LAPI и «другой сервер» Nginx Manager."""
    calls: list = []

    def log_message(self, *a):  # noqa: D401
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        Mock.calls.append(("GET", u.path, dict(parse_qs(u.query)), dict(self.headers), None))
        if u.path.startswith("/api/v2/"):
            if self.headers.get("Key") != AB_KEY:
                return self._send(401, {"errors": [{"detail": "Authentication failed"}]})
            if u.path == "/api/v2/check":
                ip = parse_qs(u.query)["ipAddress"][0]
                return self._send(200, {"data": {"ipAddress": ip, "abuseConfidenceScore": 100, "totalReports": 321,
                                                 "numDistinctUsers": 45, "isp": "Demo Hosting", "usageType":
                                                 "Data Center/Web Hosting/Transit", "domain": "demo.test",
                                                 "countryCode": "NL", "isTor": False, "isWhitelisted": False,
                                                 "lastReportedAt": "2026-11-15T10:00:00+00:00"}})
            if u.path == "/api/v2/blacklist":
                return self._send(200, {"meta": {}, "data": [{"ipAddress": "198.51.100.7"},
                                                             {"ipAddress": "2001:db8::7"}, {"ipAddress": "bad"}]})
        if u.path == "/v1/decisions/stream":
            if self.headers.get("X-Api-Key") != "bouncerkey123":
                return self._send(403, {"message": "access forbidden"})
            return self._send(200, {"new": [{"scope": "Ip", "value": "203.0.113.9", "type": "ban"},
                                            {"scope": "Range", "value": "192.0.2.0/24", "type": "ban"},
                                            {"scope": "Country", "value": "XX", "type": "ban"}], "deleted": []})
        if u.path == "/api/sync/hello":
            return self._send(200, {"id": "peer000000000001", "name": "web-2", "version": "2.3.0", "role": "admin"})
        self._send(404, {"detail": "Not Found"})

    def do_POST(self):  # noqa: N802
        u = urlparse(self.path)
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        Mock.calls.append(("POST", u.path, {}, dict(self.headers), raw))
        if u.path == "/api/v2/report":
            if self.headers.get("Key") != AB_KEY:
                return self._send(401, {"errors": [{"detail": "Authentication failed"}]})
            return self._send(200, {"data": {"ipAddress": parse_qs(raw.decode())["ip"][0], "abuseConfidenceScore": 100}})
        if u.path == "/api/sync/bans":
            if self.headers.get("Authorization") != "Bearer nm_peertoken_peertoken_1234":
                return self._send(401, {"detail": "Требуется вход"})
            return self._send(200, {"added": len(json.loads(raw)["bans"]), "removed": 0, "updated": 0, "name": "web-2"})
        if u.path == "/api/sync/protection":
            return self._send(200, {"ok": True, "applied": True, "version": 7})
        self._send(404, {"detail": "Not Found"})


@pytest.fixture(scope="module")
def mock():
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


@pytest.fixture()
def app(tmp_path, monkeypatch, mock):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(I, "ABUSEIPDB_API", mock + "/api/v2")
    settings.ensure_dirs()
    Mock.calls.clear()
    return App()


# =============================================================================
#  Технологии сайтов
# =============================================================================
def test_fingerprint_detect():
    wp = FP.detect([("Server", "Apache/2.4.58 (Ubuntu)"), ("X-Powered-By", "PHP/8.2.12"),
                    ("Set-Cookie", "wordpress_test_cookie=WP; path=/")],
                   '<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/themes/a.css">')
    got = {t["id"]: t["version"] for t in wp}
    assert got == {"wordpress": "6.4.2", "apache": "2.4.58", "php": "8.2.12"}
    assert [t["cat"] for t in wp] == ["cms", "server", "lang"]
    bx = {t["id"] for t in FP.detect([("Set-Cookie", "BITRIX_SM_GUEST_ID=1"), ("Set-Cookie", "PHPSESSID=x")], "")}
    assert bx == {"bitrix", "php"}
    conf = FP.detect([], '<title>Log In - Confluence</title><meta name="ajs-version-number" content="8.5.3">')
    assert conf[0]["id"] == "confluence" and conf[0]["version"] == "8.5.3"
    assert FP.detect([], "<title>My notes about Jira and Confluence</title>") == []  # упоминание — не продукт
    nx = {t["id"] for t in FP.detect([("X-Powered-By", "Next.js")], '<script id="__NEXT_DATA__">')}
    assert nx == {"nextjs", "nodejs"}
    jk = FP.detect([("X-Jenkins", "2.426.1")], "")
    assert jk[0]["id"] == "jenkins" and jk[0]["version"] == "2.426.1"
    assert "wordpress" in FP.keywords(["wordpress", "jquery"]) and "jquery" not in FP.keywords(["jquery"])


def test_fingerprint_scan_and_vulns(app, monkeypatch):
    """Сканирование сайта через бэкенд (с переходом по перенаправлению) и уязвимости найденных продуктов."""
    port = free_port()

    class App(BaseHTTPRequestHandler):
        server_version, sys_version = "demo", ""

        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            assert self.headers["Host"] == "wp.test"
            if self.path == "/":
                self.send_response(302)
                self.send_header("Location", "/home/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b'<meta name="generator" content="WordPress 6.4.2" />'
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/8.2.12")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", port), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        from app.models import Backend, Site
        site = Site(name="Блог", domains=["wp.test"], backends=[Backend(address="127.0.0.1", port=port)])
        r = FP.scan_site(site)
        assert r["status"] == 200 and {t["id"] for t in r["tech"]} == {"wordpress", "php"}
        monkeypatch.setattr(app.nginx, "load_state", lambda: type("S", (), {"sites": [(1, site)]})())
        res = app.protection.vulndb.scan_tech()
        assert {t["id"] for t in res["1"]["tech"]} == {"wordpress", "php"} and res["1"]["name"] == "Блог"
        app.db.executemany("INSERT INTO vulns(cve,name,vendor,product,kev,kev_added,updated) VALUES(?,?,?,?,?,?,?)",
                           [("CVE-2099-1001", "WP core", "WordPress", "WordPress Core", 1, "2099-01-01", 0),
                            ("CVE-2099-1002", "PHP-CGI", "PHP Group", "PHP", 1, "2020-01-01", 0),
                            ("CVE-2099-1003", "Other", "Acme", "Router", 1, "2099-01-01", 0)])
        db = app.protection.vulndb
        assert set(db.watch_keywords()) >= {"wordpress", "php group php"}
        mine = {r["cve"] for r in db.search(flt="mine")["rows"]}
        assert mine == {"CVE-2099-1001", "CVE-2099-1002"}
        tv = db.tech_vulns()[0]
        assert {t["id"]: t["kev"] for t in tv["tech"]} == {"wordpress": 1, "php": 1}
        assert db.get("CVE-2099-1001")["on_sites"][0]["version"] == "6.4.2"
        assert db.summary()["mine_kev"] == 2
        # новая уязвимость в найденном продукте — событие «внимание»
        db._announce_new(["CVE-2099-1001"], {"CVE-2099-1001": {"vendor": "WordPress", "product": "WordPress Core"}})
        assert app.db.kv_get("vulndb_new")["watch"] == ["CVE-2099-1001"]
    finally:
        srv.shutdown()


# =============================================================================
#  Сети провайдеров (ASN)
# =============================================================================
def make_asn_db(path: Path) -> None:
    from mmdb_writer import MMDBWriter
    from netaddr import IPSet
    w = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="GeoLite2-ASN", languages=["en"])
    w.insert_network(IPSet(["198.51.100.0/25", "198.51.100.128/25", "2001:db8::/32"]),
                     {"autonomous_system_number": 64500, "autonomous_system_organization": "Demo Hosting"})
    w.insert_network(IPSet(["203.0.113.0/24"]), {"autonomous_system_number": 64501,
                                                 "autonomous_system_organization": "Example Cloud"})
    w.to_db_file(str(path))


def test_asn_parse_build_lookup(tmp_path):
    pytest.importorskip("mmdb_writer")
    assert A.parse_asns("AS64500, 64501 as64500") == [64500, 64501]
    with pytest.raises(ValueError):
        A.parse_asns("ASX")
    db = tmp_path / "asn.mmdb"
    make_asn_db(db)
    text, st = A.build(str(db), [64500])
    lines = text.splitlines()
    assert lines[0].startswith("# nm-asn") and "asns=64500" in lines[0]
    assert "198.51.100.0/24 64500;" in lines and "2001:db8::/32 64500;" in lines  # соседние сети объединены
    assert st["orgs"][64500] == "Demo Hosting" and not any("203.0.113" in x for x in lines)
    lk = A.ASNLookup()
    lk.load(str(db), str(tmp_path))
    assert lk.lookup("203.0.113.5") == (64501, "Example Cloud") and lk.lookup("192.0.2.1") == (0, "")
    hdr = tmp_path / "asn-nets.conf"
    hdr.write_text(text)
    assert not A.needs_rebuild(str(hdr), str(db), {64500}) and A.needs_rebuild(str(hdr), str(db), {64500, 64501})
    from app.models import CustomRule
    r = CustomRule(name="сеть", field="asn", op="in", value="AS64500 64501", action="challenge")
    assert r.value == "64500 64501"
    with pytest.raises(Exception):
        CustomRule(name="сеть", field="asn", op="contains", value="AS1")


def test_asn_rule_nginx_and_analytics(app, tmp_path):
    pytest.importorskip("mmdb_writer")
    from app.config import settings
    from app.models import CustomRule, ProtectionSettings
    from app.nginx.generator import Generator, GlobalSettings, PanelSettings, Paths, State
    make_asn_db(settings.geoip_dir / "dbip-asn-lite.mmdb")
    app.stats.reload_geoip()
    prot = ProtectionSettings(custom_rules=[CustomRule(id="net1", name="сеть", field="asn", op="in", value="AS64501",
                                                       action="block")])
    state = State([], [], GlobalSettings(), PanelSettings(), {}, protection=prot)
    app.nginx.prepare_asn(state)
    assert "203.0.113.0/24 64501;" in settings.asn_file.read_text()
    paths = app.nginx.paths(str(settings.live_dir))
    assert paths.asn_file == str(settings.asn_file)
    files = Generator(state, app.nginx.caps(), paths).render()
    conf = files["http.d/05-protection.conf"]
    assert "geo $nm_asn {" in conf and "map $nm_asn $nm_cr_net1 {" in conf and '    64501 "1";' in conf
    # без базы ASN правило не действует и предупреждает
    paths2 = Paths(**{**paths.__dict__, "asn_file": ""})
    g2 = Generator(state, app.nginx.caps(), paths2)
    assert "$nm_asn" not in g2.render()["http.d/05-protection.conf"] and any("ASN" in w for w in g2.warnings)
    # атакующие сети в аналитике и профиле адреса
    pr = app.protection
    now = time.time()
    for i in range(4):
        pr.observe({"method": "GET", "status": 403, "host": "s.test", "ustatus": "", "ip": f"203.0.113.{i}",
                    "uri": "/.env", "ua": "curl/8", "wf": "files/files-env", "wa": "block", "rid": f"a{i}"}, "1", "NL",
                   now)
    pr.observe({"method": "GET", "status": 403, "host": "s.test", "ustatus": "", "ip": "198.51.100.9",
                "uri": "/.git/config", "ua": "curl/8", "wf": "files/files-git", "wa": "block", "rid": "b"}, "1", "", now)
    pr.flush()
    nets = pr.analytics.analytics(1)["networks"]
    assert nets[0] == {"asn": 64501, "org": "Example Cloud", "n": 4, "ips": 4, "country": "NL"}
    att = pr.analytics.attackers(1, q="AS64500")
    assert [r["ip"] for r in att] == ["198.51.100.9"] and att[0]["org"] == "Demo Hosting"
    prof = pr.analytics.ip_profile("203.0.113.1", 1)
    assert prof["network"]["asn"] == 64501 and prof["network"]["ips"] == 4


# =============================================================================
#  AbuseIPDB и CrowdSec
# =============================================================================
def test_report_categories_and_comment():
    cats = I.report_categories([("waf", "sqli/sqli-union"), ("waf", "vuln/CVE-2021-40539"), ("fakebot", "fakebot/google"),
                                ("ratelimit", "ratelimit/login")], "sqlmap")
    assert cats == [15, 16, 18, 19, 21]
    assert I.report_categories([("waf", "xss/xss-script")]) == [21]
    c = I.report_comment([("waf", "sqli/sqli-union", 12), ("waf", "files/files-env", 3)])
    assert "(15)" in c and "sqli/sqli-union x12" in c and "example" not in c


def test_abuseipdb_and_crowdsec(app, mock):
    pr = app.protection
    assert pr.intel.check("198.51.100.1") == {"error": "не задан ключ AbuseIPDB («Защита → Обмен данными»)"}
    p = pr.settings().model_copy(update={"abuseipdb_key": AB_KEY, "abuseipdb_report": "auto",
                                         "abuseipdb_report_score": 40, "abuseipdb_blacklist": True,
                                         "crowdsec_url": mock, "crowdsec_key": "bouncerkey123"})
    pr.save(p)
    r = pr.intel.check("198.51.100.1")
    assert r["score"] == 100 and r["reports"] == 321 and r["isp"] == "Demo Hosting" and r["link"].endswith("198.51.100.1")
    n = len(Mock.calls)
    pr.intel.check("198.51.100.1")
    assert len(Mock.calls) == n  # кэш на сутки
    # жалоба: категории по правилам, без доменов сайтов
    now = time.time()
    for i in range(30):
        pr.observe({"method": "GET", "status": 403, "host": "secret-site.example", "ustatus": "", "ip": "198.51.100.66",
                    "uri": f"/?id=1+UNION+SELECT+{i}", "ua": "sqlmap/1.8", "wf": "sqli/sqli-union", "wa": "block",
                    "rid": f"r{i}"}, "1", "", now - 30)
    pr.flush()
    with pytest.raises(ValueError):
        pr.intel.report("192.0.2.200")  # атак не было
    sent = pr.intel.auto_report()
    assert sent == 1 and "198.51.100.66" in pr.intel.reported()
    body = next(c[4] for c in Mock.calls if c[1] == "/api/v2/report").decode()
    from urllib.parse import parse_qs as pq
    form = pq(body)
    assert form["ip"] == ["198.51.100.66"] and form["categories"] == ["15,16,21"]
    assert "secret-site" not in body and "sqli%2Fsqli-union" in body or "sqli/sqli-union" in form["comment"][0]
    assert pr.intel.auto_report() == 0  # не чаще раза в сутки на адрес
    assert pr.intel.status()["abuseipdb_report"]["sent"] == 1
    # списки: чёрный список AbuseIPDB и решения CrowdSec → файл списков угроз
    st = asyncio.run(pr.update_intel("abuseipdb", force=True))
    assert st["ok"] and st["count"] == 2
    st = asyncio.run(pr.update_intel("crowdsec", force=True))
    assert st["ok"] and st["count"] == 2
    content, total = pr.render_threats()
    assert '203.0.113.9 "crowdsec:block";' in content and '192.0.2.0/24 "crowdsec:block";' in content
    assert '198.51.100.7 "abuseipdb:challenge";' in content and total == 4
    assert pr.rule_title("threat", "threat/crowdsec:block") == "Список угроз: CrowdSec (решения агента)"
    assert pr.ip_in_feeds("192.0.2.5")[0]["name"].startswith("CrowdSec")
    # nginx: geo $nm_threat подключается, даже если обычные списки угроз выключены
    from app.protection.nginx import ProtectionConf
    from app.nginx.generator import GlobalSettings, PanelSettings, State
    state = State([], [], GlobalSettings(), PanelSettings(), {}, protection=pr.settings())
    pc = ProtectionConf(state, app.nginx.paths("/x"), app.nginx.caps())
    assert pc.feeds_on()
    # неверный ключ CrowdSec — понятная ошибка
    pr.save(pr.settings().model_copy(update={"crowdsec_key": "wrongkey123"}))
    st = asyncio.run(pr.update_intel("crowdsec", force=True))
    assert not st["ok"] and "cscli bouncers add" in st["error"]


def test_intel_api_masks_secrets(app, mock):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.utils import hash_password
    api = create_app()
    with TestClient(api) as c:
        nm = api.state.nm
        nm.db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username='admin'",
                      (hash_password("Test-Passw0rd!"),))
        nm.protection.save(nm.protection.settings().model_copy(update={"abuseipdb_key": AB_KEY}))
        assert c.post("/api/auth/login", json={"username": "admin", "password": "Test-Passw0rd!"}).status_code == 200
        hdr = {"X-NM-CSRF": "1"}
        s = c.get("/api/protection/settings").json()["settings"]
        assert s["abuseipdb_key"] == "••••••••"
        assert c.put("/api/protection/settings", json=s, headers=hdr).status_code == 200
        assert nm.protection.settings().abuseipdb_key == AB_KEY  # маска — ключ не меняется
        r = c.get("/api/protection/ip/198.51.100.3/intel").json()
        assert r["abuseipdb"]["score"] == 100
        assert c.get("/api/protection/ip/bad/intel").status_code == 400
        assert c.post("/api/protection/intel/test", json={"what": "abuseipdb"}, headers=hdr).json()["ok"]
        assert c.get("/api/protection/intel").json()["abuseipdb"]["configured"]


# =============================================================================
#  Отчёт: раздел «Безопасность»
# =============================================================================
def test_report_security_section(app):
    from app.services import reports
    pr = app.protection
    now = time.time()
    for i in range(5):
        pr.observe({"method": "GET", "status": 403, "host": "s.test", "ustatus": "", "ip": "198.51.100.77",
                    "uri": "/remote/fgt_lang", "ua": "curl/8", "wf": "vuln/CVE-2018-13379", "wa": "block",
                    "rid": f"x{i}"}, "1", "NL", now - 120)
    pr.flush()
    app.db.kv_set("vulndb_new", {"ts": now - 60, "cves": ["CVE-2099-1"], "watch": ["CVE-2099-1"]})
    lines = reports.security_lines(app, now - 3600, now + 1, 3600)
    text = "\n".join(lines)
    assert "атак: 5" in text and "CVE-2018-13379 — 5" in text and "198.51.100.77 (NL)" in text
    assert "CVE-2099-1" in text
    assert reports.security_lines(app, now - 10 * 86400, now - 9 * 86400, 86400) == [" • атак за период не было"]


# =============================================================================
#  Автообновление баз GeoIP
# =============================================================================
def test_geoip_update(app, tmp_path, monkeypatch):
    pytest.importorskip("mmdb_writer")
    from app.config import settings
    from app.services import geoupdate as G
    db = tmp_path / "src.mmdb"
    make_asn_db(db)
    import gzip
    (tmp_path / "asn.mmdb.gz").write_bytes(gzip.compress(db.read_bytes()))
    assert G.months(time.mktime((2026, 1, 15, 0, 0, 0, 0, 0, -1))) == ["2026-01", "2025-12"]
    assert G.urls("asn", time.time())[-1].endswith("/dbip-asn.mmdb")
    monkeypatch.setitem(G.KINDS["asn"], "dbip", "file:///nonexistent/{ym}.gz")
    monkeypatch.setattr(G, "MIRROR", f"file://{tmp_path}/asn.mmdb.gz?{{name}}".split("?")[0])
    up = app.geoupdate
    assert up.due("asn", time.time())
    res = up.update_sync(only="asn")
    assert res["asn"]["ok"] and (settings.geoip_dir / "dbip-asn-lite.mmdb").stat().st_size > 0
    assert not up.due("asn", time.time())
    asyncio.run(app.refresh_geo())
    assert app.stats.asn.lookup("203.0.113.1")[0] == 64501
    # повреждённый файл не заменяет рабочую базу
    (tmp_path / "asn.mmdb.gz").write_bytes(gzip.compress(b"not a database"))
    res = up.update_sync(force=True, only="asn")
    assert not res["asn"]["ok"] and app.stats.asn.lookup("203.0.113.1")[0] == 64501


# =============================================================================
#  Несколько серверов
# =============================================================================
def test_peers_receive_and_push(app, mock):
    from app.models import PanelSettings, Peer
    ps = app.peers
    me = ps.origin()["id"]
    with pytest.raises(ValueError):
        ps.receive_bans({"id": me, "name": "я"}, [], "sync")
    o = {"id": "peer000000000001", "name": "web-2"}
    app.bans.add("198.51.100.10", None, "своя", "manual")
    r = ps.receive_bans(o, [{"net": "203.0.113.5", "expires_at": time.time() + 3600, "reason": "сканер"},
                            {"net": "198.51.100.10", "expires_at": None},           # своя блокировка важнее
                            {"net": "127.0.0.1", "expires_at": None},               # доверенный — не блокируем
                            {"net": "192.0.2.0/24", "expires_at": time.time() - 5},  # истекла
                            {"net": "bad", "expires_at": None}], "sync")
    assert r["added"] == 1 and r["removed"] == 0
    row = app.db.one("SELECT * FROM bans WHERE net='203.0.113.5'")
    assert row["source"] == "sync:peer000000000001" and "web-2" in row["reason"]
    assert app.db.one("SELECT source FROM bans WHERE net='198.51.100.10'")["source"] == "manual"
    r = ps.receive_bans(o, [], "sync")  # блокировку сняли на том сервере
    assert r["removed"] == 1 and not app.db.one("SELECT 1 FROM bans WHERE net='203.0.113.5'")
    # отправка: свои блокировки (кроме полученных), токен получателя
    ps.receive_bans(o, [{"net": "203.0.113.6", "expires_at": None}], "sync")
    panel = PanelSettings(peers=[Peer(name="web-2", url=mock, token="nm_peertoken_peertoken_1234", protection=True)])
    app.save_panel(panel)
    res = ps.push_bans()
    pid = panel.peers[0].id
    assert res[pid]["ok"] and res[pid]["sent"] == 1
    body = json.loads(next(c[4] for c in reversed(Mock.calls) if c[1] == "/api/sync/bans"))
    assert [b["net"] for b in body["bans"]] == ["198.51.100.10"] and body["origin"]["id"] == me
    assert ps.status()[pid]["bans_ok"]
    assert ps.test(panel.peers[0])["ok"]
    assert ps.push_protection()[pid]["ok"]
    sent = json.loads(next(c[4] for c in reversed(Mock.calls) if c[1] == "/api/sync/protection"))
    assert "waf_modes" in sent["settings"]
    bad = PanelSettings(peers=[Peer(name="web-2", url=mock, token="nm_wrongtoken_wrongtoken_99")])
    app.save_panel(bad)
    res = ps.push_bans()
    assert not res[bad.peers[0].id]["ok"] and "токен" in res[bad.peers[0].id]["error"]
    with pytest.raises(Exception):
        Peer(name="x", url="ftp://host", token="nm_" + "a" * 30)


def test_sync_api(app):
    """Приём блокировок и настроек защиты через API с токеном; свои правила, привязанные к сайтам, остаются."""
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.models import CustomRule
    api = create_app()
    with TestClient(api) as c:
        nm = api.state.nm
        uid = nm.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        token = nm.auth.create_token(uid, "sync", role="admin")
        h = {"Authorization": f"Bearer {token}"}
        assert c.get("/api/sync/hello", headers=h).json()["id"] == nm.peers.origin()["id"]
        r = c.post("/api/sync/bans", headers=h, json={"origin": {"id": "abcabcabcabc0001", "name": "web-3"},
                                                      "bans": [{"net": "203.0.113.77", "expires_at": None}]}).json()
        assert r["added"] == 1
        assert c.post("/api/sync/bans", headers=h, json={"bans": []}).status_code == 400
        nm.protection.save(nm.protection.settings().model_copy(update={"custom_rules": [
            CustomRule(id="mine1", name="свой сайт", sites=[1], field="path", op="prefix", value="/x")],
            "crowdsec_url": "http://127.0.0.1:8080", "crowdsec_key": "localkey123"}))
        incoming = nm.protection.settings().model_dump()
        incoming.update(waf_modes={"sqli": "detect"}, crowdsec_url="http://10.0.0.1:8080", crowdsec_key="other12345",
                        custom_rules=[{"id": "glob1", "name": "общее", "field": "path", "op": "prefix", "value": "/y",
                                       "sites": []}, {"id": "site9", "name": "чужой сайт", "sites": [9], "field": "path",
                                                      "op": "prefix", "value": "/z"}])
        r = c.post("/api/sync/protection", headers=h, json={"origin": {"id": "abcabcabcabc0001", "name": "web-3"},
                                                            "settings": incoming}).json()
        assert r["ok"]
        p = nm.protection.settings()
        assert p.waf_modes == {"sqli": "detect"} and p.crowdsec_url == "http://127.0.0.1:8080"
        assert sorted(x.id for x in p.custom_rules) == ["glob1", "mine1"]
        v = nm.auth.create_token(uid, "viewer", role="viewer")
        assert c.post("/api/sync/bans", headers={"Authorization": f"Bearer {v}"},
                      json={"origin": {"id": "x" * 16}, "bans": []}).status_code == 403
        st = c.get("/api/peers", headers=h).json()
        assert st["incoming"][0]["name"] == "web-3" and st["incoming"][0]["active"] == 1


def test_peer_tokens_masked(app):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.models import PanelSettings, Peer
    api = create_app()
    with TestClient(api) as c:
        nm = api.state.nm
        nm.save_panel(PanelSettings(peers=[Peer(name="web-2", url="https://10.0.0.2:8088",
                                                token="nm_secrettoken_secrettoken_1")]))
        uid = nm.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        h = {"Authorization": f"Bearer {nm.auth.create_token(uid, 't', role='admin')}"}
        d = c.get("/api/settings/panel", headers=h).json()
        assert d["peers"][0]["token"] == "••••••••"
        d["peers"][0]["name"] = "web-2 (новое имя)"
        assert c.put("/api/settings/panel", headers=h, json=d).status_code == 200
        p = nm.panel().peers[0]
        assert p.token == "nm_secrettoken_secrettoken_1" and p.name == "web-2 (новое имя)"
