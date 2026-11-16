"""Защита от атак 2.1: проверка роботов по официальным адресам, правила ограничения частоты, свои правила по
стране, ModSecurity + OWASP CRS (тело запроса), аналитика. Живые проверки — на настоящем nginx."""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from app.models import (Backend, CustomRule, GlobalSettings, PanelSettings, ProtectionSettings, RateRule, Site,
                        SiteProtection, VerifiedBot)
from app.nginx.generator import Generator, Paths, State
from app.protection.nginx import find_crs
from app.protection.service import _json_nets, bucket_step, classify_ua, parse_feed, rule_category
from tests.test_protection import Backend200, free_port

TMP = Path(os.environ["NM_TEST_TMP"]) / "prot2"


def http(port, path="/", host="a.test", method="GET", headers=None, source="127.0.0.1", body=b""):
    s = socket.create_connection(("127.0.0.1", port), timeout=10, source_address=(source, 0))
    try:
        lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
        lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
        if body:
            lines.append(f"Content-Length: {len(body)}")
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
    except ConnectionResetError:
        return None
    finally:
        s.close()
    return int(buf.split()[1]) if buf else None


def test_parse_json_feed_and_helpers():
    doc = {"creationTime": "x", "prefixes": [{"ipv4Prefix": "66.249.64.0/27"}, {"ipv6Prefix": "2001:4860:4801:10::/64"},
                                            {"ipv4Prefix": "66.249.64.0/27"}]}
    nets, bad = parse_feed(json.dumps(doc))
    assert nets == ["66.249.64.0/27", "2001:4860:4801:10::/64"] and bad == 0
    assert set(_json_nets(doc)) == {"66.249.64.0/27", "2001:4860:4801:10::/64"}
    ddg = {"creationTime": "2025-11-04T15:57:38.092840+00:00", "prefixes": [{"ipv4Prefix": "104.43.54.127"}]}
    assert parse_feed(json.dumps(ddg))[0] == ["104.43.54.127"]
    assert classify_ua("sqlmap/1.8#stable") == "sqlmap" and classify_ua("") == "empty"
    assert classify_ua("Mozilla/5.0 (compatible; Googlebot/2.1)") == "bot"
    assert classify_ua("python-requests/2.31") == "python" and classify_ua("Mozilla/5.0 (X11)") == "browser"
    assert rule_category("waf", "sqli/sqli-union") == "sqli" and rule_category("modsec", "modsec/942100") == "sqli"
    assert rule_category("modsec", "modsec/941110") == "xss" and rule_category("threat", "threat/x:block") == "threat"
    assert bucket_step(1) == 300 and bucket_step(24) == 1800 and bucket_step(24 * 30) == 6 * 3600


def test_models_validation():
    r = RateRule(name="Поиск", path="/search", methods=["GET", "GET"], rate="30r/m")
    assert r.methods == ["GET"] and re.match(r"^[0-9a-f]{8}$", r.id)
    with pytest.raises(Exception):
        RateRule(name="x", path="search", rate="30r/m")
    c = CustomRule(name="страны", field="country", op="in", value="ru, cn")
    assert c.value == "RU CN"
    with pytest.raises(Exception):
        CustomRule(name="страны", field="country", op="contains", value="RU")
    with pytest.raises(Exception):
        VerifiedBot(id="x", name="x", url="https://x.test/b.json", ua='bad"ua')
    with pytest.raises(Exception):
        ProtectionSettings(modsec_disabled_ids=[0])
    assert ProtectionSettings(modsec_disabled_ids=[942100, 942100, 941100]).modsec_disabled_ids == [941100, 942100]
    assert len(ProtectionSettings().verified_bots) == 8


@pytest.fixture(scope="module")
def live2():
    if not shutil.which("nginx") or os.geteuid() != 0:
        pytest.skip("нужен nginx и root")
    from app.db import Database
    from app.nginx.manager import NginxManager
    TMP.mkdir(parents=True, exist_ok=True)
    os.chmod(TMP.parent, 0o755)
    os.chmod(TMP, 0o755)
    for d in ("logs", "cache/default", "live", "pages"):
        (TMP / d).mkdir(parents=True, exist_ok=True)
    mgr = NginxManager(Database(TMP / "t.db"))
    caps = mgr.caps()
    if "http_secure_link" not in caps.modules:
        pytest.skip("в nginx нет модуля secure_link")
    caps.pid_path = str(TMP / "nginx.pid")
    crs_dir, crs_ver = find_crs()
    modsec = bool(caps.modsecurity and crs_dir)
    bport, port, stub, panel = free_port(), free_port(), free_port(), free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", bport), Backend200)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    prot = ProtectionSettings(
        rate_rules=[RateRule(id="srch", name="Поиск", path="/search", methods=["GET"], rate="2r/m", burst=0, sites=[1])],
        custom_rules=[CustomRule(id="geo", name="страна", field="country", op="in", value="RU", action="block")],
        verified_bots=[VerifiedBot(id="google", name="Google", url="file:///dev/null", ua="googlebot")],
        fake_bot_action="block", modsec_enabled=modsec, modsec_mode="block")
    be = [Backend(address="127.0.0.1", port=bport)]
    s1 = Site(name="Частота и роботы", domains=["a.test"], http_port=port, backends=be,
              protection=SiteProtection(challenge="off", modsec="off"))
    s2 = Site(name="Проверка браузера", domains=["chal.test"], http_port=port, backends=be,
              protection=SiteProtection(challenge="on", modsec="off"))
    s3 = Site(name="ModSecurity блок", domains=["ms.test"], http_port=port, backends=be,
              protection=SiteProtection(challenge="off", modsec_exclude_paths=["/upload/"], bypass_ips=["127.0.0.9"]))
    s4 = Site(name="ModSecurity запись", domains=["msd.test"], http_port=port, backends=be,
              protection=SiteProtection(challenge="off", modsec="detect"))
    state = State([(1, s1), (2, s2), (3, s3), (4, s4)], [], GlobalSettings(access_log_buffer=""), PanelSettings(), {},
                  protection=prot)
    for name, text in (("threats.conf", ""), ("attack.conf", 'default "";\n'), ("bans.conf", ""),
                       ("geo.conf", "127.0.0.5/32 RU;\n"), ("bots.conf", "127.0.0.6 google;\n"),
                       ("bots-ua.conf", '"~*(?:googlebot)" google;\n')):
        (TMP / name).write_text(text)
    p = Paths(str(TMP / "stage"), str(TMP / "stage"), "/var/acme", str(TMP / "logs"), str(TMP / "cache"), stub, panel,
              str(TMP), bans_file=str(TMP / "bans.conf"), threats_file=str(TMP / "threats.conf"),
              attack_file=str(TMP / "attack.conf"), geo_file=str(TMP / "geo.conf"), challenge_secret="s",
              challenge_key="k", bots_file=str(TMP / "bots.conf"), bots_ua_file=str(TMP / "bots-ua.conf"),
              crs_dir=crs_dir and crs_dir, crs_version=crs_ver)
    gen = Generator(state, caps, p)
    files = gen.render()
    alt = {"80": str(free_port()), "443": str(free_port())}
    for rel, content in files.items():
        content = re.sub(r"(listen\s+(?:\[::\]:)?)(80|443)\b", lambda m: m.group(1) + alt[m.group(2)], content)
        (TMP / "stage" / rel).parent.mkdir(parents=True, exist_ok=True)
        (TMP / "stage" / rel).write_text(content)
    conf = str(TMP / "stage" / "nginx.conf")
    t = subprocess.run(["nginx", "-t", "-c", conf], capture_output=True, text=True)
    assert t.returncode == 0, t.stderr
    r = subprocess.run(["nginx", "-c", conf], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    time.sleep(0.3)
    yield {"port": port, "files": files, "log": TMP / "logs" / "nm-access.log", "modsec": modsec,
           "audit": TMP / "logs" / "nm-modsec-audit.log", "warnings": gen.warnings}
    subprocess.run(["nginx", "-s", "stop", "-c", conf], capture_output=True)
    srv.shutdown()


def last(live, n=1):
    return [json.loads(x) for x in live["log"].read_text().strip().splitlines()[-n:]]


def test_live_rate_rule(live2):
    port = live2["port"]
    codes = [http(port, "/search?q=1") for _ in range(4)]
    assert codes[0] == 200 and 429 in codes
    rec = last(live2)[0]
    assert rec["rs"] == "REJECTED" and rec["ri"] == "srch" and rec["s"] == "429"
    # правило касается только GET /search — другие пути и методы не ограничены
    assert all(http(port, "/other") == 200 for _ in range(4))
    assert http(port, "/search", method="POST") == 200


def test_live_country_rule(live2):
    port = live2["port"]
    assert http(port, "/", source="127.0.0.5") == 403
    rec = last(live2)[0]
    assert rec["wf"] == "custom/geo" and rec["wa"] == "block"
    assert http(port, "/", source="127.0.0.1") == 200


def test_live_fake_and_verified_bots(live2):
    port = live2["port"]
    ua = {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
    assert http(port, "/", headers=ua) == 403          # назвался Googlebot, но адрес не Google
    rec = last(live2)[0]
    assert rec["wf"] == "fakebot/google" and rec["bt"] == "google:0"
    assert http(port, "/", headers=ua, source="127.0.0.6") == 200   # настоящий
    assert last(live2)[0]["bt"] == "google:1"
    # проверенный робот проходит без страницы проверки браузера, обычный посетитель — нет
    assert http(port, "/", host="chal.test", headers=ua, source="127.0.0.6") == 200
    assert last(live2)[0]["ch"] == ""
    http(port, "/", host="chal.test")
    assert last(live2)[0]["ch"] == "c"


def test_live_modsecurity(live2):
    if not live2["modsec"]:
        pytest.skip("нет модуля ModSecurity или OWASP CRS")
    port = live2["port"]
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    body = b"user=admin&q=1' UNION SELECT password FROM users--"
    audit = live2["audit"]
    start = audit.stat().st_size if audit.exists() else 0
    assert http(port, "/login", host="ms.test", method="POST", headers=form, body=body) == 403   # тело запроса
    assert http(port, "/login", host="ms.test", method="POST", headers=form, body=b"user=admin&q=hello") == 200
    assert http(port, "/upload/x", host="ms.test", method="POST", headers=form, body=body) == 200   # исключённый путь
    assert http(port, "/login", host="ms.test", method="POST", headers=form, body=body, source="127.0.0.9") == 200
    assert http(port, "/login", host="msd.test", method="POST", headers=form, body=body) == 200     # только запись
    js = {"Content-Type": "application/json"}
    assert http(port, "/api", host="ms.test", method="POST", headers=js,
                body=b'{"q": "<script>alert(document.cookie)</script>"}') == 403
    assert http(port, "/", host="a.test", method="POST", headers=form, body=body) == 200           # сайт без ModSecurity
    time.sleep(0.5)
    lines = audit.read_bytes()[start:].decode().strip().splitlines()
    trs = [json.loads(x)["transaction"] for x in lines]
    ids = [t["unique_id"] for t in trs]
    assert any(i.startswith("3--") for i in ids) and any(i.startswith("4--") for i in ids)
    assert not any(i.startswith("3-a-") for i in ids)   # доверенный адрес не проверяется

    # разбор журнала аудита панелью → журнал атак
    from app.protection.service import ProtectionService

    class FakeApp:
        pass

    from app.db import Database
    app = FakeApp()
    app.db = Database(TMP / "audit.db")
    svc = ProtectionService(app)
    svc._settings = ProtectionSettings(autoban_waf=0)
    for t in trs:
        svc.observe_modsec(t)
    svc.flush()
    rows = app.db.query("SELECT site, kind, rule, action, status FROM attack_log ORDER BY id")
    assert {(r["site"], r["action"]) for r in rows} >= {("3", "blocked"), ("4", "detected")}
    assert all(r["kind"] == "modsec" and r["rule"].startswith("modsec/9") for r in rows)
    assert any(r["rule"].startswith("modsec/942") for r in rows) and any(r["rule"].startswith("modsec/941") for r in rows)
    assert "SQL" in svc.rule_title("modsec", next(r["rule"] for r in rows if r["rule"].startswith("modsec/942")))


def test_live_post_block_page(live2):
    """POST, отклонённый фильтром запросов, получает 403 со страницей (а не 405 от статического файла)."""
    port = live2["port"]
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    assert http(port, "/?f=../../etc/passwd", method="POST", headers=form, body=b"a=1") == 403
    assert last(live2)[0]["s"] == "403"
    conf = "".join(live2["files"].values())
    assert "error_page 418 =403 @nm_blocked" in conf
    # страница проверки браузера: адрес посетителя — только в X-Real-IP (X-Forwarded-For uvicorn принял бы за адрес
    # клиента панели и отказал бы: страница принимается только от nginx)
    loc = conf[conf.index("location = /.nm-challenge {"):]
    loc = loc[:loc.index("}")]
    assert 'proxy_set_header X-Forwarded-For "";' in loc and "proxy_set_header X-Real-IP $remote_addr;" in loc


def test_analytics_attackers_profile_rule(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    app = App()
    pr = app.protection
    now = time.time()
    base = {"method": "GET", "status": 403, "host": "s.test", "ustatus": ""}
    for i in range(6):
        pr.observe({**base, "ip": "203.0.113.50", "uri": f"/?id=1+UNION+SELECT+{i}", "ua": "sqlmap/1.8",
                    "wf": "sqli/sqli-union", "wa": "block", "rid": f"r{i}"}, "1", "CN", now - 60 * i)
    pr.observe({**base, "ip": "203.0.113.51", "uri": "/.env", "ua": "curl/8", "wf": "files/files-env", "wa": "block",
                "rid": "x"}, "1", "US", now)
    pr.observe({**base, "ip": "203.0.113.52", "uri": "/search", "ua": "Mozilla/5.0", "status": 429, "wf": "", "wa": "",
                "rs": "REJECTED", "ri": "srch", "rid": "y"}, "1", "", now)
    pr.observe({**base, "ip": "66.249.66.1", "uri": "/", "ua": "Googlebot", "status": 200, "wf": "", "wa": "",
                "bt": "google:1", "rid": "z"}, "1", "", now)
    pr.record_challenge("1", "solved", 0.7)
    pr.record_challenge("1", "failed")
    pr.flush()
    a = pr.analytics.analytics(24)
    assert a["attacks"] == 8 and a["unique_ips"] == 3
    assert {c["key"] for c in a["categories"]} >= {"sqli", "files", "ratelimit"}
    assert a["tools"][0]["key"] == "sqlmap" and a["tools"][0]["n"] == 6
    assert a["challenge"]["solved"]["n"] == 1 and a["solve"]["lt1"] == 1 and a["challenge"]["failed"]["n"] == 1
    assert a["bots"] == [{"id": "google", "name": "Googlebot и другие роботы Google", "ok": 1, "fake": 0}]
    assert a["ratelimit"][0]["id"] == "srch" and a["rules"][0]["rule"] == "sqli/sqli-union"
    assert a["rules"][0]["ips"] == 1 and sum(a["rules"][0]["spark"]) == 6
    att = pr.analytics.attackers(24)
    top = att[0]
    assert top["ip"] == "203.0.113.50" and top["tool"] == "sqlmap" and top["n"] == 6 and top["score"] >= 50
    prof = pr.analytics.ip_profile("203.0.113.50")
    assert prof["summary"]["n"] == 6 and prof["rules"][0]["rule"] == "sqli/sqli-union" and prof["uas"][0]["tool"] == "sqlmap"
    rd = pr.analytics.rule_detail("waf", "sqli/sqli-union")
    assert rd["totals"]["blocked"] == 6 and rd["meta"]["category"] and rd["ips"][0]["ip"] == "203.0.113.50"
    # история «Под атакой»
    import asyncio
    asyncio.run(pr.set_attack(1, True, minutes=10, user="admin", reason="тест"))
    asyncio.run(pr.set_attack(1, False, user="admin"))
    per = pr.analytics.analytics(1)["periods"]
    assert per and per[0]["site"] == "1" and per[0]["end"] and per[0]["who"] == "admin"
