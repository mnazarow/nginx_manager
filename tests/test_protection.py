"""Защита от атак: каталог правил (примеры ловятся, обычные запросы — нет), сборка конфигурации и её поведение в
настоящем nginx (блокировка, запись, исключения, свои правила, списки угроз, хотлинкинг, защита входа, SNI,
пропуск проверки браузера), журнал атак, оценка, проверка пропуска и задачи proof-of-work."""
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.models import (Backend, CustomRule, GlobalSettings, PanelSettings, ProtectionSettings, Site, SiteProtection,
                        ThreatFeed)
from app.nginx.generator import Generator, Paths, State
from app.protection import rules as W
from app.protection.challenge import leading_zero_bits, pass_token, safe_return
from app.protection.service import parse_feed, selftest_cases

TMP = Path(os.environ["NM_TEST_TMP"]) / "prot"
SECRET = "test-secret-123"


# ---------------------------------------------------------------- каталог
def test_catalog_examples_and_false_positives():
    bad = []
    for r in W.RULES:
        assert r.cat in W.CATEGORIES, r.id
        W.nginx_quote(r.pattern)
        assert r.examples, f"{r.id}: нет примера атаки"
        for ex in r.examples:
            if not W.match(r, ex):
                bad.append(f"не ловит {r.id}: {ex}")
        if r.level == 1 and not r.cat.startswith("bots") and r.cat != "redirect":
            for t in r.targets:
                corpus = W.BENIGN_URIS if t == "uri" else W.BENIGN_UA if t == "ua" else []
                bad += [f"ложное {r.id}: {b}" for b in corpus if W.match(r, b)]
    assert not bad, bad
    assert len({r.id for r in W.RULES}) == len(W.RULES)
    assert len(W.RULES) >= 90 and sum(1 for r in W.RULES if r.cve) >= 25


def test_scan_and_quote():
    hits = {r.id for r in W.scan({"uri": "/?id=1 UNION SELECT 1,2", "ua": "sqlmap/1.7"})}
    assert {"sqli-union", "scan-ua"} <= hits
    assert W.nginx_quote(r'a\"b') == '"a\\"b"' and W.nginx_quote("x\\\\y") == '"x\\\\\\\\y"'
    with pytest.raises(ValueError):
        W.nginx_quote(r"a\nb")


def test_parse_feed():
    text = "# comment\n1.2.3.4\n10.0.0.0/8 ; SBL1\n1.2.3.4\nbad\n0.0.0.0/0\n2001:db8::/32\n5.6.7.8 5.6.7.255 24 x\n"
    nets, bad = parse_feed(text)
    assert nets == ["1.2.3.4", "10.0.0.0/8", "2001:db8::/32", "5.6.7.8"] and bad == 2


def test_challenge_crypto():
    assert leading_zero_bits(bytes([0, 0, 0x0F])) == 20 and leading_zero_bits(bytes([0x80])) == 0
    assert safe_return("//evil.com") == "/" and safe_return("/a?b=1") == "/a?b=1"
    assert safe_return("https://x") == "/" and safe_return("/.nm-challenge/verify") == "/"
    # формат совпадает с secure_link_md5 nginx: base64url(md5("срокIP секрет")) без «=»
    import base64
    raw = hashlib.md5(b"2000000000127.0.0.1 s").digest()
    assert pass_token("s", 2000000000, "127.0.0.1") == base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_selftest_cases_cover_categories():
    cats = {c["cat"] for c in selftest_cases(2)}
    assert {"sqli", "xss", "traversal", "rce", "java", "files", "scanners", "cve", "protocol"} <= cats


def test_models_validation():
    with pytest.raises(Exception):
        SiteProtection(waf_disabled_rules=["no-such-rule"])
    with pytest.raises(Exception):
        SiteProtection(waf_exclude_paths=["api"])
    with pytest.raises(Exception):
        CustomRule(name="x", field="ip", op="contains", value="1.2.3.4")
    with pytest.raises(Exception):
        ThreatFeed(id="Bad Id", name="x", url="https://e.com/l.txt")
    r = CustomRule(name="x", field="path", op="prefix", value="/admin")
    assert len(r.id) == 8
    assert ProtectionSettings(waf_modes={"sqli": "detect", "nope": "block"}).waf_modes == {"sqli": "detect"}


# ---------------------------------------------------------------- nginx вживую
def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Backend200(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "proxy": self.headers.get("Proxy"),
                           "xorig": self.headers.get("X-Original-URL")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET
    do_TRACE = do_GET

    def log_message(self, *a):
        pass


def req(port, path="/", host="prot.test", method="GET", headers=None, source="127.0.0.1"):
    s = socket.create_connection(("127.0.0.1", port), timeout=5, source_address=(source, 0))
    try:
        lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
        lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
    except ConnectionResetError:
        return None, b""
    finally:
        s.close()
    if not buf:
        return None, b""
    head, _, body = buf.partition(b"\r\n\r\n")
    return int(head.split()[1]), body


@pytest.fixture(scope="module")
def live_nginx():
    if not shutil.which("nginx") or os.geteuid() != 0:
        pytest.skip("нужен nginx и root")
    from app.nginx.manager import NginxManager
    from app.db import Database
    TMP.mkdir(parents=True, exist_ok=True)
    os.chmod(TMP.parent, 0o755)  # воркеру nginx нужен доступ к странице блокировки
    os.chmod(TMP, 0o755)
    for d in ("logs", "cache/default", "live", "pages"):
        (TMP / d).mkdir(parents=True, exist_ok=True)
    caps = NginxManager(Database(TMP / "t.db")).caps()
    if "http_secure_link" not in caps.modules:
        pytest.skip("в nginx нет модуля secure_link")
    caps.pid_path = str(TMP / "nginx.pid")
    bport, http, stub, panel = free_port(), free_port(), free_port(), free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", bport), Backend200)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    prot = ProtectionSettings(
        waf_modes={"sqli": "detect", "bots_ai": "block"},
        custom_rules=[CustomRule(id="blk", name="закрыть /secret", field="path", op="prefix", value="/secret"),
                      CustomRule(id="drp", name="evilbot", field="ua", op="contains", value="evilbot", action="drop"),
                      CustomRule(id="alw", name="партнёр", field="ip", op="in", value="127.0.0.3", action="allow"),
                      CustomRule(id="lg", name="метка", field="header", header="X-Test", op="equals", value="1",
                                 action="log")],
        threat_feeds=[ThreatFeed(id="t1", name="тест", url="file:///dev/null", enabled=True)])
    sp = SiteProtection(waf_exclude_paths=["/editor/"], waf_disabled_rules=["xss-dom"], login_protection=True,
                        login_paths=["/wp-login.php"], login_rate="1r/m", login_burst=0, hotlink=True,
                        hotlink_ext=["png"], bypass_ips=["127.0.0.2"], challenge="off")
    s1 = Site(name="Защищённый", domains=["prot.test"], http_port=http,
              backends=[Backend(address="127.0.0.1", port=bport)], protection=sp)
    s2 = Site(name="Проверка браузера", domains=["chal.test"], http_port=http,
              backends=[Backend(address="127.0.0.1", port=bport)], protection=SiteProtection(challenge="on"))
    s3 = Site(name="Без защиты", domains=["off.test"], http_port=http,
              backends=[Backend(address="127.0.0.1", port=bport)], protection=SiteProtection(enabled=False))
    state = State([(1, s1), (2, s2), (3, s3)], [], GlobalSettings(access_log_buffer=""), PanelSettings(), {},
                  protection=prot)
    threats = TMP / "threats.conf"
    threats.write_text('127.0.0.4 "t1:block";\n')
    attack = TMP / "attack.conf"
    attack.write_text('default "";\n')
    p = Paths(str(TMP / "stage"), str(TMP / "stage"), "/var/acme", str(TMP / "logs"), str(TMP / "cache"), stub, panel,
              str(TMP), bans_file=str(TMP / "bans.conf"), threats_file=str(threats), attack_file=str(attack),
              challenge_secret=SECRET, challenge_key="k")
    (TMP / "bans.conf").write_text("")
    gen = Generator(state, caps, p)
    files = gen.render()
    # сервер по умолчанию всегда слушает 80/443 — на машине с работающим nginx переносим их на свободные порты
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
    yield {"port": http, "files": files, "log": TMP / "logs" / "nm-access.log"}
    subprocess.run(["nginx", "-s", "stop", "-c", conf], capture_output=True)
    srv.shutdown()


def last_log(live, n=1):
    lines = live["log"].read_text().strip().splitlines()
    return [json.loads(x) for x in lines[-n:]]


def test_live_waf_block_detect_and_exclusions(live_nginx):
    port = live_nginx["port"]
    assert req(port, "/")[0] == 200
    st, body = req(port, "/?f=../../etc/passwd")
    assert st == 403 and "Номер запроса".encode() in body  # страница блокировки с номером запроса (SSI)
    rec = last_log(live_nginx)[0]
    assert rec["wf"] == "traversal/trav-dotdot" and rec["wa"] == "block" and rec["s"] == "403"
    # SQL-инъекции в режиме «запись»: запрос проходит, в журнале — detect
    assert req(port, "/?id=1%20union%20select%201,2")[0] == 200
    rec = last_log(live_nginx)[0]
    assert rec["wf"] == "sqli/sqli-union" and rec["wa"] == "detect"
    # заголовки: сканер и Log4Shell
    assert req(port, "/", headers={"User-Agent": "sqlmap/1.7"})[0] == 403
    assert req(port, "/", headers={"X-Api-Version": "${jndi:ldap://x/a}"})[0] == 403
    assert req(port, "/", headers={"User-Agent": "GPTBot/1.2"})[0] == 403  # bots_ai включены в блокировку
    # исключённый путь и отключённое правило сайта
    assert req(port, "/editor/?q=<script>alert(1)</script>")[0] == 200
    assert last_log(live_nginx)[0]["wa"].startswith("x")
    assert req(port, "/?q=document.cookie")[0] == 200
    assert last_log(live_nginx)[0]["wa"] == "off"
    # нестандартный метод
    assert req(port, "/", method="TRACE")[0] in (403, 405)
    # сайт без защиты
    assert req(port, "/?f=../../etc/passwd", host="off.test")[0] == 200


def test_live_bypass_custom_threats(live_nginx):
    port = live_nginx["port"]
    # доверенный IP сайта и «пропустить» из своих правил
    assert req(port, "/?f=../../etc/passwd", source="127.0.0.2")[0] == 200
    assert last_log(live_nginx)[0]["wa"].startswith("a")
    assert req(port, "/?f=../../etc/passwd", source="127.0.0.3")[0] == 200
    # свои правила: блок, разрыв соединения, запись
    assert req(port, "/secret/x")[0] == 403
    assert last_log(live_nginx)[0]["wf"] == "custom/blk"
    assert req(port, "/", headers={"User-Agent": "Mozilla evilbot"})[0] is None  # 444 — соединение закрыто
    assert req(port, "/", headers={"X-Test": "1"})[0] == 200
    rec = last_log(live_nginx)[0]
    assert rec["wf"] == "custom/lg" and rec["wa"] == "log"
    # побеждает самое строгое действие: «записать» не ослабляет блокировку фильтром
    assert req(port, "/?f=../../etc/passwd", headers={"X-Test": "1"})[0] == 403
    assert last_log(live_nginx)[0]["wf"].startswith("traversal/")
    # из двух своих правил одного уровня действует верхнее в списке
    assert req(port, "/secret/x", headers={"User-Agent": "evilbot"})[0] == 403
    assert last_log(live_nginx)[0]["wf"] == "custom/blk"
    # список угроз
    assert req(port, "/", source="127.0.0.4")[0] == 403
    assert last_log(live_nginx)[0]["wf"] == "threat/t1:block"


def test_live_headers_hotlink_login(live_nginx):
    port = live_nginx["port"]
    st, body = req(port, "/h", headers={"Proxy": "http://evil:8080", "X-Original-URL": "/admin"})
    assert st == 200 and json.loads(body) == {"path": "/h", "proxy": None, "xorig": None}  # httpoxy и др. вырезаны
    assert req(port, "/img/a.png", headers={"Referer": "https://evil.example/page"})[0] == 403
    assert req(port, "/img/a.png", headers={"Referer": "http://prot.test/page"})[0] == 200
    assert req(port, "/img/a.png")[0] == 200  # без Referer — можно
    assert req(port, "/wp-login.php")[0] == 200
    assert req(port, "/wp-login.php")[0] == 429  # 1 запрос в минуту
    assert req(port, "/other")[0] == 200


def test_live_challenge_pass(live_nginx):
    port = live_nginx["port"]
    # без пропуска — на страницу проверки (панели в тесте нет → 502 от internal-локации)
    st, _ = req(port, "/", host="chal.test")
    assert st == 502
    assert last_log(live_nginx)[0]["ch"] == "c"
    exp = int(time.time()) + 600
    good = pass_token(SECRET, exp, "127.0.0.1")
    st, body = req(port, "/page", host="chal.test", headers={"Cookie": f"nm_pass={good}; nm_pass_e={exp}"})
    assert st == 200 and b'"/page"' in body
    assert last_log(live_nginx)[0]["ch"] == "c1"
    # пропуск другого IP и просроченный — снова проверка
    other = pass_token(SECRET, exp, "10.0.0.1")
    assert req(port, "/", host="chal.test", headers={"Cookie": f"nm_pass={other}; nm_pass_e={exp}"})[0] == 502
    old = int(time.time()) - 10
    stale = pass_token(SECRET, old, "127.0.0.1")
    assert req(port, "/", host="chal.test", headers={"Cookie": f"nm_pass={stale}; nm_pass_e={old}"})[0] == 502
    assert last_log(live_nginx)[0]["ch"] == "c0"
    # исключённые пути проверку не проходят
    assert req(port, "/robots.txt", host="chal.test")[0] == 200


def test_observe_counts_and_autoban(tmp_path, monkeypatch):
    """Строки журнала → журнал атак, счётчики, кандидаты на блокировку (фильтр и ловушки)."""
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    app = App()
    app.save_panel(PanelSettings(autoban_enabled=True))
    app.protection.save(ProtectionSettings(autoban_waf=3))
    sid = app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                         ("S", 1, json.dumps(Site(name="S", domains=["s.test"], type="redirect",
                                                  redirect={"url": "https://x.test"}).model_dump()), 0, 0))
    pr = app.protection
    now = time.time()
    base = {"ip": "203.0.113.9", "method": "GET", "ua": "x", "host": "s.test", "rid": "r1", "ustatus": ""}
    for i in range(3):
        pr.observe({**base, "uri": f"/?a=../{i}", "status": 403, "wf": "traversal/trav-dotdot", "wa": "block"},
                   str(sid), "NL", now + i)
    pr.observe({**base, "uri": "/.git/config", "status": 404, "wf": "", "wa": "", "ip": "203.0.113.10"},
               str(sid), "", now)
    pr.observe({**base, "uri": "/?q=1&nm_selftest=ab1", "status": 403, "wf": "sqli/sqli-union", "wa": "block"},
               str(sid), "", now)
    assert pr.flush() == 5
    ov = pr.overview(1)
    assert ov["totals"].get("blocked") == 3 and ov["totals"].get("banned") == 1  # самопроверка не считается
    cands = app.bans.detector.take()
    rules = {c["rule"]: c for c in cands}
    assert rules["waf"]["ip"] == "203.0.113.9" and rules["honeypot"]["ip"] == "203.0.113.10"
    app.bans.detector.candidates = cands
    banned = app.bans.process_candidates()
    assert {b["rule"] for b in banned} == {"waf", "honeypot"}
    hp = next(b for b in banned if b["rule"] == "honeypot")
    assert hp["minutes"] == ProtectionSettings().honeypot_minutes
    ev = pr.events(10)
    assert ev[0]["title"] and all(e["test"] == 0 for e in ev)
    assert pr.events(10, test=True)[0]["uri"].endswith("nm_selftest=ab1")


def test_score_and_attack_file(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    app = App()
    s = Site(name="S", domains=["s.test"], type="redirect", redirect={"url": "https://x.test"})
    sc = app.protection.score(1, s)
    assert 0 <= sc["score"] <= 100 and sc["grade"] in "ABCDF" and len(sc["checks"]) >= 20
    st = app.protection.attack_state()
    st["sites"]["5"] = {"until": None}
    st["global"] = {"until": time.time() - 1}
    app.db.kv_set("attack_mode", st)
    txt = app.protection.render_attack_file()
    assert 'default "";' in txt and '"5" "c";' in txt


def test_autoban_off_metrics_and_diagnostics(tmp_path, monkeypatch):
    """Без общей автоблокировки фильтр не создаёт кандидатов, ловушки — создают; счётчики попадают в /metrics,
    а диагностика сообщает о сбое списка угроз и о провале самопроверки."""
    import asyncio

    from app.config import settings
    from app.core import App
    from app.services import metrics
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    app = App()
    app.save_panel(PanelSettings(autoban_enabled=False))
    app.protection.save(ProtectionSettings(autoban_waf=1, threat_feeds=[
        {"id": "bad", "name": "Плохой", "url": "file:///nonexistent/feed.txt", "enabled": True}]))
    sid = str(app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                             ("S", 1, json.dumps(Site(name="S", domains=["s.test"], type="redirect",
                                                      redirect={"url": "https://x.test"}).model_dump()), 0, 0)))
    pr = app.protection
    now = time.time()
    base = {"ip": "203.0.113.20", "method": "GET", "ua": "x", "host": "s.test", "rid": "r1", "ustatus": ""}
    for i in range(3):
        pr.observe({**base, "uri": f"/?a=../{i}", "status": 403, "wf": "traversal/trav-dotdot", "wa": "block"},
                   sid, "", now + i)
    pr.observe({**base, "uri": "/.git/config", "status": 404, "wf": "", "wa": "", "ip": "203.0.113.21"}, sid, "",
               now)
    rules = {c["rule"] for c in app.bans.detector.take()}
    assert rules == {"honeypot"}
    assert pr.totals[(sid, "waf", "blocked")] == 3
    from app.models import AlertRule
    v, det = app.metric(AlertRule(name="a", metric="attacks_blocked", site=sid, window=60))
    assert v > 0 and "waf: 3" in det
    pr.flush()
    assert app.metric(AlertRule(name="a", metric="attacks_blocked", window=60))[0] == v
    assert app.metric(AlertRule(name="a", metric="under_attack"))[0] == 0
    text = metrics.render(app)
    assert f'nm_attacks_total{{site_id="{sid}",site="S",kind="waf",action="blocked"}} 3' in text
    assert 'nm_under_attack{site_id="*",site="(все сайты)"} 0' in text
    res = asyncio.run(pr.update_feeds(force=True))
    assert res["feeds"]["bad"]["ok"] is False
    app.db.kv_set(f"selftest_{sid}", {"ts": now, "summary": {"failed": 2, "false_positives": 0}})
    out = asyncio.run(app.diag.c_protection())
    by_id = {r["id"]: r for r in out}
    assert by_id["prot_feed_bad"]["status"] == "warn"
    assert by_id[f"prot_selftest_{sid}"]["status"] == "warn"
    assert "prot_waf" in by_id
