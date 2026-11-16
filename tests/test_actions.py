"""Защита 2.4: сверка версий продуктов с затронутыми версиями уязвимостей, углублённое определение технологий,
кнопки действий в Telegram, событие «активный атакующий», перенос правил сайтов между серверами по доменам."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.protection import fingerprint as FP
from app.protection import vulndb as V
from app.services import tgbot as TG
from tests.test_protection import free_port

RANGES = [{"product": "PHP Group PHP", "v": "8.1.*", "lt": "8.1.29"},
          {"product": "PHP Group PHP", "v": "8.2.*", "lt": "8.2.20"},
          {"product": "PHP Group PHP", "v": "8.3.0", "lte": "8.3.7"}]


@pytest.fixture()
def app(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    return App()


# =============================================================================
#  Сверка версий
# =============================================================================
def test_version_affected():
    va = V.version_affected
    assert va("8.2.12", RANGES) is True and va("8.2.20", RANGES) is False and va("8.3.7", RANGES) is True
    assert va("8.3.8", RANGES) is False and va("8.1.30", RANGES) is False and va("7.4.3", RANGES) is False
    assert va("", RANGES) is None and va("8.2.1", []) is None
    assert va("6.4.2", [{"product": "WordPress", "v": "0", "lt": "6.4.3"}]) is True
    assert va("2.4.49", [{"product": "Apache HTTP Server", "v": "2.4.49"}]) is True
    assert va("2.4.58", [{"product": "Apache HTTP Server", "v": "2.4.49"}]) is False
    assert va("2.4.58", [{"product": "Apache HTTP Server", "v": "n/a"}]) is None  # не с чем сравнивать
    # диапазоны другого продукта той же уязвимости не мешают
    mixed = [{"product": "Fortinet FortiProxy", "v": "7.0.0", "lte": "7.0.6"},
             {"product": "Fortinet FortiOS", "v": "7.2.0", "lte": "7.2.1"}]
    assert va("7.0.3", mixed, ["fortios"]) is False and va("7.2.1", mixed, ["fortios"]) is True
    # в записи нет диапазонов этого продукта — вывода о версии нет (WordPress 6.4.2 и «WP Squared < 11.136»)
    cpanel = [{"product": "WebPros cPanel", "v": "11.40.0.0", "lt": "11.86.0.41"},
              {"product": "WebPros WP Squared", "v": "0", "lt": "11.136.1.7"}]
    assert va("6.4.2", cpanel, ["wordpress"]) is None
    rec = V.parse_cve_record(json.dumps({"cveMetadata": {}, "containers": {"cna": {"affected": [
        {"vendor": "PHP Group", "product": "PHP", "versions": [{"version": "8.2.*", "lessThan": "8.2.20",
                                                                 "status": "affected"},
                                                                {"version": "8.4.0", "status": "unaffected"}]}]}}}).encode())
    assert json.loads(rec["ranges"]) == [{"product": "PHP Group PHP", "v": "8.2.*", "lt": "8.2.20"}]


def test_installed_versions_and_insight(app):
    db = app.protection.vulndb
    app.db.executemany("INSERT INTO vulns(cve,name,vendor,product,kev,kev_added,ransomware,cvss,ranges,updated) "
                       "VALUES(?,?,?,?,?,?,?,?,?,0)",
                       [("CVE-2024-4577", "PHP-CGI argument injection", "PHP Group", "PHP", 1, "2024-06-12", 1, 9.8,
                         json.dumps(RANGES)),
                        ("CVE-2099-0002", "Old PHP", "PHP Group", "PHP", 1, "2099-01-01", 0, 7.5,
                         json.dumps([{"product": "PHP Group PHP", "v": "5.0", "lt": "5.6"}])),
                        ("CVE-2099-0003", "No ranges", "PHP Group", "PHP", 1, "2099-01-01", 0, 7.0, "[]")])
    app.db.kv_set("site_tech", {"3": {"ts": time.time(), "name": "Блог", "tech": [
        {"id": "php", "name": "PHP", "cat": "lang", "version": "8.2.12", "evidence": "x"},
        {"id": "wordpress", "name": "WordPress", "cat": "cms", "version": "", "evidence": "y"}]}})
    tv = db.tech_vulns()[0]
    php = next(t for t in tv["tech"] if t["id"] == "php")
    assert php["kev"] == 3 and php["affected_n"] == 1 and php["affected"][0]["cve"] == "CVE-2024-4577"
    card = db.get("CVE-2024-4577")
    assert card["on_sites"] == [{"site": "3", "name": "Блог", "tech": "PHP", "version": "8.2.12", "affected": True}]
    assert db.get("CVE-2099-0002")["on_sites"][0]["affected"] is False
    found = [x for x in app.protection.analytics.insights() if x[0] == "vuln_installed"]
    assert found and found[0][1] == "crit" and found[0][2] == "3" and "CVE-2024-4577" in found[0][3]


# =============================================================================
#  Углублённое определение технологий
# =============================================================================
def test_deep_probe(app):
    port = free_port()

    class App(BaseHTTPRequestHandler):
        server_version, sys_version = "demo", ""

        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            routes = {"/": (200, b"<html>home</html>"),
                      "/status.php": (200, b'{"installed":true,"versionstring":"27.1.3","productname":"Nextcloud"}'),
                      "/jenkins/login": (403, b"denied")}
            st, body = routes.get(self.path, (404, b"no"))
            self.send_response(st)
            if self.path == "/jenkins/login":
                self.send_header("X-Jenkins", "2.440.1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", port), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        from app.models import Backend, Site
        site = Site(name="Портал", domains=["portal.test"], backends=[Backend(address="127.0.0.1", port=port)])
        assert FP.scan_site(site)["tech"] == []
        deep = {t["id"]: t["version"] for t in FP.scan_site(site, deep=True)["tech"]}
        assert deep == {"nextcloud": "27.1.3", "jenkins": "2.440.1"}
        merged = FP.merge([{"id": "php", "name": "PHP", "cat": "lang", "version": "", "evidence": "cookie"}],
                          [{"id": "php", "name": "PHP", "cat": "lang", "version": "8.3.1", "evidence": "адрес /x"}])
        assert merged[0]["version"] == "8.3.1" and "адрес /x" in merged[0]["evidence"]
    finally:
        srv.shutdown()


# =============================================================================
#  Telegram: кнопки действий
# =============================================================================
class TgMock(BaseHTTPRequestHandler):
    calls: list = []
    updates: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        method = self.path.rsplit("/", 1)[-1]
        TgMock.calls.append((method, body))
        if method == "getUpdates":
            res, TgMock.updates = TgMock.updates, []
            out = {"ok": True, "result": res}
        else:
            out = {"ok": True, "result": {"message_id": 99}}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def test_telegram_actions(app):
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), TgMock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        from app.models import AlertChannel
        from app.services.alerts import send
        ch = AlertChannel(name="TG", type="telegram", telegram_token="123:abc", telegram_chat_id="-100500",
                          telegram_api=f"http://127.0.0.1:{port}", telegram_actions=True,
                          telegram_admins=["@boss", "4242"])
        cid = app.db.execute("INSERT INTO alert_channels(name,type,enabled,data,created_at,updated_at) "
                             "VALUES(?,?,?,?,0,0)", (ch.name, ch.type, 1, ch.model_dump_json()))
        key = TG.secret(app.db)
        # подпись: IPv6 с двоеточиями, подделка не проходит, длина в пределах 64 байт
        data6 = TG.callback_data(key, "b", "2001:db8:1234:5678:9abc:def0:1234:5678")
        assert len(data6) <= 64 and TG.parse_callback(key, data6) == ("b", "2001:db8:1234:5678:9abc:def0:1234:5678")
        assert TG.parse_callback(key, TG.callback_data(key, "b", "203.0.113.5")[:-1] + "0") is None
        assert TG.parse_callback(b"other", TG.callback_data(key, "b", "203.0.113.5")) is None
        # уведомление об автоблокировке: кнопки «Разблокировать» и «Пожаловаться»
        ip, acts = TG.actions_for("bans", "Автоблокировка 203.0.113.5 на 1 ч: x", {"ip": "203.0.113.5"})
        assert ip == "203.0.113.5" and acts == ["u", "r"]
        assert TG.actions_for("protection", "Активный атакующий", {"ip": "203.0.113.6", "attacker": True})[1] == ["b", "r"]
        assert TG.actions_for("certs", "x", {"ip": "203.0.113.5"}) == ("", [])
        mk = TG.keyboard(key, "203.0.113.5", ["u", "r"], "https://panel.test/#x")
        send(ch, "Событие", "Автоблокировка", "warning", {"telegram_markup": mk})
        sent = [b for m, b in TgMock.calls if m == "sendMessage"][-1]
        assert sent["reply_markup"]["inline_keyboard"][0][0]["text"] == "Разблокировать"
        assert sent["reply_markup"]["inline_keyboard"][-1][0]["url"] == "https://panel.test/#x"
        ch_off = ch.model_copy(update={"telegram_actions": False})
        send(ch_off, "Событие", "x", "warning", {"telegram_markup": mk})
        assert "reply_markup" not in [b for m, b in TgMock.calls if m == "sendMessage"][-1]
        # нажатия: разрешённый пользователь блокирует, чужой чат и чужой пользователь — отказ, подделка — отказ
        bot = app.tgbot
        assert [c for c, _ in bot.channels()] == [cid]

        def cq(data, chat="-100500", user=None, i="1"):
            return {"update_id": int(i), "callback_query": {
                "id": i, "data": data, "from": user or {"id": 4242, "username": "boss"},
                "message": {"message_id": 7, "chat": {"id": int(chat)}}}}
        TgMock.updates = [cq(TG.callback_data(key, "b", "203.0.113.5"), i="10"),
                          cq(TG.callback_data(key, "b", "203.0.113.7"), chat="-999", i="11"),
                          cq(TG.callback_data(key, "b", "203.0.113.8"), user={"id": 1, "username": "random"}, i="12"),
                          cq("nm1:b:203.0.113.9:000000000000", i="13")]
        n = bot.poll_once("k", ch, timeout=0)
        assert n == 4 and bot.offsets["k"] == 14
        answers = [b["text"] for m, b in TgMock.calls if m == "answerCallbackQuery"]
        assert answers[-4:] == ["203.0.113.5 заблокирован на сутки", "Действие доступно только в чате уведомлений",
                                "Нет прав: вас нет в списке разрешённых пользователей канала",
                                "Кнопка устарела или подделана"]
        row = app.db.one("SELECT * FROM bans WHERE net='203.0.113.5'")
        assert row and row["username"] == "telegram:@boss"
        assert not app.db.one("SELECT 1 FROM bans WHERE net IN ('203.0.113.7','203.0.113.8','203.0.113.9')")
        audit = app.db.one("SELECT * FROM audit_log WHERE target='203.0.113.5'")
        assert audit["username"] == "telegram:@boss" and audit["action"] == "ip_banned"
        TgMock.updates = [cq(TG.callback_data(key, "u", "203.0.113.5"), user={"id": 4242}, i="20")]
        bot.poll_once("k", ch, timeout=0)
        assert not app.db.one("SELECT 1 FROM bans WHERE net='203.0.113.5'")
        reply = [b for m, b in TgMock.calls if m == "sendMessage"][-1]
        assert reply["reply_to_message_id"] == 7 and "разблокирован" in reply["text"]
    finally:
        srv.shutdown()


def test_event_markup_and_attacker_event(app):
    """Событие «активный атакующий» с подробностями для кнопок; клавиатура в уведомлении о событии."""
    pr = app.protection
    now = time.time()
    for i in range(40):
        pr.observe({"method": "GET", "status": 403, "host": "s.test", "ustatus": "", "ip": "198.51.100.44",
                    "uri": f"/?id=1+UNION+SELECT+{i}", "ua": "sqlmap/1.8", "wf": "sqli/sqli-union", "wa": "block",
                    "rid": f"r{i}"}, "1", "NL", now - 60)
    pr.flush()
    assert pr.announce_attackers(now) == []  # оценка 70 ниже порога 80 по умолчанию
    pr.save(pr.settings().model_copy(update={"announce_score": 60}))
    assert pr.announce_attackers(now) == ["198.51.100.44"]
    assert pr.announce_attackers(now) == []  # не чаще раза в сутки на адрес
    ev = app.db.one("SELECT * FROM events WHERE message LIKE 'Активный атакующий%'")
    det = json.loads(ev["details"])
    assert det["ip"] == "198.51.100.44" and det["attacker"] and "sqlmap" in ev["message"]
    pr.save(pr.settings().model_copy(update={"announce_score": 0}))
    assert pr.announce_attackers(now + 90000) == []


# =============================================================================
#  Несколько серверов: правила сайтов по доменам
# =============================================================================
def test_sync_site_rules_by_domain(app):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.models import Backend, CustomRule, Site
    api = create_app()
    with TestClient(api) as c:
        nm = api.state.nm
        for name, dom in (("Магазин", "shop.test"), ("Блог", "blog.test")):
            s = Site(name=name, domains=[dom, f"www.{dom}"], backends=[Backend(address="127.0.0.1", port=9)])
            nm.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,0,0)",
                          (name, 1, s.model_dump_json()))
        ids = {s.name: sid for sid, s in nm.nginx.load_state().sites}
        nm.protection.save(nm.protection.settings().model_copy(update={"custom_rules": [
            CustomRule(id="own1", name="своё", sites=[ids["Блог"]], field="path", op="prefix", value="/b")]}))
        uid = nm.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        h = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'sync', role='admin')}"}
        incoming = nm.protection.settings().model_dump()
        incoming["custom_rules"] = [
            {"id": "shop1", "name": "магазин", "sites": [17], "field": "path", "op": "prefix", "value": "/admin"},
            {"id": "gone1", "name": "чужой", "sites": [18], "field": "path", "op": "prefix", "value": "/x"}]
        incoming["rate_rules"] = [{"id": "rr1", "name": "поиск", "sites": [17], "path": "/search", "rate": "30r/m"}]
        r = c.post("/api/sync/protection", headers=h, json={
            "origin": {"id": "abcabcabcabc0002", "name": "web-2"}, "settings": incoming,
            "sites": {"17": ["www.shop.test"], "18": ["other.test"]}}).json()
        assert r["ok"] and r["mapped"] == 2 and r["dropped"] == 1
        p = nm.protection.settings()
        rules = {x.id: x.sites for x in p.custom_rules}
        assert rules == {"shop1": [ids["Магазин"]], "own1": [ids["Блог"]]}
        assert p.rate_rules[0].sites == [ids["Магазин"]]


def test_vuln_card_paths_in_map(app):
    """Карточка уязвимости: какие пути эксплойта в карте nginx, а какие отсеяны."""
    from app.config import settings
    db = app.protection.vulndb
    for cve, paths in (("CVE-2024-4577", {"/php-cgi/php-cgi.exe": "a", "/index.php": "a"}),
                       ("CVE-2024-45770", {"/other/x.cgi": "a"})):
        app.db.execute("INSERT INTO vulns(cve,name,kev,template,paths,updated) VALUES(?,?,?,?,?,0)",
                       (cve, cve, 1, f"http/cves/2024/{cve}.yaml", json.dumps(paths)))
    content, stats = db.build_map()
    settings.vuln_file.write_text(content)
    assert '"/php-cgi/php-cgi.exe" "CVE-2024-4577:a";' in content and "/index.php" not in content
    card = db.get("CVE-2024-4577")
    assert card["in_map"] == {"/php-cgi/php-cgi.exe": "a"} and set(card["paths"]) == {"/php-cgi/php-cgi.exe", "/index.php"}
    assert db.get("CVE-2024-45770")["in_map"] == {"/other/x.cgi": "a"}
