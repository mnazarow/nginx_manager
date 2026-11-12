"""Интеграционные тесты REST API: вход, CSRF, роли, токены, сайты, блокировки, анализ, метрики, документация.

Сервис запускается целиком (с фоновыми задачами) на временных каталогах из conftest.py; nginx не
перезагружается — конфигурация в тестах не применяется.
"""
import time

import pytest
from fastapi.testclient import TestClient

PW = "Test-Passw0rd!"
H = {"X-NM-CSRF": "1"}


@pytest.fixture(scope="module")
def client():
    from app.main import create_app
    from app.utils import hash_password
    app = create_app()
    with TestClient(app) as c:
        app.state.nm.db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username='admin'",
                                (hash_password(PW),))
        yield c


@pytest.fixture(scope="module")
def admin(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": PW})
    assert r.status_code == 200, r.text
    return client


SITE = {"name": "Тестовый сайт", "domains": ["test.example.com"], "type": "proxy",
        "backends": [{"address": "127.0.0.1", "port": 9901}]}


def test_requires_auth(client):
    c = TestClient(client.app)  # без cookie
    assert c.get("/api/sites").status_code == 401
    assert c.get("/metrics").status_code == 401
    assert c.get("/healthz").status_code == 200


def test_login_errors(client):
    c = TestClient(client.app)
    r = c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code in (401, 403) and "detail" in r.json()


def test_csrf_required_for_session(admin):
    r = admin.post("/api/sites", json=SITE)  # без заголовка X-NM-CSRF
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]


def test_state_schema_overview(admin):
    st = admin.get("/api/state").json()
    assert st["user"]["username"] == "admin" and "insights" in st
    sch = admin.get("/api/schema").json()
    assert "site" in sch["models"] and all("anchor" in f for f in sch["models"]["site"])
    assert admin.get("/api/overview").status_code == 200


def test_site_crud_preview_and_validation(admin):
    r = admin.post("/api/sites", json=SITE, headers=H)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    got = admin.get(f"/api/sites/{sid}").json()
    assert got["data"]["domains"] == ["test.example.com"]
    data = got["data"]
    data["backends"].append({"address": "127.0.0.1", "port": 9902, "backup": True})
    assert admin.put(f"/api/sites/{sid}", json=data, headers=H).status_code == 200
    prev = admin.post("/api/sites/preview", json=data, params={"sid": sid}, headers=H).json()
    assert "server_name test.example.com;" in prev["config"] and "backup;" in prev["config"]
    assert "if ($nm_banned)" in prev["config"]
    bad = dict(SITE, domains=["bad domain;"])
    r = admin.post("/api/sites", json=bad, headers=H)
    assert r.status_code == 422 and r.json()["errors"]
    assert admin.get("/api/config/pending").json()["pending"] is True
    assert admin.delete(f"/api/sites/{sid}", headers=H).status_code == 200
    assert admin.get(f"/api/sites/{sid}").status_code == 404


def test_basic_auth_hashes_not_exposed(admin):
    site = dict(SITE, name="Закрытый", domains=["secret.example.com"],
                security={"basic_auth": True, "basic_auth_users": [{"username": "boss", "password": "Secret-1"}]})
    r = admin.post("/api/sites", json=site, headers=H)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    got = admin.get(f"/api/sites/{sid}").json()["data"]
    user = got["security"]["basic_auth_users"][0]
    assert user["password_hash"] == "" and user["password"] == ""
    # сохранение без пароля сохраняет прежний хеш
    assert admin.put(f"/api/sites/{sid}", json=got, headers=H).status_code == 200
    diff = admin.get("/api/config/pending").json()["diff"]
    htp = [d for d in diff if d["file"].endswith(".htpasswd")]
    assert htp and "$apr1$" not in htp[0]["diff"] and "boss:<хеш скрыт" in htp[0]["diff"]
    # хеш с переводом строки (дописать пользователя в htpasswd) отклоняется
    got["security"]["basic_auth_users"][0]["password_hash"] = "$apr1$x$y\nevil:$apr1$a$b"
    assert admin.put(f"/api/sites/{sid}", json=got, headers=H).status_code == 422
    assert admin.delete(f"/api/sites/{sid}", headers=H).status_code == 200


def test_roles_and_tokens(admin, client):
    r = admin.post("/api/users", json={"username": "viewer1", "password": "Viewer-Pass1", "role": "viewer"}, headers=H)
    assert r.status_code == 200, r.text
    v = TestClient(client.app)
    assert v.post("/api/auth/login", json={"username": "viewer1", "password": "Viewer-Pass1"}).status_code == 200
    assert v.get("/api/sites").status_code == 200
    assert v.post("/api/sites", json=SITE, headers=H).status_code == 403
    assert v.get("/api/users").status_code == 403
    assert v.post("/api/certs/selftest", json={"domain": "x.test"}, headers=H).status_code == 403
    tok = admin.post("/api/auth/tokens", json={"name": "ci", "role": "viewer"}, headers=H).json()
    token = tok.get("token")
    assert token and token.startswith("nm_")
    t = TestClient(client.app)
    assert t.get("/api/sites", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert t.get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert t.get("/api/sites", headers={"Authorization": "Bearer nm_wrong"}).status_code == 401


def test_bans(admin):
    r = admin.post("/api/bans", json={"nets": ["203.0.113.7", "198.51.100.0/24"], "minutes": 60, "reason": "тест"},
                   headers=H)
    assert r.status_code == 200, r.text
    data = admin.get("/api/bans").json()
    nets = {b["net"] for b in data["items"]}
    assert {"203.0.113.7", "198.51.100.0/24"} <= nets
    from app.config import settings
    assert "203.0.113.7 1;" in settings.bans_file.read_text()
    assert admin.post("/api/bans", json={"nets": ["10.0.0.0/4"]}, headers=H).status_code == 400
    assert admin.post("/api/bans", json={"nets": ["127.0.0.1"]}, headers=H).status_code == 400  # доверенный
    bid = next(b["id"] for b in data["items"] if b["net"] == "203.0.113.7")
    assert admin.delete(f"/api/bans/{bid}", headers=H).status_code == 200
    assert "203.0.113.7" not in settings.bans_file.read_text()


def test_insights_and_catalog(admin):
    cat = admin.get("/api/insights/catalog").json()
    assert len(cat["scenarios"]) >= 70 and "err5" in cat["metrics"]
    assert cat["metrics"]["connections"]["capacity"] > 0
    now = time.time()
    res = admin.get("/api/insights", params={"from": now - 3600, "to": now}).json()
    assert set(res["counts"]) == {"crit", "warn", "info"} and res["checked"] == len(cat["scenarios"])
    assert admin.post("/api/insights/mute", json={"id": "single_backend", "mute": True}, headers=H).json()["ok"]
    assert "single_backend" in admin.get("/api/insights/catalog").json()["muted"]
    admin.post("/api/insights/mute", json={"id": "single_backend", "mute": False}, headers=H)
    assert admin.post("/api/insights/mute", json={"id": "nope"}, headers=H).status_code == 404


def test_metrics_format(admin):
    r = admin.get("/metrics")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert "nginx_manager_info{" in r.text and "# TYPE nm_bans_active gauge" in r.text


def test_docs_and_traversal(admin):
    docs = admin.get("/api/docs").json()
    assert any(d["name"] == "18-insights.md" for d in docs)
    assert admin.get("/api/docs/17-bans.md").status_code == 200
    assert admin.get("/api/docs/..%2f..%2fetc%2fpasswd").status_code == 404
    assert admin.get("/api/backup/download/..%2fnginx-manager.db").status_code == 404


def test_settings_validation(admin):
    p = admin.get("/api/settings/panel").json()
    p["ip_detect_url"] = "file:///etc/passwd"
    r = admin.put("/api/settings/panel", json=p, headers=H)
    assert r.status_code == 422


def test_backup_export(admin):
    r = admin.get("/api/backup/export")
    assert r.status_code == 200
    data = r.json()
    assert data["format"] == "nginx-manager-export" and {"sites", "global"} <= set(data)


def test_websocket_tick(admin):
    with admin.websocket_connect("/api/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"] in ("tick", "hello", "state")


def test_thresholds(admin):
    r = admin.put("/api/insights/thresholds", json={"thresholds": {"err5": {"warn": 0.5, "crit": 2}}}, headers=H)
    assert r.status_code == 200 and r.json()["thresholds"]["err5"]["custom"] is True
    cat = admin.get("/api/insights/catalog").json()
    assert cat["metrics"]["err5"]["warn"] == 0.5 and cat["metrics"]["err5"]["default_warn"] == 1.0
    assert any(s["custom"] for s in cat["scenarios"] if s["id"] == "e5xx_rate")
    bad = admin.put("/api/insights/thresholds", json={"thresholds": {"err5": {"warn": 5, "crit": 1}}}, headers=H)
    assert bad.status_code == 400
    assert admin.put("/api/insights/thresholds", json={"thresholds": {"rps": {"warn": 1, "crit": 2}}},
                     headers=H).status_code == 400  # у rps нет порогов
    admin.put("/api/insights/thresholds", json={"thresholds": {"err5": None}}, headers=H)
    assert admin.get("/api/insights/catalog").json()["metrics"]["err5"]["custom"] is False


def test_report_preview(admin):
    for period in ("day", "week"):
        r = admin.get("/api/reports/preview", params={"period": period}).json()
        assert r["title"].startswith("Отчёт") and "Запросов:" in r["text"] and "Сейчас:" in r["text"]
    assert admin.post("/api/reports/send", json={"period": "day", "channels": []}, headers=H).status_code == 400


def test_silences(admin, client):
    nmapp = client.app.state.nm
    rules = admin.get("/api/alerts/rules").json()
    assert rules, "должны быть правила по умолчанию"
    rid = rules[0]["id"]
    assert nmapp.alerts.silence_for(rid) is None
    r = admin.post("/api/alerts/silences", json={"minutes": 30, "rule_ids": [rid], "reason": "работы"}, headers=H)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    assert nmapp.alerts.silence_for(rid)["id"] == sid
    assert nmapp.alerts.silence_for(rid + 100000) is None          # другое правило не заглушено
    assert admin.get("/api/state").json()["silence"]["id"] == sid
    planned = admin.post("/api/alerts/silences", json={"minutes": 60, "starts_at": time.time() + 3600}, headers=H)
    lst = admin.get("/api/alerts/silences").json()
    assert {s["state"] for s in lst} == {"active", "planned"}
    assert admin.post("/api/alerts/silences", json={"minutes": 1}, headers=H).status_code == 400
    assert admin.post("/api/alerts/silences", json={"minutes": 30, "rule_ids": [999999]}, headers=H).status_code == 400
    assert admin.delete(f"/api/alerts/silences/{sid}", headers=H).status_code == 200
    assert admin.delete(f"/api/alerts/silences/{planned.json()['id']}", headers=H).status_code == 200
    assert nmapp.alerts.silence_for(rid) is None
    assert admin.get("/api/state").json()["silence"] is None


def test_silence_blocks_notifications(client):
    import asyncio
    from app.models import AlertRule
    nmapp = client.app.state.nm
    sent = []
    import app.services.alerts as A
    orig = A.send
    A.send = lambda *a, **k: sent.append(a)
    try:
        nmapp.db.execute("INSERT INTO silences(created_at, starts_at, ends_at, rule_ids, reason) VALUES(?,?,?,?,?)",
                         (time.time(), time.time() - 1, time.time() + 600, "[]", "тест"))
        rule = AlertRule(name="t", metric="error_5xx_rate", threshold=1)
        res = asyncio.run(nmapp.alerts.notify(rule, "t", "x", "warning", None, 1))
        assert res and "тишина" in res[0] and not sent
    finally:
        A.send = orig
        nmapp.db.execute("UPDATE silences SET ends_at=?", (time.time() - 1,))


def test_sites_bulk(admin):
    ids = []
    for i in range(3):
        r = admin.post("/api/sites", json=dict(SITE, name=f"Пакет {i}", domains=[f"bulk{i}.example.com"]), headers=H)
        assert r.status_code == 200, r.text
        ids.append(r.json()["id"])
    r = admin.post("/api/sites/bulk", json={"ids": ids, "action": "disable"}, headers=H).json()
    assert r["changed"] == 3 and r["applied"] is None
    rows = {s["id"]: s for s in admin.get("/api/sites").json()}
    assert not any(rows[i]["enabled"] for i in ids)
    assert admin.post("/api/sites/bulk", json={"ids": ids, "action": "disable"}, headers=H).json()["changed"] == 0
    r = admin.post("/api/sites/bulk", json={"ids": ids[:2], "action": "tag_add", "tag": "прод"}, headers=H).json()
    assert r["changed"] == 2
    rows = {s["id"]: s for s in admin.get("/api/sites").json()}
    assert rows[ids[0]]["tags"] == ["прод"] and rows[ids[2]]["tags"] == []
    assert admin.post("/api/sites/bulk", json={"ids": ids, "action": "tag_add"}, headers=H).status_code == 400
    assert admin.post("/api/sites/bulk", json={"ids": ids, "action": "explode"}, headers=H).status_code == 400
    assert admin.post("/api/sites/bulk", json={"ids": ids, "action": "tag_remove", "tag": "прод"}, headers=H).json()["changed"] == 2
    r = admin.post("/api/sites/bulk", json={"ids": ids, "action": "delete"}, headers=H).json()
    assert r["changed"] == 3
    assert all(admin.get(f"/api/sites/{i}").status_code == 404 for i in ids)


def test_geo_status_and_site_rules(admin):
    site = dict(SITE, name="Гео", domains=["geo.example.com"],
                security={"geo_mode": "allow", "geo_countries": ["ru", "KZ"], "geo_exceptions": ["198.51.100.0/24"]})
    r = admin.post("/api/sites", json=site, headers=H)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    assert admin.get(f"/api/sites/{sid}").json()["data"]["security"]["geo_countries"] == ["RU", "KZ"]
    g = admin.get("/api/geo").json()
    assert any(s["id"] == sid and s["mode"] == "allow" for s in g["sites"]) and "db" in g and "blocked" in g
    row = next(s for s in admin.get("/api/sites").json() if s["id"] == sid)
    assert row["geo"] == {"mode": "allow", "countries": ["RU", "KZ"]}
    bad = dict(site, security={"geo_mode": "deny", "geo_countries": []})
    assert admin.put(f"/api/sites/{sid}", json=bad, headers=H).status_code == 422
    schema = admin.get("/api/schema").json()
    assert "RU" in schema["countries"] and len(schema["country_groups"]["eu"]) == 27
    assert admin.delete(f"/api/sites/{sid}", headers=H).status_code == 200
