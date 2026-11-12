"""Интеграционные тесты REST API: вход, CSRF, роли, токены, сайты, блокировки, анализ, метрики, документация.

Сервис запускается целиком (с фоновыми задачами) на временных каталогах из conftest.py; nginx не
перезагружается — конфигурация в тестах не применяется.
"""
import json
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


def test_backup_roundtrip(admin):
    """Экспорт → удаление всего → импорт: сайты (с паролями Basic Auth и правилами по странам), потоки,
    правила и каналы оповещений и глобальные настройки возвращаются как были."""
    site = dict(SITE, name="Резерв", domains=["backup.example.com"],
                security={"basic_auth": True, "basic_auth_users": [{"username": "boss", "password": "Secret-1"}],
                          "geo_mode": "deny", "geo_countries": ["CN"]})
    sid = admin.post("/api/sites", json=site, headers=H).json()["id"]
    stid = admin.post("/api/streams", json={"name": "PG", "listen_port": 15432, "backends": [{"port": 5432}]},
                      headers=H).json()["id"]
    rule = admin.post("/api/alerts/rules", json={"name": "5xx", "metric": "error_5xx_rate", "threshold": 7,
                                                 "site": str(sid)}, headers=H)
    assert rule.status_code == 200, rule.text
    ch = admin.post("/api/alerts/channels", json={"name": "hook", "type": "webhook", "url": "https://hooks.example/x"},
                    headers=H)
    assert ch.status_code == 200, ch.text
    g = admin.get("/api/settings/global").json()
    g["worker_connections"] = 4321
    assert admin.put("/api/settings/global", json=g, headers=H).status_code == 200
    before_sites = {s["name"]: admin.get(f"/api/sites/{s['id']}").json()["data"] for s in admin.get("/api/sites").json()}
    before_diff = {d["file"] for d in admin.get("/api/config/pending").json()["diff"]}
    data = admin.get("/api/backup/export").json()
    assert any(s["data"]["name"] == "Резерв" for s in data["sites"])
    # всё удаляем и меняем глобальные настройки
    for s in admin.get("/api/sites").json():
        admin.delete(f"/api/sites/{s['id']}", headers=H)
    admin.delete(f"/api/streams/{stid}", headers=H)
    g["worker_connections"] = 1024
    admin.put("/api/settings/global", json=g, headers=H)
    assert admin.get("/api/sites").json() == []
    r = admin.post("/api/backup/import", json=data, headers=H)
    assert r.status_code == 200, r.text
    after_sites = {s["name"]: admin.get(f"/api/sites/{s['id']}").json()["data"] for s in admin.get("/api/sites").json()}
    assert after_sites == before_sites
    assert [s["name"] for s in admin.get("/api/streams").json()] == ["PG"]
    assert any(x["data"]["name"] == "5xx" for x in admin.get("/api/alerts/rules").json())
    assert any(x["data"]["name"] == "hook" for x in admin.get("/api/alerts/channels").json())
    assert admin.get("/api/settings/global").json()["worker_connections"] == 4321
    diff = admin.get("/api/config/pending").json()["diff"]
    assert {d["file"] for d in diff} == before_diff
    htp = next(d for d in diff if d["file"].endswith(".htpasswd"))
    assert "boss:<хеш скрыт" in htp["diff"]  # хеш пароля пережил экспорт и импорт
    bad = admin.post("/api/backup/import", json={"format": "other"}, headers=H)
    assert bad.status_code in (400, 422)
    # режим «добавить»: новые номера, правило оповещения переезжает на новый номер сайта
    r = admin.post("/api/backup/import", json=data, params={"mode": "merge"}, headers=H)
    assert r.status_code == 200, r.text
    copies = sorted(s["id"] for s in admin.get("/api/sites").json() if s["name"] == "Резерв")
    assert len(copies) == 2
    rules = [x["data"] for x in admin.get("/api/alerts/rules").json() if x["data"]["name"] == "5xx"]
    assert sorted(x["site"] for x in rules) == sorted(str(i) for i in copies)
    for s in admin.get("/api/sites").json():
        admin.delete(f"/api/sites/{s['id']}", headers=H)


def test_websocket_tick(admin):
    with admin.websocket_connect("/api/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"] in ("tick", "hello", "state")
        # мусор от клиента не рвёт соединение и не ломает общий цикл рассылки
        for junk in ("не json", "[1, 2]", '{"type": "live", "on": true, "filter": {"min_rt": "abc", "ip": [1], "q": 5}}',
                     '{"type": "live", "on": true, "filter": "x"}', '{"type": "errors", "on": 1}'):
            ws.send_text(junk)
        ws.send_text('{"type": "ping"}')
        for _ in range(10):
            if ws.receive_json()["type"] == "pong":
                break
        else:
            raise AssertionError("нет ответа на ping")


def test_live_filter_sanitized():
    from app.api.routes import _live_filter
    from app.core import App
    f = _live_filter({"site": 3, "status": "5xx", "ip": ["x"], "min_rt": "oops", "q": {"a": 1}, "evil": "1"})
    assert f == {"site": "3", "status": "5xx", "hide_bots": False}
    item = {"site": "3", "s": 502, "ip": "1.2.3.4", "u": "/x", "host": "h", "ua": "", "rt": 0.7, "bot": False}
    assert App._match(item, f) and App._match(item, _live_filter({"min_rt": "500"}))
    assert not App._match(item, _live_filter({"min_rt": 900}))
    assert _live_filter(None) == {} and _live_filter([1]) == {}


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
        assert "тыс," not in r["text"] and "млн," not in r["text"]
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
    rec = admin.get("/api/audit", params={"q": "sites_bulk", "limit": 1}).json()[0]
    assert rec["target"] == "delete" and json.loads(rec["details"])["changed"] == 3


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


def test_sla_and_heatmap(admin, client):
    db = client.app.state.nm.db
    now = int(time.time()) // 3600 * 3600
    rows = [(now - 3600 * i, "*", 1000, 0, 0, 0, 990, 0, 0, 10 if i < 24 else 0, 50.0, 1.0, 0.0, 0, 0, "{}")
            for i in range(1, 24 * 10)]
    db.executemany("INSERT OR REPLACE INTO stats_hour(ts,site,req,bout,bin,s1,s2,s3,s4,s5,rt_sum,rt_max,urt_sum,urt_n,"
                   "uniq,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    r = admin.get("/api/stats/sla", params={"days": 30, "slo": 99.9}).json()
    assert len(r["days"]) == 30 and r["slo"] == 99.9
    total = next(x for x in r["sites"] if x["site"] == "*")
    assert total["name"] == "Все сайты"
    assert abs(total["a1"] - 99.0) < 0.05          # последние сутки: 1% ошибок
    assert total["a30"] > total["a1"] and 0 < total["budget_left"] < 10 and total["breached_days"] >= 1
    hm = admin.get("/api/stats/heatmap", params={"weeks": 1}).json()
    assert len(hm) >= 24 * 6 and hm[0][1] == 1000
    db.execute("DELETE FROM stats_hour WHERE site='*'")


# ---------------------------------------------------------------- устойчивость: мусор во все маршруты
UNSAFE = {"/api/nginx/{action}", "/api/config/apply", "/api/config/versions/{vid}/rollback", "/api/diagnostics/fix",
          "/api/backup/import", "/api/alerts/channels/test", "/api/reports/send", "/api/certs", "/api/certs/{cid}/renew",
          "/api/import/nginx/commit", "/api/users/{uid}", "/api/auth/password", "/api/auth/logout",
          "/api/auth/sessions/{sid}", "/api/backup/create", "/api/geo/rebuild", "/api/diagnostics/run",
          "/api/health/check", "/api/certs/selftest"}
GARBAGE_QUERY = [{}, {"from": "abc", "to": "-1", "limit": "-5", "offset": "x", "site": "../../etc/passwd",
                      "minutes": "1e309", "days": "0", "weeks": "999", "slo": "NaN", "points": "0", "q": "%' OR 1=1 --",
                      "status": "5xx", "kind": "bogus", "seconds": "-1", "period": "year", "key": "\x00"}]
GARBAGE_BODY = [None, {}, {"x": [1, {"y": None}]}, [], "строка", {"name": "\x00" * 3, "ids": ["a"], "minutes": -1}]


def test_no_server_errors_on_garbage(admin):
    import itertools

    from fastapi.routing import APIRoute

    from app.api.routes import router
    problems, calls = [], 0
    for route in router.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/") or route.path in UNSAFE:
            continue
        paths = [route.path]
        if "{" in route.path:
            paths = [route.path.replace("{" + p + "}", v) for p in ("sid", "vid", "cid", "rid", "uid", "tid", "ban_id",
                                                                   "stid", "name", "action", "key", "kind")
                     for v in ("999999", "abc", "..%2F..%2Fetc")
                     if "{" + p + "}" in route.path] or [route.path]
            paths = [p for p in paths if "{" not in p]
        for method, path in itertools.product(route.methods, paths):
            if method == "GET":
                for q in GARBAGE_QUERY:
                    r = admin.get(path, params=q)
                    calls += 1
                    if r.status_code >= 500:
                        problems.append((method, path, q, r.status_code, r.text[:200]))
            else:
                for body in GARBAGE_BODY:
                    r = admin.request(method, path, json=body, headers=H)
                    calls += 1
                    if r.status_code >= 500:
                        problems.append((method, path, body, r.status_code, r.text[:200]))
    assert calls > 300
    assert not problems, problems[:15]


def test_every_route_requires_auth():
    """Без входа доступны только вход, выход и версия; все остальные маршруты API отвечают 401/403."""
    from fastapi.routing import APIRoute

    from app.api.routes import router
    from app.main import create_app
    public = {("POST", "/api/auth/login"), ("POST", "/api/auth/logout"), ("GET", "/api/version")}
    leaks = []
    with TestClient(create_app()) as c:
        for r in router.routes:
            if not isinstance(r, APIRoute):
                continue
            path = r.path
            for p in ("sid", "vid", "cid", "rid", "uid", "tid", "ban_id", "stid", "name", "action", "key", "kind"):
                path = path.replace("{" + p + "}", "1")
            for m in r.methods:
                if (m, r.path) in public:
                    continue
                code = c.request(m, path, json={}, headers=H).status_code
                if code not in (401, 403):
                    leaks.append((m, r.path, code))
        assert c.get("/metrics").status_code == 401
    assert not leaks, leaks


def test_login_policy_enforced_on_server(admin, client):
    from app.utils import totp_code
    r = admin.post("/api/users", json={"username": "tmpop", "password": "Temp-Passw0rd!", "role": "operator"}, headers=H)
    assert r.status_code == 200
    op = TestClient(client.app)
    login = op.post("/api/auth/login", json={"username": "tmpop", "password": "Temp-Passw0rd!"}).json()
    assert login["must_change_password"] is True
    assert op.get("/api/sites").status_code == 200                       # смотреть можно
    r = op.post("/api/sites", json=SITE, headers=H)
    assert r.status_code == 403 and "временный пароль" in r.json()["detail"]   # изменять — нет
    r = op.post("/api/auth/tokens", json={"name": "обход", "days": 1}, headers=H)  # и токеном политику не обойти
    assert r.status_code == 403
    assert op.post("/api/auth/password", json={"current": "Temp-Passw0rd!", "new": "Fresh-Passw0rd!"},
                   headers=H).status_code == 200
    op = TestClient(client.app)
    assert op.post("/api/auth/login", json={"username": "tmpop", "password": "Fresh-Passw0rd!"}).status_code == 200
    r = op.post("/api/sites", json=dict(SITE, name="Политика", domains=["policy.example.com"]), headers=H)
    assert r.status_code == 200, r.text
    admin.delete(f"/api/sites/{r.json()['id']}", headers=H)
    # 2FA: код нельзя использовать повторно
    sec = op.post("/api/auth/totp/setup", headers=H).json()["secret"]
    assert op.post("/api/auth/totp/enable", json={"secret": sec, "code": totp_code(sec)}, headers=H).status_code == 200
    c1, c2 = TestClient(client.app), TestClient(client.app)
    assert c1.post("/api/auth/login", json={"username": "tmpop", "password": "Fresh-Passw0rd!"}).json() == {"totp_required": True}
    code = totp_code(sec)
    assert c1.post("/api/auth/login", json={"username": "tmpop", "password": "Fresh-Passw0rd!", "otp": code}).status_code == 200
    r = c2.post("/api/auth/login", json={"username": "tmpop", "password": "Fresh-Passw0rd!", "otp": code})
    assert r.status_code == 401 and "уже использован" in r.json()["detail"]
    # обязательная 2FA для администраторов: включить её без своей 2FA нельзя
    panel = admin.get("/api/settings/panel").json()
    r = admin.put("/api/settings/panel", json=dict(panel, require_2fa_admin=True), headers=H)
    assert r.status_code == 400 and "двухфакторную" in r.json()["detail"]
    # неизвестный пользователь и неверный пароль неотличимы
    a = client.post("/api/auth/login", json={"username": "no-such-user", "password": "x"}).json()["detail"]
    b = client.post("/api/auth/login", json={"username": "tmpop", "password": "wrong"}).json()["detail"]
    assert a == b
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["username"] == "tmpop")
    assert admin.delete(f"/api/users/{uid}", headers=H).status_code == 200


def test_raw_directives_policy(admin, client):
    """Оператор не может добавить в «Свои директивы» то, что читает файлы или выполняет код от root;
    наблюдатель не может запускать nginx -t для черновика."""
    r = admin.post("/api/users", json={"username": "rawop", "password": "Raw-Passw0rd!", "role": "operator"}, headers=H)
    uid = r.json()["id"]
    admin.put(f"/api/users/{uid}", json={"password": "Raw-Passw0rd2!"}, headers=H)
    nmapp = client.app.state.nm
    nmapp.db.execute("UPDATE users SET must_change_password=0 WHERE id=?", (uid,))
    op = TestClient(client.app)
    assert op.post("/api/auth/login", json={"username": "rawop", "password": "Raw-Passw0rd2!"}).status_code == 200
    evil = dict(SITE, name="Сырые", domains=["raw.example.com"], custom_server="include /etc/shadow;")
    r = op.post("/api/sites", json=evil, headers=H)
    assert r.status_code == 403 and "include /etc/shadow" in r.json()["detail"]
    r = op.post("/api/sites/preview", params={"test": 1}, json=evil, headers=H)
    assert r.status_code == 403
    for txt in ("access_log /etc/cron.d/x;", "location /l { content_by_lua_block { ngx.say(1) } }"):
        assert op.post("/api/sites", json=dict(evil, custom_server=txt), headers=H).status_code == 403, txt
    ok = dict(evil, custom_server="add_header X-Test 1;\naccess_log /var/log/nginx/raw.log;")
    r = op.post("/api/sites", json=ok, headers=H)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    # администратор добавил include — оператор по-прежнему может менять остальные поля сайта
    data = admin.get(f"/api/sites/{sid}").json()["data"]
    data["custom_server"] += "\ninclude snippets/../../../etc/passwd;"
    assert admin.put(f"/api/sites/{sid}", json=data, headers=H).status_code == 200
    data["client_max_body_size"] = "20m"
    assert op.put(f"/api/sites/{sid}", json=data, headers=H).status_code == 200
    data["locations"] = [{"path": "/x", "custom": "include /etc/hosts;"}]
    assert op.put(f"/api/sites/{sid}", json=data, headers=H).status_code == 403
    # наблюдатель видит черновик, но не запускает nginx -t
    nmapp.db.execute("UPDATE users SET role='viewer' WHERE id=?", (uid,))
    assert op.post("/api/sites/preview", json=ok, headers=H).status_code == 200
    assert op.post("/api/sites/preview", params={"test": 1}, json=ok, headers=H).status_code == 403
    admin.delete(f"/api/sites/{sid}", headers=H)
    admin.delete(f"/api/users/{uid}", headers=H)


def test_token_roles(admin, client):
    """Токен «только чтение» для мониторинга; роль токена не выше роли пользователя и следует за её понижением."""
    r = admin.post("/api/auth/tokens", json={"name": "prom", "days": 30, "role": "viewer"}, headers=H)
    assert r.status_code == 200, r.text
    tok = r.json()["token"]
    t = TestClient(client.app)
    hdr = {"Authorization": f"Bearer {tok}"}
    assert t.get("/api/sites", headers=hdr).status_code == 200
    assert t.post("/api/sites", json=SITE, headers=hdr).status_code == 403            # только чтение
    assert t.post("/api/auth/tokens", json={"name": "x"}, headers=hdr).status_code == 403  # токен не плодит токены
    lst = admin.get("/api/auth/tokens").json()
    assert next(x for x in lst if x["name"] == "prom")["role"] == "viewer"
    assert admin.post("/api/auth/tokens", json={"name": "bad", "role": "root"}, headers=H).status_code == 400
    assert admin.post("/api/auth/tokens", json={"name": "bad", "days": -1}, headers=H).status_code == 400
    # оператор не может выпустить токен администратора; понижение пользователя понижает его токены
    uid = admin.post("/api/users", json={"username": "tokop", "password": "Tok-Passw0rd!", "role": "operator"},
                     headers=H).json()["id"]
    client.app.state.nm.db.execute("UPDATE users SET must_change_password=0 WHERE id=?", (uid,))
    op = TestClient(client.app)
    assert op.post("/api/auth/login", json={"username": "tokop", "password": "Tok-Passw0rd!"}).status_code == 200
    assert op.post("/api/auth/tokens", json={"name": "a", "role": "admin"}, headers=H).status_code == 403
    optok = op.post("/api/auth/tokens", json={"name": "deploy"}, headers=H).json()["token"]   # как у пользователя
    site = dict(SITE, name="Токен", domains=["tok.example.com"])
    r = t.post("/api/sites", json=site, headers={"Authorization": f"Bearer {optok}"})
    assert r.status_code == 200, r.text
    admin.delete(f"/api/sites/{r.json()['id']}", headers=H)
    admin.put(f"/api/users/{uid}", json={"role": "viewer"}, headers=H)
    assert t.post("/api/sites", json=site, headers={"Authorization": f"Bearer {optok}"}).status_code == 403
    admin.delete(f"/api/users/{uid}", headers=H)
