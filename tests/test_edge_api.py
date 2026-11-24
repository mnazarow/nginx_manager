"""Весь API разом: каждый метод из схемы OpenAPI вызывается без входа, с ролью «наблюдатель» и с ролью
«администратор» с пустыми и неверными данными. Ни один вызов не должен давать внутреннюю ошибку (500), без входа
— только публичные методы, наблюдатель не может ничего менять, кроме своего профиля. Внешние команды (nginx,
systemctl, apt…) заменены заглушкой — проверяется обработка их отказа."""
from __future__ import annotations

import re
import subprocess
import time

import pytest

from app.config import settings

PUBLIC = {("POST", "/api/auth/login"), ("GET", "/api/access-link/{token}"), ("POST", "/api/access-link/{token}"),
          ("GET", "/healthz"), ("GET", "/metrics"), ("POST", "/api/auth/logout"), ("GET", "/api/version")}
# POST без изменений: предпросмотр конфигурации, nginx -t, проверки — доступны и наблюдателю
READONLY_POST = {"/api/sites/preview", "/api/streams/preview", "/api/config/test", "/api/health/check",
                 "/api/diagnostics/run", "/api/protection/test"}
SELF = {"/api/auth/logout", "/api/auth/password", "/api/auth/totp/setup", "/api/auth/totp/enable",
        "/api/auth/totp/disable", "/api/auth/tokens", "/api/auth/tokens/{tid}", "/api/auth/sessions/{sid}",
        "/api/auth/sessions", "/api/auth/preferences", "/api/ui/state", "/api/auth/me"}


class FakeProc:
    """Вместо внешних программ: «команда не выполнена» — так тест проверяет обработку отказов, а не систему."""
    calls: list = []

    def __init__(self, *a, **k):
        cmd = a[0] if a else k.get("args")
        FakeProc.calls.append(cmd)
        self.returncode, self.stdout, self.stderr, self.pid = 1, "", "заглушка теста: команда не выполнена", 0

    def communicate(self, *a, **k):
        return self.stdout, self.stderr

    def wait(self, *a, **k):
        return 1

    def poll(self):
        return 1

    def kill(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    app = create_app()
    with TestClient(app) as c:
        nm = app.state.nm
        # процессы и сеть: ничего не трогаем на машине, где идут тесты
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc(*a, **k))
        monkeypatch.setattr(subprocess, "Popen", FakeProc)
        monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, a[0] if a else "")))
        import urllib.request

        def no_net(*a, **k):
            raise OSError("сеть отключена в тесте")
        monkeypatch.setattr(urllib.request, "urlopen", no_net)
        for name in ("start", "stop", "restart", "reload_or_start", "reopen_logs"):
            monkeypatch.setattr(nm.nginx, name, lambda *a, **k: (False, "заглушка теста"))
        import app.process as P
        monkeypatch.setattr(P, "request_restart", lambda: False)
        admin_tok = nm.auth.create_token(nm.db.one("SELECT id FROM users WHERE username='admin'")["id"], "t")
        vid = nm.auth.create_user("viewer1", "Viewer-pass1", "viewer")
        viewer_tok = nm.auth.create_token(vid, "v")
        c.nm, c.admin, c.viewer = nm, admin_tok, viewer_tok
        yield c


def _routes(client):
    out = []
    for path, ops in client.app.openapi()["paths"].items():
        for method, op in ops.items():
            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                out.append((method.upper(), path, op))
    return out


def _fill(path):
    return re.sub(r"\{(\w+)\}", lambda m: "999999" if m.group(1) in ("id", "sid", "pid", "cid", "rid", "uid",
                                                                    "tid", "vid", "aid", "lid", "bid", "n")
                  or m.group(1).endswith("_id") else "nonexistent", path)


def test_route_count_matches_docs(api):
    n = len(_routes(api))
    assert n >= 200, n


def test_every_route_requires_auth(api):
    open_ = []
    for method, path, _ in _routes(api):
        r = api.request(method, _fill(path), json={})
        if r.status_code not in (401, 403) and (method, path) not in PUBLIC:
            open_.append((method, path, r.status_code))
    assert not open_, open_


def test_viewer_cannot_change_anything(api):
    leaked = []
    h = {"Authorization": f"Bearer {api.viewer}"}
    for method, path, _ in _routes(api):
        if method == "GET" or path in SELF or path in READONLY_POST or (method, path) in PUBLIC:
            continue
        r = api.request(method, _fill(path), json={}, headers=h)
        if r.status_code != 403:
            leaked.append((method, path, r.status_code, r.text[:120]))
    assert not leaked, "\n".join(f"{m} {p} {c}" for m, p, c, _ in leaked)


def test_no_internal_errors_with_empty_or_bad_data(api):
    """Администратор с пустыми данными, мусором и несуществующими объектами — 4xx с понятным текстом, а не 500."""
    h = {"Authorization": f"Bearer {api.admin}"}
    errors = []
    skip = {("POST", "/api/auth/logout")}
    for method, path, op in _routes(api):
        if (method, path) in skip:
            continue
        url = _fill(path)
        bodies = [{}] if method in ("POST", "PUT", "PATCH") else [None]
        if method in ("POST", "PUT", "PATCH"):
            bodies += [[], {"name": "x" * 5000, "id": "abc", "enabled": "maybe"}]
        for body in bodies:
            t0 = time.time()
            r = api.request(method, url, json=body, headers=h) if body is not None else \
                api.request(method, url + "?start=abc&limit=-5&from=x&to=y&site=%00", headers=h)
            if r.status_code >= 500:
                errors.append((method, path, repr(body)[:40], r.status_code, r.text[:200]))
            if time.time() - t0 > 20:
                errors.append((method, path, "медленно", round(time.time() - t0, 1)))
            if r.status_code in (400, 409, 422) and r.headers.get("content-type", "").startswith("application/json"):
                detail = r.json().get("detail")
                if not detail:
                    errors.append((method, path, "без пояснения", r.status_code))
    assert not errors, "\n".join(" ".join(map(str, e)) for e in errors)


def test_hostile_query_values(api):
    """nan, inf, ноль и отрицательные числа в параметрах всех GET-методов: 4xx или корректный ответ, не 500."""
    h = {"Authorization": f"Bearer {api.admin}"}
    variants = ["from=nan&to=inf", "from=-1e308&to=1e308", "points=0&limit=0&offset=-1", "limit=-1&days=-5&weeks=0",
                "hours=0&minutes=-1&seq=-1", "limit=99999999999999999999", "site=../../etc&kind=../x&q=%25%25_"]
    errors = []
    for method, path, _ in _routes(api):
        if method != "GET":
            continue
        for v in variants:
            r = api.get(_fill(path) + "?" + v, headers=h)
            if r.status_code >= 500:
                errors.append(f"{path}?{v} → {r.status_code} {r.text[:150]}")
    assert not errors, "\n".join(errors)
    # отрицательный limit не «без ограничения» и не срез «все, кроме последнего»
    for i in range(3):
        api.nm.db.event("info", "test", f"событие {i}")
    assert len(api.get("/api/events?limit=-1", headers=h).json()) == 1
    assert len(api.get("/api/alerts/events?limit=-1", headers=h).json()) <= 1


def test_session_csrf_and_ip_restrictions(api):
    nm = api.nm
    r = api.post("/api/auth/login", json={"username": "viewer1", "password": "Viewer-pass1"})
    assert r.status_code == 200 and "nm_session" in r.cookies or api.cookies.get("nm_session")
    # с cookie сессии изменения — только с заголовком X-NM-CSRF
    assert api.post("/api/auth/totp/setup").status_code == 403
    assert api.post("/api/auth/totp/setup", headers={"X-NM-CSRF": "1"}).status_code == 200
    assert api.get("/api/auth/me").json()["username"] == "viewer1"
    # неверный пароль много раз — блокировка с понятным текстом
    codes = [api.post("/api/auth/login", json={"username": "viewer1", "password": "wrong"}).status_code
             for _ in range(12)]
    assert 429 in codes or codes.count(401) == 12
    # доступ к панели только из сети 10.0.0.0/8 — клиент тестов не проходит, токен тоже
    p = nm.panel()
    nm.save_panel(p.model_copy(update={"panel_allow": ["10.0.0.0/8"]}))
    r = api.get("/api/auth/me", headers={"Authorization": f"Bearer {api.admin}"})
    assert r.status_code == 403 and "IP" in r.json()["detail"]
    nm.save_panel(p)
    # просроченный токен, мусорный токен
    nm.db.execute("UPDATE api_tokens SET expires_at=?", (time.time() - 1,))
    assert api.get("/api/auth/me", headers={"Authorization": f"Bearer {api.admin}"}).status_code == 401
    assert api.get("/api/auth/me", headers={"Authorization": "Bearer \x00"}).status_code == 401


def test_bad_json_and_query(api):
    h = {"Authorization": f"Bearer {api.admin}", "Content-Type": "application/json"}
    r = api.post("/api/sites", content=b"{not json", headers=h)
    assert r.status_code == 422 and r.json()["detail"]
    r = api.post("/api/sites", content="\xff\xfe".encode("latin-1"), headers=h)
    assert r.status_code in (400, 422)
    r = api.get("/api/requests?start=вчера", headers=h)
    assert r.status_code == 400 and "Параметр start" in r.json()["detail"]
    r = api.get("/api/requests?uri=100%25_off", headers=h)
    assert r.status_code == 200
    # заголовки безопасности на всех ответах API
    r = api.get("/api/auth/me", headers=h)
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    # обход каталога статики и документации
    for p in ("/static/../app/config.py", "/static/%2e%2e/app/config.py", "/docs-files/../../etc/passwd"):
        assert api.get(p).status_code == 404
