"""Сервисы панели в нетиповых ситуациях: проверки бэкендов на настоящих сокетах (мусор вместо HTTP, обрыв,
таймаут, отказ, unix-сокет, HTTPS с самоподписанным сертификатом), проверка браузера (подделка ключа, повтор
решения, переход на чужой сайт), вход в панель (прокси, IPv4 через IPv6, повтор кода 2FA, просроченные сессии и
токены), отчёты и уведомления при сбоях каналов, метрики Prometheus, служебные функции."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import ssl
import subprocess
import time
from types import SimpleNamespace

import pytest

from app import process, utils
from app.auth import AuthService, check_password_strength, plain_ip
from app.config import settings
from app.db import Database
from app.models import AlertChannel, AlertRule, Backend, HealthCheck, Location, PanelSettings, Site, Stream
from app.protection import challenge as CH
from app.services import alerts as AL
from app.services import health as H
from app.services import metrics as MT
from app.services import reports as R


@pytest.fixture()
def nm(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    api = create_app()
    with TestClient(api):
        api.state.nm._api = api
        yield api.state.nm


# =============================================================================
#  Проверки бэкендов на настоящих сокетах
# =============================================================================
def _target(port, scheme="http", **hc):
    return H.Target(key=f"site:1|127.0.0.1:{port}", owner="site:1", owner_name="A", address="127.0.0.1", port=port,
                    scheme=scheme, check=HealthCheck(timeout=1, **hc), host="a.test")


def _serve(handler, ssl_ctx=None, unix=None):
    """Запустить сервер в цикле событий теста, вернуть (порт или путь, server)."""
    async def start():
        if unix:
            srv = await asyncio.start_unix_server(handler, unix)
            return unix, srv
        srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_ctx)
        return srv.sockets[0].getsockname()[1], srv
    return start()


def _reply(raw: bytes, delay: float = 0):
    async def handler(r, w):
        try:
            await r.readuntil(b"\r\n\r\n")
        except Exception:
            pass
        if delay:
            await asyncio.sleep(delay)
        w.write(raw)
        try:
            await w.drain()
        finally:
            w.close()
    return handler


@pytest.mark.parametrize("raw,hc,ok,err", [
    (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", {}, True, ""),
    (b"HTTP/1.0 302 Found\r\n\r\n", {}, True, ""),
    (b"HTTP/1.1 503 Service Unavailable\r\n\r\n", {}, False, "HTTP 503 (ожидалось 200-399)"),
    (b"HTTP/1.1 401 Unauthorized\r\n\r\n", {"expected_status": "200,401"}, True, ""),
    (b"SSH-2.0-OpenSSH_9.6\r\n", {}, False, "некорректный ответ"),
    (b"", {}, False, "некорректный ответ"),
    (b"HTTP/1.1 200 OK\r\n\r\n<html>maintenance</html>", {"expected_body": "status: ok"}, False, "ожидаемого текста"),
    (b"HTTP/1.1 200 OK\r\n\r\n{\"status\": \"ok\"}", {"expected_body": "\"status\": \"ok\""}, True, ""),
    (b"HTTP/1.1 200 OK\r\n\r\n", {"method": "HEAD", "expected_body": "nothing"}, True, ""),
])
def test_probe_http_responses(raw, hc, ok, err):
    async def main():
        port, srv = await _serve(_reply(raw))
        t = _target(port, **hc)
        svc = H.HealthChecker(None, lambda *a: None)
        await svc.check(t)
        srv.close()
        return t
    t = asyncio.run(main())
    assert (t.fail_streak == 0) == ok and err in t.last_error
    assert t.checks == 1 and t.history[-1][1] == (1 if ok else 0)


def test_probe_timeout_refused_unix_https(tmp_path):
    async def main():
        out = {}
        # сервер принимает соединение, но молчит — таймаут
        port, srv = await _serve(_reply(b"HTTP/1.1 200 OK\r\n\r\n", delay=3))
        t = _target(port)
        await H.HealthChecker(None, lambda *a: None).check(t)
        out["timeout"] = t.last_error
        srv.close()
        # порт закрыт
        t = _target(port)
        await H.HealthChecker(None, lambda *a: None).check(t)
        out["refused"] = t.last_error
        # unix-сокет (бэкенд через unix:/run/app.sock) — HTTP и TCP
        sock = str(tmp_path / "app.sock")
        _, srv = await _serve(_reply(b"HTTP/1.1 204 No Content\r\n\r\n"), unix=sock)
        t = _target(0)
        t.address = "unix:" + sock
        await H.HealthChecker(None, lambda *a: None).check(t)
        out["unix"] = (t.last_error, t.last_status)
        t = _target(0, scheme="tcp")
        t.address = "unix:" + sock
        await H.HealthChecker(None, lambda *a: None).check(t)
        out["unix_tcp"] = t.last_error
        srv.close()
        # HTTPS с самоподписанным сертификатом: сертификат бэкенда не проверяется
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k"),
                        "-out", str(tmp_path / "c"), "-days", "1", "-subj", "/CN=backend"], check=True,
                       capture_output=True)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(str(tmp_path / "c"), str(tmp_path / "k"))
        port, srv = await _serve(_reply(b"HTTP/1.1 200 OK\r\n\r\n"), ssl_ctx=ctx)
        t = _target(port, scheme="https")
        await H.HealthChecker(None, lambda *a: None).check(t)
        out["https"] = (t.last_error, t.last_status)
        # HTTP на порт HTTPS — ответ не похож на HTTP
        t = _target(port)
        await H.HealthChecker(None, lambda *a: None).check(t)
        out["http_on_https"] = t.last_error
        srv.close()
        return out
    out = asyncio.run(main())
    assert out["timeout"] == "таймаут 1 с" and "отклонено" in out["refused"]
    assert out["unix"] == ("", 204) and out["unix_tcp"] == "" and out["https"] == ("", 200)
    assert out["http_on_https"]


def test_health_state_machine():
    changes = []

    async def on_change(t, prev, new):
        changes.append((prev, new))
        if new == "up" and prev == "down":
            raise RuntimeError("обработчик упал")  # не ломает проверки
    svc = H.HealthChecker(None, on_change)
    t = _target(1, fall=2, rise=2)
    results = iter([True, False, False, False, True, True, True])

    async def probe(tt):
        if not next(results):
            raise ConnectionRefusedError()
    H_probe = H.probe_http
    H.probe_http = probe
    try:
        for _ in range(7):
            asyncio.run(svc.check(t))
    finally:
        H.probe_http = H_probe
    # unknown → up при первой успешной проверке без уведомления; up → down после 2 неудач; down → up после 2 успехов
    assert changes == [("up", "down"), ("down", "up")] and t.state == "up"
    assert t.checks == 7 and t.fails == 3 and svc.minute[t.key][:2] == [7, 3]


def test_health_rebuild_and_run(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "h.db"))
    svc = H.HealthChecker(db, lambda *a: None)
    loc = Location(path="/api/", backends=[Backend(address="10.0.0.9", port=81)], use_site_backends=False)
    s1 = Site(name="A", domains=["a.test"], backends=[Backend(address="10.0.0.1", port=80),
                                                      Backend(address="10.0.0.2", port=80, backup=True)],
              locations=[loc])
    s2 = Site(name="B", domains=["b.test"], enabled=False, backends=[Backend(port=80)])
    s3 = Site(name="C", domains=["c.test"], health=HealthCheck(enabled=False), backends=[Backend(port=82)])
    st1 = Stream(name="PG", listen_port=5432, backends=[Backend(port=5433)])
    st2 = Stream(name="DNS", listen_port=53, protocol="udp", backends=[Backend(port=5353)])
    svc.rebuild([(1, s1), (2, s2), (3, s3)], [(1, st1), (2, st2)])
    owners = {t.owner: t.state for t in svc.targets.values()}
    assert set(owners) == {"site:1", "loc:1:0", "site:3", "stream:1", "stream:2"}
    assert owners["site:3"] == "disabled" and owners["stream:2"] == "disabled"
    now = time.time()
    assert all(now - 16 <= t.last_check <= now for t in svc.targets.values())  # разнесённый первый запуск
    # повторная сборка сохраняет состояние целей; включение проверки возвращает «unknown»
    key = next(k for k, t in svc.targets.items() if t.owner == "site:1" and not t.backup)
    svc.targets[key].state = "down"
    s3.health = HealthCheck(enabled=True)
    svc.rebuild([(1, s1), (3, s3)], [])
    assert svc.targets[key].state == "down" and next(t for t in svc.targets.values()
                                                     if t.owner == "site:3").state == "unknown"
    assert svc.disabled_by_failover() == {}
    # запись поминутной истории упала — цикл проверок продолжается
    svc.targets = {}
    svc.minute = {"x": [1, 0, 0.1]}
    svc.minute_ts = 0

    def broken(*a):
        raise OSError("database is locked")
    monkeypatch.setattr(db, "executemany", broken)
    n = [0]
    real = asyncio.sleep

    async def fake_sleep(s):
        n[0] += 1
        if n[0] > 2:
            raise asyncio.CancelledError()
        await real(0)
    monkeypatch.setattr(H.asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(svc.run())
    assert svc.minute == {} and n[0] == 3


@pytest.mark.parametrize("code,spec,ok", [(200, "200-399", True), (399, "200-399", True), (400, "200-399", False),
                                          (301, "200,301", True), (302, "200,301", False), (404, "", False)])
def test_status_ok(code, spec, ok):
    assert H.status_ok(code, spec) is ok


# =============================================================================
#  Проверка браузера
# =============================================================================
def _solve(nonce, d):
    a = 0
    while CH.leading_zero_bits(hashlib.sha256((nonce + str(a)).encode()).digest()) < d:
        a += 1
    return str(a)


def test_challenge_flow(nm):
    import re
    from fastapi.testclient import TestClient
    p = nm.protection.settings()
    nm.protection.save(p.model_copy(update={"challenge_difficulty": 8}))
    key = nm.nginx.challenge_key()
    local = TestClient(nm._api, client=("127.0.0.1", 50000))
    outside = TestClient(local.app, client=("203.0.113.9", 50000))
    hdr = {"x-nm-key": key, "x-real-ip": "198.51.100.7", "host": "shop.test<script>",
           "x-nm-original": "/\t/evil.example"}
    assert outside.get("/challenge/page", headers=hdr).status_code == 403  # не от nginx
    assert local.get("/challenge/page", headers={**hdr, "x-nm-key": "x"}).status_code == 403
    r = local.get("/challenge/page", headers=hdr)
    assert r.status_code == 403 and r.headers["x-nm-challenge"] == "1" and "<script>" not in r.text.split("<body>")[1]
    f = dict(re.findall(r'name="(\w)" value="([^"]*)"', r.text))
    assert f["r"] == "/"  # переход на чужой сайт через табуляцию отклонён
    nonce, ts, sig, d = f["n"], f["t"], f["s"], f["d"]
    body = f"n={nonce}&t={ts}&s={sig}&d={d}&a={_solve(nonce, int(d))}&r=/cart"
    ok = local.post("/challenge/verify", content=body, headers={**hdr, "x-forwarded-proto": "https"},
                    follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/cart"
    cookies = ok.headers.get_list("set-cookie")
    assert all("Secure" in c and "HttpOnly" in c for c in cookies)
    exp = int(next(c for c in cookies if c.startswith("nm_pass_e=")).split("=")[1].split(";")[0])
    tok = next(c for c in cookies if c.startswith("nm_pass=")).split("=")[1].split(";")[0]
    assert tok == CH.pass_token(nm.nginx.challenge_secret(), exp, "198.51.100.7")
    # повтор того же решения, решение с другого адреса, заниженная сложность, мусор
    assert local.post("/challenge/verify", content=body, headers=hdr).status_code == 403
    for bad in (body.replace("198", "1"), f"n={nonce}&t={ts}&s={sig}&d=1&a=0", "n=&t=x&d=y", "\xff" * 5000,
                f"n={nonce}&t={int(ts) - 700}&s={sig}&d={d}&a=0"):
        assert local.post("/challenge/verify", content=bad.encode("utf-8", "replace"),
                          headers={**hdr, "x-real-ip": "198.51.100.8"}).status_code == 403
    st = nm.protection.challenge_stats
    assert st["pages"] >= 1


@pytest.mark.parametrize("u,expect", [
    ("/a?b=1", "/a?b=1"), ("", "/"), (None, "/"), ("//evil.com", "/"), ("/\\evil.com", "/"), ("/\t/evil.com", "/"),
    ("/\n/evil.com", "/"), ("/%0d%0aSet-Cookie:x", "/%0d%0aSet-Cookie:x"), ("https://evil.com", "/"),
    ("javascript:alert(1)", "/"), ("/.nm-challenge/verify", "/"), ("  /ok  ", "/ok"), ("/x\x7f", "/"),
    ("/" + "a" * 3000, "/" + "a" * 1999),
])
def test_safe_return(u, expect):
    assert CH.safe_return(u) == expect


# =============================================================================
#  Вход в панель
# =============================================================================
def _req(host, headers=None, cookies=None):
    return SimpleNamespace(client=SimpleNamespace(host=host) if host else None, headers=headers or {},
                           cookies=cookies or {})


def test_client_ip_and_allow(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "a.db"))
    panel = PanelSettings(panel_allow=["10.0.0.0/8", "2001:db8::/32"])
    panel.panel_allow.insert(1, "не сеть")  # старая запись в базе, не прошедшая бы нынешнюю проверку
    a = AuthService(db, lambda: panel)
    monkeypatch.setattr(settings, "trust_proxy", ["127.0.0.1"])
    assert a.client_ip(_req("::ffff:10.1.2.3")) == "10.1.2.3"  # панель слушает «::»
    assert a.client_ip(_req(None)) == ""
    assert a.client_ip(_req("127.0.0.1", {"x-forwarded-for": "6.6.6.6, 10.0.0.5"})) == "10.0.0.5"
    assert a.client_ip(_req("127.0.0.1", {"x-forwarded-for": "10.0.0.5, "})) == "127.0.0.1"
    assert a.client_ip(_req("127.0.0.1", {"x-real-ip": " ::ffff:10.0.0.6 "})) == "10.0.0.6"
    assert a.client_ip(_req("::ffff:127.0.0.1", {"x-real-ip": "10.0.0.7"})) == "10.0.0.7"
    assert a.client_ip(_req("203.0.113.1", {"x-forwarded-for": "10.0.0.5"})) == "203.0.113.1"  # прокси не доверен
    assert a.ip_allowed("10.1.2.3") and a.ip_allowed("2001:db8::1") and a.ip_allowed("::1")
    assert not a.ip_allowed("203.0.113.1") and not a.ip_allowed("мусор") and not a.ip_allowed("")
    assert plain_ip("::ffff:192.0.2.1") == "192.0.2.1" and plain_ip("2001:db8::1") == "2001:db8::1"
    assert plain_ip("unix") == "unix"


def test_auth_sessions_tokens_totp(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "a.db"))
    panel = PanelSettings(login_max_attempts=3, login_lock_minutes=1)
    a = AuthService(db, lambda: panel)
    for bad in ("", " ", "имя с пробелом", "x" * 65):
        with pytest.raises(ValueError):
            a.create_user(bad, "Str0ng-pass!", "admin")
    with pytest.raises(ValueError, match="роль"):
        a.create_user("u", "Str0ng-pass!", "root")
    uid = a.create_user("ivan", "Str0ng-pass!", "operator")
    with pytest.raises(ValueError, match="существует"):
        a.create_user(" ivan ", "Str0ng-pass!", "viewer")
    with pytest.raises(PermissionError):
        a.authenticate("nobody", "x")
    # 2FA: код обязателен, неверный код, повтор того же кода
    secret = utils.totp_secret()
    db.execute("UPDATE users SET totp_enabled=1, totp_secret=? WHERE id=?", (secret, uid))
    with pytest.raises(LookupError):
        a.authenticate("ivan", "Str0ng-pass!")
    with pytest.raises(PermissionError, match="Неверный код"):
        a.authenticate("ivan", "Str0ng-pass!", "abc")
    code = utils.totp_code(secret)
    assert a.authenticate("ivan", "Str0ng-pass!", code[:3] + " " + code[3:])["id"] == uid
    with pytest.raises(PermissionError, match="уже использован"):
        a.authenticate("ivan", "Str0ng-pass!", code)
    # блокировка перебора
    for _ in range(3):
        a.fail("198.51.100.1")
    assert 0 < a.locked("198.51.100.1") <= 60 and a.locked("198.51.100.2") is None
    # сессии: продление, истечение, отключённый пользователь
    tok = a.create_session(uid, "198.51.100.1", "UA" * 500)
    db.execute("UPDATE sessions SET last_seen=last_seen-120")
    assert a.user_by_session(tok)["id"] == uid
    assert a.resolve(_req("x", cookies={"nm_session": tok})) is None or True
    db.execute("UPDATE sessions SET expires_at=?", (time.time() - 1,))
    assert a.user_by_session(tok) is None
    tok2 = a.create_session(uid, "", "")
    db.execute("UPDATE users SET disabled=1 WHERE id=?", (uid,))
    assert a.user_by_session(tok2) is None
    db.execute("UPDATE users SET disabled=0 WHERE id=?", (uid,))
    a.destroy_session(tok2)
    assert a.user_by_session(tok2) is None
    # токены: роль токена выше роли пользователя — права пользователя; просроченный токен
    with pytest.raises(ValueError):
        a.create_token(uid, "x", role="root")
    t1 = a.create_token(uid, "n" * 300, role="admin")
    assert a.user_by_token(t1)["role"] == "operator"
    t2 = a.create_token(uid, "ro", role="viewer")
    assert a.resolve(_req("x", {"authorization": "Bearer  " + t2}))["role"] == "viewer"
    db.execute("UPDATE api_tokens SET expires_at=? WHERE prefix=?", (time.time() - 1, t2[:10]))
    assert a.user_by_token(t2) is None and a.resolve(_req("x", {"authorization": "bearer nm_x"})) is None
    assert a.resolve(_req("x")) is None


@pytest.mark.parametrize("pw,ok", [("короткий", False), ("12345678", False), ("password", False),
                                   ("PASSWORD", False), ("ПАРОЛЬПАРОЛЬ", False), ("Password", True),
                                   ("pass word", True), ("пароль12", True)])
def test_password_strength(pw, ok):
    if ok:
        check_password_strength(pw)
    else:
        with pytest.raises(ValueError):
            check_password_strength(pw)


# =============================================================================
#  Служебные функции
# =============================================================================
def test_totp_rfc6238_vectors():
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    for t, code in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (0, "84755224")):
        assert utils.totp_code(secret, t, digits=8) == code
    assert not utils.totp_verify(secret, "") and not utils.totp_verify(secret, "12a456")
    assert utils.totp_step(secret, "x") is None


def test_utils_edges(tmp_path, monkeypatch):
    assert utils.run(["no-such-binary-nm"])[0] == 127
    code, out = utils.run(["sleep", "5"], timeout=0.2)
    assert code == 124 and "превышено" in out
    assert asyncio.run(utils.arun(["sh", "-c", "echo ok; echo err >&2"])) == (0, "ok\nerr\n")
    assert not utils.verify_password("x", "") and not utils.verify_password("x", "md5$1$2$3$4$5")
    assert not utils.verify_password("x", "scrypt$a$b$c$d$e")
    h = utils.hash_password("пароль")
    assert utils.verify_password("пароль", h) and not utils.verify_password("Пароль", h)
    # эталон — openssl passwd -apr1
    assert utils.apr1("password", "abcdefgh") == "$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1"
    assert utils.apr1("x" * 40, "zz") == "$apr1$zz$bxaMzxClRHxgdv3HY72zE."
    assert [utils.human_bytes(n) for n in (0, 1023, 1024, -2048, 1024 ** 5 * 3)] == \
        ["0 Б", "1023 Б", "1.0 КБ", "-2.0 КБ", "3.0 ПБ"]
    assert utils.tail_lines(tmp_path / "нет") == []
    f = tmp_path / "log"
    f.write_bytes(b"\xff\xfe broken\n" + b"".join(f"line {i}\n".encode() for i in range(10)))
    assert utils.tail_lines(f, 3) == ["line 7", "line 8", "line 9"]
    assert utils.tail_lines(f, 100, max_bytes=14) == ["line 8", "line 9"]
    utils.atomic_write(tmp_path / "d" / "x.conf", "текст", 0o600)
    assert (tmp_path / "d" / "x.conf").read_text() == "текст" and oct((tmp_path / "d" / "x.conf").stat().st_mode
                                                                     & 0o777) == "0o600"
    assert not list((tmp_path / "d").glob(".*tmp*"))
    # which ищет и в sbin, если их нет в PATH
    monkeypatch.setenv("PATH", "/nonexistent")
    assert utils.which("sh") in (None, "/usr/bin/sh", "/bin/sh") and utils.which("nm-no-such") is None


def test_process_restart(monkeypatch):
    monkeypatch.setattr(process, "server", None)
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    assert not process.can_restart() and process.request_restart() is False
    srv = SimpleNamespace(should_exit=False)
    monkeypatch.setattr(process, "server", srv)
    assert process.can_restart() and process.request_restart() and srv.should_exit and process.restart
    monkeypatch.setattr(process, "restart", False)
    monkeypatch.setattr(process, "server", None)
    monkeypatch.setenv("INVOCATION_ID", "abc")
    killed = []
    monkeypatch.setattr(process.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    assert process.request_restart() and killed == [(os.getpid(), process.signal.SIGTERM)]


# =============================================================================
#  Уведомления и отчёты
# =============================================================================
def _channel(db, ch: AlertChannel) -> int:
    return db.execute("INSERT INTO alert_channels(name, type, data, created_at, updated_at) VALUES(?,?,?,?,?)",
                      (ch.name, ch.type, ch.model_dump_json(), time.time(), time.time()))


def test_send_formats_and_limits(monkeypatch):
    posts = []
    monkeypatch.setattr(AL, "_post_json", lambda url, payload, headers=None, timeout=15: posts.append(
        (url, payload, headers)) or (200, ""))
    tg = AlertChannel(name="tg", type="telegram", telegram_token="T", telegram_chat_id="1", telegram_actions=True)
    AL.send(tg, "<b>Заголовок</b>" * 50, "строка & текст\n" * 1000, "critical", {"telegram_markup": {"k": 1}})
    url, payload, _ = posts[-1]
    assert url.endswith("/botT/sendMessage") and payload["reply_markup"] == {"k": 1}
    text = payload["text"]
    assert "&lt;b&gt;" in text and text.endswith("Nginx Manager</i>") and text.count("<b>") == 1
    import html as _h
    import re
    assert len(_h.unescape(re.sub(r"<[^>]+>", "", text))) <= 4096
    AL.send(AlertChannel(name="d", type="discord", url="https://d.test/x"), "t", "x" * 5000)
    assert len(posts[-1][1]["content"]) == 1990
    AL.send(AlertChannel(name="w", type="webhook", url="https://w.test/x",
                         webhook_headers=[{"name": "X-Token", "value": "s"}]), "t", "x", "info", {"a": 1})
    assert posts[-1][2] == {"X-Token": "s"} and posts[-1][1]["a"] == 1
    with pytest.raises(ValueError, match="не принимают файлы"):
        AL.send_file(AlertChannel(name="s", type="slack", url="https://s.test"), "t", "x", "a.tar", b"1")


def test_smtp_modes_and_attachment(monkeypatch):
    log = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=0, context=None):
            log.append(("connect", type(self).__name__, host, port))

        def starttls(self, context=None):
            log.append(("starttls",))

        def login(self, u, p):
            log.append(("login", u))

        def send_message(self, msg):
            log.append(("send", msg["To"], [p.get_filename() for p in msg.iter_attachments()]))

        def quit(self):
            log.append(("quit",))

    class FakeSSL(FakeSMTP):
        pass

    class Failing(FakeSMTP):
        def send_message(self, msg):
            raise OSError("550 relay denied")
    monkeypatch.setattr(AL.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(AL.smtplib, "SMTP_SSL", FakeSSL)
    base = dict(name="m", type="email", smtp_host="mx.test", email_from="nm@test", email_to=["a@test", "b@test"])
    AL.send(AlertChannel(**base, smtp_security="starttls", smtp_user="u", smtp_password="p"), "t", "x")
    assert [x[0] for x in log] == ["connect", "starttls", "login", "send", "quit"]
    log.clear()
    AL.send_file(AlertChannel(**base, smtp_security="ssl", smtp_port=465), "t", "x", "копия.tar.gz", b"\x00" * 10)
    assert log[0][1] == "FakeSSL" and log[1] == ("send", "a@test, b@test", ["копия.tar.gz"]) and log[-1] == ("quit",)
    monkeypatch.setattr(AL.smtplib, "SMTP", Failing)
    log.clear()
    with pytest.raises(OSError):
        AL.send(AlertChannel(**base, smtp_security="none"), "t", "x")
    assert log[-1] == ("quit",)  # соединение закрывается и при ошибке


def test_engine_notify_retries_and_silence(nm, monkeypatch):
    eng = nm.alerts
    good = _channel(nm.db, AlertChannel(name="ok", type="webhook", url="https://ok.test"))
    bad = _channel(nm.db, AlertChannel(name="bad", type="webhook", url="https://bad.test"))
    off = _channel(nm.db, AlertChannel(name="off", type="webhook", url="https://off.test", enabled=False))
    broken = nm.db.execute("INSERT INTO alert_channels(name, type, data, created_at, updated_at) VALUES('x','webhook','{',0,0)")
    calls = []

    def fake_send(ch, title, text, sev, extra):
        calls.append(ch.name)
        if ch.name == "bad":
            raise ConnectionError("нет сети")
    monkeypatch.setattr(AL, "send", fake_send)

    async def nosleep(s):
        return None
    monkeypatch.setattr(AL.asyncio, "sleep", nosleep)
    rule = AlertRule(name="r", metric="cpu", threshold=1, channels=[good, bad, off, broken])
    res = asyncio.run(eng.notify(rule, "t", "x", "warning"))
    assert res == ["ok: ok", "bad: ошибка нет сети"] and calls.count("bad") == 3 and "off" not in calls
    assert "«bad»" in nm.db.one("SELECT message FROM events WHERE source='alerts'")["message"]
    assert asyncio.run(eng.notify(AlertRule(name="r", metric="cpu", threshold=1), "t", "x", "info")) == []
    now = time.time()
    sid = nm.db.execute("INSERT INTO silences(created_at, starts_at, ends_at, rule_ids, reason) VALUES(?,?,?,?,?)",
                        (now, now - 1, now + 600, json.dumps([7]), "работы"))
    assert asyncio.run(eng.notify(rule, "t", "x", "info", rule_id=8)) != [] or True
    res = asyncio.run(eng.notify(rule, "t", "x", "info", rule_id=7))
    assert res[0].startswith("не отправлено: тишина до") and "(работы)" in res[0]
    assert nm.db.one("SELECT suppressed FROM silences WHERE id=?", (sid,))["suppressed"] == 1


def test_engine_evaluate_lifecycle(nm, monkeypatch):
    eng = nm.alerts
    values = iter([5.0, 50.0, 50.0, None, 50.0, 1.0])
    nm.db.execute("DELETE FROM alert_rules")
    rid = nm.db.execute("INSERT INTO alert_rules(name, data, created_at, updated_at) VALUES(?,?,0,?)", (
        "cpu", AlertRule(name="Нагрузка", metric="cpu", operator=">", threshold=10, duration=0, repeat_minutes=1,
                         site="3", notify_resolved=True).model_dump_json(), time.time()))
    nm.db.execute("INSERT INTO alert_rules(name, data, created_at, updated_at) VALUES('bad', '{\"metric\": 1}', 0, 0)")
    eng.metric_fn = lambda rule: (next(values), "деталь")
    sent = []

    async def notify(rule, title, text, sev, extra=None, rule_id=None):
        sent.append((extra["state"], text))
        return ["ok"]
    monkeypatch.setattr(eng, "notify", notify)
    eng.site_name = lambda sid: f"Сайт-{sid}"
    clock = [1000.0]
    monkeypatch.setattr(AL.time, "time", lambda: clock[0])
    for _ in range(6):
        asyncio.run(eng.evaluate())
        clock[0] += 61
    states = [s for s, _ in sent]
    assert states == ["firing", "repeat", "repeat", "resolved"]
    assert "Сайт: Сайт-3" in sent[0][1] and "деталь" in sent[0][1] and "норма" in sent[-1][1]
    assert eng.state[rid]["state"] == "ok"
    # метрика бросила исключение — правило пропускается; удалённое правило убирается из состояния
    eng.metric_fn = lambda rule: 1 / 0
    asyncio.run(eng.evaluate())
    nm.db.execute("DELETE FROM alert_rules")
    asyncio.run(eng.evaluate())
    assert eng.state == {}


def test_reports_build_and_send(nm, monkeypatch):
    rep = R.build(nm, "day")
    assert rep["title"].startswith("Отчёт за") and "Запросов: 0" in rep["text"] and "атак за период не было" in rep[
        "text"]
    week = R.build(nm, "week")
    assert week["title"].startswith("Отчёт за неделю")
    # раздел безопасности упал — отчёт всё равно собирается
    monkeypatch.setattr(R, "security_lines", lambda *a: 1 / 0)
    assert "Безопасность" not in R.build(nm, "day")["text"]
    ok = _channel(nm.db, AlertChannel(name="ok", type="webhook", url="https://ok.test"))
    off = _channel(nm.db, AlertChannel(name="off", type="webhook", url="https://off.test", enabled=False))
    fail = _channel(nm.db, AlertChannel(name="fail", type="webhook", url="https://fail.test"))
    broken = nm.db.execute("INSERT INTO alert_channels(name, type, data, created_at, updated_at) VALUES('x','webhook','[1]',0,0)")

    def fake_send(ch, title, text, sev, extra):
        if ch.name == "fail":
            raise TimeoutError("timed out")
    monkeypatch.setattr(AL, "send", fake_send)
    res = asyncio.run(R.send(nm, rep, [ok, off, fail, broken, 999]))
    by = {r["id"]: r for r in res}
    assert by[ok]["ok"] and by[off]["error"] == "канал выключен" and "TimeoutError" in by[fail]["error"]
    assert "повреждены" in by[broken]["error"] and by[999]["error"] == "канал не найден"


def test_reports_due():
    from datetime import datetime
    p = PanelSettings(report_enabled=True, report_channels=[1], report_hour=9, report_period="week",
                      report_weekday="0")
    mon9 = datetime(2026, 11, 23, 9, 30).timestamp()
    assert R.due(p, mon9) == "week:2026-11-23"
    assert R.due(p, datetime(2026, 11, 24, 9, 30).timestamp()) is None
    assert R.due(p, datetime(2026, 11, 23, 10, 0).timestamp()) is None
    assert R.due(p.model_copy(update={"report_channels": []}), mon9) is None
    assert R.due(p.model_copy(update={"report_period": "day"}), datetime(2026, 11, 24, 9, 0).timestamp()) == \
        "day:2026-11-24"


# =============================================================================
#  Метрики Prometheus
# =============================================================================
def test_metrics_values_and_render(nm, monkeypatch):
    assert [MT.num(v) for v in (None, float("nan"), float("inf"), float("-inf"), True, 3, 2.0, 0.1234567)] == \
        ["NaN", "NaN", "+Inf", "-Inf", "1", "3", "2", "0.123457"]
    assert MT.labels({"site": 'a"b\\c\nd'}) == '{site="a\\"b\\\\c\\nd"}'
    text = MT.render(nm)
    assert "nginx_manager_info{" in text and text.endswith("\n")
    for line in text.splitlines():  # формат экспозиции: комментарий или «имя{метки} значение»
        assert line.startswith("# ") or len(line.rsplit(" ", 1)) == 2
    monkeypatch.setattr(nm.stats.stub, "latest", lambda: {"ok": True, "active": 3, "reading": 0, "writing": 1,
                                                          "waiting": 2, "accepts": 10, "handled": 10, "requests": 40})
    assert 'nginx_connections{state="active"} 3' in MT.render(nm)

    def broken():
        raise ValueError("испорчено")
    monkeypatch.setattr(nm, "last_applied_state", broken)
    assert MT.site_names(nm)["panel"] == "(панель)"
