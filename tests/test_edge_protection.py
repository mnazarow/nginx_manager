"""Защита от атак в нетиповых ситуациях: списки угроз странного формата (JSON роботов, DShield, мусор, слишком
широкие сети, /dev/zero вместо файла), самопроверка против молчащего, закрывающего и TLS-сервера, журнал
ModSecurity с обрывами, ротацией и гигантскими записями, автоматический режим «Под атакой»."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import urllib.error

import pytest

from app.config import settings
from app.models import ThreatFeed
from app.protection import service as PS
from tests.test_settings_backup import _insert, _site


@pytest.fixture()
def nm(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "log_dir", tmp_path / "logs")
    (tmp_path / "logs").mkdir()
    settings.ensure_dirs()
    api = create_app()
    with TestClient(api):
        yield api.state.nm


# =============================================================================
#  Списки угроз
# =============================================================================
@pytest.mark.parametrize("text,nets,bad", [
    ("1.2.3.4\n5.6.7.0/24 # комментарий\n; строка-комментарий\n\n", ["1.2.3.4", "5.6.7.0/24"], 0),
    ("1.2.3.4\n1.2.3.4/32\n", ["1.2.3.4"], 0),  # дубликаты
    ("10.0.0.0/7\n::/8\n0.0.0.0/0\n", [], 3),  # слишком широкие сети — вероятно, ошибка в списке
    ("192.0.2.0 192.0.2.255 24 DShield\n", ["192.0.2.0/24"], 0),  # вся сеть, а не первый адрес
    ("192.0.2.0\t192.0.2.255\t24\t1234\tEvilNet\tCN\n", ["192.0.2.0/24"], 0),
    ("203.0.113.9 some text 5\n", ["203.0.113.9"], 0),
    ("198.51.100.1-198.51.100.9\n", ["198.51.100.1"], 0),
    ("мусор\n300.1.1.1\n", [], 2),
    ('{"prefixes": [{"ipv4Prefix": "66.249.64.0/27"}, {"ipv6Prefix": "2001:4860:4801:10::/64"}], '
     '"creationTime": "2026-11-24T10:00:00"}', ["66.249.64.0/27", "2001:4860:4801:10::/64"], 0),
    ("[\"203.0.113.5\", {\"ip\": \"203.0.113.6\"}]", ["203.0.113.5", "203.0.113.6"], 0),
    ("{не json\n1.2.3.4\n", ["1.2.3.4"], 1),
    ("1.2.3.4, 5.6.7.8\n", ["1.2.3.4"], 0),
])
def test_parse_feed(text, nets, bad):
    got, nbad = PS.parse_feed(text)
    assert (sorted(got), nbad) == (sorted(nets), bad)


def test_fetch_feed_files_and_errors(tmp_path, monkeypatch):
    f = tmp_path / "list.txt"
    f.write_text("1.2.3.4\n")
    assert PS.fetch_feed(f"file://{f}") == "1.2.3.4\n"
    for bad in ("/dev/zero", str(tmp_path)):  # устройство и каталог не читаются (иначе — бесконечное чтение)
        with pytest.raises(ValueError, match="не обычный файл"):
            PS.fetch_feed(f"file://{bad}")
    monkeypatch.setattr(PS, "MAX_FEED_BYTES", 5)
    with pytest.raises(ValueError, match="больше"):
        PS.fetch_feed(f"file://{f}")
    assert PS.feed_error(urllib.error.HTTPError("u", 404, "Not Found", {}, None)) == "сервер ответил 404 Not Found"
    assert "нет связи" in PS.feed_error(urllib.error.URLError("Name or service not known"))
    assert PS.feed_error(socket.timeout()) == "сервер списка не ответил вовремя"
    assert PS.feed_error(ValueError("x" * 500)) == "x" * 300


def test_update_feeds_mixed_results(nm, tmp_path, monkeypatch):
    good = tmp_path / "good.txt"
    good.write_text("203.0.113.0/24\n198.51.100.7\n")
    empty = tmp_path / "empty.txt"
    empty.write_text("# только комментарии\n")
    p = nm.protection.settings()
    feeds = [ThreatFeed(id="good", name="Хороший", url=f"file://{good}", enabled=True),
             ThreatFeed(id="dup", name="Повтор", url=f"file://{good}", enabled=True, action="detect"),
             ThreatFeed(id="empty", name="Пустой", url=f"file://{empty}", enabled=True),
             ThreatFeed(id="gone", name="Пропал", url=f"file://{tmp_path}/нет.txt", enabled=True),
             ThreatFeed(id="off", name="Выключен", url=f"file://{good}", enabled=False)]
    nm.protection.save(p.model_copy(update={"threat_feeds": feeds}))
    written = {}

    def side(path, text):
        written[str(path)] = text
        return True, ""
    monkeypatch.setattr(nm.nginx, "write_side_file", side)
    res = asyncio.run(nm.protection.update_feeds(force=True))
    f = res["feeds"]
    assert f["good"]["ok"] and f["good"]["count"] == 2 and f["dup"]["ok"]
    assert not f["empty"]["ok"] and "ни одного адреса" in f["empty"]["error"] and not f["gone"]["ok"]
    assert "off" not in f and res["total"] == 2  # повтор адресов в другом списке не дублирует строку geo
    threats = written[str(settings.threats_file)]
    assert '203.0.113.0/24 "good:block";' in threats and "detect" not in threats
    ev = [r["message"] for r in nm.db.query("SELECT message FROM events WHERE source='protection'")]
    assert any("«Пустой» не обновлён" in m for m in ev) and any("«Пропал» не обновлён" in m for m in ev)
    # повторный вызов без force: свежие списки не скачиваются, ошибочные — пробуются снова
    res2 = asyncio.run(nm.protection.update_feeds())
    assert "good" not in res2["feeds"] and "empty" in res2["feeds"]
    # адрес в списках
    assert {x["name"] for x in nm.protection.ip_in_feeds("203.0.113.77")} == {"Хороший", "Повтор"}
    assert nm.protection.ip_in_feeds("198.51.100.7")[0]["net"] == "198.51.100.7"
    assert nm.protection.ip_in_feeds("2001:db8::1") == [] and nm.protection.ip_in_feeds("мусор") == []
    # nginx не принял файл — ошибка в событиях и в ответе
    monkeypatch.setattr(nm.nginx, "write_side_file", lambda path, text: (False, "nginx: [emerg] bad"))
    res3 = asyncio.run(nm.protection.update_feeds(force=True, only="good"))
    assert not res3["ok"] and "bad" in res3["output"]


# =============================================================================
#  Самопроверка: «сырые» запросы
# =============================================================================
def _server(behaviour, tls_ctx=None):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                if tls_ctx is not None:
                    c = tls_ctx.wrap_socket(c, server_side=True)
                c.recv(65536)
                behaviour(c)
            except (OSError, ssl.SSLError):
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass
    threading.Thread(target=loop, daemon=True).start()
    return srv, port


def test_raw_request_behaviours(tmp_path):
    cases = {
        "ok": lambda c: c.sendall(b"HTTP/1.1 403 Forbidden\r\nServer: nginx\r\nX-Nm: 1\r\n\r\nbody"),
        "close": lambda c: None,  # 444: соединение закрыто без ответа
        "garbage": lambda c: c.sendall(b"SSH-2.0-OpenSSH\r\n\r\n"),
        "silent": lambda c: time.sleep(2),
        "huge": lambda c: c.sendall(b"HTTP/1.1 200 OK\r\n" + b"X-A: " + b"a" * 70000 + b"\r\n\r\n"),
    }
    res = {}
    for name, beh in cases.items():
        srv, port = _server(beh)
        try:
            res[name] = PS.raw_request("127.0.0.1", port, False, "a.test", "GET", "/../etc/passwd", {"X": "ü"},
                                       timeout=0.5, body=b"x=1")
        except OSError as e:
            res[name] = type(e).__name__ + ": " + str(e)
        srv.close()
    assert res["ok"] == (403, {"server": "nginx", "x-nm": "1"})
    assert res["close"] == (None, {}) and res["garbage"] == (None, {})
    assert res["silent"] == "TimeoutError: нет ответа за 0.5 с"  # не «заблокировано»
    assert res["huge"][0] is None or res["huge"][0] == 200
    # порт закрыт — ошибка, а не «заблокировано»
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    closed_port = free.getsockname()[1]
    free.close()
    with pytest.raises(OSError):
        PS.raw_request("127.0.0.1", closed_port, False, "a.test", "GET", "/", {}, timeout=0.5)
    # TLS: сертификат не проверяется; HTTPS на порт без TLS — ошибка TLS
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k"),
                    "-out", str(tmp_path / "c"), "-days", "1", "-subj", "/CN=a.test"], check=True, capture_output=True)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(str(tmp_path / "c"), str(tmp_path / "k"))
    srv, port = _server(cases["ok"], ctx)
    assert PS.raw_request("127.0.0.1", port, True, "a.test", "GET", "/", {}, timeout=2)[0] == 403
    srv.close()
    srv, port = _server(cases["garbage"])
    with pytest.raises(OSError, match="ошибка TLS"):
        PS.raw_request("127.0.0.1", port, True, "a.test", "GET", "/", {}, timeout=2)
    srv.close()


# =============================================================================
#  Журнал ModSecurity
# =============================================================================
def _tr(rule="942100", code=403, sev="2", uri="/?id=1' or 1=1", site="3", http_code=None):
    return json.dumps({"transaction": {
        "client_ip": "203.0.113.9", "unique_id": f"{site}-1-abc", "request": {
            "method": "GET", "uri": uri, "headers": {"Host": "shop.test", "User-Agent": "sqlmap"}},
        "response": {"http_code": code if http_code is None else http_code},
        "messages": [{"message": "SQL Injection Attack Detected", "details": {"ruleId": rule, "severity": sev}},
                     {"message": "Inbound Anomaly Score", "details": {"ruleId": "949110", "severity": "2"}}]}})


def test_modsec_reader_edges(nm, monkeypatch):
    prot = nm.protection
    log = prot.modsec_log()
    assert prot.modsec_tick() == 0  # файла нет
    log.write_text(_tr() + "\n")
    prot.modsec_pos = (0, -1)
    assert prot.modsec_tick() == 0  # при запуске панели — с конца файла
    with log.open("a") as f:
        f.write(_tr(rule="941100", code=200) + "\n" + "не json\n" + '{"transaction": 5}\n'
                + _tr(rule="920350", http_code="abc", sev=[1]) + "\n"  # странные типы — без исключений
                + _tr(rule="900990") + "\n"  # служебное правило CRS — пропускается
                + _tr()[:40])  # незаконченная запись — ждёт продолжения
    n = prot.modsec_tick()
    assert n == 2
    prot.flush()
    rows = [(r["rule"], r["action"]) for r in nm.db.query("SELECT rule, action FROM attack_log ORDER BY id")]
    assert rows == [("modsec/941100", "detected"), ("modsec/920350", "detected")]
    # ротация: новый файл читается с начала
    os.rename(log, str(log) + ".1")
    log.write_text(_tr(rule="932100") + "\n")
    assert prot.modsec_tick() == 1
    # запись больше 16 МБ без перевода строки не блокирует чтение
    with log.open("a") as f:
        f.write('{"transaction": {"x": "' + "a" * (16 * 1024 * 1024 + 10))
    assert prot.modsec_tick() == 0 and prot.modsec_tick() == 0
    with log.open("a") as f:
        f.write('"}}\n' + _tr(rule="933100") + "\n")
    assert prot.modsec_tick() == 1


# =============================================================================
#  «Под атакой» автоматически
# =============================================================================
def test_auto_attack_tick(nm, monkeypatch):
    sid = _insert(nm.db, _site("A", "a.test"))
    _insert(nm.db, _site("B", "b.test"))
    p = nm.protection.settings()
    nm.protection.save(p.model_copy(update={"auto_attack": True, "auto_rps": 50, "auto_factor": 5,
                                            "auto_minutes": 10}))
    now = (time.time() // 60) * 60 + 30
    m = int(now // 60) * 60 - 60
    # обычная нагрузка за сутки ~1 запрос/с, сейчас — 100 запросов/с у сайта A
    nm.db.executemany("INSERT INTO stats_minute(ts, site, req, data) VALUES(?,?,?,'{}')",
                      [(m - 3600 - 60 * i, str(sid), 60, ) for i in range(30)] + [(m - 60, str(sid), 12000),
                                                                                   (m, str(sid), 12000)])
    calls = []

    async def set_attack(site, on, minutes=None, user="system", auto=False, reason=""):
        calls.append((site, on, auto, reason))
        st = nm.protection.attack_state()
        st["sites"][str(site)] = {"until": now + 600, "auto": auto} if on else None
        nm.db.kv_set("attack_mode", st)
    monkeypatch.setattr(nm.protection, "set_attack", set_attack)
    monkeypatch.setattr(nm.protection, "active_attack",
                        lambda now=None: (False, [k for k, v in nm.protection.attack_state()["sites"].items() if v]))
    assert asyncio.run(nm.protection.auto_attack_tick(now)) == [str(sid)]
    assert calls[0][:3] == (sid, True, True) and "запросов/с" in calls[0][3]
    assert asyncio.run(nm.protection.auto_attack_tick(now)) == []  # уже включён
    # срок истёк, но нагрузка ещё высокая — держим; спала — выключаем
    m2 = int((now + 700) // 60) * 60 - 60
    nm.db.executemany("INSERT INTO stats_minute(ts, site, req, data) VALUES(?,?,?,'{}')",
                      [(m2 - 60, str(sid), 12000), (m2, str(sid), 12000)])
    assert asyncio.run(nm.protection.auto_attack_tick(now + 700)) == []
    nm.db.execute("DELETE FROM stats_minute WHERE req=12000")
    assert asyncio.run(nm.protection.auto_attack_tick(now + 700)) == [str(sid)] and calls[-1][1] is False
    # автоматика выключена — только истечение ручных режимов
    nm.protection.save(nm.protection.settings().model_copy(update={"auto_attack": False}))
    assert asyncio.run(nm.protection.auto_attack_tick(now + 800)) == []
