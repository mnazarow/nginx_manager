"""Версия 2.9: восстановление отдельных сайтов из копии настроек, копия настроек по расписанию с отправкой
(второе S3, Telegram, e-mail), «Отправить / Забрать» в сравнении серверов, автоматический выпуск перенесённого
сертификата, списки доверенных адресов по ссылке, проверки списков (широкие подсети, порог изменений, SHA-256)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path

import pytest

from app.models import IpAccessSettings, IpListSource, PanelSettings, Peer
from app.services import iplists
from app.services import settings_backup as SB
from app.services import settings_job as SJ
from tests.test_settings_backup import _insert, _letsencrypt, _site


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(SB, "LE_DIR", tmp_path / "letsencrypt")
    settings.ensure_dirs()
    api = create_app()
    with TestClient(api) as c:
        nm = api.state.nm
        uid = nm.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        c.nm = nm
        c.h = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'adm', role='admin')}"}
        c.op = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'op', role='operator')}"}
        c.tmp = tmp_path
        yield c


# =============================================================================
#  Восстановление отдельных сайтов
# =============================================================================
def test_restore_single_sites(client, monkeypatch):
    from app.models import CertificateRequest
    nm = client.nm
    db = nm.db
    le = client.tmp / "letsencrypt"
    _letsencrypt(le, "nm-le1")
    up = nm.certs.create(CertificateRequest(type="selfsigned", domains=["a.test"]), "t")
    now = time.time()
    lid = db.execute("INSERT INTO certificates(name,type,domains,cert_path,key_path,status,data,created_at,updated_at) "
                     "VALUES(?,?,?,?,?,?,?,?,?)", ("le.test", "letsencrypt", '["le.test"]',
                                                   str(le / "live/nm-le1/fullchain.pem"),
                                                   str(le / "live/nm-le1/privkey.pem"), "valid",
                                                   json.dumps({"cert_name": "nm-le1"}), now, now))
    a = _insert(db, _site("A", "a.test", ssl={"enabled": True, "certificate_id": up}))
    b = _insert(db, _site("B", "b.test"))
    c = _insert(db, _site("LE", "le.test", ssl={"enabled": True, "certificate_id": lid}))
    name = client.post("/api/backup/settings", headers=client.h, json={}).json()["name"]
    info = client.post("/api/backup/settings/inspect", headers=client.h, json={"name": name}).json()
    items = next(s for s in info["sections"] if s["id"] == "sites")["items"]
    assert {(x["id"], x["name"], x["https"]) for x in items} == {(a, "A", True), (b, "B", False), (c, "LE", True)}
    # испортили A, удалили B, добавили D — восстанавливаем только A и B
    d = json.loads(db.one("SELECT data FROM sites WHERE id=?", (a,))["data"])
    d["backends"][0]["port"] = 9999
    db.execute("UPDATE sites SET data=? WHERE id=?", (json.dumps(d), a))
    db.execute("DELETE FROM sites WHERE id=?", (b,))
    dd = _insert(db, _site("D", "d.test"))
    applied = []

    async def fake_apply(user, comment="", source="user", state=None):
        applied.append(comment)
        return {"version": 7}
    monkeypatch.setattr(nm, "apply", fake_apply)
    r = client.post("/api/backup/settings/restore", headers=client.h,
                    json={"name": name, "sites": [a, b], "apply": True}).json()
    assert r["sites"]["updated"] == 1 and r["sites"]["created"] == 1 and r["applied"] == 7, r
    rows = {x["name"]: x for x in db.query("SELECT * FROM sites")}
    assert set(rows) == {"A", "B", "LE", "D"} and rows["D"]["id"] == dd
    assert json.loads(rows["A"]["data"])["backends"][0]["port"] == 8080
    assert json.loads(rows["A"]["data"])["ssl"]["certificate_id"] == up  # тот же файл сертификата — тот же номер
    assert db.one("SELECT COUNT(*) n FROM certificates")["n"] == 2
    assert r["safety"].endswith("before-settings-restore.settings.tar.gz")
    assert client.post("/api/backup/settings/restore", headers=client.h,
                       json={"name": name, "sites": [999]}).status_code == 400


def test_restore_site_on_new_server(client, tmp_path, monkeypatch):
    """Отдельный сайт на чистом сервере: сертификат Let's Encrypt — с данными certbot, загруженный — как есть."""
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import create_app
    nm = client.nm
    le = client.tmp / "letsencrypt"
    _letsencrypt(le, "nm-le2")
    now = time.time()
    lid = nm.db.execute("INSERT INTO certificates(name,type,domains,cert_path,key_path,status,data,created_at,"
                        "updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                        ("le.test", "letsencrypt", '["le.test"]', str(le / "live/nm-le2/fullchain.pem"),
                         str(le / "live/nm-le2/privkey.pem"), "valid", json.dumps({"cert_name": "nm-le2"}), now, now))
    sid = _insert(nm.db, _site("LE", "le.test", ssl={"enabled": True, "certificate_id": lid}))
    _insert(nm.db, _site("Other", "other.test"))
    name = client.post("/api/backup/settings", headers=client.h, json={"password": "Secret-Pass-1"}).json()["name"]
    blob = (Path(nm.db.path).parent / "backups" / name).read_bytes()
    le2 = tmp_path / "le-new"
    monkeypatch.setattr(SB, "LE_DIR", le2)
    monkeypatch.setattr(settings, "data_dir", tmp_path / "new")
    settings.ensure_dirs()
    api2 = create_app()
    with TestClient(api2) as c2:
        nm2 = api2.state.nm
        uid = nm2.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        h2 = {"Authorization": f"Bearer {nm2.auth.create_token(uid, 'x', role='admin')}"}
        up = c2.post("/api/backup/upload", headers=h2, params={"filename": name}, content=blob).json()
        r = c2.post("/api/backup/settings/restore", headers=h2,
                    json={"name": up["name"], "password": "Secret-Pass-1", "sites": [sid], "apply": False}).json()
        assert r["sites"]["created"] == 1 and any("данными certbot" in n for n in r["notes"]), r
        assert [x["name"] for x in nm2.db.query("SELECT name FROM sites")] == ["LE"]
        cert = nm2.db.one("SELECT * FROM certificates")
        assert cert["type"] == "letsencrypt" and cert["cert_path"] == str(le2 / "live/nm-le2/fullchain.pem")
        assert (le2 / "renewal" / "nm-le2.conf").exists() and (le2 / "live/nm-le2/privkey.pem").is_symlink()
        site = json.loads(nm2.db.one("SELECT data FROM sites")["data"])
        assert site["ssl"]["certificate_id"] == cert["id"] and site["ssl"]["enabled"]


# =============================================================================
#  Копия настроек по расписанию и отправка
# =============================================================================
def test_settings_job_schedule_and_delivery(client, monkeypatch):
    import app.services.alerts as AL
    nm = client.nm
    _insert(nm.db, _site("A", "a.test"))
    for d in ({"name": "Админ в Telegram", "type": "telegram", "telegram_token": "1:x", "telegram_chat_id": "42"},
              {"name": "Hook", "type": "webhook", "url": "http://127.0.0.1:1/h"}):
        nm.db.execute("INSERT INTO alert_channels(name, type, data, created_at, updated_at) VALUES(?,?,?,?,?)",
                      (d["name"], d["type"], json.dumps(d), time.time(), time.time()))
    ch = [r["id"] for r in nm.db.query("SELECT id FROM alert_channels ORDER BY id")]
    with pytest.raises(Exception):
        PanelSettings(sb_channels=ch)  # без пароля во внешние места не отправляется
    puts = {}

    class FakeS3:
        def __init__(self, *a):
            self.store = puts

        def put_file(self, key, path):
            self.store[key] = Path(path).read_bytes()

        def list(self, prefix=""):
            return [{"key": k} for k in sorted(self.store) if k.startswith(prefix)]

        def delete(self, key):
            self.store.pop(key, None)
    import app.services.s3 as S3
    monkeypatch.setattr(S3, "S3Client", FakeS3)
    sent = []

    def fake_send_file(channel, title, text, filename, blob):
        if channel.type != "telegram":
            raise ValueError("каналы этого типа не принимают файлы")
        sent.append((channel.name, filename, blob[:8]))
    monkeypatch.setattr(AL, "send_file", fake_send_file)
    p = nm.panel()
    nm.save_panel(p.model_copy(update={"sb_hours": 6, "sb_password": "Secret-Pass-1", "sb_channels": ch,
                                       "sb_s3": True, "sb_s3_endpoint": "https://s3.test", "sb_s3_bucket": "nm-set",
                                       "sb_s3_access_key": "AK", "sb_s3_secret_key": "SK", "sb_remote_keep": 2}))
    assert SJ.due(nm)
    r = SJ.run(nm)
    assert not r["ok"] and r["targets"]["s3_second"]["ok"] and r["targets"][f"channel:{ch[0]}"]["ok"]
    assert "не принимают файлы" in r["targets"][f"channel:{ch[1]}"]["error"]
    assert r["name"].endswith("-sched.settings.tar.gz.enc") and sent[0][1] == r["name"]
    key = "nginx-manager-settings/" + r["name"]
    assert key in puts and puts[key][:8] == b"Salted__"  # openssl enc
    assert nm.db.one("SELECT level FROM events WHERE source='backup' ORDER BY id DESC")["level"] == "error"
    assert not SJ.due(nm)
    # прошлая отправка с ошибкой — следующий запуск отправляет снова, даже без изменений
    nm.save_panel(nm.panel().model_copy(update={"sb_channels": [ch[0]]}))
    r1 = SJ.run(nm)
    assert r1["ok"] and not r1.get("skipped") and len(sent) == 2
    # без изменений — не создаётся и не отправляется
    r2 = SJ.run(nm)
    assert r2["skipped"] and len(sent) == 2
    # изменение настроек — новая копия; во внешнем хранилище остаётся sb_remote_keep
    _insert(nm.db, _site("B", "b.test"))
    time.sleep(1.1)
    r3 = SJ.run(nm)
    assert not r3.get("skipped") and len(sent) == 3
    _insert(nm.db, _site("C", "c.test"))
    time.sleep(1.1)
    SJ.run(nm)
    assert len([k for k in puts if k.startswith("nginx-manager-settings/")]) == 2
    # API: состояние и «Отправить сейчас»
    st = client.get("/api/backup/settings/job", headers=client.h).json()
    assert st["hours"] == 6 and st["encrypted"] and [t["id"] for t in st["targets"]][:1] == ["s3_second"]
    assert st["last"]["name"].endswith(".enc")
    rr = client.post("/api/backup/settings/job", headers=client.h).json()
    assert rr["targets"]["s3_second"]["ok"] and not rr.get("skipped")
    assert client.post("/api/backup/settings/job", headers=client.op).status_code == 403
    # секреты не отдаются в API настроек панели
    ps = client.get("/api/settings/panel", headers=client.h).json()
    assert "Secret-Pass-1" not in json.dumps(ps) and "SK" not in json.dumps({k: v for k, v in ps.items()
                                                                              if k.startswith("sb_s3_secret")})


def test_settings_job_digest_ignores_volatile(client):
    nm = client.nm
    _insert(nm.db, _site("A", "a.test"))
    d1 = SJ.digest(nm)
    nm.db.execute("UPDATE sites SET updated_at=?", (time.time() + 100,))
    nm.db.execute("UPDATE users SET last_login=?", (time.time(),)) if "last_login" in [
        r[1] for r in nm.db.conn().execute("PRAGMA table_info(users)")] else None
    assert SJ.digest(nm) == d1
    nm.db.execute("UPDATE sites SET name='A2'")
    assert SJ.digest(nm) != d1


def test_send_file_telegram_multipart(monkeypatch):
    import urllib.request
    from app.models import AlertChannel
    from app.services import alerts as AL
    got = {}

    class Resp:
        status = 200

        def read(self, n=-1):
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        got["url"], got["body"], got["ct"] = req.full_url, req.data, req.headers["Content-type"]
        return Resp()
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    ch = AlertChannel(name="t", type="telegram", telegram_token="1:x", telegram_chat_id="42")
    AL.send_file(ch, "Копия всех настроек", "текст", "nm.settings.tar.gz.enc", b"Salted__abc")
    assert got["url"].endswith("/bot1:x/sendDocument") and got["ct"].startswith("multipart/form-data; boundary=")
    assert b'name="document"; filename="nm.settings.tar.gz.enc"' in got["body"] and b"Salted__abc" in got["body"]
    assert b'name="chat_id"\r\n\r\n42' in got["body"]
    with pytest.raises(ValueError):
        AL.send_file(AlertChannel(name="w", type="webhook", url="https://h.test/x"), "t", "x", "f", b"1")


# =============================================================================
#  Сравнение: «Забрать сюда», «Отправить туда»
# =============================================================================
def test_compare_pull_and_export(client, monkeypatch):
    from app.services import compare as CMP
    nm = client.nm
    sid = _insert(nm.db, _site("Магазин", "shop.test"))
    # экспорт для «Забрать»: по ключу сравнения (доменам)
    assert client.post("/api/sync/sites/export", headers=client.op, json={"keys": ["shop.test"]}).status_code == 403
    assert client.post("/api/sync/sites/export", headers=client.h, json={"keys": ["nope"]}).status_code == 404
    ex = client.post("/api/sync/sites/export", headers=client.h, json={"keys": ["shop.test"]}).json()
    assert ex["sites"][0]["src_id"] == sid and ex["origin"]["id"] == nm.peers.origin()["id"]
    # сводка — с местными номерами сайтов (для «Отправить туда»)
    d = CMP.diff(CMP.summary(nm), {"sites": {}, "streams": {}, "global": {}, "protection": {}, "trusted": []})
    assert d["sites"]["only_here"][0]["id"] == sid
    # «Забрать сюда»: сайт с другого сервера создаётся здесь
    p = nm.panel()
    nm.save_panel(p.model_copy(update={"peers": [Peer(name="web-2", url="https://two.test:8088",
                                                       token="nm_" + "a" * 40)]}))
    pid = nm.panel().peers[0].id
    other = json.loads(json.dumps(ex))
    other["origin"] = {"id": "srv-b", "name": "web-2"}
    other["sites"][0]["data"]["domains"] = ["blog.test"]
    other["sites"][0]["name"] = other["sites"][0]["data"]["name"] = "Блог"
    import app.services.peers as P
    calls = []

    def fake_call(peer, m, path, body=None, verify=True, timeout=20):
        calls.append((path, body))
        return 200, other
    monkeypatch.setattr(P, "call", fake_call)

    async def fake_apply(user, comment="", source="user", state=None):
        return {"version": 3}
    monkeypatch.setattr(nm, "apply", fake_apply)
    monkeypatch.setattr(nm, "pending", lambda: {"pending": False})
    r = client.post(f"/api/peers/{pid}/pull", headers=client.h, json={"keys": ["blog.test"]}).json()
    assert calls[0] == ("/sync/sites/export", {"keys": ["blog.test"], "certs": True, "caller": nm.peers.origin()})
    assert r["sites"]["created"] == 1 and r["applied"] == 3, r
    assert {x["name"] for x in nm.db.query("SELECT name FROM sites")} == {"Магазин", "Блог"}
    assert client.post(f"/api/peers/{pid}/pull", headers=client.h, json={"keys": []}).status_code == 400
    assert client.post(f"/api/peers/{pid}/pull", headers=client.op, json={"keys": ["x"]}).status_code == 403
    monkeypatch.setattr(P, "call", lambda *a, **k: (404, None))
    assert "2.9" in client.post(f"/api/peers/{pid}/pull", headers=client.h, json={"keys": ["x"]}).json()["detail"]


# =============================================================================
#  Автоматический выпуск перенесённого сертификата
# =============================================================================
def test_auto_takeover(client, monkeypatch):
    nm = client.nm
    now = time.time()
    data = {"transfer": {"origin": "srv-a", "origin_name": "Основной", "src_id": 3, "at": now - 6 * 86400}}
    cid = nm.db.execute("INSERT INTO certificates(name, type, domains, status, not_after, data, created_at, "
                        "updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        ("shop (с сервера «Основной»)", "upload", json.dumps(["shop.test"]), "valid",
                         now + 12 * 86400, json.dumps(data), now, now))
    started = []

    async def fake_issue(old, username):
        started.append((old, username))
        return {"ok": True, "output": "Выпуск запущен (сертификат #77)"}
    monkeypatch.setattr(nm.diag, "issue_here", fake_issue)
    assert asyncio.run(nm.diag.auto_takeover()) == []  # выключено (0 дней)
    p = nm.panel()
    nm.save_panel(p.model_copy(update={"cert_takeover_days": 7}))
    assert asyncio.run(nm.diag.auto_takeover()) == []  # молчит 6 дней < 7
    nm.save_panel(nm.panel().model_copy(update={"cert_takeover_days": 5}))
    assert asyncio.run(nm.diag.auto_takeover()) == [cid] and started == [(cid, "system")]
    assert asyncio.run(nm.diag.auto_takeover()) == []  # не чаще раза в сутки
    ev = nm.db.one("SELECT level, message FROM events WHERE source='certs' ORDER BY id DESC")
    assert ev["level"] == "warning" and "не выходит на связь 6 дн." in ev["message"]
    st = nm.db.kv_get("cert_takeover")
    st[str(cid)]["at"] = now - 2 * 86400
    nm.db.kv_set("cert_takeover", st)
    nm.db.kv_set("peers_incoming", {"srv-a": {"at": now}})  # источник снова на связи
    assert asyncio.run(nm.diag.auto_takeover()) == []


# =============================================================================
#  Проверки списков и списки доверенных адресов
# =============================================================================
def test_list_guards(tmp_path):
    from app.db import Database
    from app.nginx.generator import State
    from app.models import GlobalSettings
    db = Database(str(tmp_path / "g.db"))
    url = "https://l.test/a.txt"
    s1 = _site("A", "a.test", ip_access=IpAccessSettings(enabled=True, lists=[
        IpListSource(url=url, min_prefix=16, max_change=40)]))
    st = State(sites=[(1, s1)], streams=[], glob=GlobalSettings(), panel=PanelSettings(), certs={})
    data = {"nets": ["10.0.0.0/8", "198.51.100.0/24", "2001:db8::/24", "2001:db8:1::/48"]}
    changed, done = iplists.refresh(db, st, fetcher=lambda u: data["nets"])
    assert changed and done[url]["nets"] == ["198.51.100.0/24", "2001:db8:1::/48"] and done[url]["dropped"] == 2
    # изменилось больше порога — ждёт подтверждения, действуют прежние адреса
    data["nets"] = ["203.0.113.0/24", "192.0.2.0/24", "198.51.100.0/24"]
    changed, done = iplists.refresh(db, st, force_urls=[url], fetcher=lambda u: data["nets"])
    assert not changed and done[url]["pending"]["pct"] > 40 and "подтверждения" in done[url]["error"]
    assert iplists.site_nets(db, st) == {"198.51.100.0/24": {1}, "2001:db8:1::/48": {1}}
    stat = iplists.status(db, st, 1)[0]
    assert stat["pending"]["added"] == ["192.0.2.0/24", "203.0.113.0/24"]
    changed, done = iplists.refresh(db, st, force_urls=[], accept=[url])
    assert changed and set(iplists.site_nets(db, st)) == {"203.0.113.0/24", "192.0.2.0/24", "198.51.100.0/24"}
    assert iplists.status(db, st, 1)[0]["pending"] is None
    # все записи шире /16 — список отклонён, адреса прошлой загрузки остаются
    data["nets"] = ["10.0.0.0/8"]
    _, done = iplists.refresh(db, st, force_urls=[url], fetcher=lambda u: data["nets"])
    assert "шире" in done[url]["error"] and len(iplists.site_nets(db, st)) == 3


def test_fetch_sha256(monkeypatch):
    import urllib.request
    body = b"198.51.100.7\n"

    class Resp:
        def read(self, n=-1):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=0, context=None: Resp())
    good = hashlib.sha256(body).hexdigest()
    assert iplists.fetch("https://l.test/x", sha256=good) == ["198.51.100.7"]
    with pytest.raises(ValueError, match="SHA-256"):
        iplists.fetch("https://l.test/x", sha256="0" * 64)
    with pytest.raises(Exception):
        IpListSource(url="https://l.test/x", sha256="xyz")


def test_trusted_lists(client, monkeypatch):
    nm = client.nm
    url = "https://pay.test/ips.txt"
    monkeypatch.setattr(iplists, "fetch", lambda u, timeout=20, sha256="": ["203.0.113.64/27", "2001:db8:aa::/48"])
    nm.bans.add("203.0.113.70", 60, "тест", "manual", "admin", "manual")
    r = client.put("/api/trusted", headers=client.h, json={"entries": [{"address": "198.51.100.1"}],
                                                           "lists": [{"url": url, "comment": "Платёжный шлюз"}]})
    assert r.status_code == 200, r.text
    d = client.get("/api/trusted", headers=client.h).json()
    assert d["lists"][0]["url"] == url and d["lists_status"][0]["at"] is None
    applied = []

    async def fake_snapshot(reason, source):
        applied.append((reason, source))
        return {"version": 11}
    monkeypatch.setattr(nm, "apply_snapshot", fake_snapshot)
    r = client.post("/api/trusted/lists/refresh", headers=client.h, json={}).json()
    assert r["changed"] and r["applied"] == 11 and r["lists"][0]["count"] == 2
    assert applied == [("Списки доверенных адресов обновлены вручную", "trusted-lists")]
    eff = {e.address: e.comment for e in nm.trusted_entries()}
    assert eff["203.0.113.64/27"] == "из списка «Платёжный шлюз»" and "198.51.100.1" in eff
    assert nm.bans.trusted_entry("203.0.113.70") and not nm.db.one("SELECT 1 FROM bans WHERE net='203.0.113.70'")
    # в конфигурации — в geo доверенных адресов
    st = nm.nginx.load_state()
    assert "203.0.113.64/27" in [e.address for e in st.panel.trusted_ips]
    # список убран из настроек — адреса перестают быть доверенными
    client.put("/api/trusted", headers=client.h, json={"entries": [], "lists": []})
    changed, _ = iplists.refresh_trusted(nm.db, nm.panel())
    assert changed and "203.0.113.64/27" not in nm.trusted()
    assert client.post("/api/trusted/lists/refresh", headers=client.op, json={}).status_code == 403
