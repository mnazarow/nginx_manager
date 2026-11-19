"""Версия 2.11: смена ключа подписи списков, постоянная синхронизация потоков и общих настроек, сравнение серверов по
расписанию с уведомлениями, «Что изменится» перед восстановлением, nmctl settings из S3."""
from __future__ import annotations

import json

import pytest

from app.models import IpListSource, Peer
from app.services import ed25519 as E
from app.services import settings_backup as SB
from tests.test_round210 import FakeS3, _stream
from tests.test_settings_backup import _insert, _site


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
        yield c


def test_key_rotation():
    from app.services import iplists
    old_s, old_p = E.keygen()
    new_s, new_p = E.keygen()
    both = f"{E.format_public(old_p)}, {E.format_public(new_p)}"
    m = IpListSource(url="https://l.test/a.txt", pubkey=both)
    assert m.pubkey.split() == [E.format_public(old_p), E.format_public(new_p)]
    body = b"198.51.100.0/24\n"
    for secret in (old_s, new_s):
        files = {"https://l.test/a.txt": body, "https://l.test/a.txt.sig": E.sign(secret, body)}
        iplists._get, saved = (lambda url, limit, timeout: files[url]), iplists._get
        try:
            assert iplists.fetch("https://l.test/a.txt", pubkey=m.pubkey) == ["198.51.100.0/24"]
        finally:
            iplists._get = saved
    with pytest.raises(Exception):
        IpListSource(url="https://l.test/a.txt", pubkey=" ".join(E.format_public(E.keygen()[1]) for _ in range(4)))


def test_streams_mirror(client, monkeypatch):
    from app.services import cluster_parts as CP
    nm = client.nm
    own = _stream(nm, "Свой Redis", 16379, 6379)
    origin = {"id": "srv-a", "name": "web-1"}

    def item(name, port, bport=5432):
        return {"name": name, "data": {"name": name, "listen_port": port,
                                       "backends": [{"address": "10.0.0.9", "port": bport}]}}
    r = CP.receive_streams(nm, [item("PG", 15432), item("Redis", 16379, 6380)], True, origin, True)
    assert r["created"] == 1 and r["updated"] == 1
    r = CP.receive_streams(nm, [item("PG", 15432), item("Redis", 16379, 6380)], True, origin, True)
    assert r["unchanged"] == 2 and r["created"] == r["updated"] == 0
    # у источника пропали оба: созданный синхронизацией удаляется, свой — остаётся
    r = CP.receive_streams(nm, [], True, origin, True)
    assert r["deleted"] == 1
    left = [json.loads(x["data"])["listen_port"] for x in nm.db.query("SELECT data FROM streams")]
    assert left == [16379] and nm.db.one("SELECT id FROM streams")["id"] == own
    # приём синхронизации выключен — отказ
    nm.save_panel(nm.panel().model_copy(update={"peers_accept_sites": False}))
    r = client.post("/api/sync/parts", headers=client.h, json={"origin": origin, "streams": [], "mirror": True})
    assert r.status_code == 403


def test_parts_tick(client, monkeypatch):
    nm = client.nm
    _stream(nm, "PG", 15432)
    nm.save_panel(nm.panel().model_copy(update={"peers": [
        Peer(name="web-2", url="https://two.test:8088", token="nm_" + "a" * 40, bans=False, streams=True,
             global_settings=True)]}))
    from app.nginx.generator import State
    st = nm.nginx.load_state()
    monkeypatch.setattr(nm, "last_applied_state", lambda: State.from_json(st.to_json()))
    monkeypatch.setattr(nm.nginx, "last_applied", lambda: {"id": 5})
    import app.services.peers as P
    calls = []

    def fake_call(peer, m, path, body=None, verify=True, timeout=20):
        calls.append((path, body))
        return 200, {"streams": {"created": 1, "updated": 0, "deleted": 0, "unchanged": 0}, "global": [],
                     "applied": 12}
    monkeypatch.setattr(P, "call", fake_call)
    r = nm.peers.parts_tick()
    pid = nm.panel().peers[0].id
    assert r[pid]["ok"] and calls[0][0] == "/sync/parts"
    body = calls[0][1]
    assert body["mirror"] and [x["name"] for x in body["streams"]] == ["PG"] and "user" not in body["global"]
    assert nm.peers.parts_tick() == {}  # та же версия — не отправляется повторно
    ps = nm.peers.status()[pid]
    assert ps["parts_version"] == 5 and ps["parts_applied"] == 12
    d = client.get("/api/peers", headers=client.h).json()["peers"][0]
    assert d["streams"] and d["global_settings"] and d["parts_version"] == 5


def test_compare_tick_events(client, monkeypatch):
    nm = client.nm
    nm.save_panel(nm.panel().model_copy(update={"peers": [Peer(name="web-2", url="https://two.test:8088",
                                                                token="nm_" + "a" * 40, bans=False)]}))
    pid = nm.panel().peers[0].id
    import app.services.compare as CMP
    empty = {"only_here": [], "only_there": [], "changed": [], "same": 3}
    res = {"ok": True, "total": 0, "sites": dict(empty), "streams": dict(empty), "global": [], "protection": [],
           "trusted": {"only_here": [], "only_there": []}}
    monkeypatch.setattr(CMP, "compare", lambda app, peer: json.loads(json.dumps(res)))

    def events():
        return [r["message"] for r in nm.db.query("SELECT message FROM events WHERE source='peers' ORDER BY id")]
    assert nm.peers.compare_tick() == {pid: {"ok": True, "total": 0}} and events() == []
    assert nm.peers.compare_tick() == {}  # раз в сутки
    res.update(total=2, global_=None)
    res["sites"] = {**empty, "only_here": [{"key": "shop.test", "name": "Магазин"}]}
    res["global"] = ["worker_connections"]
    nm.peers.compare_tick(force=True)
    assert len(events()) == 1 and "расходится с сервером «web-2»: различий 2" in events()[0] and "Магазин" in events()[0]
    nm.peers.compare_tick(force=True)
    assert len(events()) == 1  # те же расхождения — без повтора
    res["global"] = []
    res["total"] = 1
    nm.peers.compare_tick(force=True)
    assert len(events()) == 2
    res.update(total=0, sites=dict(empty))
    nm.peers.compare_tick(force=True)
    assert "совпадает" in events()[-1]
    monkeypatch.setattr(CMP, "compare", lambda app, peer: {"ok": False, "error": "нет связи"})
    nm.peers.compare_tick(force=True)
    nm.peers.compare_tick(force=True)
    assert sum("сравнить конфигурацию не удалось" in e for e in events()) == 1
    nm.save_panel(nm.panel().model_copy(update={"peers_compare_hours": 0}))
    assert nm.peers.compare_tick() == {}


def test_restore_preview(client):
    from app.models import CertificateRequest
    nm = client.nm
    db = nm.db
    a = _insert(db, _site("A", "a.test"))
    _insert(db, _site("B", "b.test"))
    nm.certs.create(CertificateRequest(type="selfsigned", domains=["a.test"]), "t")
    name = client.post("/api/backup/settings", headers=client.h, json={}).json()["name"]
    d = json.loads(db.one("SELECT data FROM sites WHERE id=?", (a,))["data"])
    d["backends"][0]["port"] = 9999
    db.execute("UPDATE sites SET data=? WHERE id=?", (json.dumps(d), a))
    db.execute("DELETE FROM sites WHERE name='B'")
    _insert(db, _site("C", "c.test"))
    g = nm.global_settings().model_dump()
    g["worker_connections"] = 1024
    db.kv_set("global_settings", g)
    r = client.post("/api/backup/settings/preview", headers=client.h,
                    json={"name": name, "sections": ["sites", "global", "certificates", "users"]}).json()
    sec = {x["id"]: x for x in r["sections"]}
    assert sec["sites"]["added"] == ["B"] and sec["sites"]["removed"] == ["C"] and sec["sites"]["changed"] == ["A"]
    assert sec["global"]["fields"] and sec["certificates"]["same"] and sec["users"]["same"]
    r = client.post("/api/backup/settings/preview", headers=client.h,
                    json={"name": name, "sites": [a, a + 1]}).json()
    by = {x["name"]: x for x in r["sites"]}
    assert by["A"]["action"] == "update" and by["A"]["fields"] == ["Бэкенды"] and by["B"]["action"] == "create"


def test_cli_settings_s3(client, tmp_path, monkeypatch, capsys):
    import app.services.s3 as S3
    from app.cli import main
    nm = client.nm
    FakeS3.store = {}
    monkeypatch.setattr(S3, "S3Client", FakeS3)
    _insert(nm.db, _site("A", "a.test"))
    p = SB.create(nm, "sched", None, "Secret-Pass-1", dest_dir=tmp_path)
    FakeS3.store["web-1/" + p.name] = p.read_bytes()
    FakeS3.store["web-1/nginx-manager-20200101-000000-sched.settings.tar.gz.enc"] = p.read_bytes()
    FakeS3.store["web-1/other/skip.settings.tar.gz"] = b"x"
    monkeypatch.setenv("NM_S3_ACCESS_KEY", "AK")
    monkeypatch.setenv("NM_S3_SECRET_KEY", "SK")
    monkeypatch.setenv("NM_BACKUP_PASSWORD", "Secret-Pass-1")
    assert main(["settings", "remote", "s3://nm-set/web-1/", "--endpoint", "https://s3.test"]) == 0
    out = capsys.readouterr().out
    assert "копий настроек: 2" in out and "skip" not in out
    assert main(["settings", "fetch", "s3://nm-set/web-1/latest", "--endpoint", "https://s3.test"]) == 0
    from app.config import settings
    assert (settings.backups_dir / p.name).exists()
    db_sites = [r["name"] for r in nm.db.query("SELECT name FROM sites")]
    nm.db.execute("DELETE FROM sites")
    import app.cli as CLI
    monkeypatch.setattr(CLI, "has_systemd", lambda: False, raising=False)
    import app.utils as U
    monkeypatch.setattr(U, "has_systemd", lambda: False)
    rc = main(["settings", "restore", f"s3://nm-set/web-1/{p.name}", "--endpoint", "https://s3.test",
               "--sections", "sites", "--no-apply"])
    assert rc == 0
    assert [r["name"] for r in nm.db.query("SELECT name FROM sites")] == db_sites
    assert main(["settings", "fetch", "ftp://x"]) == 1
    assert main(["settings", "fetch", "s3://nope/x/latest"]) == 1  # бакет не настроен в панели и нет --endpoint
