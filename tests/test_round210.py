"""Версия 2.10: подпись списков адресов (Ed25519), перенос потоков и общих настроек nginx между серверами,
продление сертификатов, полученных кнопкой «Забрать сюда», проверка копий настроек, восстановление из второго
хранилища."""
from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path

import pytest

from app.models import IpListSource, Peer
from app.services import ed25519 as E
from app.services import iplists
from app.services import settings_backup as SB
from app.services import settings_job as SJ
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
        c.op = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'op', role='operator')}"}
        yield c


def _peer(nm, name="web-2"):
    nm.save_panel(nm.panel().model_copy(update={"peers": [Peer(name=name, url="https://two.test:8088",
                                                                token="nm_" + "a" * 40)]}))
    return nm.panel().peers[0].id


# =============================================================================
#  Ed25519 и подписанные списки
# =============================================================================
def test_ed25519_rfc8032_and_formats():
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = E.public_key(sk)
    assert pk.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig = E.sign(sk, b"")
    assert sig.hex().startswith("e5564300c360ac729086e2cc806e828a") and E.verify(pk, b"", sig)
    assert not E.verify(pk, b"x", sig) and not E.verify(pk, b"", sig[:63] + bytes([sig[63] ^ 1]))
    # форматы ключа: ed25519:…, base64, тело PEM (SPKI)
    spki = base64.b64encode(E.SPKI_PREFIX + pk).decode()
    pem = f"-----BEGIN PUBLIC KEY-----\n{spki}\n-----END PUBLIC KEY-----\n"
    assert E.parse_public(E.format_public(pk)) == E.parse_public(pem) == E.parse_public(spki) == pk
    with pytest.raises(ValueError):
        E.parse_public("ed25519:AAAA")
    assert E.parse_signature(sig) == E.parse_signature(base64.b64encode(sig) + b"\n") == sig
    m = IpListSource(url="https://l.test/a.txt", pubkey=pem)
    assert m.pubkey == E.format_public(pk)
    with pytest.raises(Exception):
        IpListSource(url="https://l.test/a.txt", pubkey="ed25519:notakey")
    try:  # совместимость с библиотекой cryptography, если она есть
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return
    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert E.verify(raw, b"list", k.sign(b"list"))
    s2, p2 = E.keygen()
    Ed25519PublicKey.from_public_bytes(p2).verify(E.sign(s2, b"list"), b"list")


def test_signed_list_fetch(monkeypatch):
    secret, public = E.keygen()
    body = b"198.51.100.0/24\n203.0.113.7\n"
    files = {"https://l.test/a.txt": body, "https://l.test/a.txt.sig": base64.b64encode(E.sign(secret, body)),
             "https://sig.test/a.sig": E.sign(secret, body)}
    monkeypatch.setattr(iplists, "_get", lambda url, limit, timeout: files[url])
    pub = E.format_public(public)
    assert iplists.fetch("https://l.test/a.txt", pubkey=pub) == ["198.51.100.0/24", "203.0.113.7"]
    assert iplists.fetch("https://l.test/a.txt", pubkey=pub, sig_url="https://sig.test/a.sig")
    other = E.format_public(E.keygen()[1])
    with pytest.raises(ValueError, match="подпись"):
        iplists.fetch("https://l.test/a.txt", pubkey=other)
    files["https://l.test/a.txt"] = body + b"10.0.0.1\n"  # подменили список, подпись старая
    with pytest.raises(ValueError, match="подпись"):
        iplists.fetch("https://l.test/a.txt", pubkey=pub)
    with pytest.raises(ValueError, match="файл подписи"):
        iplists.fetch("https://l.test/a.txt", pubkey=pub, sig_url="https://nope.test/x.sig")
    # через расписание: подпись не сошлась — действуют прежние адреса
    from app.db import Database  # noqa: F401
    seen = {}

    def fetcher(url, **kw):
        seen.update(kw)
        return iplists.fetch(url, **kw)
    from app.models import PanelSettings
    import tempfile
    from app.db import Database as D
    db = D(str(Path(tempfile.mkdtemp()) / "x.db"))
    files["https://l.test/a.txt"] = body
    p = PanelSettings(trusted_lists=[IpListSource(url="https://l.test/a.txt", pubkey=pub)])
    changed, done = iplists.refresh_trusted(db, p, fetcher=fetcher)
    assert changed and seen["pubkey"] == pub and done["https://l.test/a.txt"]["count"] == 2
    files["https://l.test/a.txt"] = b"0.0.0.0/1\n"
    changed, done = iplists.refresh_trusted(db, p, force_urls=["https://l.test/a.txt"], fetcher=fetcher)
    assert not changed and "подпись" in done["https://l.test/a.txt"]["error"]
    assert [n for n, _ in iplists.trusted_entries(db, p)] == ["198.51.100.0/24", "203.0.113.7"]
    assert iplists.trusted_status(db, p)[0]["signed"]


def test_cli_lists(tmp_path, capsys):
    from app.cli import main
    key = tmp_path / "k.txt"
    lst = tmp_path / "office.txt"
    lst.write_text("198.51.100.0/24\n")
    assert main(["lists", "keygen", "-o", str(key)]) == 0
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    pub = [x for x in capsys.readouterr().out.split() if x.startswith("ed25519:")][0]
    assert main(["lists", "sign", str(lst), "--key", str(key)]) == 0
    assert (tmp_path / "office.txt.sig").exists()
    assert main(["lists", "verify", str(lst), "--pub", pub]) == 0
    lst.write_text("0.0.0.0/0\n")
    assert main(["lists", "verify", str(lst), "--pub", pub]) == 1
    assert main(["lists", "keygen", "-o", str(key)]) == 1  # не перезаписывает


# =============================================================================
#  Потоки и общие настройки между серверами
# =============================================================================
def _stream(nm, name, port, backend_port=5432):
    from app.models import Stream
    s = Stream(name=name, listen_port=port, backends=[{"address": "10.0.0.5", "port": backend_port}])
    now = time.time()
    return nm.db.execute("INSERT INTO streams(name, enabled, data, created_at, updated_at) VALUES(?,?,?,?,?)",
                         (s.name, 1, json.dumps(s.model_dump(mode="json")), now, now))


def test_streams_and_global_transfer(client, monkeypatch):
    from app.services import cluster_parts as CP
    from app.services import compare as CMP
    nm = client.nm
    sid = _stream(nm, "PostgreSQL", 15432)
    _stream(nm, "Redis", 16379, 6379)
    ex = client.post("/api/sync/parts/export", headers=client.h, json={"streams": ["*:15432/tcp"], "global": True}).json()
    assert [x["name"] for x in ex["streams"]] == ["PostgreSQL"] and ex["streams"][0]["src_id"] == sid
    assert "user" not in ex["global"] and "worker_connections" in ex["global"]
    assert client.post("/api/sync/parts/export", headers=client.op, json={"global": True}).status_code == 403
    assert client.post("/api/sync/parts/export", headers=client.h, json={"streams": ["nope"]}).status_code == 404
    # сводка сравнения — с номерами потоков
    d = CMP.diff(CMP.summary(nm), {"sites": {}, "streams": {}, "global": {}, "protection": {}, "trusted": []})
    assert {x["key"]: x["id"] for x in d["streams"]["only_here"]}["*:15432/tcp"] == sid
    # приём: поток с тем же ключом обновляется, новый создаётся; свои поля общих настроек сохраняются
    st = json.loads(json.dumps(ex["streams"][0]))
    st["data"]["backends"][0]["port"] = 6543
    new = json.loads(json.dumps(st))
    new["data"]["listen_port"], new["data"]["name"] = 13306, "MySQL"
    g = {**ex["global"], "worker_connections": 8192, "user": "nobody", "resolver": "9.9.9.9"}
    nm.db.kv_set("global_settings", {**nm.global_settings().model_dump(), "user": "www-data"})
    applied = []

    async def fake_apply(user, comment="", source="user", state=None):
        applied.append(comment)
        return {"version": 4}
    monkeypatch.setattr(nm, "apply", fake_apply)
    monkeypatch.setattr(nm, "pending", lambda: {"pending": False})
    r = client.post("/api/sync/parts", headers=client.h, json={
        "origin": {"id": "srv-b", "name": "web-2"}, "streams": [st, new], "global": g, "apply": True}).json()
    assert r["streams"]["created"] == 1 and r["streams"]["updated"] == 1 and r["applied"] == 4, r
    assert any("worker_connections" in x or "соединений" in x.lower() for x in r["global"]), r["global"]
    gl = nm.global_settings()
    assert gl.worker_connections == 8192 and gl.user == "www-data" and gl.resolver != "9.9.9.9"
    rows = {json.loads(x["data"])["listen_port"]: json.loads(x["data"]) for x in nm.db.query("SELECT data FROM streams")}
    assert rows[15432]["backends"][0]["port"] == 6543 and rows[13306]["name"] == "MySQL" and 16379 in rows
    assert "web-2" in applied[0]
    # с другого сервера: «Забрать сюда» и «Отправить туда»
    pid = _peer(nm)
    import app.services.peers as P
    calls = []

    def fake_call(peer, m, path, body=None, verify=True, timeout=20):
        calls.append((path, body))
        if path == "/sync/parts/export":
            return 200, {"origin": {"id": "srv-b", "name": "web-2"},
                         "streams": [{**new, "data": {**new["data"], "listen_port": 15353, "protocol": "udp",
                                                      "name": "DNS"}}]}
        return 200, {"streams": {"created": 1, "updated": 0, "skipped": 0, "items": []}, "applied": 9}
    monkeypatch.setattr(P, "call", fake_call)
    r = client.post(f"/api/peers/{pid}/parts/pull", headers=client.h, json={"streams": ["*:15353/udp"]}).json()
    assert calls[-1][0] == "/sync/parts/export" and r["streams"]["created"] == 1
    assert any(CP.stream_key(__import__("app.models", fromlist=["Stream"]).Stream.model_validate(
        json.loads(x["data"]))) == "*:15353/udp" for x in nm.db.query("SELECT data FROM streams"))
    r = client.post(f"/api/peers/{pid}/parts/push", headers=client.h,
                    json={"streams": ["*:16379/tcp"], "global": True}).json()
    path, body = calls[-1]
    assert path == "/sync/parts" and body["streams"][0]["name"] == "Redis" and "user" not in body["global"]
    assert r["applied"] == 9
    assert client.post(f"/api/peers/{pid}/parts/push", headers=client.h, json={}).status_code == 400
    assert client.post(f"/api/peers/{pid}/parts/pull", headers=client.op, json={"global": True}).status_code == 403
    monkeypatch.setattr(P, "call", lambda *a, **k: (404, None))
    assert "2.10" in client.post(f"/api/peers/{pid}/parts/pull", headers=client.h,
                                 json={"global": True}).json()["detail"]


def test_pulled_cert_renewal_registration(client, monkeypatch):
    from app.models import CertificateRequest
    from app.services import transfer as TF
    nm = client.nm
    cid = nm.certs.create(CertificateRequest(type="selfsigned", domains=["shop.test"]), "t")
    _insert(nm.db, _site("Магазин", "shop.test", ssl={"enabled": True, "certificate_id": cid}))
    pid = _peer(nm, "web-3")
    nm.db.kv_set("peers_instance", {pid: "inst-3"})
    r = client.post("/api/sync/sites/export", headers=client.h,
                    json={"keys": ["shop.test"], "caller": {"id": "inst-3", "name": "web-3"}}).json()
    assert r["renew"] == "web-3" and TF.peers_for_cert(nm.db, cid) == [pid]
    r = client.post("/api/sync/sites/export", headers=client.h,
                    json={"keys": ["shop.test"], "caller": {"id": "unknown"}}).json()
    assert r["renew"] is None
    # «Забрать сюда»: если источник не знает этот сервер — предупреждение
    import app.services.peers as P
    payload = {"origin": {"id": "srv-x", "name": "web-3"}, "renew": None, "sites": r["sites"], "certs": r["certs"]}
    payload["sites"][0]["data"]["domains"] = ["shop2.test"]
    monkeypatch.setattr(P, "call", lambda peer, m, path, body=None, verify=True, timeout=20: (200, payload))
    res = client.post(f"/api/peers/{pid}/pull", headers=client.h, json={"keys": ["shop2.test"], "apply": False}).json()
    assert res["renew"] is False and "сами не придут" in res["renew_note"]
    payload["renew"] = "web-1"
    res = client.post(f"/api/peers/{pid}/pull", headers=client.h, json={"keys": ["shop2.test"], "apply": False}).json()
    assert res["renew"] is True and "renew_note" not in res


# =============================================================================
#  Проверка копий настроек и второе хранилище
# =============================================================================
class FakeS3:
    store: dict = {}

    def __init__(self, *a):
        self.bucket = a[2] if len(a) > 2 else "fake"

    def put_file(self, key, path):
        self.store[key] = Path(path).read_bytes()

    def get_to_file(self, key, dest):
        if key not in self.store:
            raise ValueError("NoSuchKey")
        Path(dest).write_bytes(self.store[key])

    def list(self, prefix=""):
        return [{"key": k, "size": len(v), "last_modified": "2026-11-19T10:00:00Z"}
                for k, v in sorted(self.store.items()) if k.startswith(prefix)]

    def delete(self, key):
        self.store.pop(key, None)


def test_verify_and_second_storage(client, monkeypatch):
    from app.models import CertificateRequest
    import app.services.s3 as S3
    nm = client.nm
    FakeS3.store = {}
    monkeypatch.setattr(S3, "S3Client", FakeS3)
    nm.certs.create(CertificateRequest(type="selfsigned", domains=["a.test"]), "t")
    _insert(nm.db, _site("A", "a.test"))
    nm.save_panel(nm.panel().model_copy(update={"sb_password": "Secret-Pass-1", "sb_s3": True,
                                                "sb_s3_endpoint": "https://s3.test", "sb_s3_bucket": "nm-b2",
                                                "sb_s3_access_key": "AK", "sb_s3_secret_key": "SK"}))
    r = SJ.run(nm, force=True, source="manual")
    assert r["ok"] and r["targets"]["s3_second"]["ok"]
    v = client.post("/api/backup/settings/verify", headers=client.h).json()
    assert v["ok"], v
    assert {x["where"] for x in v["items"]} == {"на сервере", "второе хранилище"}
    assert all(x["certs"] == 1 and x["sections"]["users"] >= 1 for x in v["items"])
    assert not SJ.verify_due(nm)
    # копия в хранилище испорчена — проверка сообщает, диагностика показывает ошибку
    key = next(iter(FakeS3.store))
    FakeS3.store[key] = FakeS3.store[key][:-40] + b"0" * 40
    v = SJ.verify(nm)
    bad = [x for x in v["items"] if not x["ok"]]
    assert not v["ok"] and bad[0]["where"] == "второе хранилище" and "не открывается" in bad[0]["problems"][0]
    diag = asyncio.run(nm.diag.c_backups())
    assert next(x for x in diag if x["id"] == "backup_settings_verify")["status"] == "fail"
    ev = nm.db.one("SELECT level, message FROM events WHERE source='backup' ORDER BY id DESC")
    assert ev["level"] == "error" and "второе хранилище" in ev["message"]
    # без пароля зашифрованную копию проверить нельзя
    loc = SJ.latest_local()
    assert "пароль" in SJ.verify_file(nm, loc, "")["problems"][0]
    # второе хранилище: список и скачивание на сервер для восстановления
    FakeS3.store["nginx-manager-settings/other.txt"] = b"x"
    d = client.get("/api/backup/settings/s3", headers=client.h).json()
    assert [x["name"] for x in d["items"]] == [Path(key).name] and d["bucket"] == "nm-b2"
    FakeS3.store[key] = (Path(nm.db.path).parent / "backups" / Path(key).name).read_bytes()
    (Path(nm.db.path).parent / "backups" / Path(key).name).unlink()
    r = client.post("/api/backup/settings/s3/download", headers=client.h, json={"name": Path(key).name}).json()
    assert r["encrypted"] and (Path(nm.db.path).parent / "backups" / r["name"]).exists()
    info = client.post("/api/backup/settings/inspect", headers=client.h,
                       json={"name": r["name"], "password": "Secret-Pass-1"}).json()
    assert any(s["id"] == "sites" and s["count"] == 1 for s in info["sections"])
    assert client.post("/api/backup/settings/s3/download", headers=client.h,
                       json={"name": "../../etc/passwd"}).status_code == 400
    assert client.get("/api/backup/settings/s3", headers=client.op).status_code == 403
