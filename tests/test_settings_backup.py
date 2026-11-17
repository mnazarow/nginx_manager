"""Копия всех настроек: создание (с шифрованием), проверка, восстановление по разделам, откат при ошибке nginx,
загрузка файла, nmctl settings, перенос на «новый сервер»."""
from __future__ import annotations

import json
import os
import tarfile
import time
from pathlib import Path

import pytest

from app.models import Backend, IpAccessSettings, IpEntry, Site
from app.services import settings_backup as SB


def _insert(db, s: Site) -> int:
    now = time.time()
    return db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                      (s.name, int(s.enabled), json.dumps(s.model_dump()), now, now))


def _site(name, domain, **kw):
    return Site(name=name, domains=[domain], backends=[Backend(address="127.0.0.1", port=8080)], **kw)


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


def _letsencrypt(le: Path, name: str):
    """Каталог certbot с одним сертификатом: archive, live (ссылки), renewal, accounts."""
    from tests.test_cluster import _selfsigned
    pem, key = _selfsigned(le.parent / "le-src", "le.test")
    (le / "archive" / name).mkdir(parents=True)
    (le / "archive" / name / "fullchain1.pem").write_text(pem)
    (le / "archive" / name / "privkey1.pem").write_text(key)
    (le / "live" / name).mkdir(parents=True)
    for f in ("fullchain", "privkey"):
        os.symlink(f"../../archive/{name}/{f}1.pem", le / "live" / name / f"{f}.pem")
    (le / "renewal").mkdir()
    (le / "renewal" / f"{name}.conf").write_text(f"archive_dir = {le}/archive/{name}\n")
    (le / "accounts" / "acme-v02.api.letsencrypt.org" / "directory" / "abc").mkdir(parents=True)
    (le / "accounts" / "acme-v02.api.letsencrypt.org" / "directory" / "abc" / "private_key.json").write_text("{}")


def test_create_inspect_restore_roundtrip(client, monkeypatch):
    from app.models import CertificateRequest
    nm = client.nm
    db = nm.db
    le = client.tmp / "letsencrypt"
    _letsencrypt(le, "nm-abc123")
    up = nm.certs.create(CertificateRequest(type="selfsigned", domains=["shop.test"]), "t")
    now = time.time()
    lid = db.execute("INSERT INTO certificates(name,type,domains,cert_path,key_path,status,data,created_at,updated_at) "
                     "VALUES(?,?,?,?,?,?,?,?,?)", ("le.test", "letsencrypt", '["le.test"]',
                                                   str(le / "live/nm-abc123/fullchain.pem"),
                                                   str(le / "live/nm-abc123/privkey.pem"), "valid",
                                                   json.dumps({"cert_name": "nm-abc123"}), now, now))
    s1 = _insert(db, _site("Магазин", "shop.test", ssl={"enabled": True, "certificate_id": up},
                           ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="203.0.113.10")])))
    _insert(db, _site("LE", "le.test", ssl={"enabled": True, "certificate_id": lid}))
    nm.protection.save(nm.protection.settings().model_copy(update={"block_status": 444}))
    nm.save_panel(nm.panel().model_copy(update={"trusted_ips": [IpEntry(address="198.51.100.7", comment="офис")]}))
    nm.bans.add("192.0.2.66", None, "ручная", "manual")
    db.kv_set("challenge_secret", "secret-1")
    # ---- создание: без пароля и с паролем
    r = client.post("/api/backup/settings", headers=client.h, json={}).json()
    plain = r["name"]
    assert plain.endswith("-all.settings.tar.gz") and not r["encrypted"]
    assert client.post("/api/backup/settings", headers=client.h, json={"password": "short"}).status_code == 400
    assert client.post("/api/backup/settings", headers=client.op, json={}).status_code == 403
    enc = client.post("/api/backup/settings", headers=client.h, json={"password": "Secret-Pass-1"}).json()["name"]
    assert enc.endswith(".settings.tar.gz.enc")
    path = Path(nm.db.path).parent / "backups" / plain
    with tarfile.open(path) as t:
        names = t.getnames()
    assert {"manifest.json", "settings.json", f"certs/{up}/privkey.pem", f"certs/{lid}/fullchain.pem"} <= set(names)
    assert "letsencrypt/renewal/nm-abc123.conf" in names and "letsencrypt/live/nm-abc123/fullchain.pem" in names
    assert any(n.startswith("letsencrypt/accounts/") for n in names)
    # ---- проверка
    bad = client.post("/api/backup/settings/inspect", headers=client.h, json={"name": enc, "password": "wrong"})
    assert bad.status_code == 400 and "расшифровать" in bad.json()["detail"]
    assert client.post("/api/backup/settings/inspect", headers=client.h, json={"name": enc}).status_code == 400
    info = client.post("/api/backup/settings/inspect", headers=client.h,
                       json={"name": enc, "password": "Secret-Pass-1"}).json()
    secs = {s["id"]: s for s in info["sections"]}
    assert secs["sites"]["count"] == 2 and "Магазин" in secs["sites"]["names"]
    assert secs["bans"]["names"] == ["192.0.2.66"] and info["files"]["letsencrypt"] >= 5
    # ---- всё испортили
    db.execute("DELETE FROM sites")
    _insert(db, _site("Чужой", "other.test"))
    nm.protection.save(nm.protection.settings().model_copy(update={"block_status": 403}))
    nm.save_panel(nm.panel().model_copy(update={"trusted_ips": []}))
    db.execute("DELETE FROM bans")
    for f in (le / "live/nm-abc123").iterdir():
        f.unlink()
    (le / "renewal/nm-abc123.conf").unlink()
    Path(db.one("SELECT key_path FROM certificates WHERE id=?", (up,))["key_path"]).unlink()
    db.execute("DELETE FROM certificates")
    applied = []

    async def fake_apply(user, comment="", source="user", state=None):
        applied.append(source)
        return {"version": 42}
    monkeypatch.setattr(nm, "apply", fake_apply)
    # ---- восстановление всего, кроме пользователей
    sections = [s for s in SB.SECTIONS if s != "users"]
    r = client.post("/api/backup/settings/restore", headers=client.h,
                    json={"name": enc, "password": "Secret-Pass-1", "sections": sections}).json()
    assert r["applied"] == 42 and applied == ["restore"] and not r.get("rolled_back") and r["notes"] == []
    assert r["safety"].endswith("-before-settings-restore.settings.tar.gz")
    assert sorted(x["name"] for x in db.query("SELECT name FROM sites")) == ["LE", "Магазин"]
    assert db.one("SELECT id FROM sites WHERE name='Магазин'")["id"] == s1  # номера сохранены
    shop = json.loads(db.one("SELECT data FROM sites WHERE id=?", (s1,))["data"])
    assert shop["ssl"]["certificate_id"] == up and shop["ip_access"]["entries"][0]["address"] == "203.0.113.10"
    assert nm.protection.settings().block_status == 444
    assert [e.address for e in nm.panel().trusted_ips] == ["198.51.100.7"]
    assert db.one("SELECT 1 FROM bans WHERE net='192.0.2.66' AND source='manual'")
    c_up = db.one("SELECT * FROM certificates WHERE id=?", (up,))
    assert c_up["status"] == "valid" and Path(c_up["key_path"]).is_file()
    assert oct(Path(c_up["key_path"]).stat().st_mode)[-3:] == "600"
    c_le = db.one("SELECT * FROM certificates WHERE id=?", (lid,))
    assert c_le["cert_path"] == str(le / "live/nm-abc123/fullchain.pem") and Path(c_le["cert_path"]).is_file()
    assert (le / "live/nm-abc123/fullchain.pem").is_symlink() and (le / "renewal/nm-abc123.conf").is_file()
    assert db.kv_get("challenge_secret") == "secret-1"
    ev = db.one("SELECT message FROM events WHERE source='backup' ORDER BY id DESC")["message"]
    assert "восстановлены" in ev
    # ---- раздел отдельно: только сайты, сертификатов нет — HTTPS выключается с пояснением
    db.execute("DELETE FROM certificates")
    r = client.post("/api/backup/settings/restore", headers=client.h,
                    json={"name": plain, "sections": ["sites"], "apply": False}).json()
    assert "applied" not in r and len(r["notes"]) == 2 and "HTTPS выключен" in r["notes"][0]


def test_restore_rolls_back_when_nginx_fails(client, monkeypatch):
    from app.nginx.manager import ApplyError
    nm = client.nm
    db = nm.db
    _insert(db, _site("Был", "old.test"))
    name = client.post("/api/backup/settings", headers=client.h, json={}).json()["name"]
    db.execute("DELETE FROM sites")
    _insert(db, _site("Текущий", "cur.test"))

    async def broken(user, comment="", source="user", state=None):
        raise ApplyError("nginx: [emerg] unknown directive", "out")
    monkeypatch.setattr(nm, "apply", broken)
    r = client.post("/api/backup/settings/restore", headers=client.h,
                    json={"name": name, "sections": ["sites"]}).json()
    assert r["rolled_back"] and "unknown directive" in r["apply_error"]
    assert [x["name"] for x in db.query("SELECT name FROM sites")] == ["Текущий"]  # вернулись прежние
    assert "отменено" in db.one("SELECT message FROM events WHERE source='backup' ORDER BY id DESC")["message"]
    # неверные запросы
    assert client.post("/api/backup/settings/restore", headers=client.h,
                       json={"name": name, "sections": []}).status_code == 400
    assert client.post("/api/backup/settings/restore", headers=client.h,
                       json={"name": "../etc/passwd", "sections": ["sites"]}).status_code == 404


def test_users_section_and_validation(client, tmp_path):
    nm = client.nm
    db = nm.db
    name = client.post("/api/backup/settings", headers=client.h, json={}).json()["name"]
    path = Path(db.path).parent / "backups" / name
    # без администратора — отказ
    manifest, data, files = SB.read(path)
    t = data["users"]["users"]
    role = t["columns"].index("role")
    for r in t["rows"]:
        r[role] = "viewer"
    broken = tmp_path / "nginx-manager-x-broken.settings.tar.gz"
    _rewrite(path, broken, data)
    with pytest.raises(ValueError, match="администратора"):
        SB.restore(nm, broken, ["users"])
    # испорченная контрольная сумма
    _rewrite(path, broken, data, keep_manifest=True)
    with pytest.raises(ValueError, match="контрольная сумма"):
        SB.read(broken)
    # ссылка из архива наружу — отказ
    evil = tmp_path / "evil.settings.tar.gz"
    with tarfile.open(path) as src, tarfile.open(evil, "w:gz") as dst:
        for m in src.getmembers():
            dst.addfile(m, src.extractfile(m) if m.isfile() else None)
        ln = tarfile.TarInfo("letsencrypt/live/x/privkey.pem")
        ln.type, ln.linkname = tarfile.SYMTYPE, "../../../../etc/shadow"
        dst.addfile(ln)
    with pytest.raises(ValueError, match="Недопустимая ссылка"):
        SB.read(evil)
    # пользователи: замена и выход всех
    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES('лишний','scrypt$x','viewer',?)",
               (time.time(),))
    r = client.post("/api/backup/settings/restore", headers=client.h,
                    json={"name": name, "sections": ["users"], "apply": False}).json()
    assert r["relogin"] and not db.one("SELECT 1 FROM users WHERE username='лишний'")
    assert db.one("SELECT COUNT(*) AS n FROM sessions")["n"] == 0
    assert db.one("SELECT COUNT(*) AS n FROM api_tokens")["n"] == 2  # токены из копии (те, что были при создании)


def _rewrite(src: Path, dst: Path, data, keep_manifest=False):
    import hashlib
    import io
    body = json.dumps(data, ensure_ascii=False).encode()
    with tarfile.open(src) as t:
        manifest = json.loads(t.extractfile("manifest.json").read())
        if not keep_manifest:
            manifest["files"]["settings.json"] = hashlib.sha256(body).hexdigest()
        else:
            manifest["files"]["settings.json"] = "0" * 64
        with tarfile.open(dst, "w:gz") as out:
            for name, blob in (("manifest.json", json.dumps(manifest).encode()), ("settings.json", body)):
                info = tarfile.TarInfo(name)
                info.size = len(blob)
                out.addfile(info, io.BytesIO(blob))
            for m in t.getmembers():
                if m.name.startswith(("certs/", "letsencrypt/")):
                    out.addfile(m, t.extractfile(m) if m.isfile() else None)


def test_upload_and_list(client):
    nm = client.nm
    name = client.post("/api/backup/settings", headers=client.h, json={"password": "Secret-Pass-1"}).json()["name"]
    blob = (Path(nm.db.path).parent / "backups" / name).read_bytes()
    r = client.post("/api/backup/upload", headers=client.h, params={"filename": "с-сервера-1.settings.tar.gz.enc"},
                    content=blob).json()
    assert r["settings"] and r["encrypted"] and r["name"].endswith(".settings.tar.gz.enc")
    assert client.post("/api/backup/upload", headers=client.h, params={"filename": "x.tar.gz"},
                       content=b"not a tar").status_code == 400
    kinds = {b["name"]: b["kind"] for b in client.get("/api/backup/list", headers=client.h).json()}
    assert kinds[name] == "settings-enc" and kinds[r["name"]] == "settings-enc"
    # копия базы вместе с копией настроек той же отметкой; удаление старых — вместе
    d = client.post("/api/backup/create", headers=client.h).json()["name"]
    st = d[:-3] + ".settings.tar.gz"
    assert st in kinds or (Path(nm.db.path).parent / "backups" / st).is_file()
    from app.services.backup import prune_backups
    for i in range(3):
        p = Path(nm.db.path).parent / "backups" / f"nginx-manager-2020010{i}-000000-auto.db"
        p.write_text("x")
        p.with_name(p.name[:-3] + ".settings.tar.gz").write_text("x")
    prune_backups(1, 1)
    left = sorted(x.name for x in (Path(nm.db.path).parent / "backups").glob("nginx-manager-2020*"))
    assert left == ["nginx-manager-20200102-000000-auto.db", "nginx-manager-20200102-000000-auto.settings.tar.gz"]


def test_new_server_restore(client, tmp_path, monkeypatch):
    """Копия с одного сервера восстанавливается на чистом: сайты, сертификаты, пользователи."""
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import create_app
    from app.models import CertificateRequest
    nm = client.nm
    cid = nm.certs.create(CertificateRequest(type="selfsigned", domains=["a.test"]), "t")
    _insert(nm.db, _site("A", "a.test", ssl={"enabled": True, "certificate_id": cid}))
    name = client.post("/api/backup/settings", headers=client.h, json={"password": "Secret-Pass-1"}).json()["name"]
    blob = (Path(nm.db.path).parent / "backups" / name).read_bytes()
    monkeypatch.setattr(settings, "data_dir", tmp_path / "new")
    settings.ensure_dirs()
    api2 = create_app()
    with TestClient(api2) as c2:
        nm2 = api2.state.nm
        uid = nm2.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        h2 = {"Authorization": f"Bearer {nm2.auth.create_token(uid, 'x', role='admin')}"}
        up = c2.post("/api/backup/upload", headers=h2, params={"filename": name}, content=blob).json()
        r = c2.post("/api/backup/settings/restore", headers=h2,
                    json={"name": up["name"], "password": "Secret-Pass-1", "sections": list(SB.SECTIONS),
                          "apply": False}).json()
        assert r["relogin"] and r["notes"] == []
        assert nm2.db.one("SELECT name FROM sites")["name"] == "A"
        c = nm2.db.one("SELECT * FROM certificates")
        assert c["status"] == "valid" and str(tmp_path / "new") in c["cert_path"]


def test_cli_settings(tmp_path, monkeypatch, capsys):
    from app import cli
    from app.config import settings
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(SB, "LE_DIR", tmp_path / "le")
    settings.ensure_dirs()
    db = cli._db()
    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES('admin','scrypt$x','admin',?)",
               (time.time(),))
    _insert(db, _site("A", "a.test"))
    monkeypatch.setenv("NM_BACKUP_PASSWORD", "Cli-Pass-12345")
    assert cli.main(["settings", "backup", "-o", str(tmp_path)]) == 0
    f = next(tmp_path.glob("nginx-manager-*-cli.settings.tar.gz.enc"))
    assert cli.main(["settings", "inspect", str(f)]) == 0 and "sites" in capsys.readouterr().out
    db.execute("DELETE FROM sites")
    monkeypatch.setattr("app.utils.has_systemd", lambda: False)
    assert cli.main(["settings", "restore", str(f), "--sections", "sites", "--no-apply"]) == 0
    assert db.one("SELECT name FROM sites")["name"] == "A"
    monkeypatch.delenv("NM_BACKUP_PASSWORD")
    assert cli.main(["settings", "inspect", str(f)]) == 1
