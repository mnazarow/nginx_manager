"""Восстановление базы из копии: проверка копии, отложенная замена файла при запуске, перенос работающей
конфигурации, загрузка копий на сервер, nmctl restore. Каждый тест — в собственном каталоге данных."""
import gzip
import json
import shutil
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import settings

PW = "Restore-Passw0rd!"
H = {"X-NM-CSRF": "1"}
SITE = {"name": "до копии", "domains": ["before.example.com"], "type": "proxy",
        "backends": [{"address": "127.0.0.1", "port": 9901}]}


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    """Отдельный каталог данных: тест подменяет файл базы и не должен мешать остальным."""
    d = tmp_path / "data"
    monkeypatch.setattr(settings, "data_dir", d)
    monkeypatch.delenv("INVOCATION_ID", raising=False)  # не под systemd: панель не перезапускает себя сама
    settings.ensure_dirs()
    return d


def _client():
    from app.main import create_app
    return TestClient(create_app())


def _login(c):
    from app.utils import hash_password
    c.app.state.nm.db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username='admin'",
                              (hash_password(PW),))
    r = c.post("/api/auth/login", json={"username": "admin", "password": PW})
    assert r.status_code == 200, r.text


def _copy(c) -> str:
    r = c.post("/api/backup/create", headers=H)
    assert r.status_code == 200, r.text
    return r.json()["name"]


# ---------------------------------------------------------------------------- проверка копии
def test_inspect_rejects_bad_files(data_dir):
    from app.services.backup import inspect_db
    d = settings.backups_dir
    cases = {"nginx-manager-x.db": b"hello world, not a database at all",
             "nginx-manager-gz.db": gzip.compress(b"SQLite format 3\x00" + b"\0" * 100),
             "nginx-manager-enc.db": b"Salted__12345678" + b"\1" * 64,
             "nginx-manager-json.db": b'{"format": "nginx-manager-export"}'}
    expect = {"nginx-manager-x.db": "не является файлом базы", "nginx-manager-gz.db": "сжатый",
              "nginx-manager-enc.db": "зашифрованный", "nginx-manager-json.db": "Импорт настроек"}
    for name, body in cases.items():
        (d / name).write_bytes(body)
        with pytest.raises(ValueError, match=expect[name]):
            inspect_db(d / name)
    other = d / "nginx-manager-other.db"  # чужая база SQLite
    con = sqlite3.connect(str(other))
    con.execute("CREATE TABLE t(x)")
    con.execute("PRAGMA user_version=3")
    con.commit()
    con.close()
    with pytest.raises(ValueError, match="не база Nginx Manager"):
        inspect_db(other)
    with pytest.raises(ValueError, match="не найден"):
        inspect_db(d / "nginx-manager-missing.db")


def test_inspect_copy_and_refusals(data_dir):
    from app.db import SCHEMA
    from app.services.backup import inspect_db
    with _client() as c:
        _login(c)
        assert c.post("/api/sites", json=SITE, headers=H).status_code == 200
        name = _copy(c)
        r = c.get(f"/api/backup/inspect/{name}")
        assert r.status_code == 200, r.text
        info = r.json()
        assert info["sites"] == 1 and info["schema"] == len(SCHEMA) and info["admins"] == ["admin"]
        assert info["data_until"] and info["users"][0]["role"] == "admin"
        # осмотр копии не оставляет рядом служебных файлов SQLite и они не попадают в список
        assert not list(settings.backups_dir.glob("*-wal")) and not list(settings.backups_dir.glob("*-shm"))
        assert all(b["kind"] in ("db", "json") for b in c.get("/api/backup/list").json())
        assert c.get("/api/backup/inspect/nope.db").status_code == 404
    src = settings.backups_dir / name
    for patch, msg in ((["UPDATE users SET role='viewer'"], "нет ни одного активного администратора"),
                       (["UPDATE users SET disabled=1"], "нет ни одного активного администратора"),
                       ([f"PRAGMA user_version={len(SCHEMA) + 1}"], "более новой версией"),):
        bad = settings.backups_dir / "nginx-manager-bad.db"
        shutil.copyfile(src, bad)
        con = sqlite3.connect(str(bad))
        for sql in patch:
            con.execute(sql)
        con.commit()
        con.close()
        with pytest.raises(ValueError, match=msg):
            inspect_db(bad)
    # повреждённый файл: обрезан посередине
    raw = src.read_bytes()
    bad.write_bytes(raw[:len(raw) // 2])
    with pytest.raises(ValueError):
        inspect_db(bad)


# ---------------------------------------------------------------------------- полный цикл
def test_restore_full_cycle(data_dir):
    with _client() as c:
        _login(c)
        assert c.post("/api/sites", json=SITE, headers=H).status_code == 200
        name = _copy(c)
        later = dict(SITE, name="после копии", domains=["after.example.com"])
        assert c.post("/api/sites", json=later, headers=H).status_code == 200
        # «в nginx работает» версия, применённая после копии: её надо перенести в восстановленную базу
        db = c.app.state.nm.db
        db.execute("INSERT INTO config_versions(ts,username,comment,source,status,files,state,output,checksum) "
                   "VALUES(?,?,?,?,?,?,?,?,?)", (time.time(), "admin", "после копии", "user", "applied",
                                                 json.dumps({"nginx.conf": "# работающая\n"}),
                                                 json.dumps({"sites": [], "streams": [], "global": {}}), "", "abc"))
        # операторы и наблюдатели не восстанавливают
        r = c.post("/api/backup/restore", json={"name": name}, headers=H)
        assert r.status_code == 200, r.text
        res = r.json()
        assert res["restart"] is False and res["safety"].endswith("-before-restore.db")
        st = c.get("/api/backup/restore").json()
        assert st["pending"]["source"] == name and st["can_restart"] is False
        # повторно — нельзя, пока не выполнено
        assert c.post("/api/backup/restore", json={"name": name}, headers=H).status_code == 409
        assert (data_dir / "restore-pending.db").exists()
        audit = db.query("SELECT action FROM audit_log WHERE action='backup_restore_scheduled'")
        assert audit
    # «перезапуск»: новый процесс панели заменяет базу при старте
    with _client() as c:
        _login(c)
        sites = [s["name"] for s in c.get("/api/sites").json()]
        assert sites == ["до копии"], sites
        assert not (data_dir / "restore-pending.db").exists()
        st = c.get("/api/backup/restore").json()
        assert st["pending"] is None and st["last"]["ok"] and st["last"]["source"] == name
        db = c.app.state.nm.db
        ev = db.query("SELECT level, message FROM events WHERE source='backup' ORDER BY id DESC LIMIT 1")[0]
        assert ev["level"] == "warning" and "База восстановлена из копии" in ev["message"]
        assert "отличаются от работающей конфигурации" in ev["message"]
        assert db.query("SELECT 1 FROM audit_log WHERE action='backup_restored'")
        carried = db.one("SELECT * FROM config_versions WHERE status='applied' ORDER BY id DESC LIMIT 1")
        assert carried["source"] == "restore" and carried["checksum"] == "abc"
        assert db.kv_get("applied_version") == carried["id"]
        assert c.app.state.nm.pending()["pending"] is True
        # прежняя база сохранена и сама годится для восстановления (в ней оба сайта)
        r = c.get(f"/api/backup/inspect/{res['safety']}")
        assert r.status_code == 200 and r.json()["sites"] == 2


def test_restore_cancel_and_failed_restore(data_dir):
    from app.services.backup import RESTORE_LAST, _read_json
    with _client() as c:
        _login(c)
        name = _copy(c)
        assert c.post("/api/backup/restore", json={"name": name}, headers=H).status_code == 200
        r = c.delete("/api/backup/restore", headers=H)
        assert r.json()["cancelled"] is True
        assert c.get("/api/backup/restore").json()["pending"] is None
        # запланировано, но к моменту запуска файл испорчен — панель стартует с прежней базой
        assert c.post("/api/sites", json=SITE, headers=H).status_code == 200
        assert c.post("/api/backup/restore", json={"name": name}, headers=H).status_code == 200
    (data_dir / "restore-pending.db").write_bytes(b"broken")
    with _client() as c:
        _login(c)
        assert [s["name"] for s in c.get("/api/sites").json()] == ["до копии"]
        last = _read_json(data_dir / RESTORE_LAST)
        assert last["ok"] is False and f"{name} не является файлом базы" in last["error"]
        ev = c.app.state.nm.db.query("SELECT level, message FROM events WHERE source='backup' ORDER BY id DESC")[0]
        assert ev["level"] == "error" and "не выполнено" in ev["message"]
        diag = c.post("/api/diagnostics/run", headers=H).json()
        assert any(x.get("id") == "backup_restore" for x in diag["results"]), diag["results"]


def test_restore_requires_admin(data_dir):
    with _client() as c:
        _login(c)
        name = _copy(c)
        r = c.post("/api/users", json={"username": "op", "password": "Oper-Passw0rd!", "role": "operator"}, headers=H)
        assert r.status_code == 200, r.text
        o = TestClient(c.app)
        assert o.post("/api/auth/login", json={"username": "op", "password": "Oper-Passw0rd!"}).status_code == 200
        assert o.post("/api/backup/restore", json={"name": name}, headers=H).status_code == 403
        assert o.get(f"/api/backup/inspect/{name}").status_code == 403
        assert o.post("/api/backup/upload?filename=x.db", content=b"x", headers=H).status_code == 403


# ---------------------------------------------------------------------------- загрузка копий на сервер
def test_upload_backup(data_dir):
    with _client() as c:
        _login(c)
        name = _copy(c)
        raw = (settings.backups_dir / name).read_bytes()
        up = dict(H, **{"Content-Type": "application/octet-stream"})
        # сжатая база с другого сервера: распаковывается и проверяется
        r = c.post("/api/backup/upload", params={"filename": "server-a.db.gz"}, content=gzip.compress(raw), headers=up)
        assert r.status_code == 200, r.text
        got = r.json()
        assert got["name"].endswith("-uploaded-server-a.db") and got["info"]["admins"] == ["admin"]
        assert (settings.backups_dir / got["name"]).read_bytes() == raw
        # экспорт настроек
        js = (settings.backups_dir / name.replace(".db", ".json")).read_bytes()
        r = c.post("/api/backup/upload", params={"filename": "export.json"}, content=js, headers=up)
        assert r.status_code == 200 and r.json()["name"].endswith(".json") and r.json()["info"] is None
        # ошибки: мусор под видом базы, не тот JSON, зашифрованная копия, повтор имени, пустой файл
        for fn, body, code, msg in (("x.db", b"garbage" * 10, 400, "не является файлом базы"),
                                    ("y.json", b'{"a": 1}', 400, "не файл экспорта"),
                                    ("z.db.gz.enc", b"Salted__xx", 400, "расшифруйте"),
                                    ("bad.db.gz", b"not gzip", 400, "распаковать"),
                                    (name, raw, 409, "уже есть"),
                                    ("empty.db", b"", 400, "Пустой")):
            r = c.post("/api/backup/upload", params={"filename": fn}, content=body, headers=up)
            assert r.status_code == code and msg in r.json()["detail"], (fn, r.text)
        names = [b["name"] for b in c.get("/api/backup/list").json()]
        assert not [n for n in names if n.endswith(".part")]
        assert len([n for n in names if n.endswith(".db")]) == 2  # исходная копия и загруженная


# ---------------------------------------------------------------------------- nmctl restore
def test_cli_restore(data_dir, monkeypatch, capsys):
    from app import cli
    from app.db import Database
    monkeypatch.setattr(cli, "_service_active", lambda: False)
    monkeypatch.setattr(cli, "_panel_answers", lambda: False)
    assert cli.main(["backup"]) == 0
    copy = sorted(settings.backups_dir.glob("nginx-manager-*-cli.db"))[-1]
    capsys.readouterr()
    assert cli.main(["restore", str(copy), "--yes"]) == 1  # в копии нет администратора — войти было бы нельзя
    assert "нет ни одного активного администратора" in capsys.readouterr().err
    assert cli.main(["user", "add", "boss", "--role", "admin", "--password", PW]) == 0
    time.sleep(1.1)  # копии именуются с точностью до секунды
    assert cli.main(["backup"]) == 0
    copy = sorted(settings.backups_dir.glob("nginx-manager-*-cli.db"))[-1]
    db = Database(settings.db_path)
    db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES('лишний',1,'{}',0,0)")
    db.close()
    gz = Path(str(copy) + ".gz")
    gz.write_bytes(gzip.compress(copy.read_bytes()))
    capsys.readouterr()
    code = cli.main(["restore", str(gz), "--yes"])
    cap = capsys.readouterr()
    out = cap.out
    assert code == 0, cap.out + cap.err
    assert "База восстановлена" in out and "before-restore" in out
    db = Database(settings.db_path)
    assert db.scalar("SELECT COUNT(*) FROM sites") == 0
    db.close()
    # итог восстановления запишется в журнал при следующем запуске панели
    assert (data_dir / "restore-result.json").exists()
    # зашифрованная копия из S3 (.db.gz.enc), лежащая вне каталога копий: пароль из NM_BACKUP_PASS
    from app.services.backup import _encrypt
    outside = data_dir.parent / "from-s3"
    outside.mkdir()
    gz2 = outside / gz.name
    shutil.copyfile(gz, gz2)
    enc = _encrypt(gz2, "s3cret-pass")
    monkeypatch.setenv("NM_BACKUP_PASS", "wrong")
    assert cli.main(["restore", str(enc), "--yes"]) == 1
    assert "неверный пароль" in capsys.readouterr().err
    assert not list(settings.backups_dir.glob("*.enc"))  # после ошибки промежуточная копия не остаётся
    monkeypatch.setenv("NM_BACKUP_PASS", "s3cret-pass")
    code = cli.main(["restore", str(enc), "--yes"])
    cap = capsys.readouterr()
    assert code == 0, cap.out + cap.err
    assert not list(settings.backups_dir.glob("*.enc")) and enc.exists()  # промежуточные файлы убраны, исходный цел
    # копия, которую нельзя восстановить, — понятная ошибка и код 1
    bad = settings.backups_dir / "nginx-manager-bad.db"
    bad.write_bytes(b"nothing")
    assert cli.main(["restore", str(bad), "--yes"]) == 1
    assert "не является файлом базы" in capsys.readouterr().err
