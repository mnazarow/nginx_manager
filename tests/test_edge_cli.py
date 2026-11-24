"""nmctl в нетиповых ситуациях: без аргументов, несуществующие пользователи и версии, слабые пароли, повреждённые
файлы копий и JSON, запуск без терминала (пароль не ввести), повреждённая база, неизвестный сервер для переноса.
Код возврата и понятное сообщение вместо трассировки."""
from __future__ import annotations

import gzip
import io
import json
import sqlite3

import pytest

from app import cli
from app.config import settings
from app.db import Database
from app.nginx.manager import NginxManager


@pytest.fixture()
def env(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    # процесс nginx не трогаем: «перечитать» и «запущен» — заглушки
    monkeypatch.setattr(NginxManager, "reload_or_start", lambda self: (True, "заглушка"))
    monkeypatch.setattr(NginxManager, "is_running", lambda self: True)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False, raising=False)

    def run(*argv, stdin=None):
        if stdin is not None:
            monkeypatch.setattr(cli.sys, "stdin", io.StringIO(stdin))
        code = cli.main(list(argv))
        out = capsys.readouterr()
        return code, out.out + out.err
    return run


def test_help_and_simple_listings(env):
    assert env()[0] == 0
    code, out = env("status")
    assert code == 0 and "Nginx Manager" in out and "Сайтов:          0" in out
    assert env("versions")[0] == 0 and env("sites") == (0, "")
    code, out = env("peers")
    assert code == 0 and "Других серверов нет" in out
    assert env("allowlist", "show") == (0, "(доступ с любых IP)\n")
    for args in (("os", "--json"), ("deps", "--json"), ("deps", "--packages", "apt")):
        assert env(*args)[0] in (0, 1)


def test_users(env):
    assert env("user", "add") == (2, "Укажите имя пользователя\n")
    code, out = env("user", "add", "ivan", "--password", "слабый")
    assert code == 1 and "короче" in out
    assert env("user", "add", "ivan", "--password", "Str0ng-pass!", "--role", "viewer")[0] == 0
    code, out = env("user", "add", "ivan", "--password", "Str0ng-pass!")
    assert code == 1 and "существует" in out
    code, out = env("user", "list")
    assert "ivan" in out and "viewer" in out
    for action in ("reset-2fa", "disable", "enable", "role"):
        assert env("user", action, "ivan", "--role", "operator")[0] == 0
    assert env("user", "passwd", "ivan", "--password", "12345678")[0] == 1  # слабый пароль
    assert env("user", "passwd", "ivan", "--password", "N3w-pass!!")[0] == 0
    code, out = env("user", "passwd", "petr", "--password", "N3w-pass!!")
    assert code == 1 and "не найден" in out
    # пароль не задан и терминала нет (cron) — понятное сообщение, а не трассировка EOFError
    code, out = env("user", "add", "olga", stdin="")
    assert code == 1 and "Нет ввода" in out
    assert env("user", "delete", "ivan")[0] == 0
    db = Database(settings.db_path)
    actions = [r["action"] for r in db.query("SELECT action FROM audit_log WHERE username='cli'")]
    assert "cli_user_delete" in actions


def test_allowlist_clear(env):
    db = Database(settings.db_path)
    db.kv_set("panel_settings", {"panel_allow": ["10.0.0.0/8"]})
    code, out = env("allowlist", "clear")
    assert code == 0 and db.kv_get("panel_settings")["panel_allow"] == []


def test_versions_rollback_and_apply(env, monkeypatch):
    assert env("rollback", "999") == (1, "Версия не найдена\n")
    # nginx -t не прошёл — сообщение и пояснение, код 1
    monkeypatch.setattr(NginxManager, "test_config", lambda self, conf=None: (
        False, "nginx: [emerg] unknown directive \"brotli\" in /x.conf:1\nnginx: configuration file test failed"))
    code, out = env("apply", "-m", "проверка")
    assert code == 1 and "не прошла проверку" in out and "brotli" in out
    monkeypatch.setattr(NginxManager, "test_config", lambda self, conf=None: (True, "ok"))
    code, out = env("apply")
    assert code == 0 and "Применена версия" in out
    vid = Database(settings.db_path).scalar("SELECT MAX(id) FROM config_versions WHERE status='applied'")
    code, out = env("rollback", str(vid))
    assert code == 0 and "Откат выполнен" in out
    code, out = env("versions", "--limit", "5")
    assert "applied" in out and "failed" in out
    assert env("test")[0] == 0
    # версия с испорченным состоянием
    db = Database(settings.db_path)
    db.execute("UPDATE config_versions SET state='не json' WHERE id=?", (vid,))
    code, out = env("rollback", str(vid))
    assert code == 1 and "✗" in out


def test_export_import(env, tmp_path):
    code, out = env("export")
    data = json.loads(out)
    assert code == 0 and "sites" in data
    f = tmp_path / "s.json"
    f.write_text(json.dumps(data))
    code, out = env("import", str(f), "--mode", "merge")
    assert code == 0 and "Импорт завершён" in out
    f.write_text("{не json")
    assert env("import", str(f))[0] == 1
    assert env("import", str(tmp_path / "нет.json"))[0] == 1


def _snapshot(tmp_path) -> bytes:
    """Согласованная копия базы (с учётом журнала WAL), как делает панель."""
    out = tmp_path / "snap.db"
    out.unlink(missing_ok=True)
    src, dst = sqlite3.connect(settings.db_path), sqlite3.connect(out)
    src.backup(dst)
    src.close()
    dst.close()
    return out.read_bytes()


def test_backup_and_restore_edges(env, tmp_path, monkeypatch):
    code, out = env("backup")
    assert code == 0 and "Резервная копия" in out
    assert env("restore", str(tmp_path / "нет.db"))[0] == 1
    bad = tmp_path / "broken.db.gz"
    bad.write_bytes(b"\x1f\x8b\x08\x00 broken gzip")
    monkeypatch.setattr(cli, "_service_active", lambda: False)
    monkeypatch.setattr(cli, "_panel_answers", lambda: False)
    code, out = env("restore", str(bad))
    assert code == 1 and "распаковать" in out
    # копия без администраторов не восстанавливается: войти было бы невозможно
    good = tmp_path / "copy.db.gz"
    good.write_bytes(gzip.compress(_snapshot(tmp_path)))
    code, out = env("restore", str(good), "--yes")
    assert code == 1 and "администратора" in out
    # настоящая копия: без терминала и без --yes — отказ
    assert env("user", "add", "boss", "--password", "Str0ng-pass!", "--role", "admin")[0] == 0
    good.write_bytes(gzip.compress(_snapshot(tmp_path)))
    code, out = env("restore", str(good))
    assert code == 1 and "--yes" in out
    # панель запущена не как сервис — базу под ней не меняем
    monkeypatch.setattr(cli, "_panel_answers", lambda: True)
    code, out = env("restore", str(good), "--yes")
    assert code == 1 and "не как сервис" in out
    monkeypatch.setattr(cli, "_panel_answers", lambda: False)
    code, out = env("restore", str(good), "--yes")
    assert code == 0 and "База восстановлена" in out
    # зашифрованная копия, пароль не ввести
    enc = tmp_path / "copy.db.gz.enc"
    enc.write_bytes(b"Salted__" + b"x" * 64)
    monkeypatch.delenv("NM_BACKUP_PASS", raising=False)
    code, out = env("restore", str(enc), stdin="")
    assert code == 1


def test_settings_lists_transfer_vulns(env, tmp_path, monkeypatch):
    junk = tmp_path / "junk.settings.tar.gz"
    junk.write_bytes(b"not a tar")
    assert env("settings", "inspect", str(junk))[0] == 1
    assert env("settings", "inspect")[0] == 1
    monkeypatch.delenv("NM_BACKUP_PASSWORD", raising=False)
    code, out = env("settings", "backup", "-o", str(tmp_path), stdin="")
    assert code == 0 and "без пароля" in out  # копия без шифрования — с предупреждением
    pw = tmp_path / "pw"
    pw.write_text("Длинный-пароль-1\n")
    code, out = env("settings", "backup", "-o", str(tmp_path), "--password-file", str(pw))
    assert code == 0
    made = next(tmp_path.glob("*.settings.tar.gz.enc"))
    code, out = env("settings", "inspect", str(made), "--password-file", str(pw))
    assert code == 0
    pw.write_text("неверный")
    assert env("settings", "inspect", str(made), "--password-file", str(pw))[0] == 1
    assert env("settings", "restore", "s3://", "--endpoint", "http://127.0.0.1:1")[0] == 1
    # подпись списков
    key = tmp_path / "k.txt"
    code, out = env("lists", "keygen", "-o", str(key))
    pub = next(ln for ln in out.split() if ln.startswith("ed25519:"))
    lst = tmp_path / "list.txt"
    lst.write_text("203.0.113.5\n")
    assert env("lists", "sign", str(lst), "--key", str(key))[0] == 0
    assert env("lists", "verify", str(lst), "--pub", pub)[0] == 0
    lst.write_text("203.0.113.6\n")
    assert env("lists", "verify", str(lst), "--pub", pub)[0] == 1
    assert env("lists", "sign", str(lst), "--key", str(tmp_path / "нет"))[0] == 1
    # перенос на неизвестный сервер, без выбора сайтов
    code, out = env("transfer", "--to", "web-9", "--all")
    assert code == 1 and "✗" in out
    # база уязвимостей: поиск по пустой базе, карточка несуществующей
    assert env("vulns", "status")[0] in (0, 1)
    assert env("vulns", "search", "nginx")[0] in (0, 1)
    assert env("vulns", "show", "CVE-0000-0000")[0] in (0, 1)


def test_corrupt_database(env):
    settings.db_path.write_bytes(b"SQLite format 3\x00" + b"\xff" * 4000)
    for p in settings.db_path.parent.glob("nginx-manager.db-*"):
        p.unlink()
    code, out = env("sites")
    assert code == 1 and "База данных" in out and "nmctl restore" in out
    with pytest.raises(sqlite3.DatabaseError):
        Database(settings.db_path).query("SELECT 1 FROM sites")
