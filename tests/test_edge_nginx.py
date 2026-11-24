"""Применение конфигурации и управление nginx в нетиповых ситуациях: nginx -t не принял черновик или итоговую
конфигурацию, reload не прошёл, nginx упал после reload, каталог live — обычная папка, файлы вне версий
(блокировки, сети стран), разбор ошибок nginx, чистка версий, права, управление процессом без systemd.

Проверка конфигурации — настоящим nginx -t (если он установлен и тесты идут от root), reload и запуск — подделки."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import threading
import time
from pathlib import Path

import pytest

from app.config import settings
from app.db import Database
from app.models import Backend, GlobalSettings, PanelSettings, Site, Stream
from app.nginx import manager as M
from app.nginx.generator import State

NGINX = bool(shutil.which("nginx")) and os.geteuid() == 0
needs_nginx = pytest.mark.skipif(not NGINX, reason="нужен nginx и root")


def _state(port=9001, name="Магазин"):
    site = Site(name=name, domains=["shop.test"], backends=[Backend(address="127.0.0.1", port=port)])
    stream = Stream(name="PG", listen_port=25432, backends=[Backend(port=5432)])
    return State([(1, site)], [(1, stream)], GlobalSettings(), PanelSettings(), {})


@pytest.fixture()
def mgr(tmp_path, monkeypatch):
    """Менеджер с изолированными каталогами: live, версии, nginx.conf — во временной папке."""
    root = tmp_path / "managed"
    monkeypatch.setattr(settings, "managed_dir", root)
    monkeypatch.setattr(settings, "nginx_conf", tmp_path / "nginx.conf")
    settings.ensure_dirs()
    m = M.NginxManager(Database(str(tmp_path / "nm.db")))
    real_test = m.test_config
    calls = {"reload": 0, "test": []}

    def test_config(conf=None):
        calls["test"].append(conf)
        return real_test(conf or settings.nginx_conf)
    monkeypatch.setattr(m, "test_config", test_config)

    def reload_or_start():
        calls["reload"] += 1
        return True, "reloaded"
    monkeypatch.setattr(m, "reload_or_start", reload_or_start)
    monkeypatch.setattr(m, "is_running", lambda: True)
    monkeypatch.setattr(M.time, "sleep", lambda s: None)
    m.calls = calls
    return m


# =============================================================================
#  Полный цикл применения
# =============================================================================
@needs_nginx
def test_apply_success_and_versions(mgr):
    try:
        res = mgr.apply_sync(_state(), "admin", "первая версия")
    except M.ApplyError as e:
        raise AssertionError(e.output)
    assert res["version"] and mgr.calls["reload"] == 1
    live = settings.live_dir
    assert live.is_symlink() and Path(os.readlink(live)).parent == settings.versions_dir
    conf = settings.nginx_conf.read_text()
    assert M.MARKER in conf and mgr.is_managed()
    row = mgr.db.one("SELECT status, username, comment FROM config_versions WHERE id=?", (res["version"],))
    assert dict(row) == {"status": "applied", "username": "admin", "comment": "первая версия"}
    assert mgr.db.kv_get("applied_version") == res["version"]
    # вторая версия: live переключается, прежняя версия остаётся на диске
    first = os.readlink(live)
    time.sleep(0.002)
    res2 = mgr.apply_sync(_state(port=9002), "admin", "вторая")
    assert os.readlink(live) != first and Path(first).is_dir()
    assert mgr.last_applied()["id"] == res2["version"]


@needs_nginx
def test_apply_recreates_missing_side_files(mgr):
    """Файл блокировок или доступа по ссылке удалили вручную — применение не падает с «open() failed»."""
    mgr.apply_sync(_state(), "admin")
    settings.bans_file.unlink()
    settings.grants_file.unlink(missing_ok=True)
    mgr.apply_sync(_state(port=9010), "admin")
    assert settings.bans_file.exists() and "создан пустым" in settings.bans_file.read_text()
    ev = mgr.db.one("SELECT level, message FROM events WHERE source='config' AND message LIKE 'Созданы пустые%' "
                    "ORDER BY id DESC")
    assert ev and "bans.conf" in ev["message"]
    assert mgr._ensure_side_files({"x.conf": f"include {settings.bans_file};\ninclude /etc/nginx/mime.types;\n"
                                                f"include {settings.live_dir}/sites/*.conf;"}) == []


@needs_nginx
def test_apply_rejected_by_nginx_keeps_live(mgr, monkeypatch):
    mgr.apply_sync(_state(), "admin")
    live_before = os.readlink(settings.live_dir)
    conf_before = settings.nginx_conf.read_text()
    real = mgr.test_config

    def broken(conf=None):  # черновик: nginx -t сообщает об ошибке в файле сайта
        if conf is not None and "versions" in str(conf):
            site_file = next(Path(conf).parent.glob("sites/site-1-*.conf"))
            return False, (f"nginx: [emerg] unknown directive \"proxy_passs\" in {site_file}:3\n"
                           "nginx: configuration file test failed")
        return real(conf)
    monkeypatch.setattr(mgr, "test_config", broken)
    with pytest.raises(M.ApplyError) as e:
        mgr.apply_sync(_state(port=9100), "ivan", "опечатка")
    err = e.value
    assert err.site_id == 1 and err.errors[0]["kind"] == "site" and err.errors[0]["object_id"] == 1
    assert "proxy_passs" in err.errors[0]["hint"] and err.errors[0]["context"]
    assert os.readlink(settings.live_dir) == live_before and settings.nginx_conf.read_text() == conf_before
    row = mgr.db.one("SELECT status, username FROM config_versions ORDER BY id DESC")
    assert dict(row) == {"status": "failed", "username": "ivan"}
    # каталог отклонённой версии удалён
    assert len(list(settings.versions_dir.iterdir())) == 1


@needs_nginx
def test_apply_final_test_fails_rolls_back(mgr, monkeypatch):
    mgr.apply_sync(_state(), "admin")
    live_before, conf_before = os.readlink(settings.live_dir), settings.nginx_conf.read_text()
    real = mgr.test_config

    def final_fails(conf=None):
        if conf is None:
            return False, "nginx: [emerg] open() \"/etc/nginx/mime.types\" failed (2: No such file or directory)"
        return real(conf)
    monkeypatch.setattr(mgr, "test_config", final_fails)
    with pytest.raises(M.ApplyError, match="изменения отменены") as e:
        mgr.apply_sync(_state(port=9200), "admin")
    assert "не существует" in e.value.errors[0]["hint"]
    assert os.readlink(settings.live_dir) == live_before and settings.nginx_conf.read_text() == conf_before
    assert mgr.calls["reload"] == 1  # только первое применение


@needs_nginx
def test_apply_reload_fails_or_nginx_dies(mgr, monkeypatch):
    mgr.apply_sync(_state(), "admin")
    live_before = os.readlink(settings.live_dir)
    seq = iter([(False, "nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)"), (True, "")])
    monkeypatch.setattr(mgr, "reload_or_start", lambda: next(seq))
    with pytest.raises(M.ApplyError, match="не смог перечитать") as e:
        mgr.apply_sync(_state(port=9300), "admin")
    assert "Address already in use" in e.value.output
    assert os.readlink(settings.live_dir) == live_before
    # reload прошёл, но nginx остановился — откат и запуск прежней версии
    starts = []
    monkeypatch.setattr(mgr, "reload_or_start", lambda: starts.append(1) or (True, ""))
    monkeypatch.setattr(mgr, "is_running", lambda: False)
    settings.error_log.parent.mkdir(parents=True, exist_ok=True)
    settings.error_log.write_text("2026/11/24 10:00:00 [emerg] 1#1: worker crashed\n")
    with pytest.raises(M.ApplyError, match="остановился") as e:
        mgr.apply_sync(_state(port=9301), "admin")
    assert len(starts) == 2 and "worker crashed" in e.value.output
    assert os.readlink(settings.live_dir) == live_before


@needs_nginx
def test_apply_live_dir_was_plain_directory(mgr):
    """Старая установка или ручное вмешательство: live — обычный каталог. Он сохраняется рядом, не удаляется."""
    settings.live_dir.mkdir(parents=True, exist_ok=True)
    (settings.live_dir / "manual.conf").write_text("# руками\n")
    mgr.apply_sync(_state(), "admin")
    assert settings.live_dir.is_symlink()
    old = [p for p in settings.managed_dir.iterdir() if p.name.startswith("live.old-")]
    assert old and (old[0] / "manual.conf").read_text() == "# руками\n"


@needs_nginx
def test_cleanup_keeps_current_and_limits_history(mgr):
    for i in range(13):
        mgr.apply_sync(_state(port=9400 + i), "admin")
        time.sleep(0.002)
    dirs = sorted(p.name for p in settings.versions_dir.iterdir())
    assert len(dirs) == 10 and os.path.realpath(settings.live_dir).endswith(dirs[-1])
    assert mgr.db.one("SELECT COUNT(*) n FROM config_versions")["n"] == 13


def test_apply_config_error_is_apply_error(mgr, monkeypatch):
    from app.nginx.generator import ConfigError

    def bad_render(state, include_root=None):
        raise ConfigError("два сайта на одном домене", site_id=7)
    monkeypatch.setattr(mgr, "render", bad_render)
    with pytest.raises(M.ApplyError) as e:
        mgr.apply_sync(_state(), "admin")
    assert e.value.site_id == 7 and "два сайта" in str(e.value)


def test_async_apply_serialized_and_event(mgr, monkeypatch):
    """Два применения одновременно идут по очереди; ошибка пишет событие с понятной причиной."""
    active, peak = [0], [0]
    lock = threading.Lock()

    def slow(state, username="system", comment="", source="user"):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        threading.Event().wait(0.05)  # time.sleep подменён фикстурой
        with lock:
            active[0] -= 1
        return {"version": 1, "warnings": [], "duration": 0, "output": ""}
    monkeypatch.setattr(mgr, "apply_sync", slow)
    monkeypatch.setattr(mgr, "load_state", lambda: _state())

    async def both():
        return await asyncio.gather(mgr.apply(None, "a"), mgr.apply(None, "b"))
    assert len(asyncio.run(both())) == 2 and peak[0] == 1
    ev = mgr.db.query("SELECT level, message FROM events WHERE source='config'")
    assert [e["level"] for e in ev] == ["info", "info"]

    def failing(state, username="system", comment="", source="user"):
        raise M.ApplyError("x", "nginx: [emerg] 12#12: unknown directive \"foo\"",
                           [{"level": "emerg", "message": "12#12: unknown directive \"foo\""}])
    monkeypatch.setattr(mgr, "apply_sync", failing)
    with pytest.raises(M.ApplyError):
        asyncio.run(mgr.apply(None, "petr", source="failover"))
    ev = mgr.db.one("SELECT level, message FROM events ORDER BY id DESC")
    assert ev["level"] == "error" and "автопереключение бэкендов" in ev["message"]
    assert "12#12" not in ev["message"] and "unknown directive" in ev["message"]


# =============================================================================
#  Файлы вне версий
# =============================================================================
def test_side_file_paths(mgr, tmp_path, monkeypatch):
    f = tmp_path / "side" / "bans.conf"
    # nginx ещё не настроен панелью — файл просто записывается
    ok, out = mgr.write_side_file(f, "203.0.113.1 1;\n")
    assert ok and "не запущен" in out and f.read_text() == "203.0.113.1 1;\n"
    assert mgr.write_side_file(f, "203.0.113.1 1;\n") == (True, "без изменений")
    monkeypatch.setattr(mgr, "last_applied", lambda: {"id": 1})
    # nginx -t не принял — прежнее содержимое возвращается
    monkeypatch.setattr(mgr, "test_config", lambda conf=None: (False, "nginx: [emerg] invalid"))
    ok, out = mgr.write_side_file(f, "мусор")
    assert not ok and f.read_text() == "203.0.113.1 1;\n"
    # файла не было — при ошибке удаляется
    g = tmp_path / "side" / "new.conf"
    assert not mgr.write_side_file(g, "x")[0] and not g.exists()
    # принят — reload
    monkeypatch.setattr(mgr, "test_config", lambda conf=None: (True, "syntax is ok"))
    ok, out = mgr.write_side_file(f, "198.51.100.0/24 1;\n")
    assert ok and "reloaded" in out and mgr.calls["reload"] == 1


# =============================================================================
#  Разбор ошибок nginx
# =============================================================================
@pytest.mark.parametrize("msg,expect", [
    ('unknown directive "brotli"', "Неизвестная директива «brotli»"),
    ('cannot load certificate "/x.pem": BIO_new_file() failed (SSL: error:No such file)', "не найден"),
    ('cannot load certificate key "/k.pem"', "закрытый ключ"),
    ("SSL_CTX_use_PrivateKey failed (key values mismatch)", "не соответствует"),
    ("bind() to 0.0.0.0:80 failed (98: Address already in use)", "Порт уже занят"),
    ("bind() to 0.0.0.0:8443 failed (13: Permission denied)", "порт 8443"),
    ('host not found in upstream "app.internal" in /etc/x.conf:3', "«app.internal»"),
    ('duplicate location "/api/"', "«/api/»"),
    ("could not build server_names_hash, you should increase server_names_hash_bucket_size", "bucket_size"),
    ('"proxy_pass" directive is duplicate', "«proxy_pass»"),
    ('"server" directive is not allowed here', "«server»"),
    ('invalid number of arguments in "listen" directive', "«listen»"),
    ('unexpected "}"', "скобка"),
    ('conflicting server name "a.test" on 0.0.0.0:80, ignored', "«a.test»"),
    ("duplicate listen options for 0.0.0.0:443", "listen"),
    ("a duplicate default server for 0.0.0.0:80", "по умолчанию"),
    ('no "ssl_certificate" is defined for the "listen ... ssl"', "сертификат"),
    ('open() "/etc/nginx/x" failed (13: Permission denied)', "Нет прав"),
    ('open() "/etc/nginx/x" failed (2: No such file)', "не существует"),
    ('zero size shared memory zone "nm_rl_1"', "«nm_rl_1»"),
    ('unknown "nm_foo" variable', "$nm_foo"),
    ("pcre2_compile() failed: missing closing parenthesis in \"(\"", "регулярном"),
    ("что-то совсем новое", ""),
])
def test_explain_nginx_error(msg, expect):
    text = M.explain_nginx_error(msg)
    assert (expect in text) if expect else text == ""


def test_parse_errors_outside_root_and_garbage(mgr):
    out = ("nginx: [warn] the \"listen ... http2\" directive is deprecated in /etc/nginx/conf.d/x.conf:5\n"
           "просто строка\n\x00\x01 бинарный мусор\n"
           "nginx: [emerg] unexpected end of file, expecting \";\" or \"}\" in /tmp/root/streams/stream-4-pg.conf:9\n")
    files = {"streams/stream-4-pg.conf": "\n".join(f"line {i}" for i in range(1, 12))}
    errs = mgr.parse_errors(out, files, "/tmp/root")
    assert [e["level"] for e in errs] == ["warn", "emerg"]
    assert errs[0]["file"] == "/etc/nginx/conf.d/x.conf" and "kind" not in errs[0]
    assert errs[1]["kind"] == "stream" and errs[1]["object_id"] == 4
    ctx = errs[1]["context"]
    assert [c["n"] for c in ctx] == [6, 7, 8, 9, 10, 11] and next(c for c in ctx if c["error"])["n"] == 9
    assert mgr.parse_errors("", {}, "/x") == []


# =============================================================================
#  Права, история, состояние
# =============================================================================
def test_fix_permissions_and_unreadable(mgr, monkeypatch):
    vd = settings.versions_dir / "20260101-000000-000"
    (vd / "auth").mkdir(parents=True)
    (vd / "sites").mkdir()
    (vd / "sites" / "a.conf").write_text("x")
    os.chmod(vd / "sites" / "a.conf", 0o600)
    (vd / "auth" / "s.htpasswd").write_text("u:x")
    os.chmod(vd / "auth" / "s.htpasswd", 0o644)
    os.chmod(vd, 0o700)
    fixed = mgr.fix_permissions("nobody-such-user")
    assert str(vd) in fixed and oct((vd / "sites" / "a.conf").stat().st_mode & 0o777) == "0o644"
    assert oct((vd / "auth" / "s.htpasswd").stat().st_mode & 0o777) == "0o640"
    assert mgr.fix_permissions("nobody-such-user") == []  # повторно — нечего исправлять
    assert mgr.unreadable_paths("nobody-such-user") == []  # неизвестный пользователь — пропуск
    # nobody не пройдёт в каталог 0700 на пути к странице ошибок
    os.symlink(vd, settings.live_dir)
    (vd / "pages").mkdir()
    (vd / "pages" / "error-502.html").write_text("x")
    os.chmod(vd, 0o700)
    bad = mgr.unreadable_paths("nobody")
    assert any("нет права прохода" in b for b in bad)


def test_restore_state_and_original_backup(mgr):
    st = {"sites": [{"id": 5, "data": {"name": "A", "domains": ["a.test"]}}],
          "streams": [{"id": 2, "data": {"name": "S", "listen_port": 2000, "enabled": False}}],
          "global": GlobalSettings(worker_connections=2048).model_dump()}
    mgr.restore_state_to_db(st)
    assert [dict(r) for r in mgr.db.query("SELECT id, name, enabled FROM sites")] == [{"id": 5, "name": "A",
                                                                                        "enabled": 1}]
    assert mgr.db.one("SELECT enabled FROM streams WHERE id=2")["enabled"] == 0
    # исходный nginx.conf сохраняется один раз и только если он не наш
    settings.nginx_conf.write_text("user www-data;\n")
    mgr.ensure_original_backup()
    orig = settings.nginx_conf.with_name("nginx.conf.nm-orig")
    assert orig.read_text() == "user www-data;\n"
    settings.nginx_conf.write_text("# изменено\n")
    mgr.ensure_original_backup()
    assert orig.read_text() == "user www-data;\n"


def test_masked_and_diff(mgr):
    files = {"auth/site-1.htpasswd": "u:$apr1$secret", "nginx.conf": "a\nb\n"}
    masked = mgr.masked(files)
    assert "secret" not in json.dumps(masked) and masked["nginx.conf"] == "a\nb\n"
    d = mgr.diff({"nginx.conf": "a\nb\n", "old.conf": "x"}, {"nginx.conf": "a\nc\n", "new.conf": "y"})
    kinds = {x["file"]: x["status"] for x in d}
    assert kinds == {"nginx.conf": "modified", "old.conf": "removed", "new.conf": "added"}


# =============================================================================
#  Управление процессом без systemd
# =============================================================================
def test_process_control_without_systemd(tmp_path, monkeypatch):
    m = M.NginxManager(Database(str(tmp_path / "p.db")))
    cmds = []
    monkeypatch.setattr(M, "has_systemd", lambda: False)
    monkeypatch.setattr(M.time, "sleep", lambda s: None)
    monkeypatch.setattr(M, "run", lambda cmd, timeout=0: cmds.append(cmd) or (0, "ok"))
    running = iter([True, True, False, True])
    monkeypatch.setattr(m, "is_running", lambda: next(running))
    assert m.reload_or_start() == (True, "ok") and cmds[-1][1:] == ["-s", "reload"]
    assert m.stop() == (True, "ok") and cmds[-1][1:] == ["-s", "quit"]
    ok, _ = m.restart()
    assert ok and cmds[-1] == [m.binary]
    assert m.reopen_logs() == (True, "ok") and cmds[-1][1:] == ["-s", "reopen"]
    m.dump_config()
    assert cmds[-1][1:] == ["-T"]
    # с systemd: reload через systemctl, когда юнит активен
    monkeypatch.setattr(M, "has_systemd", lambda: True)
    monkeypatch.setattr(m, "is_running", lambda: True)
    m.reload_or_start()
    assert cmds[-1] == ["systemctl", "reload", "nginx"]
    m.restart()
    assert cmds[-1] == ["systemctl", "restart", "nginx"]
    # nginx не запущен — reload превращается в запуск; запуск не удался
    monkeypatch.setattr(m, "is_running", lambda: False)
    monkeypatch.setattr(M, "run", lambda cmd, timeout=0: (1, "Job for nginx.service failed"))
    assert m.reload_or_start() == (False, "Job for nginx.service failed")


def test_master_process_pid_file_garbage(tmp_path, monkeypatch):
    m = M.NginxManager(Database(str(tmp_path / "p.db")))
    pid = tmp_path / "nginx.pid"
    caps = m.caps()
    monkeypatch.setattr(caps, "pid_path", str(pid))
    monkeypatch.setattr(m, "caps", lambda refresh=False: caps)
    for content in ("", "не число", "999999999", str(os.getpid())):  # пусто, мусор, нет процесса, не nginx
        pid.write_text(content)
        p = m.master_process()
        assert p is None or "nginx" in p.name()
    pid.unlink()
    assert m.master_process() is None or "nginx" in m.master_process().name()
