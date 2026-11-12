"""Консольная утилита nmctl и полный прогон диагностики (каждая проверка должна отработать без исключений)."""
import asyncio
import json
import os

import pytest

from app import cli

TMP = os.environ["NM_TEST_TMP"]


def run(capsys, *args):
    code = cli.main(list(args))
    out = capsys.readouterr().out
    return code, out


def test_users_lifecycle(capsys):
    code, out = run(capsys, "user", "add", "cli-op", "--role", "operator", "--password", "Cli-Passw0rd!")
    assert code == 0, out
    code, out = run(capsys, "user", "list")
    assert code == 0 and "cli-op" in out and "operator" in out
    assert run(capsys, "user", "role", "cli-op", "--role", "viewer")[0] == 0
    assert run(capsys, "user", "passwd", "cli-op", "--password", "Another-Passw0rd!")[0] == 0
    assert run(capsys, "user", "disable", "cli-op")[0] == 0
    assert run(capsys, "user", "enable", "cli-op")[0] == 0
    assert run(capsys, "user", "reset-2fa", "cli-op")[0] == 0
    code, out = run(capsys, "user", "passwd", "cli-op", "--password", "123")
    assert code != 0  # слабый пароль отклоняется
    assert run(capsys, "user", "delete", "cli-op")[0] == 0
    code, out = run(capsys, "user", "list")
    assert "cli-op" not in out
    assert run(capsys, "user", "delete", "nobody-here")[0] != 0


def test_allowlist_export_import_backup(capsys, tmp_path):
    assert run(capsys, "allowlist", "show")[0] == 0
    assert run(capsys, "allowlist", "clear")[0] == 0
    code, out = run(capsys, "export")
    assert code == 0
    data = json.loads(out)
    assert data["format"] == "nginx-manager-export"
    f = tmp_path / "export.json"
    f.write_text(out)
    code, out = run(capsys, "import", str(f), "--mode", "merge")
    assert code == 0, out
    bad = tmp_path / "bad.json"
    bad.write_text('{"format": "other"}')
    assert run(capsys, "import", str(bad))[0] != 0
    for junk in ('[1, 2]', '{"format": "nginx-manager-export", "sites": [{"id": 1}]}',
                 '{"format": "nginx-manager-export", "sites": [5]}', 'не json',
                 '{"format": "nginx-manager-export", "alert_rules": [7]}',
                 '{"format": "nginx-manager-export", "certificates": [{"name": "x"}]}',
                 '{"format": "nginx-manager-export", "users": [{"username": "u", "role": "root"}]}'):
        bad.write_text(junk)
        assert run(capsys, "import", str(bad))[0] == 1, junk   # понятная ошибка, не трассировка
    assert run(capsys, "import", str(tmp_path / "missing.json"))[0] == 1
    code, out = run(capsys, "backup")
    assert code == 0 and ".db" in out


def test_status_sites_versions(capsys):
    for args in (["status"], ["sites"], ["versions", "--limit", "5"], []):
        code, out = run(capsys, *args)
        assert code == 0, (args, out)


def test_diagnostics_every_check_runs_without_exceptions():
    """Все ~40 проверок диагностики выполняются на этой системе без внутренних ошибок."""
    from app.core import App

    async def go():
        app = App()
        res = await app.diag.run_all()
        app.db.close()
        return res
    res = asyncio.run(go())
    crashed = [r for r in res["results"] if "завершилась с ошибкой" in r["message"]]
    assert not crashed, crashed
    assert res["summary"] and sum(res["summary"].values()) >= 20


@pytest.mark.skipif(os.geteuid() != 0, reason="нужен root")
def test_diag_command_prints_summary(capsys):
    code, out = run(capsys, "diag", "-p")
    assert "Итого:" in out and code in (0, 1)


def test_background_task_failure_is_isolated():
    """Сбой одной фоновой задачи пишется в «События» и не прерывает остальные."""
    from app.core import App

    async def boom():
        raise RuntimeError("сломалось")

    async def go():
        app = App()
        await app._guard("проверочная задача", boom())
        ev = app.db.one("SELECT * FROM events WHERE source='panel' ORDER BY id DESC LIMIT 1")
        app.db.close()
        return ev
    ev = asyncio.run(go())
    assert ev["level"] == "error" and "проверочная задача" in ev["message"] and "сломалось" in ev["message"]
