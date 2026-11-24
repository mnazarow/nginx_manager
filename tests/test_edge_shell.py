"""Скрипты установки и файл настроек панели в нетиповых ситуациях: panel.conf с кавычками, комментариями,
export и CRLF; неизвестная ОС; подтверждение без терминала; повтор команд; выбор Python; вывод ошибки команды."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
needs_bash = pytest.mark.skipif(not shutil.which("bash"), reason="нужен bash")


def sh(script: str, tmp: Path, env=None, stdin=None):
    full = f'set -u\nLOG_FILE="{tmp}/setup.log"\nsource "{ROOT}/packaging/common.sh"\nLOG_FILE="{tmp}/setup.log"\n' \
           f'CONF_DIR="{tmp}"\n{script}\n'
    r = subprocess.run(["bash", "-c", full], capture_output=True, text=True, timeout=60, env=env, input=stdin)
    return r.returncode, r.stdout, r.stderr


@needs_bash
@pytest.mark.parametrize("conf,port", [
    ("BIND_PORT=9000\n", "9000"), ("NM_BIND_PORT=9001\n", "9001"), ('BIND_PORT="9002"\n', "9002"),
    ("BIND_PORT=9003   # свой порт\n", "9003"), ("BIND_PORT=9004\r\n", "9004"), ("export NM_BIND_PORT=9005\n", "9005"),
    ("BIND_PORT=abc\n", "8088"), ("BIND_PORT=70000\n", "8088"), ("", "8088"), ("BIND_PORT=1\nBIND_PORT=9006\n", "9006"),
    ("# BIND_PORT=9999\n", "8088"),
])
def test_panel_port(tmp_path, conf, port):
    (tmp_path / "panel.conf").write_bytes(conf.encode())
    assert sh("panel_port", tmp_path)[1].strip() == port


@needs_bash
def test_panel_port_without_file(tmp_path):
    assert sh("panel_port", tmp_path)[1].strip() == "8088"


@needs_bash
@pytest.mark.parametrize("release,pkg", [
    ('ID=ubuntu\nVERSION_ID="24.04"\nID_LIKE=debian\n', "apt"), ('ID=debian\nVERSION_ID="12"\n', "apt"),
    ('ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n', "dnf|yum"),
    ('ID=almalinux\nID_LIKE="rhel centos fedora"\nVERSION_ID="8.10"\n', "dnf|yum"),
    ('ID=opensuse-leap\nID_LIKE="suse opensuse"\n', "zypper"), ('ID=arch\n', "unknown"), ("", "unknown"),
])
def test_detect_os(tmp_path, release, pkg):
    (tmp_path / "os-release").write_text(release)
    code, out, _ = sh(f'OS_RELEASE_FILE="{tmp_path}/os-release" detect_os; echo "$PKG|$OS_MAJOR|$OS_ID"', tmp_path)
    got = out.strip().split("|")
    assert code == 0 and got[0] in pkg.split("|")
    if "VERSION_ID" in release:
        assert got[1].isdigit()


@needs_bash
def test_detect_os_missing(tmp_path):
    code, _, err = sh(f'OS_RELEASE_FILE="{tmp_path}/нет" detect_os; echo дошли', tmp_path)
    assert code == 1 and "Не удалось определить ОС" in err


@needs_bash
def test_confirm_retry_run(tmp_path):
    # без терминала и без ASSUME_YES — «нет»; с ASSUME_YES=1 — «да»
    assert sh('confirm "Удалить?" && echo да || echo нет', tmp_path, stdin="y\n")[1].strip() == "нет"
    assert sh('ASSUME_YES=1; confirm "Удалить?" && echo да', tmp_path)[1].strip() == "да"
    # повтор: команда удаётся со второй попытки (sleep заменён)
    code, out, err = sh('sleep() { :; }; cnt=0; f() { cnt=$((cnt+1)); [ $cnt -ge 2 ]; }; retry 3 f && echo "ok $cnt"',
                        tmp_path)
    assert out.strip() == "ok 2" and "попытка 1 не удалась" in err
    code, out, err = sh("sleep() { :; }; retry 2 false || echo сдались", tmp_path)
    assert out.strip() == "сдались"
    # ошибка команды: код возврата и хвост вывода на экране, полный вывод — в журнале
    code, out, err = sh('run bash -c "for i in \\$(seq 1 30); do echo строка \\$i; done; exit 3"; echo "rc=$?"',
                        tmp_path)
    assert "rc=3" in out and "кодом 3" in err and "строка 30" in err and "строка 1\n" not in err
    assert "строка 1" in (tmp_path / "setup.log").read_text()


@needs_bash
def test_find_python_and_pkg_unknown(tmp_path):
    code, out, _ = sh("find_python", tmp_path)
    assert code == 0 and "python3" in out
    # PATH без подходящего Python — ошибка, а не пустая строка с кодом 0
    code, out, _ = sh('PATH=/nonexistent; find_python; echo "rc=$?"', tmp_path)
    assert "rc=1" in out
    code, out, _ = sh('PKG=unknown; pkg_install curl; echo "rc=$?"; pkg_installed curl; echo "rc2=$?"', tmp_path)
    assert "rc=1" in out and "rc2=1" in out


def test_python_conf_parsing(tmp_path, monkeypatch):
    from app import config as CFG
    f = tmp_path / "panel.conf"
    f.write_text('# комментарий\nexport NM_BIND_PORT=9100   # свой порт\nBIND_HOST="0.0.0.0" # все адреса\n'
                 "TRUST_PROXY='10.0.0.1,10.0.0.2'\nLOG_LEVEL = debug\nпустая строка без равно\nNM_DEV_MODE=1\r\n"
                 'TLS_CERT="/etc/x # не комментарий.pem"\n')
    vals = CFG._read_conf_file(f)
    assert vals["BIND_PORT"] == "9100" and vals["BIND_HOST"] == "0.0.0.0"
    assert vals["TRUST_PROXY"] == "10.0.0.1,10.0.0.2" and vals["LOG_LEVEL"] == "debug" and vals["DEV_MODE"] == "1"
    assert vals["TLS_CERT"] == "/etc/x # не комментарий.pem"
    assert CFG._read_conf_file(tmp_path / "нет") == {}
    with pytest.raises(ValueError, match="BIND_PORT='abc' — ожидается целое число"):
        CFG._int({"BIND_PORT": "abc"}, "BIND_PORT")
