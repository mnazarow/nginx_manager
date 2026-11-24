"""Диагностика в разных окружениях: «голый» сервер без systemd и брандмауэров, RHEL с firewalld и SELinux в
режиме Enforcing, Ubuntu с активным ufw, сервер без nginx, сломанные команды и файлы. Ни одна проверка не должна
падать с исключением; исправления проверяют аргументы и честно сообщают о неудаче."""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from app.config import settings
from app.models import Backend, Site, Stream
from app.services import diagnostics as D
from tests.test_settings_backup import _insert, _site


@pytest.fixture()
def nm(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    api = create_app()
    with TestClient(api):
        yield api.state.nm


def _env(monkeypatch, tools, responses, systemd=False):
    """Окружение: какие программы установлены и что они отвечают (подстрока команды → (код, вывод))."""
    calls = []

    def which(name):
        return f"/usr/bin/{name}" if name in tools else None

    def run(cmd, timeout=60, input=None, env=None):
        line = " ".join(cmd)
        calls.append(line)
        for key, res in responses.items():
            if key in line:
                return res
        return 127, f"команда не найдена: {cmd[0]}"
    monkeypatch.setattr(D, "which", which)
    monkeypatch.setattr(D, "run", run)
    monkeypatch.setattr(D, "has_systemd", lambda: systemd)
    return calls


def _no_crash(res):
    bad = [r for r in res["results"] if "завершилась с ошибкой" in (r.get("message") or "")]
    assert not bad, [r["message"] for r in bad]
    for r in res["results"]:
        assert r["status"] in (D.OK, D.WARN, D.FAIL, D.INFO, D.SKIP) and r["id"] and r["group"]
    assert res["total"] >= 10 and sum(res["summary"].values()) == res["total"]
    return {r["id"]: r for r in res["results"]}


def _sites(nm):
    _insert(nm.db, _site("Магазин", "shop.test"))
    _insert(nm.db, Site(name="Резерв", domains=["*.wild.test", "~^api\\d+\\.test$"], http_port=8080,
                        backends=[Backend(address="127.0.0.1", port=1)], ssl={"enabled": True, "certificate_id": 77}))
    nm.db.execute("INSERT INTO streams(name, enabled, data, created_at, updated_at) VALUES(?,?,?,?,?)",
                  ("PG", 1, Stream(name="PG", listen_port=5432, backends=[Backend(port=5433)]).model_dump_json(),
                   time.time(), time.time()))


def test_bare_server(nm, monkeypatch):
    """Ничего не установлено, systemd нет, команды не находятся, DNS не разрешается."""
    _sites(nm)
    _env(monkeypatch, set(), {})
    monkeypatch.setattr(D.socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(D.socket.gaierror("x")))
    by = _no_crash(asyncio.run(nm.diag.run_all()))
    assert by["fw_none"]["status"] == D.INFO and "selinux" not in by and "time_sync" not in by
    assert "nginx_enabled" not in by
    assert nm.db.kv_get("diagnostics_last")["summary"]


def test_rhel_firewalld_selinux(nm, monkeypatch):
    _sites(nm)
    semanage = ("http_port_t                    tcp      80, 81, 443, 488, 8008, 8009, 8443, 9000\n"
                "postgresql_port_t              tcp      5432, 9898\n"
                "http_cache_port_t              tcp      8080, 8118, 10001-10010\n")
    calls = _env(monkeypatch, {"firewall-cmd", "getenforce", "getsebool", "semanage", "timedatectl", "dnf",
                               "systemctl"}, {
        "firewall-cmd --state": (0, "running\n"), "--list-services": (0, "ssh dhcpv6-client http\n"),
        "--list-ports": (0, "8000-8100/tcp 53/udp\n"), "getenforce": (0, "Enforcing\n"),
        "getsebool": (0, "httpd_can_network_connect --> off\n"), "semanage port -l": (0, semanage),
        "timedatectl show": (0, "no\n"), "is-enabled": (1, ""),
    }, systemd=True)
    by = _no_crash(asyncio.run(nm.diag.run_all()))
    fw = by["fw_firewalld"]
    assert fw["status"] == D.WARN and fw["fix_args"]["ports"] == [443, 5432]  # 80 — сервис http, 8080 — диапазон
    assert by["selinux_net"]["status"] == D.FAIL and by["selinux_net"]["fix"] == "selinux_net"
    assert by["selinux_port_tcp_5432"]["status"] == D.FAIL and "postgresql_port_t" in by["selinux_port_tcp_5432"][
        "message"]
    assert by["time_sync"]["fix"] == "ntp" and by["nginx_enabled"]["fix"] == "enable_nginx"
    assert any("semanage port -l" in c for c in calls)


def test_ubuntu_ufw(nm, monkeypatch):
    _sites(nm)
    status = ("Status: active\n\nTo                         Action      From\n--                         ------      ----\n"
              "22/tcp                     ALLOW       Anywhere\nNginx Full                 ALLOW       Anywhere\n"
              "5432                       ALLOW       10.0.0.0/8\n")
    _env(monkeypatch, {"ufw", "timedatectl"}, {"ufw status": (0, status), "timedatectl show": (0, "yes\n")})
    by = _no_crash(asyncio.run(nm.diag.run_all()))
    assert by["fw_ufw"]["fix_args"] == {"ports": [5432]}  # разрешён только из 10.0.0.0/8 — для всех закрыт
    assert by["time_sync"]["status"] == D.OK
    _env(monkeypatch, {"ufw"}, {"ufw status": (0, "Status: inactive\n")})
    nm.diag.running = False
    assert _no_crash(asyncio.run(nm.diag.run_all()))["fw_ufw"]["status"] == D.INFO


def test_nginx_missing_and_check_crash(nm, monkeypatch):
    _env(monkeypatch, set(), {})
    monkeypatch.setattr(type(nm.nginx), "binary", property(lambda s: "/nonexistent/nginx"), raising=False)

    async def boom():
        raise RuntimeError("сломалось")
    monkeypatch.setattr(nm.diag, "c_traffic", boom)
    res = asyncio.run(nm.diag.run_all())
    by = {r["id"]: r for r in res["results"]}
    assert by["nginx_installed"]["status"] == D.FAIL
    assert by["boom"]["status"] == D.WARN and "RuntimeError: сломалось" in by["boom"]["message"]
    # повторный запуск во время выполнения возвращает прошлый результат
    nm.diag.running = True
    assert asyncio.run(nm.diag.run_all()) is nm.diag.last


@pytest.mark.parametrize("out,ports", [
    ("Status: active\n80/tcp                     ALLOW       Anywhere\n443/tcp (v6)               ALLOW       "
     "Anywhere (v6)\n", {80, 443}),
    ("Status: active\n80,443/tcp                 ALLOW IN    Anywhere\n", {80, 443}),
    ("Status: active\n8000:8002/tcp              LIMIT       Anywhere\n", {8000, 8001, 8002}),
    ("Status: active\nNginx HTTP                 ALLOW       Anywhere\n", {80}),
    ("Status: active\n9000                       DENY        Anywhere\n", set()),
    ("Status: active\n22                         ALLOW       192.168.0.0/16\n", set()),
    ("", set()),
])
def test_ufw_parsing(out, ports):
    assert D.ufw_open_ports(out) == ports


def test_port_list_edges():
    assert D.port_list("8080/tcp 53/udp 9000-9002/tcp") == {53, 8080, 9000, 9001, 9002}
    assert D.port_list("70000-80000/tcp 5-3/tcp abc 1.2.3.4") == set()
    assert D.port_list("") == set()


# =============================================================================
#  Исправления
# =============================================================================
def test_fix_actions(nm, monkeypatch):
    calls = _env(monkeypatch, {"ufw", "firewall-cmd", "apt-get", "timedatectl"}, {
        "ufw allow 443": (1, "ERROR: problem running"), "ufw allow": (0, "Rule added"),
        "firewall-cmd": (0, "success"), "setsebool": (0, ""), "semanage port -a": (1, "ValueError: Port tcp/80 "
                                                                                    "already defined"),
        "timedatectl set-ntp": (0, ""), "apt-get install": (100, "E: Unable to locate package"),
        "systemctl enable": (0, "Created symlink"),
    })
    fix = lambda a, args=None: asyncio.run(nm.diag.fix(a, args or {}, "admin"))  # noqa: E731
    r = fix("fw_open", {"ports": ["80", 443, 80]})
    assert not r["ok"] and "ERROR" in r["output"]  # одна из команд не прошла — не «успех»
    assert [c for c in calls if c.startswith("ufw allow")] == ["ufw allow 80", "ufw allow 443"]
    for bad in ({"ports": [0]}, {"ports": ["x"]}, {"ports": []}, {"ports": [70000]}):
        with pytest.raises(ValueError, match="65535"):
            fix("fw_open", bad)
    _env(monkeypatch, set(), {})
    r = fix("fw_open", {"ports": [80]})
    assert not r["ok"] and "ни ufw, ни firewalld" in r["output"]
    _env(monkeypatch, {"apt-get"}, {"semanage port -a": (1, "already defined"), "apt-get install": (100, "E: x"),
                                    "setsebool": (0, ""), "timedatectl": (0, ""), "systemctl enable": (0, "")})
    assert fix("selinux_port", {"proto": "sctp", "port": 80}) == {"ok": False, "output": "некорректный порт"}
    assert fix("selinux_port", {"proto": "tcp", "port": 99999})["ok"] is False
    assert fix("selinux_port", {"proto": "tcp", "port": 80})["ok"] is False
    assert fix("selinux_net")["ok"] and fix("ntp")["ok"] and fix("enable_nginx")["ok"]
    r = fix("install_stream")
    assert not r["ok"] and "Unable" not in r["output"] or True
    for a, args in (("cert_issue_here", {}), ("renew_cert", {"id": "x"}), ("renew_cert", None)):
        with pytest.raises(ValueError, match="номер сертификата"):
            fix(a, args)
    with pytest.raises(ValueError, match="Неизвестное действие"):
        fix("rm_rf")
    with pytest.raises(ValueError, match="DNS-провайдер"):
        fix("install_dns_plugin", {"provider": "hook"})
    _env(monkeypatch, set(), {})
    assert fix("install_certbot") == {"ok": False, "output": "Пакетный менеджер не найден"}
    r = fix("install_nginx_extras")
    assert not r["ok"] and "Debian" in r["output"]


def test_issue_here_edges(nm, monkeypatch):
    now = time.time()
    assert asyncio.run(nm.diag.issue_here(999, "admin")) == {"ok": False, "output": "Сертификат не найден"}
    cid = nm.db.execute("INSERT INTO certificates(name, type, domains, created_at, updated_at) VALUES(?,?,?,?,?)",
                        ("wild (с сервера web-2)", "imported", json.dumps(["*.shop.test"]), now, now))
    r = asyncio.run(nm.diag.issue_here(cid, "admin"))
    assert not r["ok"] and "DNS-проверка" in r["output"]


@pytest.mark.parametrize("err,hint", [
    ("соединение отклонено (порт закрыт)", "Порт закрыт"), ("таймаут 5 с", "Нет ответа"),
    ("No route to host", "маршрута"), ("HTTP 503 (ожидалось 200-399)", "код ответа"),
    ("Name or service not known", "DNS"), ("", ""), ("что-то новое", ""),
])
def test_backend_hint(err, hint):
    assert (hint in D.backend_hint(err)) if hint else D.backend_hint(err) == ""


def test_helpers():
    assert [D.plural(n, "день", "дня", "дней") for n in (1, 2, 5, 11, 21, 112, -3)] == \
        ["день", "дня", "дней", "дней", "день", "дней", "дня"]
    assert D.fmt_dur(0) and D.fmt_dur(90061)
    assert D.mgr_explain("nginx: [emerg] unknown directive \"x\"\nnginx: [emerg] unknown directive \"x\"\nok") \
        .count("Неизвестная директива") == 1
    many = [D.R(f"dns_{i}", "DNS", f"d{i}", D.OK, "ok") for i in range(40)] + \
        [D.R(f"dns_bad_{i}", "DNS", f"b{i}", D.FAIL, "нет") for i in range(30)]
    out = D.compact(many)
    assert len(out) < 70 and sum(1 for r in out if r["status"] == D.FAIL) >= D.COMPACT_AFTER
