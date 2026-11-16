"""Доступ к сайту только с разрешённых адресов (раздел сайта «Доступ по IP») и доверенные адреса (никогда не
блокируются): модели и перенос старых настроек, конфигурация и поведение в настоящем nginx, блокировки, API,
пакеты для функций панели."""
from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from app.models import (Backend, BasicAuthUser, GlobalSettings, IpAccessSettings, IpEntry, PanelSettings,
                        ProtectionSettings, SecuritySettings, Site, SiteProtection)
from app.nginx.generator import Generator, Paths, State
from app.utils import apr1
from tests.test_protection import Backend200, free_port, req

TMP = Path(os.environ["NM_TEST_TMP"]) / "access"


# =============================================================================
#  Модели
# =============================================================================
def test_models_and_migration():
    s = Site.model_validate({"name": "x", "domains": ["a.test"], "backends": [{"address": "127.0.0.1", "port": 80}],
                             "security": {"access_mode": "allowlist", "allow": ["203.0.113.0/24", "10.1.1.1"]}})
    assert s.ip_access.enabled and [e.address for e in s.ip_access.entries] == ["203.0.113.0/24", "10.1.1.1"]
    assert s.ip_access.allow_trusted is False and s.security.access_mode == "all" and s.security.allow == []
    # прежний «IP из белого списка входят без пароля» → «Остальным — пароль»
    s2 = Site.model_validate({"name": "x", "domains": ["a.test"], "backends": [{"address": "127.0.0.1", "port": 80}],
                              "security": {"access_mode": "allowlist", "allow": ["203.0.113.5"], "basic_auth": True,
                                           "satisfy_any": True,
                                           "basic_auth_users": [{"username": "u", "password_hash": apr1("x")}]}})
    assert s2.ip_access.deny == "password" and not s2.security.satisfy_any
    assert IpEntry(address="203.0.113.5/32").address == "203.0.113.5"
    assert IpEntry(address="2001:db8::1/128").address == "2001:db8::1"
    for bad in ("all", "", "300.1.1.1", "example.com"):
        with pytest.raises(Exception):
            IpEntry(address=bad)
    with pytest.raises(Exception):
        IpAccessSettings(enabled=True, public_paths=["api/x"])
    with pytest.raises(Exception):
        IpAccessSettings(enabled=True, public_paths=['/a"b'])
    a = IpAccessSettings(enabled=True, entries=[IpEntry(address="10.0.0.1"), IpEntry(address="10.0.0.1/32")])
    assert len(a.entries) == 1
    with pytest.raises(Exception, match="Защита паролем"):
        Site(name="x", domains=["a.test"], backends=[Backend(address="127.0.0.1", port=80)],
             ip_access=IpAccessSettings(enabled=True, deny="password"))


# =============================================================================
#  Настоящий nginx
# =============================================================================
@pytest.fixture(scope="module")
def live():
    if not shutil.which("nginx") or os.geteuid() != 0:
        pytest.skip("нужен nginx и root")
    from app.db import Database
    from app.nginx.manager import NginxManager
    TMP.mkdir(parents=True, exist_ok=True)
    os.chmod(TMP.parent, 0o755)
    os.chmod(TMP, 0o755)
    for d in ("logs", "cache/default", "live", "pages", "stage"):
        (TMP / d).mkdir(parents=True, exist_ok=True)
    caps = NginxManager(Database(TMP / "t.db")).caps()
    caps.pid_path = str(TMP / "nginx.pid")
    bport, http, stub, panel = free_port(), free_port(), free_port(), free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", bport), Backend200)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    be = [Backend(address="127.0.0.1", port=bport)]
    users = [BasicAuthUser(username="boss", password_hash=apr1("Secret123"))]
    sites = [
        (1, Site(name="Админка", domains=["adm.test"], http_port=http, backends=be,
                 ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="127.0.0.6", comment="офис"),
                                                                   IpEntry(address="127.0.0.64/30")],
                                            public_paths=["/hook/"]))),
        (2, Site(name="Скрытый", domains=["hid.test"], http_port=http, backends=be,
                 ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="127.0.0.6")], deny="444",
                                            allow_trusted=False))),
        (3, Site(name="С паролем", domains=["pw.test"], http_port=http, backends=be,
                 security=SecuritySettings(basic_auth=True, basic_auth_users=users),
                 ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="127.0.0.6")], deny="password"))),
        (4, Site(name="Открытый", domains=["open.test"], http_port=http, backends=be,
                 security=SecuritySettings(rate_limit=True, rate="1r/m", burst=0),
                 protection=SiteProtection(challenge="off"))),
    ]
    panel_s = PanelSettings(trusted_ips=[IpEntry(address="127.0.0.9", comment="мониторинг"),
                                         IpEntry(address="127.0.0.18", comment="в заблокированной подсети")])
    state = State(sites, [], GlobalSettings(access_log_buffer=""), panel_s, {}, protection=ProtectionSettings())
    (TMP / "bans.conf").write_text("127.0.0.16/28 1;\n127.0.0.9 0;\n127.0.0.18 0;\n")  # как BanService.render_file
    attack = TMP / "attack.conf"
    attack.write_text('default "";\n')
    p = Paths(str(TMP / "stage"), str(TMP / "stage"), "/var/acme", str(TMP / "logs"), str(TMP / "cache"), stub, panel,
              str(TMP), bans_file=str(TMP / "bans.conf"), attack_file=str(attack), challenge_secret="s",
              challenge_key="k")
    files = Generator(state, caps, p).render()
    alt = {"80": str(free_port()), "443": str(free_port())}
    for rel, content in files.items():
        content = re.sub(r"(listen\s+(?:\[::\]:)?)(80|443)\b", lambda m: m.group(1) + alt[m.group(2)], content)
        (TMP / "stage" / rel).parent.mkdir(parents=True, exist_ok=True)
        (TMP / "stage" / rel).write_text(content)
    conf = str(TMP / "stage" / "nginx.conf")
    t = subprocess.run(["nginx", "-t", "-c", conf], capture_output=True, text=True)
    assert t.returncode == 0, t.stderr
    r = subprocess.run(["nginx", "-c", conf], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    time.sleep(0.3)
    yield {"port": http, "files": files}
    subprocess.run(["nginx", "-s", "stop", "-c", conf], capture_output=True)
    srv.shutdown()


def test_live_ip_access(live):
    port = live["port"]
    site1 = next(v for k, v in live["files"].items() if "site-1-" in k)
    assert "geo $nm_ipacl_1" in site1 and "127.0.0.9 1;" in site1  # доверенные — в разрешённых
    st = lambda path, src, host="adm.test", **kw: req(port, path, host=host, source=src, **kw)[0]  # noqa: E731
    assert st("/", "127.0.0.6") == 200            # из списка
    assert st("/", "127.0.0.65") == 200           # из подсети /30
    assert st("/", "127.0.0.1") == 200            # сам сервер
    assert st("/", "127.0.0.9") == 200            # доверенный адрес
    assert st("/", "127.0.0.70") == 403           # остальные
    assert st("/hook/pay", "127.0.0.70") == 200   # открытый путь
    assert st("/hookx", "127.0.0.70") == 403
    assert st("/.well-known/acme-challenge/t", "127.0.0.70") != 403  # проверка Let's Encrypt открыта
    # 444 — соединение закрывается без ответа; доверенные адреса сюда не пускаются (allow_trusted выключено)
    assert st("/", "127.0.0.70", "hid.test") is None and st("/", "127.0.0.9", "hid.test") is None
    assert st("/", "127.0.0.6", "hid.test") == 200
    # пароль для остальных, без пароля — разрешённым
    auth = {"Authorization": "Basic " + base64.b64encode(b"boss:Secret123").decode()}
    assert st("/", "127.0.0.6", "pw.test") == 200
    assert st("/", "127.0.0.70", "pw.test") == 401
    assert st("/", "127.0.0.70", "pw.test", headers=auth) == 200


def test_live_trusted_never_blocked(live):
    port = live["port"]
    # заблокированная подсеть 127.0.0.16/28: доверенный адрес внутри неё открыт
    assert req(port, "/", host="open.test", source="127.0.0.20")[0] in (None, 403, 444)
    assert req(port, "/", host="open.test", source="127.0.0.18")[0] == 200
    # фильтр запросов: доверенному — без проверки
    assert req(port, "/?f=../../etc/passwd", host="open.test", source="127.0.0.70")[0] == 403
    assert req(port, "/?f=../../etc/passwd", host="open.test", source="127.0.0.9")[0] == 200
    # ограничение частоты 1 в минуту: второй запрос — 429/503, у доверенного — без ограничения
    codes = [req(port, "/x", host="open.test", source="127.0.0.71")[0] for _ in range(3)]
    assert codes[0] == 200 and codes[-1] in (429, 503)
    assert all(req(port, "/x", host="open.test", source="127.0.0.9")[0] == 200 for _ in range(4))


# =============================================================================
#  Блокировки, API, перенос прежних списков
# =============================================================================
@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    a = create_app()
    with TestClient(a) as c:
        nm = a.state.nm
        uid = nm.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        c.headers.update({"Authorization": f"Bearer {nm.auth.create_token(uid, 't', role='admin')}"})
        yield c, nm


def test_trusted_api_and_bans(api):
    c, nm = api
    nm.bans.add("198.51.100.7", 60, "x")
    nm.bans.add("203.0.113.0/24", 60, "сеть")
    r = c.put("/api/trusted", json={"entries": [{"address": "198.51.100.7", "comment": "офис"},
                                                 {"address": "198.51.100.7/32"}, "192.0.2.0/28"]})
    assert r.status_code == 200 and r.json()["count"] == 2 and r.json()["unbanned"] == 1
    assert [e.address for e in nm.panel().trusted_ips] == ["198.51.100.7", "192.0.2.0/28"]
    assert c.put("/api/trusted", json={"entries": [{"address": "0.0.0.0/0"}]}).status_code == 400
    bad = c.put("/api/trusted", json={"entries": [{"address": "1.2.3"}]})
    assert bad.status_code == 422 and bad.json()["errors"][0]["loc"].startswith("trusted_ips.0")
    # доверенные не блокируются: ни вручную (API, сервис), ни подсетью, включающей доверенную
    r = c.post("/api/bans", json={"nets": ["198.51.100.7"], "minutes": 60, "reason": "", "force": True})
    assert r.status_code == 400 and "Доверенные адреса" in r.json()["detail"]
    with pytest.raises(ValueError):
        nm.bans.add("192.0.2.5", 60)
    with pytest.raises(ValueError):
        nm.bans.add("198.51.100.0/24", 60)  # подсеть с доверенным адресом
    nm.bans.add("203.0.113.9", 60)
    text = nm.bans.render_file()
    assert "203.0.113.0/24 1;" in text and "198.51.100.7 0;" in text and "192.0.2.0/28 0;" in text
    # проверка адреса
    d = c.get("/api/trusted/check", params={"ip": "192.0.2.3"}).json()
    assert d["trusted"]["address"] == "192.0.2.0/28" and d["banned"] is None
    d = c.get("/api/trusted/check", params={"ip": "203.0.113.9"}).json()
    assert d["trusted"] is None and d["banned"]["net"] in ("203.0.113.0/24", "203.0.113.9")
    assert c.get("/api/trusted/check", params={"ip": "x"}).status_code == 400
    g = c.get("/api/trusted").json()
    assert g["always"][:2] == ["127.0.0.1", "::1"] and len(g["entries"]) == 2
    # Telegram /ban доверенного — отказ
    from app.models import AlertChannel
    ch = AlertChannel(name="T", type="telegram", telegram_token="1:x", telegram_chat_id="-5", telegram_actions=True)
    msg = {"message_id": 1, "text": "/ban 192.0.2.4", "chat": {"id": -5}, "from": {"id": 1}}
    assert "доверенных" in nm.tgbot.command(ch, msg)[0]


def test_migrate_old_exception_lists(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    a = App()
    a.db.kv_set("trusted_migrated", False)
    a.save_panel(a.panel().model_copy(update={"autoban_whitelist": ["203.0.113.0/24"]}))
    a.protection.save(a.protection.settings().model_copy(update={"bypass_ips": ["198.51.100.1", "203.0.113.0/24"]}))
    a.migrate_trusted()
    tr = a.panel().trusted_ips
    assert [e.address for e in tr] == ["203.0.113.0/24", "198.51.100.1"]
    assert "Никогда не блокировать" in tr[0].comment and "Доверенные IP" in tr[1].comment
    assert a.panel().autoban_whitelist == [] and a.protection.settings().bypass_ips == []
    a.migrate_trusted()  # повторно — без изменений
    assert len(a.panel().trusted_ips) == 2


def test_deps_report(tmp_path, monkeypatch):
    from app.services import deps

    class Caps:
        modules = {"http_ssl"}
        stream_available = False
        modsecurity = False

    class Mgr:
        def caps(self, refresh=False):
            return Caps()

        def load_state(self):
            raise RuntimeError("нет базы")

        def crs(self):
            return "", ""

    class DB:
        def kv_get(self, k, d=None):
            return {"modsec_enabled": True}
    monkeypatch.setattr(deps, "_dpkg_installed", lambda n: n == "nginx-core")
    monkeypatch.setattr(deps, "which", lambda n: None if n == "certbot" else "/usr/bin/" + n)
    items = {x["id"]: x for x in deps.report(DB(), Mgr())}
    assert not items["certbot"]["ok"] and not items["stream"]["ok"] and not items["secure_link"]["ok"]
    assert items["modsecurity"]["needed"] and not items["modsecurity"]["ok"]
    assert deps.missing_packages(list(items.values()), "apt") == [
        "certbot", "libnginx-mod-stream", "nginx-extras", "libnginx-mod-http-modsecurity", "modsecurity-crs"]
    assert deps.missing_packages(list(items.values()), "dnf") == ["certbot", "nginx-mod-stream"]
    monkeypatch.setattr(deps, "_dpkg_installed", lambda n: False)  # nginx с nginx.org — nginx-extras не нужен
    items = deps.report(DB(), Mgr())
    assert "nginx-extras" not in deps.missing_packages(items, "apt")
