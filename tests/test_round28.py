"""Версия 2.8: уведомление об использовании ссылки для доступа (кнопка «Закрыть доступ» в Telegram), списки
адресов по ссылке, сравнение конфигурации с другим сервером, выпуск сертификата здесь вместо перенесённого."""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from app.db import Database
from app.models import IpAccessSettings, IpEntry, IpListSource
from app.services import access_links as AL
from app.services import compare as CMP
from app.services import iplists
from app.services import tgbot
from tests.test_links_sync import _insert, _site


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    api = create_app()
    with TestClient(api) as c:
        nm = api.state.nm
        uid = nm.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        c.nm = nm
        c.h = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'adm', role='admin')}"}
        c.op = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'op', role='operator')}"}
        c.vw = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'vw', role='viewer')}"}
        yield c


# =============================================================================
#  Списки адресов по ссылке
# =============================================================================
def test_iplists_parse_and_merge():
    text = """# офисы
203.0.113.10   офис
198.51.100.0/24 # VPN
198.51.100.7/24
{"prefixes": [{"ipv4Prefix": "192.0.2.0/25"}, {"ipv6Prefix": "2001:DB8::/48"}]}
0.0.0.0/0
1.2.3.4.5 версия 10.1.2 не адрес; 999.1.1.1
2001:db8::1
"""
    nets = iplists.parse(text)
    assert nets == ["203.0.113.10", "198.51.100.0/24", "192.0.2.0/25", "2001:db8::/48", "2001:db8::1"]
    m = iplists.merge({"198.51.100.0/24": {3}, "198.51.100.7": {5}, "10.0.0.0/8": {4}, "10.1.0.0/16": {6},
                       "2001:db8::/32": {7}, "2001:db8::1": {8}})
    assert m["198.51.100.7"] == {3, 5} and m["198.51.100.0/24"] == {3}
    assert m["10.1.0.0/16"] == {4, 6} and m["2001:db8::1"] == {7, 8}
    with pytest.raises(Exception):
        IpListSource(url="file:///etc/passwd")


def test_iplists_refresh_and_render(tmp_path):
    from app.nginx.generator import State
    from app.models import GlobalSettings, PanelSettings
    db = Database(str(tmp_path / "l.db"))
    url, url2 = "https://lists.test/office.txt", "https://lists.test/ci.json"
    s1 = _site(ip_access=IpAccessSettings(enabled=True, lists=[IpListSource(url=url, hours=6)]))
    s2 = _site(name="Второй", domains=["two.test"],
               ip_access=IpAccessSettings(enabled=True, lists=[IpListSource(url=url, hours=24),
                                                                IpListSource(url=url2)]))
    off = _site(name="Выкл", domains=["off.test"], ip_access=IpAccessSettings(enabled=False,
                                                                               lists=[IpListSource(url=url2)]))
    st = State(sites=[(1, s1), (2, s2), (3, off)], streams=[], glob=GlobalSettings(), panel=PanelSettings(), certs={})
    src = iplists.sources(st)
    assert src[url]["hours"] == 6 and src[url]["sites"] == [1, 2] and src[url2]["sites"] == [2]
    calls = []
    data = {url: ["198.51.100.0/24"], url2: ["203.0.113.0/28", "2001:db8::/48"]}

    def fake(u):
        calls.append(u)
        if isinstance(data[u], Exception):
            raise data[u]
        return data[u]
    changed, done = iplists.refresh(db, st, fetcher=fake)
    assert changed and set(done) == {url, url2} and len(calls) == 2
    changed, done = iplists.refresh(db, st, fetcher=fake)  # срок не подошёл
    assert not changed and not done and len(calls) == 2
    data[url] = ValueError("HTTP 500")
    changed, done = iplists.refresh(db, st, force_urls=[url], fetcher=fake)
    assert not changed and done[url]["ok"] is False and done[url]["nets"] == ["198.51.100.0/24"]
    nets = iplists.site_nets(db, st)
    assert nets == {"198.51.100.0/24": {1, 2}, "203.0.113.0/28": {2}, "2001:db8::/48": {2}}
    lid, token = AL.create(db, 1, 8, 24, 1, "", "t")
    AL.grant(db, AL.find(db, token), "203.0.113.5", "")
    text = AL.render(db, nets)
    assert '198.51.100.0/24 ",1,2,";' in text and '203.0.113.0/28 ",2,";' in text
    assert '203.0.113.5 ",1,2,";' in text  # адрес по ссылке входит в подсеть списка второго сайта
    stat = iplists.status(db, st, 2)
    assert [x["count"] for x in stat] == [1, 2] and stat[0]["error"] == "HTTP 500" and stat[1]["ok"]
    # список больше не используется — забывается
    st2 = State(sites=[(1, _site())], streams=[], glob=GlobalSettings(), panel=PanelSettings(), certs={})
    changed, _ = iplists.refresh(db, st2, fetcher=fake)
    assert changed and db.kv_get(iplists.KV) == {} and iplists.site_nets(db, st2) == {}


def test_iplists_generator():
    from tests.test_cluster import _gen
    s = _site(ip_access=IpAccessSettings(enabled=True, lists=[IpListSource(url="https://l.test/a.txt")]))
    _, files = _gen([(4, s)], grants_file="/etc/nm/ip-grants.conf")
    conf = "\n".join(files.values())
    assert "include /etc/nm/ip-grants.conf;" in conf and "map $nm_ipgrant $nm_ipg_4" in conf


def test_iplists_api(client, monkeypatch):
    nm = client.nm
    url = "https://lists.test/office.txt"
    sid = _insert(nm.db, _site(ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="198.51.100.1")],
                                                          lists=[IpListSource(url=url, comment="офис")])))
    monkeypatch.setattr(iplists, "fetch", lambda u, timeout=20, sha256="": ["203.0.113.0/24", "2001:db8::/48"])
    assert client.post("/api/ip-lists/check", headers=client.op, json={"url": "ftp://x"}).status_code == 400
    r = client.post("/api/ip-lists/check", headers=client.op, json={"url": url}).json()
    assert r == {"ok": True, "count": 2, "sample": ["203.0.113.0/24", "2001:db8::/48"], "v6": 1, "dropped": 0}
    assert client.post("/api/ip-lists/check", headers=client.vw, json={"url": url}).status_code == 403
    # до применения списков нет
    assert client.get(f"/api/sites/{sid}/ip-lists", headers=client.vw).json()["lists"] == []
    assert client.post(f"/api/sites/{sid}/ip-lists/refresh", headers=client.op).status_code == 400
    written = []

    async def fake_sync(force=False):
        written.append(AL.render(nm.db, nm.grants.lists()))
        return True, ""
    monkeypatch.setattr(nm.grants, "sync", fake_sync)
    from app.nginx.generator import State
    st = nm.nginx.load_state()
    monkeypatch.setattr(nm, "last_applied_state", lambda: State.from_json(st.to_json()))
    r = client.post(f"/api/sites/{sid}/ip-lists/refresh", headers=client.op).json()
    assert r["ok"] and r["lists"][0]["count"] == 2 and r["lists"][0]["comment"] == "офис" and not r["errors"]
    assert f'203.0.113.0/24 ",{sid},";' in written[-1]
    d = client.get(f"/api/sites/{sid}/ip-lists", headers=client.vw).json()["lists"]
    assert d[0]["sample"] == ["203.0.113.0/24", "2001:db8::/48"] and d[0]["at"]


# =============================================================================
#  Уведомление об использовании ссылки, кнопка «Закрыть доступ»
# =============================================================================
def test_tg_grant_button(tmp_path):
    key = b"k" * 24
    assert tgbot.parse_callback(key, tgbot.callback_data(key, "g", "17")) == ("g", "17")
    assert tgbot.parse_callback(key, tgbot.callback_data(key, "g", "1.2.3.4")) is None
    assert tgbot.parse_callback(key, "nm1:g:17:" + "0" * 12) is None
    assert tgbot.actions_for("access", "Доступ по ссылке", {"grant": 17, "ip": "203.0.113.5"}) == ("17", ["g"])
    assert tgbot.actions_for("access", "Истёк временный доступ", {"ip": "203.0.113.5"}) == ("", [])
    kb = tgbot.keyboard(key, "17", ["g"])
    assert kb["inline_keyboard"][0][0]["text"] == "Закрыть доступ"


def test_link_use_notify_and_revoke(client, monkeypatch):
    import app.api.access_links as A
    nm = client.nm
    sid = _insert(nm.db, _site(ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="198.51.100.1")])))
    p = nm.panel()
    nm.save_panel(p.model_copy(update={"event_channels": [1]}))
    sent = []

    async def fake_deliver(level, source, message, details=None, repeats=0, force_channels=None):
        sent.append((source, message, details, force_channels))
        return []
    monkeypatch.setattr(nm.events, "deliver", fake_deliver)

    async def fake_sync(force=False):
        return True, ""
    monkeypatch.setattr(nm.grants, "sync", fake_sync)
    monkeypatch.setattr(A, "_guard", lambda request: (nm, request.headers.get("x-real-ip", "")))
    hv = {"X-NM-Site": str(sid), "X-Real-IP": "203.0.113.50", "User-Agent": "Mozilla/5.0"}
    quiet = client.post(f"/api/sites/{sid}/access-links", headers=client.op, json={"notify": False}).json()
    loud = client.post(f"/api/sites/{sid}/access-links", headers=client.op, json={"comment": "подрядчик"}).json()
    links = {x["id"]: x for x in client.get(f"/api/sites/{sid}/access-links", headers=client.vw).json()["links"]}
    assert links[quiet["id"]]["notify"] == 0 and links[loud["id"]]["notify"] == 1
    assert client.post(f"/access-link/{quiet['token']}", headers=hv).status_code == 200
    assert sent == []
    assert client.post(f"/access-link/{loud['token']}", headers={**hv, "X-Real-IP": "203.0.113.51"}).status_code == 200
    for _ in range(20):
        if sent:
            break
        time.sleep(0.05)
    src, msg, det, ch = sent[0]
    assert src == "access" and ch == [1] and "203.0.113.51" in msg and "подрядчик" in msg and det["grant"]
    # событие в журнал записано, но повторно в каналы не уходит
    ev = nm.db.one("SELECT details FROM events WHERE source='access' ORDER BY id DESC")
    assert json.loads(ev["details"])["notified"] is True
    # нажатие «Закрыть доступ» в Telegram
    nm.events.loop = None
    out = nm.tgbot.act("g", str(det["grant"]), "tg:ivan", "42")
    assert out == "Доступ для 203.0.113.51 закрыт"
    assert nm.tgbot.act("g", str(det["grant"]), "tg:ivan", "42") == "Этот доступ уже закрыт"
    assert nm.db.one("SELECT action FROM audit_log ORDER BY id DESC")["action"] == "access_grant_revoked"
    assert all(g["ip"] != "203.0.113.51" for g in AL.active_grants(nm.db, sid))


# =============================================================================
#  Сравнение конфигурации
# =============================================================================
def test_compare_diff():
    def summ(sites, glob=None, prot=None, trusted=()):
        return {"me": {"id": "x", "name": "x"}, "version": "2.8.0", "config_version": 5, "sites": sites,
                "streams": {}, "global": glob or {"worker_connections": "a"}, "protection": prot or {"waf": "b"},
                "trusted": list(trusted)}
    site = {"name": "Магазин", "enabled": True, "sections": {"backends": "1", "ssl": "2", "domains": "3"},
            "cert": {"domains": ["shop.test"], "not_after": 2e9, "status": "valid"}}
    a = summ({"shop.test": site, "only.test": {**site, "name": "Только здесь"}}, trusted=["203.0.113.1"])
    b = summ({"shop.test": {**site, "sections": {**site["sections"], "backends": "9"},
                            "cert": {**site["cert"], "not_after": 2e9 + 10 * 86400}},
              "there.test": {**site, "name": "Там"}}, glob={"worker_connections": "z"}, trusted=["203.0.113.2"])
    d = CMP.diff(a, b)
    assert [x["name"] for x in d["sites"]["only_here"]] == ["Только здесь"]
    assert [x["name"] for x in d["sites"]["only_there"]] == ["Там"]
    ch = d["sites"]["changed"][0]
    assert ch["fields"] == ["Бэкенды"] and ch["cert_days"] and d["sites"]["same"] == 0
    assert d["global"] and d["protection"] == []
    assert d["trusted"] == {"only_here": ["203.0.113.1"], "only_there": ["203.0.113.2"]}
    assert d["total"] == 6
    assert CMP.diff(a, a)["total"] == 0


def test_compare_api(client, monkeypatch):
    from app.models import Peer
    nm = client.nm
    _insert(nm.db, _site(name="Магазин", domains=["shop.test"]))
    s = CMP.summary(nm)
    assert "shop.test" in s["sites"] and s["sites"]["shop.test"]["name"] == "Магазин"
    assert "127.0.0.1" not in json.dumps(s)  # адреса бэкендов не передаются — только хеши
    assert client.get("/api/sync/summary", headers=client.vw).status_code == 403
    assert client.get("/api/sync/summary", headers=client.op).json()["sites"]["shop.test"]
    p = nm.panel()
    nm.save_panel(p.model_copy(update={"peers": [Peer(name="Второй", url="https://two.test:8088",
                                                       token="nm_" + "a" * 40)]}))
    pid = nm.panel().peers[0].id
    import app.services.peers as P
    other = json.loads(json.dumps(s))
    other["sites"]["shop.test"]["sections"]["backends"] = "changed"
    monkeypatch.setattr(P, "call", lambda peer, m, path, body=None, verify=True, timeout=20: (200, other))
    r = client.post(f"/api/peers/{pid}/compare", headers=client.op).json()
    assert r["ok"] and r["total"] == 1 and r["sites"]["changed"][0]["fields"] == ["Бэкенды"]
    assert client.get("/api/peers", headers=client.vw).json()["peers"][0]["compare"]["total"] == 1
    monkeypatch.setattr(P, "call", lambda *a, **k: (404, None))
    assert "2.8" in client.post(f"/api/peers/{pid}/compare", headers=client.op).json()["error"]
    assert client.post("/api/peers/nope/compare", headers=client.op).status_code == 404


# =============================================================================
#  Перенесённый сертификат: выпустить здесь
# =============================================================================
def test_transfer_takeover(client, monkeypatch):
    nm = client.nm
    now = time.time()
    data = {"transfer": {"origin": "srv-a", "origin_name": "Основной", "src_id": 3, "at": now - 5 * 86400}}
    cid = nm.db.execute("INSERT INTO certificates(name, type, domains, status, not_after, data, created_at, "
                        "updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        ("shop (с сервера «Основной»)", "upload", json.dumps(["shop.test", "www.shop.test"]),
                         "valid", now + 5 * 86400, json.dumps(data), now, now))
    c = next(x for x in nm.certs.list() if x["id"] == cid)
    r = nm.diag.transfer_check(c)
    assert r["status"] == "fail" and "не выходит на связь 5 дн." in r["message"] and r["fix"] == "cert_issue_here"
    nm.db.kv_set("peers_incoming", {"srv-a": {"at": now}})
    r = nm.diag.transfer_check(c)
    assert r["status"] == "warn" and "продлённый оттуда не пришёл" in r["message"]
    nm.db.execute("UPDATE certificates SET not_after=? WHERE id=?", (now + 60 * 86400, cid))
    assert nm.diag.transfer_check(next(x for x in nm.certs.list() if x["id"] == cid)) is None
    sid = _insert(nm.db, _site(name="Магазин", domains=["shop.test"], ssl={"enabled": True, "certificate_id": cid}))
    issued = {}

    async def fake_issue(req, username, after=None):
        issued["req"] = req
        issued["after"] = after
        return 99
    monkeypatch.setattr(nm.certs, "issue_letsencrypt", fake_issue)
    applied = []

    async def fake_apply(user, comment="", source="user", state=None):
        applied.append(comment)
        return {"version": 1}
    monkeypatch.setattr(nm, "apply", fake_apply)
    res = asyncio.run(nm.diag.fix("cert_issue_here", {"id": cid}, "admin"))
    assert res["ok"] and "#99" in res["output"]
    assert issued["req"].domains == ["shop.test", "www.shop.test"] and issued["req"].challenge == "http"
    assert issued["req"].name == "shop (выпущен здесь)"
    asyncio.run(issued["after"](99))
    assert json.loads(nm.db.one("SELECT data FROM sites WHERE id=?", (sid,))["data"])["ssl"]["certificate_id"] == 99
    assert applied == ["Переход на сертификат, выпущенный здесь"]
    # wildcard без учётной записи DNS — понятная ошибка
    nm.db.execute("UPDATE certificates SET domains=? WHERE id=?", (json.dumps(["*.shop.test"]), cid))
    res = asyncio.run(nm.diag.fix("cert_issue_here", {"id": cid}, "admin"))
    assert not res["ok"] and "DNS" in res["output"]
