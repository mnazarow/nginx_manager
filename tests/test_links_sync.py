"""Версия 2.7: доступ к сайту по ссылке, синхронизация сайтов между серверами, отказы «Доступа по IP» в анализе,
оповещениях и метриках, команды nmctl os / peers / transfer."""
from __future__ import annotations

import json
import time

import pytest

from app.db import Database
from app.models import Backend, IpAccessSettings, IpEntry, PanelSettings, Peer, Site
from app.services import access_links as AL
from app.services import transfer as TF


def _site(name="Внутренний", domains=("int.test",), **kw):
    return Site(name=name, domains=list(domains), backends=[Backend(address="127.0.0.1", port=8080)], **kw)


def _insert(db, s: Site) -> int:
    now = time.time()
    return db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                      (s.name, int(s.enabled), json.dumps(s.model_dump()), now, now))


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
#  Доступ по ссылке
# =============================================================================
def test_access_links_unit(tmp_path):
    db = Database(str(tmp_path / "l.db"))
    for bad in ((0, 24, 1), (8, 0, 1), (8, 24, 0), (8, 24, 101), (24 * 91, 24, 1)):
        with pytest.raises(ValueError):
            AL.create(db, 5, *bad, "", "t")
    lid, token = AL.create(db, 5, 8, 24, 2, "подрядчик", "admin")
    row = AL.find(db, token)
    assert row["id"] == lid and row["token_hash"] != token and AL.find(db, "x") is None and AL.find(db, "") is None
    assert AL.state(row, 5) == "ok" and AL.state(row, 6) == "other_site" and AL.state(None, 5) == "missing"
    g = AL.grant(db, row, "203.0.113.5", "Mozilla")
    assert g["ip"] == "203.0.113.5" and 8 * 3600 - 5 < g["expires_at"] - time.time() <= 8 * 3600
    # тот же адрес ещё раз — та же запись (продление), использование списано
    g2 = AL.grant(db, AL.find(db, token), "203.0.113.5", "Mozilla")
    assert g2["id"] == g["id"] and AL.state(AL.find(db, token), 5) == "used"
    lid2, t2 = AL.create(db, 7, 1, 1, 1, "", "admin")
    AL.grant(db, AL.find(db, t2), "203.0.113.5", "")
    text = AL.render(db)
    assert '203.0.113.5 ",5,7,";' in text
    db.execute("UPDATE ipaccess_links SET expires_at=? WHERE id=?", (time.time() - 1, lid2))
    assert AL.state(AL.find(db, t2), 7) == "expired"
    db.execute("UPDATE ipaccess_grants SET expires_at=? WHERE site=7", (time.time() - 1,))
    assert '",5,"' in AL.render(db) and ",7," not in AL.render(db)
    with pytest.raises(ValueError):
        AL.grant(db, row, "не адрес", "")
    assert AL.hours_text(0.5) == "30 мин" and AL.hours_text(8) == "8 ч" and AL.hours_text(72) == "3 дн."
    db.execute("UPDATE ipaccess_grants SET expires_at=?", (time.time() - 40 * 86400,))
    AL.cleanup(db)
    assert db.one("SELECT COUNT(*) AS n FROM ipaccess_grants")["n"] == 0


def test_access_link_generator():
    from tests.test_cluster import _gen
    s = _site(ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="203.0.113.10")]),
              protection={"waf_exclude_paths": []})
    g, files = _gen([(1, s)], challenge_key="k1", grants_file="/etc/nm/grants.conf")
    conf = next(v for k, v in files.items() if k.startswith("sites/site-1-"))
    base = files["http.d/00-base.conf"]
    assert "geo $nm_ipgrant" in base and "include /etc/nm/grants.conf;" in base
    assert 'map $nm_ipgrant $nm_ipg_1' in conf and '"~,1," 1;' in conf
    assert 'map "$nm_ipacl_1$nm_ipg_1:$uri" $nm_ipdeny_1' in conf and '"~^01:" 0;' in conf
    assert r'"~^00:/\\.nm\\-access/" 0;' in conf
    assert "location ^~ /.nm-access/" in conf and "/access-link/;" in conf and 'X-NM-Site "1"' in conf
    prot = files["http.d/05-protection.conf"]
    # без фильтра запросов, своих правил и проверки браузера: только проверка кода в панели
    wx = prot.split("map $uri $nm_wx_1 {")[1].split("}")[0]
    cx = prot.split("map $uri $nm_cx_1 {")[1].split("}")[0]
    assert r"nm\-access/" in wx and r"nm\-access/" in cx
    # доступ по IP выключен — ни карты, ни location
    g2, files2 = _gen([(1, _site())])
    assert "nm_ipgrant" not in files2["http.d/00-base.conf"]
    assert ".nm-access" not in next(v for k, v in files2.items() if k.startswith("sites/site-1-"))


def test_access_link_api_and_page(client, monkeypatch):
    import app.api.access_links as A
    nm = client.nm
    sid = _insert(nm.db, _site(ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="198.51.100.1")]),
                               ssl={"enabled": False}))
    plain = _insert(nm.db, _site(name="Открытый", domains=["open.test"]))
    assert client.post(f"/api/sites/{plain}/access-links", headers=client.h, json={}).status_code == 400
    assert client.post(f"/api/sites/{sid}/access-links", headers=client.vw, json={}).status_code == 403
    assert client.post(f"/api/sites/{sid}/access-links", headers=client.op, json={"uses": 0}).status_code == 400
    r = client.post(f"/api/sites/{sid}/access-links", headers=client.op,
                    json={"hours": 4, "valid_hours": 24, "uses": 1, "comment": "подрядчик"}).json()
    assert r["url"] == f"http://int.test/.nm-access/{r['token']}"
    d = client.get(f"/api/sites/{sid}/access-links", headers=client.vw).json()
    assert d["links"][0]["comment"] == "подрядчик" and "token" not in d["links"][0] and d["grants"] == []
    # страница для посетителя: только через nginx этого сервера (адрес и ключ)
    assert client.get(f"/access-link/{r['token']}", headers={"X-NM-Site": str(sid)}).status_code == 403
    synced = []

    async def fake_sync(force=False):
        synced.append(AL.render(nm.db))
        return True, ""
    monkeypatch.setattr(nm.grants, "sync", fake_sync)
    monkeypatch.setattr(A, "_guard", lambda request: (nm, request.headers.get("x-real-ip", "")))
    hv = {"X-NM-Site": str(sid), "X-Real-IP": "203.0.113.50", "User-Agent": "TelegramBot (like TwitterBot)"}
    page = client.get(f"/access-link/{r['token']}", headers=hv)
    assert page.status_code == 200 and "203.0.113.50" in page.text and "Открыть доступ" in page.text
    assert AL.find(nm.db, r["token"])["uses_left"] == 1  # предпросмотр ссылки доступ не выдаёт
    assert client.get(f"/access-link/{r['token']}", headers={**hv, "X-NM-Site": "999"}).status_code == 410
    ok = client.post(f"/access-link/{r['token']}", headers={**hv, "User-Agent": "Mozilla/5.0"})
    assert ok.status_code == 200 and "Доступ открыт" in ok.text and synced and '203.0.113.50 ",' in synced[-1]
    assert client.post(f"/access-link/{r['token']}", headers=hv).status_code == 410  # одноразовая
    assert client.get("/access-link/неверный", headers=hv).status_code == 410
    d = client.get(f"/api/sites/{sid}/access-links", headers=client.vw).json()
    assert d["grants"][0]["ip"] == "203.0.113.50" and d["links"][0]["state"] == "used"
    ev = nm.db.one("SELECT message FROM events WHERE source='access' ORDER BY id DESC")["message"]
    assert "203.0.113.50" in ev and "подрядчик" in ev
    # адрес из списка сайта — страница сообщает, что доступ уже есть
    r2 = client.post(f"/api/sites/{sid}/access-links", headers=client.op, json={"uses": 3}).json()
    page = client.get(f"/access-link/{r2['token']}", headers={**hv, "X-Real-IP": "198.51.100.1"})
    assert "уже есть в списке" in page.text and "ещё 3 раз" in page.text
    # досрочное закрытие и отзыв ссылки
    gid = d["grants"][0]["id"]
    assert client.delete(f"/api/sites/{sid}/access-grants/{gid}", headers=client.op).json()["ok"]
    assert "203.0.113.50" not in synced[-1]
    lid = client.get(f"/api/sites/{sid}/access-links", headers=client.vw).json()["links"][0]["id"]
    assert client.delete(f"/api/sites/{sid}/access-links/{lid}", headers=client.op).json()["ok"]
    assert client.delete(f"/api/sites/{sid}/access-links/{lid}", headers=client.op).status_code == 404


# =============================================================================
#  Синхронизация сайтов
# =============================================================================
def test_mirror_sync_receiver(client, monkeypatch):
    nm = client.nm
    origin = {"id": "aaaa0000bbbb3333", "name": "web-1"}
    own = _insert(nm.db, _site(name="Свой", domains=["own.test"]))
    pre = _insert(nm.db, _site(name="Был до синхронизации", domains=["pre.test"]))
    a = _site(name="A", domains=["a.test"], tags=["cluster"])
    b = _site(name="B", domains=["pre.test"], tags=["cluster"])

    def body(sites, **kw):
        return {"origin": origin, "mirror": True, "apply": False, "certs": [],
                "sites": [{"src_id": i, "name": s.name, "enabled": s.enabled, "data": s.model_dump()} for i, s in sites],
                **kw}
    r = client.post("/api/sync/sites", headers=client.h, json=body([(10, a), (11, b)])).json()
    assert r["sites"]["created"] == 1 and r["sites"]["updated"] == 1  # B совпал по домену с местным сайтом
    m = TF.mirrored(nm.db)
    a_id = next(k for k, v in m.items() if k not in (own, pre))
    assert m[pre] == "web-1" and own not in m
    # без изменений — ничего не меняется и не пишется в журнал переносов
    n_log = len(nm.db.kv_get("transfers_in", []) or [])
    r = client.post("/api/sync/sites", headers=client.h, json=body([(10, a), (11, b)])).json()
    assert r["sites"]["unchanged"] == 2 and len(nm.db.kv_get("transfers_in", []) or []) == n_log
    # домены сайта на источнике поменялись — тот же местный сайт (по номеру у источника)
    a2 = a.model_copy(update={"domains": ["a2.test"]})
    r = client.post("/api/sync/sites", headers=client.h, json=body([(10, a2), (11, b)])).json()
    assert r["sites"]["updated"] == 1
    assert json.loads(nm.db.one("SELECT data FROM sites WHERE id=?", (a_id,))["data"])["domains"] == ["a2.test"]
    # сайты пропали из синхронизации: созданный удаляется, бывший здесь раньше — остаётся (больше не обновляется)
    r = client.post("/api/sync/sites", headers=client.h, json=body([])).json()
    acts = {it["name"]: it["action"] for it in r["sites"]["items"]}
    assert acts == {"A": "deleted", "B": "released"} and r["sites"]["deleted"] == 1
    assert not nm.db.one("SELECT 1 FROM sites WHERE id=?", (a_id,)) and nm.db.one("SELECT 1 FROM sites WHERE id=?", (pre,))
    assert TF.mirrored(nm.db) == {}
    # приём выключен, токен оператора — отказ
    assert client.post("/api/sync/sites", headers=client.op, json=body([(10, a)])).status_code == 403
    nm.save_panel(nm.panel().model_copy(update={"peers_accept_sites": False}))
    assert client.post("/api/sync/sites", headers=client.h, json=body([(10, a)])).status_code == 403
    # отметка в списке сайтов и в карточке
    nm.save_panel(nm.panel().model_copy(update={"peers_accept_sites": True}))
    client.post("/api/sync/sites", headers=client.h, json=body([(10, a)]))
    lst = {s["name"]: s["synced_from"] for s in client.get("/api/sites", headers=client.vw).json()}
    assert lst["A"] == "web-1" and lst["Свой"] == ""
    sid = next(k for k in TF.mirrored(nm.db))
    assert client.get(f"/api/sites/{sid}", headers=client.vw).json()["synced_from"] == "web-1"


def test_mirror_sync_sender(client, monkeypatch):
    from app.models import CertificateRequest
    from app.services import peers as P
    nm = client.nm
    cid = nm.certs.create(CertificateRequest(type="selfsigned", domains=["a.test"]), "t")
    s1 = _insert(nm.db, _site(name="A", domains=["a.test"], tags=["cluster"], ssl={"enabled": True,
                                                                                   "certificate_id": cid}))
    _insert(nm.db, _site(name="B", domains=["b.test"]))
    nm.save_panel(nm.panel().model_copy(update={"peers": [
        Peer(name="web-2", url="https://10.0.0.2:8088", token="nm_" + "a" * 30, bans=False, sites=True,
             sites_tag="cluster")]}))
    pid = nm.panel().peers[0].id
    assert nm.peers.sites_tick() == {}  # ещё нет применённой версии
    state = nm.nginx.load_state()
    nm.db.execute("INSERT INTO config_versions(ts,username,comment,source,status,files,state) VALUES(?,?,?,?,?,?,?)",
                  (time.time(), "t", "", "user", "applied", "{}", json.dumps(state.to_json())))
    sent = []
    reply = {"name": "web-2", "sites": {"created": 1, "updated": 0, "deleted": 0, "unchanged": 0, "skipped": 0},
             "certs": {"created": 1, "missing": []}, "applied": 7}

    def fake_call(peer, method, path, body=None, verify=True, timeout=20):
        sent.append(body)
        return 200, reply
    monkeypatch.setattr(P, "call", fake_call)
    res = nm.peers.sites_tick()
    assert res[pid]["ok"] and len(sent) == 1
    b = sent[0]
    assert b["mirror"] and b["apply"] and [s["name"] for s in b["sites"]] == ["A"]  # только с меткой
    assert b["certs"][0]["src_id"] == cid and "PRIVATE KEY" in b["certs"][0]["key_pem"]
    st = nm.peers.status()[pid]
    assert st["sites_ok"] and st["sites_sent"] == 1 and st["sites_applied"] == 7
    # та же версия — повторно не отправляется
    assert nm.peers.sites_tick() == {} and len(sent) == 1
    # новая версия — сертификат уже известен получателю и не пересылается
    nm.db.execute("INSERT INTO config_versions(ts,username,comment,source,status,files,state) VALUES(?,?,?,?,?,?,?)",
                  (time.time(), "t", "", "user", "applied", "{}", json.dumps(state.to_json())))
    nm.peers.sites_tick()
    assert sent[-1]["certs"] == [{"src_id": cid, "known": True}]
    # получатель сообщил, что сертификата нет, — в следующий раз сертификат уходит целиком
    reply["certs"] = {"missing": [str(cid)]}
    nm.db.execute("INSERT INTO config_versions(ts,username,comment,source,status,files,state) VALUES(?,?,?,?,?,?,?)",
                  (time.time(), "t", "", "user", "applied", "{}", json.dumps(state.to_json())))
    nm.peers.sites_tick()
    reply["certs"] = {"missing": []}
    nm.peers.sites_tick()
    assert "key_pem" in sent[-1]["certs"][0]
    # ошибка связи — событие и повтор не раньше чем через минуту
    nm.db.execute("INSERT INTO config_versions(ts,username,comment,source,status,files,state) VALUES(?,?,?,?,?,?,?)",
                  (time.time(), "t", "", "user", "applied", "{}", json.dumps(state.to_json())))

    def down(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(P, "call", down)
    assert not nm.peers.sites_tick()[pid]["ok"]
    assert nm.peers.sites_tick() == {}
    assert "сайты не синхронизированы" in nm.db.one("SELECT message FROM events WHERE source='peers' "
                                                    "ORDER BY id DESC")["message"]
    # сайты, полученные с другого сервера, дальше не отправляются
    nm.db.kv_set(TF.MIRROR_KV, {"x": {"name": "web-9", "map": {"1": [s1, True]}}})
    payload = TF.build_mirror(nm.db, state, "", {})
    assert [s["name"] for s in payload["sites"]] == ["B"]


# =============================================================================
#  Анализ, оповещения, метрики
# =============================================================================
def test_ipaccess_insights_and_alert(client):
    nm = client.nm
    s = _site(ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="203.0.113.10", comment="Офис")]))
    sid = _insert(nm.db, s)
    now = int(time.time()) // 60 * 60
    rows = [(now - 120, str(sid), "203.0.113.77", 5, "/admin", ""), (now - 120, str(sid), "198.51.100.9", 2, "/", "")]
    rows += [(now - 60 * k, str(sid), f"192.0.2.{k}", 30, "/wp-login.php", "") for k in range(1, 11)]
    nm.db.executemany("INSERT INTO ipdeny_minute(ts, site, ip, n, uri, country) VALUES(?,?,?,?,?,?)", rows)
    res = nm.insights.evaluate(time.time() - 900, time.time(), "*")
    f = {x["id"]: x for x in res["findings"] if x["site"] == str(sid)}
    assert "ipaccess_near_allowed" in f and "203.0.113.77" in f["ipaccess_near_allowed"]["summary"]
    assert f["ipaccess_near_allowed"]["evidence"]["rows"][0][2] == "203.0.113.10 (Офис)"
    assert "ipaccess_denied_high" in f and f["ipaccess_denied_high"]["level"] == "info"
    from app.models import AlertRule
    v, detail = nm.metric(AlertRule(name="x", metric="ipaccess_denied", window=900))
    assert v > 0 and "192.0.2." in detail
    nm.stats.agg.ipdeny[(now, str(sid), "203.0.113.99")] = [40, "/", ""]  # ещё не записанная минута
    v2, detail2 = nm.metric(AlertRule(name="x", metric="ipaccess_denied", window=900, site=str(sid)))
    assert v2 > v and "203.0.113.99" in detail2
    assert nm.metric(AlertRule(name="x", metric="ipaccess_denied", window=900, site="999"))[0] == 0


def test_ipaccess_prometheus(client):
    from app.services.metrics import render
    nm = client.nm
    nm.stats.agg.ipdeny_total["3"] += 5
    text = render(nm)
    assert "# TYPE nm_http_ipaccess_denied_requests_total counter" in text
    assert 'nm_http_ipaccess_denied_requests_total{site_id="3",site="#3"} 5' in text


def test_cli_os_and_transfer(tmp_path, monkeypatch, capsys):
    from app import cli
    from app.config import settings
    from app.services import osinfo, peers as P
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    monkeypatch.setattr(osinfo, "check", lambda: {"level": "eol", "message": "Поддержка X закончилась"})
    assert cli.main(["os"]) == 1 and "закончилась" in capsys.readouterr().out
    monkeypatch.setattr(osinfo, "check", lambda: {"level": "ok", "message": "до 2030"})
    assert cli.main(["os", "--json"]) == 0 and '"ok"' in capsys.readouterr().out
    db = cli._db()
    _insert(db, _site(name="A", domains=["a.test"], tags=["cluster"]))
    _insert(db, _site(name="B", domains=["b.test"]))
    db.kv_set("panel_settings", PanelSettings(peers=[Peer(name="web-2 (Франкфурт)", url="https://10.0.0.2:8088",
                                                          token="nm_" + "a" * 30)]).model_dump())
    got = []

    def fake_call(peer, method, path, body=None, verify=True, timeout=20):
        got.append((path, body))
        return 200, {"name": "web-2", "sites": {"items": [{"name": s["name"], "action": "created", "notes": []}
                                                          for s in body["sites"]], "skipped": 0},
                     "certs": {"created": 0, "updated": 0, "errors": []}, "applied": 5}
    monkeypatch.setattr(P, "call", fake_call)
    assert cli.main(["transfer", "--to", "web-2", "--tag", "cluster"]) == 0
    out = capsys.readouterr().out
    assert "A — создан" in out and "версия 5" in out and [s["name"] for s in got[0][1]["sites"]] == ["A"]
    assert cli.main(["transfer", "--to", "нет", "--all"]) == 1
    assert cli.main(["transfer", "--to", "web", "--sites", ""]) == 1
