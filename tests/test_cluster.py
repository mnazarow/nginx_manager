"""Версия 2.6: временный доступ (адрес на N часов), журнал отказов «Доступа по IP», доверенные адреса и сайты с
сертификатами между серверами, сроки поддержки ОС."""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from app.db import Database
from app.models import (Backend, GlobalSettings, IpAccessSettings, IpEntry, PanelSettings, Peer, ProtectionSettings,
                        Site)
from app.nginx.generator import Generator, Paths, State
from app.services import osinfo as O
from app.services import transfer as TF
from app.services import trusted as TR
from tests.test_collector import line

TMP = Path(os.environ["NM_TEST_TMP"]) / "cluster"


def _gen(sites, panel=None, **paths):
    from app.nginx.manager import NginxManager
    TMP.mkdir(parents=True, exist_ok=True)
    caps = NginxManager(Database(TMP / "t.db")).caps()
    st = State(sites=sites, streams=[], glob=GlobalSettings(), panel=panel or PanelSettings(), certs={},
               protection=ProtectionSettings())
    g = Generator(st, caps, Paths("/etc/nm", "/etc/nm", "/var/acme", "/var/log/nm", "/var/cache/nm", 18089, 8088,
                                  str(TMP), **{"bans_file": "/etc/nm/bans.conf", **paths}))
    return g, g.render()


def _site(**kw):
    return Site(name="Внутренний", domains=["int.test"], backends=[Backend(address="127.0.0.1", port=8080)], **kw)


# =============================================================================
#  Сроки поддержки ОС
# =============================================================================
def test_osinfo_levels():
    d = datetime.date(2026, 11, 16)
    r = O.check({"ID": "ubuntu", "VERSION_ID": "20.04", "PRETTY_NAME": "Ubuntu 20.04.6 LTS"}, d)
    assert r["level"] == "eol" and "31 мая 2025" in r["message"] and "Ubuntu Pro" in r["message"]
    r = O.check({"ID": "ubuntu", "VERSION_ID": "24.04"}, d)
    assert r["level"] == "ok" and r["eol_text"] == "мая 2029" and r["name"] == "Ubuntu 24.04"
    r = O.check({"ID": "ubuntu", "VERSION_ID": "26.10"}, datetime.date(2027, 3, 1))
    assert r["level"] == "soon" and "в июле 2027" in r["message"]
    # месяц: истёкшей поддержка считается только после конца месяца
    assert O.check({"ID": "ubuntu", "VERSION_ID": "26.10"}, datetime.date(2027, 7, 20))["level"] == "soon"
    assert O.check({"ID": "ubuntu", "VERSION_ID": "26.10"}, datetime.date(2027, 8, 1))["level"] == "eol"
    assert O.check({"ID": "debian", "VERSION_ID": "11"}, d)["level"] == "eol"
    assert O.check({"ID": "debian", "VERSION_ID": "12"}, d)["level"] == "ok"
    assert O.check({"ID": "debian", "VERSION_ID": "8"}, d)["level"] == "eol"          # старее известных
    assert O.check({"ID": "debian", "VERSION_ID": "14"}, d)["level"] == "unknown"     # новее известных
    assert O.check({"ID": "rocky", "VERSION_ID": "9.5"}, d)["eol"] == "2032-05-31"
    assert O.check({"ID": "almalinux", "VERSION_ID": "8.10"}, d)["eol"] == "2029-05-31"
    cs = O.check({"ID": "centos", "NAME": "CentOS Stream", "VERSION_ID": "9"}, datetime.date(2027, 1, 10))
    assert cs["family"] == "centos-stream" and cs["level"] == "soon"
    assert O.check({"ID": "centos", "NAME": "CentOS Linux", "VERSION_ID": "7"}, d)["level"] == "eol"
    assert O.check({"ID": "arch"}, d)["level"] == "unknown"
    # скрипт для установщика: строка «уровень|сообщение», запускается системным python3 без пакета app
    out = subprocess.run(["python3", "-I", str(Path(O.__file__))], capture_output=True, text=True, timeout=20).stdout
    assert out.split("|")[0] in ("ok", "soon", "eol", "unknown")
    js = json.loads(subprocess.run(["python3", "-I", str(Path(O.__file__)), "--json"], capture_output=True,
                                   text=True, timeout=20).stdout)
    assert "level" in js and "name" in js


# =============================================================================
#  Временный доступ
# =============================================================================
def test_expired_entries_skipped_in_config():
    now = time.time()
    s = _site(ip_access=IpAccessSettings(enabled=True, allow_trusted=False, entries=[
        IpEntry(address="203.0.113.10", comment="офис"),
        IpEntry(address="198.51.100.7", comment="подрядчик", expires=now + 3600),
        IpEntry(address="192.0.2.9", comment="истёк", expires=now - 10)]))
    panel = PanelSettings(trusted_ips=[IpEntry(address="198.51.100.200"),
                                       IpEntry(address="198.51.100.201", expires=now - 1)])
    g, files = _gen([(1, s)], panel)
    conf = next(v for k, v in files.items() if k.startswith("sites/site-1-"))
    assert "203.0.113.10 1;" in conf and "198.51.100.7 1;" in conf and "192.0.2.9" not in conf
    prot = files["http.d/05-protection.conf"]
    assert "198.51.100.200" in prot and "198.51.100.201" not in prot
    # журнал отказов: признак в формате журнала и map по сайтам
    base = files["http.d/00-base.conf"]
    assert '"ia":"$nm_ia"' in base and 'map $nm_site $nm_ia' in base and '"1" $nm_ipdeny_1;' in base
    # все разрешённые адреса истекли — предупреждение «закрыт для всех»
    s2 = _site(ip_access=IpAccessSettings(enabled=True, allow_trusted=False,
                                          entries=[IpEntry(address="192.0.2.9", expires=now - 10)]))
    g2, _ = _gen([(1, s2)])
    assert any("закрыт для всех" in w for w in g2.warnings)


def test_expire_access_job(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    app = App()
    now = time.time()
    s = _site(ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="203.0.113.10"),
                                                                 IpEntry(address="198.51.100.7", expires=now + 3600)]))
    app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                   (s.name, 1, json.dumps(s.model_dump()), now, now))
    app.save_panel(app.panel().model_copy(update={"trusted_ips": [IpEntry(address="192.0.2.50", expires=now + 60)]}))
    calls = []

    async def fake_snapshot(reason, source):
        calls.append((reason, source))
        return {"version": 1}
    monkeypatch.setattr(app, "apply_snapshot", fake_snapshot)
    import asyncio
    # ещё действуют — ничего не меняется
    assert asyncio.run(app.expire_access()) is None and not calls
    # применённая версия содержит записи, срок которых истёк после применения
    state = app.nginx.load_state()
    sj = state.to_json()
    app.db.execute("INSERT INTO config_versions(ts,username,comment,source,status,files,state) VALUES(?,?,?,?,?,?,?)",
                   (now - 5, "t", "", "user", "applied", "{}", json.dumps(sj)))
    monkeypatch.setattr(time, "time", lambda: now + 7200)
    asyncio.run(app.expire_access())
    assert calls == [("Истёк временный доступ", "expire")]
    d = json.loads(app.db.one("SELECT data FROM sites")["data"])
    assert [e["address"] for e in d["ip_access"]["entries"]] == ["203.0.113.10"]
    assert app.panel().trusted_ips == []
    ev = app.db.one("SELECT message FROM events WHERE source='access' ORDER BY id DESC")
    assert "198.51.100.7" in ev["message"] and "192.0.2.50" in ev["message"]
    # повтор той же версии — не чаще раза в 10 минут
    asyncio.run(app.expire_access())
    assert len(calls) == 1


# =============================================================================
#  Журнал отказов «Доступа по IP»
# =============================================================================
def test_ip_denials_collected(tmp_path):
    from app.models import PanelSettings as PS
    from app.stats.collector import Aggregator
    from app.stats.parsing import GeoIP
    db = Database(str(tmp_path / "c.db"))
    agg = Aggregator(db, lambda: PS(store_requests=False), GeoIP())
    base = (int(time.time()) // 60 - 3) * 60

    def ln(ts, ip, ia, status=403, uri="/admin"):
        d = json.loads(line(ts, site="5", status=status, uri=uri, ip=ip, upstream="", ustatus=""))
        d["ia"] = ia
        return json.dumps(d)
    lines = [ln(base + 1, "198.51.100.9", "1"), ln(base + 2, "198.51.100.9", "1", uri="/wp-login.php"),
             ln(base + 3, "192.0.2.5", "1"), ln(base + 4, "203.0.113.10", "0", status=200),
             ln(base + 5, "192.0.2.6", "p", status=401), ln(base + 6, "192.0.2.6", "p", status=200)]  # вошёл по паролю
    agg.ingest_access(lines)
    agg.flush(force=True)
    rows = {r["ip"]: r for r in db.query("SELECT * FROM ipdeny_minute WHERE site='5'")}
    assert rows["198.51.100.9"]["n"] == 2 and rows["198.51.100.9"]["uri"] == "/wp-login.php"
    assert rows["192.0.2.5"]["n"] == 1 and rows["192.0.2.6"]["n"] == 1 and "203.0.113.10" not in rows
    # поздняя строка той же минуты суммируется
    agg.ingest_access([ln(base + 30, "192.0.2.5", "1")])
    agg.flush(force=True)
    assert db.one("SELECT n FROM ipdeny_minute WHERE ip='192.0.2.5'")["n"] == 2


# =============================================================================
#  Доверенные адреса с других серверов
# =============================================================================
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
        c.h = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'sync', role='admin')}"}
        c.op = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'op', role='operator')}"}
        yield c


def test_trusted_store_and_effective(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    now = time.time()
    r = TR.store(db, "peer01", "web-2", [{"address": "203.0.113.0/24", "comment": "офис"},
                                         {"address": "0.0.0.0/0"}, {"address": "bad"},
                                         {"address": "192.0.2.1", "expires": now - 5},
                                         {"address": "192.0.2.2", "expires": now + 600}])
    assert r == {"changed": True, "count": 2, "added": 2, "removed": 0}
    assert TR.store(db, "peer01", "web-2", [{"address": "203.0.113.0/24"}, {"address": "192.0.2.2",
                                                                            "expires": now + 600}])["changed"] is False
    p = PanelSettings(trusted_ips=[IpEntry(address="203.0.113.0/24", comment="своя запись важнее")])
    eff = TR.effective(db, p)
    assert [(e.address, e.origin) for e in eff] == [("203.0.113.0/24", ""), ("192.0.2.2", "web-2")]
    assert [e.address for e in TR.effective(db, p.model_copy(update={"peers_accept_trusted": False}))] == \
        ["203.0.113.0/24"]
    assert TR.store(db, "peer01", "web-2", [])["removed"] == 2 and TR.by_peer(db) == []


def test_trusted_sync_api(client, monkeypatch):
    nm = client.nm
    nm.bans.add("198.51.100.66", None, "сканер", "manual")
    snaps = []

    async def fake_snapshot(reason, source):
        snaps.append(source)
        return {"version": 1}
    monkeypatch.setattr(nm, "apply_snapshot", fake_snapshot)
    origin = {"id": "abcabcabcabc0002", "name": "web-2"}
    body = {"origin": origin, "bans": [], "trusted": [{"address": "198.51.100.64/29", "comment": "VPN web-2"}]}
    # оператор: блокировки принимаются, доверенные — нет
    r = client.post("/api/sync/bans", headers=client.op, json=body).json()
    assert r["trusted"]["skipped"] == "нужен токен администратора" and not TR.by_peer(nm.db)
    r = client.post("/api/sync/bans", headers=client.h, json=body).json()
    assert r["trusted"]["changed"] and r["trusted"]["unbanned"] == 1 and snaps == ["sync"]
    assert not nm.db.one("SELECT 1 FROM bans WHERE net='198.51.100.66'")
    assert "198.51.100.64/29" in nm.trusted()
    assert "web-2" in nm.bans.trusted_entry("198.51.100.65")
    # нельзя заблокировать вручную, проверка адреса показывает источник
    assert client.post("/api/bans", headers=client.h, json={"nets": ["198.51.100.65"]}).status_code == 400
    ck = client.get("/api/trusted/check", headers=client.h, params={"ip": "198.51.100.65"}).json()
    assert ck["trusted"]["origin"] == "web-2"
    d = client.get("/api/trusted", headers=client.h).json()
    assert d["entries"] == [] and d["received"][0]["name"] == "web-2" and d["accept"] is True
    # в конфигурацию попадают и полученные
    st = nm.nginx.load_state()
    assert any(e.address == "198.51.100.64/29" and e.origin == "web-2" for e in st.panel.trusted_ips)
    # повтор того же списка — без переприменения; приём выключен — не принимаются
    client.post("/api/sync/bans", headers=client.h, json=body)
    assert snaps == ["sync"]
    nm.save_panel(nm.panel().model_copy(update={"peers_accept_trusted": False}))
    assert "198.51.100.64/29" not in nm.trusted()
    r = client.post("/api/sync/bans", headers=client.h, json={**body, "trusted": []}).json()
    assert r["trusted"]["skipped"].startswith("приём выключен")
    # свой список: origin из запроса отбрасывается, истёкшие записи не сохраняются
    r = client.put("/api/trusted", headers=client.h, json={"entries": [
        {"address": "203.0.113.5", "origin": "подделка"}, {"address": "203.0.113.6", "expires": time.time() - 1},
        {"address": "203.0.113.7", "expires": time.time() + 3600, "comment": "на час"}]}).json()
    assert r["count"] == 2 and [e.origin for e in nm.panel().trusted_ips] == ["", ""]


def test_peers_push_trusted(client, monkeypatch):
    """Отправка: свои действующие доверенные (без полученных), пустой список — если отправка выключена."""
    from app.services import peers as P
    nm = client.nm
    sent = []

    def fake_call(peer, method, path, body=None, verify=True, timeout=20):
        sent.append((path, body))
        return 200, {"added": 0, "removed": 0, "updated": 0, "name": "web-2",
                     "trusted": {"changed": True, "count": len(body.get("trusted") or [])}}
    monkeypatch.setattr(P, "call", fake_call)
    TR.store(nm.db, "abcabcabcabc0003", "web-3", [{"address": "192.0.2.200"}])
    nm.save_panel(nm.panel().model_copy(update={
        "trusted_ips": [IpEntry(address="203.0.113.10", comment="офис"),
                        IpEntry(address="203.0.113.11", expires=time.time() - 1)],
        "peers": [Peer(name="web-2", url="https://10.0.0.2:8088", token="nm_" + "a" * 30),
                  Peer(name="web-4", url="https://10.0.0.4:8088", token="nm_" + "b" * 30, trusted=False)]}))
    res = nm.peers.push_bans()
    assert all(x["ok"] for x in res.values())
    by = {b["origin"]["id"]: b for _, b in sent}
    assert len(sent) == 2
    first, second = sent[0][1], sent[1][1]
    assert [e["address"] for e in first["trusted"]] == ["203.0.113.10"] and second["trusted"] == []
    assert by
    st = client.get("/api/peers", headers=client.h).json()
    assert st["peers"][0]["trusted"] is True and st["peers"][0]["trusted_sent"] == 1
    assert st["peers"][1]["trusted"] is False


# =============================================================================
#  Перенос сайтов и сертификатов
# =============================================================================
def _selfsigned(dirpath: Path, cn: str):
    dirpath.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-days", "30", "-keyout", str(dirpath / "k.pem"), "-out", str(dirpath / "c.pem"), "-subj",
                    f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}"], check=True, capture_output=True)
    return (dirpath / "c.pem").read_text(), (dirpath / "k.pem").read_text()


def test_transfer_sites_and_certs(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.core import App
    from app.main import create_app
    from app.models import CertificateRequest
    # ---- отправитель
    monkeypatch.setattr(settings, "data_dir", tmp_path / "a")
    settings.ensure_dirs()
    a = App()
    cid = a.certs.create(CertificateRequest(type="selfsigned", domains=["shop.test", "www.shop.test"]), "t")
    now = time.time()
    s1 = Site(name="Магазин", domains=["shop.test", "www.shop.test"],
              backends=[Backend(address="10.0.0.5", port=8080)],
              ssl={"enabled": True, "certificate_id": cid}, cache={"enabled": True, "zone": "big"},
              ip_access=IpAccessSettings(enabled=True, entries=[IpEntry(address="203.0.113.10")]))
    s2 = Site(name="Блог", domains=["blog.test"], backends=[Backend(address="10.0.0.6", port=80)])
    ids = [a.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                        (s.name, 1, json.dumps(s.model_dump()), now, now)) for s in (s1, s2)]
    payload = TF.build(a.db, ids, True)
    assert len(payload["sites"]) == 2 and len(payload["certs"]) == 1
    assert "PRIVATE KEY" in payload["certs"][0]["key_pem"] and payload["certs"][0]["fingerprint"]
    with pytest.raises(ValueError):
        TF.build(a.db, [999], True)
    TF.remember(a.db, "peerX", payload["certs"])
    assert TF.peers_for_cert(a.db, cid) == ["peerX"] and TF.peers_for_cert(a.db, cid + 1) == []
    # ---- получатель
    monkeypatch.setattr(settings, "data_dir", tmp_path / "b")
    settings.ensure_dirs()
    api = create_app()
    origin = {"id": "aaaa0000bbbb1111", "name": "web-1"}
    with TestClient(api) as c:
        nm = api.state.nm
        uid = nm.db.one("SELECT id FROM users WHERE username='admin'")["id"]
        h = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'sync', role='admin')}"}
        op = {"Authorization": f"Bearer {nm.auth.create_token(uid, 'op', role='operator')}"}
        body = {"origin": origin, **payload, "overwrite": False, "apply": False}
        assert c.post("/api/sync/sites", headers=op, json=body).status_code == 403
        assert c.post("/api/sync/sites", headers=h, json={**body, "origin": nm.peers.origin()}).status_code == 400
        r = c.post("/api/sync/sites", headers=h, json=body).json()
        assert r["sites"]["created"] == 2 and r["certs"]["created"] == 1, r
        rows = {x["name"]: x for x in nm.db.query("SELECT * FROM sites")}
        shop = json.loads(rows["Магазин"]["data"])
        cert = nm.db.one("SELECT * FROM certificates")
        assert shop["ssl"]["certificate_id"] == cert["id"] and shop["ssl"]["enabled"]
        assert shop["cache"]["zone"] == "default"  # зоны «big» на получателе нет
        assert any("зоны кэша" in n for it in r["sites"]["items"] for n in it["notes"])
        assert shop["ip_access"]["entries"][0]["address"] == "203.0.113.10"
        mark = json.loads(cert["data"])["transfer"]
        assert mark["origin"] == origin["id"] and mark["src_id"] == cid and cert["type"] == "upload"
        assert cert["status"] == "valid"
        # повтор: сайты с теми же доменами пропускаются, их сертификаты не нужны — не сохраняются
        r = c.post("/api/sync/sites", headers=h, json=body).json()
        assert r["sites"]["skipped"] == 2 and r["certs"]["created"] == 0 and r["certs"]["unchanged"] == 0
        # «продление» сертификата, которого здесь нет, — не создаётся
        r = c.post("/api/sync/sites", headers=h, json={"origin": origin, "sites": [], "certs": [
            {**payload["certs"][0], "src_id": 999}]}).json()
        assert r["certs"]["created"] == 0 and nm.db.one("SELECT COUNT(*) n FROM certificates")["n"] == 1
        # замена одноимённых
        body2 = {**body, "overwrite": True}
        body2["sites"][1]["data"]["backends"][0]["port"] = 8081
        r = c.post("/api/sync/sites", headers=h, json=body2).json()
        assert r["sites"]["updated"] == 2 and nm.db.one("SELECT COUNT(*) n FROM sites")["n"] == 2
        assert json.loads(nm.db.one("SELECT data FROM sites WHERE name='Блог'")["data"])["backends"][0]["port"] == 8081
        # продлённый на источнике сертификат: только certs — файлы обновляются на месте
        pem, key = _selfsigned(tmp_path / "renew", "shop.test")
        renewed = {**payload["certs"][0], "cert_pem": pem, "key_pem": key, "fingerprint": "new"}
        r = c.post("/api/sync/sites", headers=h, json={"origin": origin, "sites": [], "certs": [renewed]}).json()
        assert r["certs"]["updated"] == 1 and nm.db.one("SELECT COUNT(*) n FROM certificates")["n"] == 1
        assert Path(nm.db.one("SELECT cert_path FROM certificates")["cert_path"]).read_text().strip() == pem.strip()
        # чужой ключ — файлы не меняются
        _, other_key = _selfsigned(tmp_path / "other", "x.test")
        r = c.post("/api/sync/sites", headers=h, json={"origin": origin, "sites": [], "certs": [
            {**renewed, "key_pem": other_key, "fingerprint": "newer"}]}).json()
        assert r["certs"]["errors"] and "не соответствует" in r["certs"]["errors"][0]
        assert Path(nm.db.one("SELECT cert_path FROM certificates")["cert_path"]).read_text().strip() == pem.strip()
        # без сертификата: HTTPS выключается, если подходящего местного нет
        body3 = {"origin": {"id": "cccc0000dddd2222", "name": "web-9"}, "certs": [], "apply": False,
                 "sites": [{"src_id": 1, "name": "Почта", "enabled": True,
                            "data": Site(name="Почта", domains=["mail.test"],
                                         backends=[Backend(address="10.0.0.7", port=80)],
                                         ssl={"enabled": True, "certificate_id": 77}).model_dump()}]}
        r = c.post("/api/sync/sites", headers=h, json=body3).json()
        assert r["sites"]["created"] == 1 and "HTTPS выключен" in r["sites"]["items"][0]["notes"][0]
        st = c.get("/api/peers", headers=h).json()
        assert st["transfers"][0]["name"] == "web-9" and len(st["transfers"]) == 7
        # применение: при чужих неприменённых изменениях — не применяется
        r = c.post("/api/sync/sites", headers=h, json={**body2, "apply": True}).json()
        assert "неприменённые" in r.get("apply_error", "")


def test_peers_transfer_sender(client, monkeypatch):
    from app.services import peers as P
    nm = client.nm
    now = time.time()
    sid = nm.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                        ("Блог", 1, json.dumps(Site(name="Блог", domains=["blog.test"], backends=[
                            Backend(address="10.0.0.6", port=80)]).model_dump()), now, now))
    nm.save_panel(nm.panel().model_copy(update={"peers": [Peer(name="web-2", url="https://10.0.0.2:8088",
                                                                 token="nm_" + "a" * 30)]}))
    pid = nm.panel().peers[0].id
    got = []

    def fake_call(peer, method, path, body=None, verify=True, timeout=20):
        got.append((path, body))
        if path == "/sync/sites":
            return 200, {"name": "web-2", "sites": {"created": 1, "updated": 0, "skipped": 0, "items": []},
                         "certs": {"created": 0, "updated": 0, "unchanged": 0, "errors": []}}
        return 404, {"detail": "Not Found"}
    monkeypatch.setattr(P, "call", fake_call)
    r = client.post(f"/api/peers/{pid}/transfer", headers=client.h, json={"sites": [sid], "apply": True}).json()
    assert r["ok"] and r["sent"] == 1 and got[0][1]["apply"] is True and got[0][1]["sites"][0]["name"] == "Блог"
    assert client.post(f"/api/peers/{pid}/transfer", headers=client.h, json={"sites": []}).status_code == 400
    assert client.post("/api/peers/nope/transfer", headers=client.h, json={"sites": [sid]}).status_code == 404

    def old_peer(peer, method, path, body=None, verify=True, timeout=20):
        return 404, {"detail": "Not Found"}
    monkeypatch.setattr(P, "call", old_peer)
    r = client.post(f"/api/peers/{pid}/transfer", headers=client.h, json={"sites": [sid]})
    assert r.status_code == 400 and "старая версия" in r.json()["detail"]
    assert client.post(f"/api/peers/{pid}/transfer", headers=client.op, json={"sites": [sid]}).status_code == 403
    # продлённый сертификат уходит туда, куда переносился
    from app.models import CertificateRequest
    cid = nm.certs.create(CertificateRequest(type="selfsigned", domains=["blog.test"]), "t")
    monkeypatch.setattr(P, "call", fake_call)
    assert nm.peers.push_cert(cid) == {}  # ещё никуда не переносился
    TF.remember(nm.db, pid, [{"src_id": cid, "fingerprint": "old"}])
    got.clear()
    assert nm.peers.push_cert(cid)[pid]["ok"]
    assert got[0][0] == "/sync/sites" and got[0][1]["sites"] == [] and got[0][1]["certs"][0]["src_id"] == cid


def test_ip_denials_api(client):
    nm = client.nm
    now = int(time.time()) // 60 * 60
    nm.db.executemany("INSERT INTO ipdeny_minute(ts, site, ip, n, uri, country) VALUES(?,?,?,?,?,?)",
                      [(now - 120, "3", "198.51.100.9", 5, "/admin", "NL"), (now - 60, "3", "198.51.100.9", 2,
                                                                             "/wp-login.php", "NL"),
                       (now - 60, "3", "192.0.2.5", 1, "/", ""), (now - 60, "4", "192.0.2.99", 9, "/", "")])
    d = client.get("/api/sites/3/ip-denials", headers=client.h, params={"hours": 6}).json()
    assert d["total"] == 8 and d["ips"] == 2 and d["step"] == 300
    assert d["top"][0]["ip"] == "198.51.100.9" and d["top"][0]["n"] == 7 and d["top"][0]["uri"] == "/wp-login.php"
    assert sum(x[1] for x in d["series"]) == 8
    assert client.get("/api/sites/3/ip-denials", headers=client.h, params={"hours": 168}).json()["step"] == 3600
