"""Сертификаты, блокировки и кнопки Telegram в нетиповых ситуациях: цепочка в обратном порядке, чужой ключ,
зашифрованный ключ, истёкший сертификат, файлы пропали; блокировка loopback и слишком широких сетей; подделанные
и устаревшие кнопки, чужой чат, пользователь не из списка, команды с мусором."""
from __future__ import annotations

import asyncio
import json
import subprocess
import time
from pathlib import Path

import pytest

from app.config import settings
from app.models import AlertChannel, CertificateRequest
from app.services import certs as CS
from app.services import tgbot as TG


@pytest.fixture()
def nm(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    api = create_app()
    with TestClient(api):
        yield api.state.nm


def _ssl(*args, cwd):
    subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=cwd)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """Свой центр: корневой → промежуточный → сайт; плюс чужой ключ, зашифрованный ключ, истёкший сертификат."""
    d = tmp_path_factory.mktemp("pki")
    _ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "3",
         "-subj", "/CN=Test Root", cwd=d)
    _ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "int.key", "-out", "int.csr", "-subj", "/CN=Test Int",
         cwd=d)
    (d / "ext.cnf").write_text("basicConstraints=CA:TRUE\n")
    _ssl("x509", "-req", "-in", "int.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out",
         "int.pem", "-days", "3", "-extfile", "ext.cnf", cwd=d)
    _ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "site.key", "-out", "site.csr", "-subj",
         "/CN=shop.test", cwd=d)
    (d / "san.cnf").write_text("subjectAltName=DNS:shop.test,DNS:*.shop.test\n")
    _ssl("x509", "-req", "-in", "site.csr", "-CA", "int.pem", "-CAkey", "int.key", "-CAcreateserial", "-out",
         "site.pem", "-days", "3", "-extfile", "san.cnf", cwd=d)
    _ssl("genpkey", "-algorithm", "RSA", "-out", "other.key", cwd=d)
    _ssl("pkey", "-in", "site.key", "-aes256", "-passout", "pass:secret", "-out", "enc.key", cwd=d)
    return {k: (d / f).read_text() for k, f in (("site", "site.pem"), ("int", "int.pem"), ("key", "site.key"),
                                                 ("other", "other.key"), ("enc", "enc.key"))}


# =============================================================================
#  Сертификаты
# =============================================================================
def test_upload_variants(nm, pki):
    svc = nm.certs

    def up(cert, key, name="x"):
        return svc.create(CertificateRequest(type="upload", name=name, cert_pem=cert, key_pem=key), "admin")
    cid = up(pki["site"] + "\n" + pki["int"], pki["key"], "правильный порядок")
    c = svc.get(cid)
    assert c["status"] == "valid" and c["domains"] == ["*.shop.test", "shop.test"] and c["data"]["chain_len"] == 2
    # цепочка в обратном порядке — исправляется сама (сертификат сайта первым)
    cid2 = up(pki["int"] + "\n" + pki["site"], pki["key"], "обратный порядок")
    full = Path(svc.get(cid2)["cert_path"]).read_text()
    assert full.startswith("-----BEGIN CERTIFICATE-----") and CS.PEM_CERT_RE.findall(full)[0].strip() == pki["site"].strip()
    assert svc.get(cid2)["status"] == "valid" and not list(Path(svc.get(cid2)["cert_path"]).parent.glob(".chain*"))
    # чужой ключ, зашифрованный ключ, не PEM — понятные отказы, запись не остаётся
    before = nm.db.scalar("SELECT COUNT(*) FROM certificates")
    for cert, key, msg in ((pki["site"] + pki["int"], pki["other"], "не соответствует"),
                           (pki["site"], pki["enc"], "зашифрован"), ("MIIB...", pki["key"], "PEM"),
                           (pki["site"], "ключ", "PEM")):
        with pytest.raises(ValueError, match=msg):
            up(cert, key)
    assert nm.db.scalar("SELECT COUNT(*) FROM certificates") == before
    # файлы пропали — статус «нет файла»; ключ удалён — ошибка
    path = Path(svc.get(cid)["key_path"])
    path.unlink()
    svc.refresh_all()
    assert svc.get(cid)["status"] == "error" and "ключа" in svc.get(cid)["last_error"]
    Path(svc.get(cid)["cert_path"]).unlink()
    svc.refresh_all()
    assert svc.get(cid)["status"] == "missing"
    # испорченный файл сертификата
    Path(svc.get(cid2)["cert_path"]).write_text("-----BEGIN CERTIFICATE-----\nmusor\n-----END CERTIFICATE-----\n")
    svc.refresh_all()
    assert svc.get(cid2)["status"] == "error"


def test_path_selfsigned_delete(nm, pki, tmp_path):
    svc = nm.certs
    with pytest.raises(ValueError, match="Файл не найден"):
        svc.create(CertificateRequest(type="path", name="p", cert_path=str(tmp_path / "нет"),
                                      key_path=str(tmp_path / "нет")), "a")
    with pytest.raises(ValueError, match="домен"):
        svc.create(CertificateRequest(type="selfsigned", name="s", domains=[]), "a")
    cid = svc.create(CertificateRequest(type="selfsigned", name="s", domains=["a.test", "b.test"]), "a")
    assert svc.get(cid)["data"]["self_signed"] and svc.get(cid)["status"] == "valid"
    asyncio.run(svc.renew(cid))
    with pytest.raises(ValueError, match="не найден"):
        asyncio.run(svc.renew(99999))
    from tests.test_settings_backup import _insert, _site
    _insert(nm.db, _site("A", "a.test", ssl={"enabled": True, "certificate_id": cid}))
    with pytest.raises(ValueError, match="используется сайтом"):
        svc.delete(cid)
    nm.save_panel(nm.panel().model_copy(update={"panel_certificate_id": 12345}))
    cid2 = svc.create(CertificateRequest(type="selfsigned", name="s2", domains=["c.test"]), "a")
    svc.delete(cid2)
    assert svc.get(cid2) is None and not (settings.certs_dir / str(cid2)).exists()
    svc.delete(99999)  # нет такого — без ошибки


@pytest.mark.parametrize("domain,cert,ok", [
    ("shop.test", ["shop.test"], True), ("SHOP.test", ["shop.TEST"], True), ("a.shop.test", ["*.shop.test"], True),
    ("shop.test", ["*.shop.test"], False), ("a.b.shop.test", ["*.shop.test"], False), ("x.test", [], False),
])
def test_domain_covered(domain, cert, ok):
    assert CS.domain_covered(domain, cert) is ok


def test_parse_date_and_forget_account(tmp_path):
    assert CS._parse_date("Nov 24 10:00:00 2026 GMT") and CS._parse_date("Nov  4 10:00:00 2026 GMT")
    assert CS._parse_date("мусор") is None
    acc = tmp_path / "acme-v02.api.letsencrypt.org" / "directory"
    for name, uri in (("a1", "https://x/acct/1"), ("a2", "https://x/acct/2"), ("a3", None)):
        (acc / name).mkdir(parents=True)
        if uri:
            (acc / name / "regr.json").write_text(json.dumps({"uri": uri}))
    server = "https://acme-v02.api.letsencrypt.org/directory"
    assert CS.forget_acme_account(server, "https://x/acct/2", base=str(tmp_path)) == 1
    assert sorted(p.name for p in acc.iterdir()) == ["a1", "a3"]
    assert CS.forget_acme_account(server, base=str(tmp_path)) == 2
    assert CS.forget_acme_account("https://other.example/dir", base=str(tmp_path)) == 0


def test_http01_selftest_edges(nm, monkeypatch):
    import socket
    import urllib.request
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(socket.gaierror("no name")))
    r = nm.certs.http01_selftest("нет.test")
    assert not r["ok"] and r["error"].startswith("DNS")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.5", 80))])
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError("refused")))
    r = nm.certs.http01_selftest("shop.test")
    assert not r["ok"] and not r["local"] and "nginx не отдаёт" in r["error"] and r["dns"] == ["203.0.113.5"]
    d = settings.acme_webroot / ".well-known" / "acme-challenge"
    assert not list(d.glob("nm-selftest-*"))  # файл проверки удалён и при ошибке


def test_auto_renew_backoff(nm, monkeypatch):
    now = time.time()
    cid = nm.db.execute("INSERT INTO certificates(name, type, domains, status, not_before, not_after, created_at, "
                        "updated_at) VALUES(?,?,?,?,?,?,?,?)", ("le", "letsencrypt", "[]", "valid", now - 80 * 86400,
                                                                now + 5 * 86400, now, now))
    runs = []

    async def fake(cid_, after, renew=False):
        runs.append(cid_)
    monkeypatch.setattr(nm.certs, "_run_certbot", fake)
    assert asyncio.run(nm.certs.auto_renew()) == [cid]
    nm.certs.jobs[cid] = {"state": "error", "finished": time.time()}  # только что не удалось — пауза
    assert asyncio.run(nm.certs.auto_renew()) == []
    nm.certs.jobs[cid] = {"state": "running"}
    assert asyncio.run(nm.certs.auto_renew()) == []
    nm.certs.jobs[cid] = {"state": "error", "finished": time.time() - 7 * 3600}
    assert asyncio.run(nm.certs.auto_renew()) == [cid] and runs == [cid, cid]


# =============================================================================
#  Блокировки
# =============================================================================
@pytest.mark.parametrize("net,msg", [("127.0.0.1", "loopback"), ("127.5.0.0/16", "loopback"), ("::1", "loopback"),
                                     ("0.0.0.0/0", "широкая"), ("10.0.0.0/7", "широкая"), ("", "пустой"),
                                     ("мусор", "")])
def test_ban_refuses(nm, net, msg):
    with pytest.raises(ValueError, match=msg):
        nm.bans.add(net, 60, "тест")


def test_ban_trusted_and_escalation(nm):
    nm.save_panel(nm.panel().model_copy(update={"trusted_ips": [{"address": "198.51.100.0/24", "comment": "офис"}]}))
    with pytest.raises(ValueError, match="доверенных.*офис"):
        nm.bans.add("198.51.100.7", 60)
    with pytest.raises(ValueError, match="доверенных"):
        nm.bans.add("198.51.0.0/16", 60)  # подсеть, включающая доверенную
    r = nm.bans.add("203.0.113.9/32", None, "бессрочно")
    assert r == {"net": "203.0.113.9", "expires_at": None}
    r2 = nm.bans.add("203.0.113.9", 5, "повтор")
    assert r2["expires_at"] and nm.db.one("SELECT offenses FROM bans WHERE net='203.0.113.9'")["offenses"] == 2
    nm.db.execute("UPDATE bans SET expires_at=?", (time.time() - 1,))
    assert nm.bans.expire() == 1 and nm.bans.remove(999) is None


# =============================================================================
#  Кнопки и команды Telegram
# =============================================================================
def _tg_channel(nm, admins=()):
    ch = AlertChannel(name="tg", type="telegram", telegram_token="123:ABC", telegram_chat_id="-100",
                      telegram_actions=True, telegram_admins=list(admins))
    nm.db.execute("INSERT INTO alert_channels(name, type, data, created_at, updated_at) VALUES(?,?,?,?,?)",
                  ("tg", "telegram", ch.model_dump_json(), time.time(), time.time()))
    return ch


def test_telegram_callbacks(nm, monkeypatch):
    ch = _tg_channel(nm, admins=["@boss", "424242"])
    bot = TG.TelegramActions(nm)
    monkeypatch.setattr(TG, "spawn_sync", lambda app: None)
    key = TG.secret(nm.db)
    good = TG.callback_data(key, "b", "2001:db8::5")
    assert len(good.encode()) <= 64 and TG.parse_callback(key, good) == ("b", "2001:db8::5")
    for bad in ("", "nm1:b", "nm2:b:1.2.3.4:x", "nm1:z:1.2.3.4:" + TG.sign(key, "z", "1.2.3.4"),
                good[:-1] + ("0" if good[-1] != "0" else "1"), TG.callback_data(key, "b", "мусор"),
                TG.callback_data(key, "g", "abc")):
        assert TG.parse_callback(key, bad) is None
    msg = {"chat": {"id": -100}, "message_id": 7}
    assert bot.handle(ch, {"data": "подделка", "message": msg}) == "Кнопка устарела или подделана"
    assert "только в чате" in bot.handle(ch, {"data": good, "message": {"chat": {"id": -999}},
                                              "from": {"id": 424242}})
    assert "Нет прав" in bot.handle(ch, {"data": good, "message": msg, "from": {"id": 7, "username": "intruder"}})
    assert "заблокирован на сутки" in bot.handle(ch, {"data": good, "message": msg, "from": {"username": "boss"}})
    # разблокировать дважды; заблокировать loopback — отказ с текстом, а не исключение
    unban = TG.callback_data(key, "u", "2001:db8::5")
    assert "разблокирован" in bot.handle(ch, {"data": unban, "message": msg, "from": {"id": 424242}})
    assert "уже не заблокирован" in bot.handle(ch, {"data": unban, "message": msg, "from": {"id": 424242}})
    lo = TG.callback_data(key, "b", "127.0.0.1")
    assert bot.handle(ch, {"data": lo, "message": msg, "from": {"id": 424242}}).startswith("Не выполнено")
    assert "закрыт" in bot.handle(ch, {"data": TG.callback_data(key, "g", "999"), "message": msg,
                                       "from": {"id": 424242}})


def test_telegram_commands(nm, monkeypatch):
    ch = _tg_channel(nm)
    bot = TG.TelegramActions(nm)
    monkeypatch.setattr(TG, "spawn_sync", lambda app: None)

    def cmd(text, chat=-100):
        return bot.command(ch, {"text": text, "chat": {"id": chat}, "from": {"id": 1, "username": "u"}})
    assert cmd("привет") is None and cmd("/unknown") is None and cmd("/status", chat=5) is None
    assert "nginx:" in cmd("/status@nm_bot")[0] and cmd("/help")[0] == TG.HELP
    assert cmd("/top")[0] == "За последний час атак не было"
    assert "Укажите адрес" in cmd("/ban")[0] and "Укажите адрес" in cmd("/ip мусор")[0]
    assert "число часов" in cmd("/ban 203.0.113.5 много")[0]
    assert "заблокирован на 6 ч" in cmd("/ban 203.0.113.5 6")[0]
    assert "заблокирован" in cmd("/ban 203.0.113.6 999999")[0]  # срок ограничен годом
    exp = nm.db.one("SELECT expires_at FROM bans WHERE net='203.0.113.6'")["expires_at"]
    assert exp - time.time() <= 365 * 86400 + 5
    text, kb = cmd("/ip 203.0.113.5")
    assert "Заблокирован" in text and kb["inline_keyboard"][0][0]["callback_data"].startswith("nm1:u:")
    assert "разблокирован" in cmd("/unban 203.0.113.5")[0]
    assert TG.actions_for("bans", "Автоблокировка 1.2.3.4", {"ip": "1.2.3.4"}) == ("1.2.3.4", ["u", "r"])
    assert TG.actions_for("x", "", {"ip": "мусор"}) == ("", []) and TG.actions_for("x", "", None) == ("", [])
    assert TG.actions_for("access", "", {"grant": "5"}) == ("5", ["g"])


def test_telegram_poll_once(nm, monkeypatch):
    ch = _tg_channel(nm)
    bot = TG.TelegramActions(nm)
    monkeypatch.setattr(TG, "spawn_sync", lambda app: None)
    sent = []
    updates = {"ok": True, "result": [
        {"update_id": 10, "message": {"text": "/status", "chat": {"id": -100}, "message_id": 1, "from": {"id": 1}}},
        {"update_id": 11, "message": {"text": "просто текст", "chat": {"id": -100}}},
        {"update_id": 12, "callback_query": {"id": "q", "data": "подделка", "message": {"message_id": 3,
                                                                                     "chat": {"id": -100}}}},
        {"update_id": 13, "edited_message": {}}]}

    def fake_api(base, token, method, payload, timeout=35):
        sent.append((method, payload))
        return updates if method == "getUpdates" else {"ok": True}
    monkeypatch.setattr(TG, "api", fake_api)
    assert bot.poll_once("k", ch, timeout=1) == 2 and bot.offsets["k"] == 14
    methods = [m for m, _ in sent]
    assert methods == ["getUpdates", "sendMessage", "answerCallbackQuery", "sendMessage"]
    monkeypatch.setattr(TG, "api", lambda *a, **k: {"ok": False, "description": "Unauthorized"})
    with pytest.raises(ValueError, match="Unauthorized"):
        bot.poll_once("k", ch, timeout=1)
