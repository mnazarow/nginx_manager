"""ACME: центры сертификации, DNS-проверка (учётные записи DNS, файлы учётных данных, команда certbot), продление.

Сквозной выпуск против настоящего ACME-сервера (Pebble) и DNS-сервера (BIND) — tools/acme_e2e.py на стенде.
"""
import json
import os
import stat
import time

import pytest
from fastapi.testclient import TestClient

from app.models import CertificateRequest, DnsAccount, PanelSettings
from app.services import acme
from app.services.certs import certbot_hint, renew_threshold

PW = "Acme-Passw0rd!"
H = {"X-NM-CSRF": "1"}
MASK = "••••••••"


# ----------------------------------------------------------------------------- чистые функции
def test_certbot_command_http_and_dns():
    http = acme.certbot_command("/usr/bin/certbot", cert_name="nm-a", domains=["a.example.com", "www.a.example.com"],
                                server=acme.CA_DIRECTORIES["letsencrypt"], email="ops@example.com", key_type="ecdsa",
                                webroot="/var/lib/nginx-manager/acme")
    assert http[:2] == ["/usr/bin/certbot", "certonly"]
    assert ["--webroot", "-w", "/var/lib/nginx-manager/acme"] == http[http.index("--webroot"):http.index("--webroot") + 3]
    assert http.count("-d") == 2 and "--force-renewal" not in http and "-m" in http
    assert http[http.index("--server") + 1] == "https://acme-v02.api.letsencrypt.org/directory"
    dns = acme.certbot_command("certbot", cert_name="nm-b", domains=["*.example.com", "example.com"],
                               server="https://ca.internal/dir", email="", key_type="rsa", challenge="dns",
                               dns_args=["--authenticator", "dns-cloudflare"], eab=("kid1", "c2VjcmV0LWhtYWM"),
                               renew=True)
    assert "--webroot" not in dns and "--authenticator" in dns and "--force-renewal" in dns
    assert "--register-unsafely-without-email" in dns
    assert dns[dns.index("--eab-kid") + 1] == "kid1"
    assert "c2VjcmV0LWhtYWM" not in acme.redact(dns) and "kid1" in acme.redact(dns)


def test_directory_presets():
    assert acme.directory_for(PanelSettings()) == acme.CA_DIRECTORIES["letsencrypt"]
    assert acme.directory_for(PanelSettings(letsencrypt_staging=True)) == acme.CA_DIRECTORIES["letsencrypt-staging"]
    assert acme.directory_for(PanelSettings(), staging=True) == acme.CA_DIRECTORIES["letsencrypt-staging"]
    assert acme.directory_for(PanelSettings(acme_ca="zerossl")) == acme.CA_DIRECTORIES["zerossl"]
    p = PanelSettings(acme_ca="custom", acme_directory="https://ca.internal:9000/acme/acme/directory")
    assert acme.directory_for(p) == "https://ca.internal:9000/acme/acme/directory"
    assert acme.ca_title(acme.CA_DIRECTORIES["google"]) == "Google Trust Services"
    with pytest.raises(ValueError):
        PanelSettings(acme_ca="custom", acme_directory="http://ca.internal/dir")  # только https
    with pytest.raises(ValueError):
        PanelSettings(acme_eab_hmac="есть пробел")


def test_credentials_files_and_args(tmp_path, monkeypatch):
    monkeypatch.setattr(acme, "creds_dir", lambda: tmp_path / "dns")
    cf = DnsAccount(name="CF", provider="cloudflare", cf_api_token="tok-123", propagation_seconds=30)
    args, env = acme.write_credentials(7, cf)
    ini = tmp_path / "dns" / "7.ini"
    assert args == ["--authenticator", "dns-cloudflare", "--dns-cloudflare-credentials", str(ini),
                    "--dns-cloudflare-propagation-seconds", "30"] and env == {}
    assert "dns_cloudflare_api_token = tok-123" in ini.read_text()
    assert stat.S_IMODE(ini.stat().st_mode) == 0o600 and stat.S_IMODE((tmp_path / "dns").stat().st_mode) == 0o700
    rfc = DnsAccount(name="BIND", provider="rfc2136", rfc_server="192.0.2.53", rfc_key_name="acme-key",
                     rfc_key_secret="c2VjcmV0", rfc_algorithm="HMAC-SHA256")
    args, _ = acme.write_credentials(8, rfc)
    text = (tmp_path / "dns" / "8.ini").read_text()
    assert "dns_rfc2136_server = 192.0.2.53" in text and "dns_rfc2136_algorithm = HMAC-SHA256" in text
    assert "dns_rfc2136_port = 53" in text and args[1] == "dns-rfc2136"
    r53 = DnsAccount(name="AWS", provider="route53", aws_access_key_id="AKIAEXAMPLE", aws_secret_access_key="s3cr3t")
    args, env = acme.write_credentials(9, r53)
    assert args == ["--authenticator", "dns-route53"] and env["AWS_SHARED_CREDENTIALS_FILE"].endswith("9.aws")
    g = DnsAccount(name="G", provider="google", google_json=json.dumps({"type": "service_account", "client_email": "a@b"}))
    args, _ = acme.write_credentials(10, g)
    assert args[-2:] == ["--dns-google-credentials", str(tmp_path / "dns" / "10.json")]
    hook = DnsAccount(name="Hook", provider="hook", hook_auth="/usr/local/bin/add.sh", hook_cleanup="/usr/local/bin/del.sh")
    args, _ = acme.write_credentials(11, hook)
    assert args == ["--manual", "--preferred-challenges", "dns", "--manual-auth-hook", "/usr/local/bin/add.sh",
                    "--manual-cleanup-hook", "/usr/local/bin/del.sh"]
    acme.remove_credentials(7)
    assert not ini.exists()


def test_dns_account_validation():
    with pytest.raises(ValueError, match="Заполните"):
        DnsAccount(name="x", provider="cloudflare")
    with pytest.raises(ValueError, match="IP-адрес"):
        DnsAccount(name="x", provider="rfc2136", rfc_server="ns1.example.com", rfc_key_name="k", rfc_key_secret="s")
    with pytest.raises(ValueError, match="одна строка"):
        DnsAccount(name="x", provider="cloudflare", cf_api_token="a b")
    with pytest.raises(ValueError):  # в файл .ini нельзя дописать строку
        DnsAccount(name="x", provider="cloudflare", cf_api_token="tok\ndns_cloudflare_email = x")
    with pytest.raises(ValueError, match="Абсолютный путь"):
        DnsAccount(name="x", provider="hook", hook_auth="add.sh; rm -rf /")
    with pytest.raises(ValueError, match="service_account"):
        DnsAccount(name="x", provider="google", google_json='{"type": "user"}')
    with pytest.raises(ValueError, match="wildcard"):
        CertificateRequest(type="letsencrypt", domains=["*.example.com"])
    with pytest.raises(ValueError, match="учётную запись DNS"):
        CertificateRequest(type="letsencrypt", domains=["example.com"], challenge="dns")
    ok = CertificateRequest(type="letsencrypt", domains=["*.example.com", "example.com"], challenge="dns", dns_account_id=3)
    assert ok.domains == ["*.example.com", "example.com"]
    assert CertificateRequest(type="selfsigned", domains=["*.example.com"]).domains == ["*.example.com"]


def test_renew_threshold_short_certs():
    day, t0 = 86400, 1_700_000_000
    assert renew_threshold(t0, t0 + 90 * day, 30) == 30 * day      # обычный 90-дневный — за 30 дней
    assert renew_threshold(t0, t0 + 45 * day, 30) == 15 * day      # 45-дневный — за треть срока
    assert renew_threshold(t0, t0 + 6 * day, 30) == 2 * day        # шестидневный — за 2 дня, а не постоянно
    assert renew_threshold(None, t0 + 90 * day, 30) == 30 * day    # срок неизвестен — по настройке


def test_certbot_hints_dns():
    assert "TXT" in certbot_hint("Detail: No TXT record found at _acme-challenge.example.com")
    assert "TSIG" in certbot_hint("Received response from server: NOTAUTH")
    assert "EAB" in certbot_hint("urn:ietf:params:acme:error:externalAccountRequired")
    assert "корневой сертификат" in certbot_hint("SSL: CERTIFICATE_VERIFY_FAILED")
    assert "Зона" in certbot_hint("Unable to determine zone identifier for example.com")


# ----------------------------------------------------------------------------- API
@pytest.fixture(scope="module")
def client():
    from app.main import create_app
    from app.utils import hash_password
    app = create_app()
    with TestClient(app) as c:
        app.state.nm.db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username='admin'",
                                (hash_password(PW),))
        yield c


@pytest.fixture(scope="module")
def admin(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": PW})
    assert r.status_code == 200, r.text
    return client


def test_dns_accounts_api(admin, client, monkeypatch):
    monkeypatch.setattr(acme, "installed_plugins", lambda refresh=False: {"webroot", "dns-cloudflare"})
    acc = {"name": "Cloudflare: example.com", "provider": "cloudflare", "cf_api_token": "tok-secret-1"}
    r = admin.post("/api/dns-accounts", json=acc, headers=H)
    assert r.status_code == 200, r.text
    aid = r.json()["id"]
    lst = admin.get("/api/dns-accounts").json()
    item = next(a for a in lst["items"] if a["id"] == aid)
    assert item["data"]["cf_api_token"] == MASK and item["plugin"] is True and item["used_by"] == []
    assert "tok-secret-1" not in json.dumps(lst)
    # маска — оставить прежний секрет
    r = admin.put(f"/api/dns-accounts/{aid}", json=dict(item["data"], name="CF основной"), headers=H)
    assert r.status_code == 200, r.text
    nmapp = client.app.state.nm
    assert nmapp.certs.dns_account(aid).cf_api_token == "tok-secret-1"
    assert admin.post(f"/api/dns-accounts/{aid}/check", headers=H).json()["ok"] is True
    # сертификат с DNS-проверкой использует запись — удалить нельзя
    cid = nmapp.db.execute("INSERT INTO certificates(name,type,domains,status,data,created_at,updated_at) "
                           "VALUES(?,?,?,?,?,?,?)", ("wild", "letsencrypt", '["*.example.com"]', "valid",
                                                     json.dumps({"challenge": "dns", "dns_account_id": aid}),
                                                     time.time(), time.time()))
    r = admin.delete(f"/api/dns-accounts/{aid}", headers=H)
    assert r.status_code == 400 and "wild" in r.json()["detail"]
    assert next(a for a in admin.get("/api/dns-accounts").json()["items"] if a["id"] == aid)["used_by"] == ["wild"]
    # смена секрета переписывает файл учётных данных, на который ссылается продление certbot
    admin.put(f"/api/dns-accounts/{aid}", json=dict(item["data"], cf_api_token="tok-secret-2"), headers=H)
    ini = acme.creds_dir() / f"{aid}.ini"
    assert "tok-secret-2" in ini.read_text() and stat.S_IMODE(ini.stat().st_mode) == 0o600
    # экспорт и импорт переносят учётную запись и ссылку на неё
    exp = admin.get("/api/backup/export").json()
    assert any(a["id"] == aid for a in exp["dns_accounts"])
    for c in exp["certificates"]:
        if c["name"] == "wild":
            c["name"] = "wild-copy"
    r = admin.post("/api/backup/import", params={"mode": "merge"}, json=exp, headers=H)
    assert r.status_code == 200, r.text
    copy = nmapp.db.one("SELECT id, data FROM certificates WHERE name='wild-copy'")
    new_aid = json.loads(copy["data"])["dns_account_id"]
    assert new_aid != aid and nmapp.certs.dns_account(new_aid).cf_api_token == "tok-secret-2"
    nmapp.db.execute("DELETE FROM certificates WHERE id IN (?, ?)", (cid, copy["id"]))
    admin.delete(f"/api/dns-accounts/{new_aid}", headers=H)
    assert admin.delete(f"/api/dns-accounts/{aid}", headers=H).status_code == 200
    assert not ini.exists()


def test_dns_accounts_roles_and_cert_request(admin, client, monkeypatch):
    monkeypatch.setattr(acme, "installed_plugins", lambda refresh=False: {"webroot"})
    nmapp = client.app.state.nm
    from app.utils import hash_password
    nmapp.db.execute("INSERT INTO users(username,password_hash,role,created_at,must_change_password) "
                     "VALUES('acmeop',?,'operator',?,0)", (hash_password(PW), time.time()))
    op = TestClient(client.app)
    assert op.post("/api/auth/login", json={"username": "acmeop", "password": PW}).status_code == 200
    acc = {"name": "BIND", "provider": "rfc2136", "rfc_server": "127.0.0.1", "rfc_key_name": "k", "rfc_key_secret": "c2VjcmV0"}
    assert op.post("/api/dns-accounts", json=acc, headers=H).status_code == 403   # секреты — только администратор
    aid = admin.post("/api/dns-accounts", json=acc, headers=H).json()["id"]
    assert op.get("/api/dns-accounts").json()["items"][0]["data"]["rfc_key_secret"] == MASK
    # wildcard без DNS-проверки — ошибка проверки данных, плагина нет — понятный отказ
    r = op.post("/api/certs", json={"type": "letsencrypt", "domains": ["*.example.com"]}, headers=H)
    assert r.status_code == 422 and "DNS" in json.dumps(r.json(), ensure_ascii=False)
    r = op.post("/api/certs", json={"type": "letsencrypt", "domains": ["*.example.com"], "challenge": "dns",
                                    "dns_account_id": aid}, headers=H)
    if nmapp.certs.certbot():
        assert r.status_code == 400 and "плагин" in r.json()["detail"], r.text
    admin.delete(f"/api/dns-accounts/{aid}", headers=H)
    nmapp.db.execute("DELETE FROM users WHERE username='acmeop'")


def test_panel_eab_secret_masked(admin):
    p = admin.get("/api/settings/panel").json()
    p.update(acme_ca="zerossl", acme_eab_kid="kid-abc", acme_eab_hmac="aG1hYy1zZWNyZXQtdmFsdWU")
    assert admin.put("/api/settings/panel", json=p, headers=H).status_code == 200
    got = admin.get("/api/settings/panel").json()
    assert got["acme_eab_hmac"] == MASK and got["acme_eab_kid"] == "kid-abc"
    assert admin.put("/api/settings/panel", json=got, headers=H).status_code == 200   # маска сохраняет секрет
    certs = admin.get("/api/certs").json()
    assert certs["ca"] == "ZeroSSL"
    got.update(acme_ca="letsencrypt", acme_eab_kid="", acme_eab_hmac="")
    assert admin.put("/api/settings/panel", json=got, headers=H).status_code == 200


def test_certbot_command_used_by_service(monkeypatch, tmp_path):
    """Сервис сертификатов собирает команду из данных сертификата: тот же центр, DNS-аргументы, окружение."""
    import asyncio

    from app.core import App
    calls = []

    def fake_run(cmd, timeout=60, input=None, env=None):
        calls.append((cmd, env))
        return 1, "Detail: No TXT record found at _acme-challenge.example.com"
    monkeypatch.setattr("app.services.certs.run", fake_run)
    monkeypatch.setattr(acme, "creds_dir", lambda: tmp_path / "dns")

    async def go():
        app = App()
        aid = app.db.execute("INSERT INTO dns_accounts(name,provider,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                             ("R53", "route53", json.dumps(DnsAccount(name="R53", provider="route53",
                                                                       aws_access_key_id="AKIA1",
                                                                       aws_secret_access_key="s").model_dump()), 0, 0))
        cid = app.db.execute("INSERT INTO certificates(name,type,domains,status,data,created_at,updated_at) "
                             "VALUES(?,?,?,?,?,?,?)", ("w", "letsencrypt", '["*.example.com"]', "valid",
                                                       json.dumps({"challenge": "dns", "dns_account_id": aid,
                                                                   "server": "https://ca.example/dir",
                                                                   "cert_name": "nm-w", "key_type": "ecdsa"}), 0, 0))
        monkeypatch.setattr(app.certs, "certbot", lambda: "/usr/bin/certbot")
        await app.certs._run_certbot(cid, renew=True)
        job = app.certs.jobs[cid]
        row = app.db.one("SELECT status, last_error FROM certificates WHERE id=?", (cid,))
        app.db.close()
        return job, row
    job, row = asyncio.run(go())
    cmd, env = calls[-1]
    assert cmd[cmd.index("--server") + 1] == "https://ca.example/dir" and "--authenticator" in cmd
    assert env["AWS_SHARED_CREDENTIALS_FILE"].endswith(".aws") and "--force-renewal" in cmd
    assert job["state"] == "error" and "TXT" in job["error"]
    assert row["status"] == "valid" and "TXT" in row["last_error"]  # неудачное продление не портит действующий
    assert os.path.exists(env["AWS_SHARED_CREDENTIALS_FILE"])


def test_expiry_levels_respect_lifetime():
    from app.services.certs import expiry_level, fmt_left, lifetime_days
    day, t0 = 86400, 1_700_000_000
    c90 = {"not_before": t0, "not_after": t0 + 90 * day}
    assert lifetime_days(c90) == 90
    assert expiry_level(dict(c90, days_left=30)) is None
    assert expiry_level(dict(c90, days_left=15)) == "warn" and expiry_level(dict(c90, days_left=5)) == "crit"
    c1 = {"not_before": t0, "not_after": t0 + day}                       # step-ca: сертификат на сутки
    assert expiry_level(dict(c1, days_left=0.6)) is None                   # обычное состояние — без тревоги
    assert expiry_level(dict(c1, days_left=0.15)) == "warn"               # продление явно опаздывает
    assert expiry_level(dict(c1, days_left=0.05)) == "crit"
    assert expiry_level({"days_left": None}) is None
    assert fmt_left(0.5) == "12 ч" and fmt_left(10.2) == "10 дн."


def test_cert_expiry_alert_metric_short_certs():
    """Метрика оповещения «Сертификат скоро истечёт» не тревожит из-за коротких сертификатов, пока они продлеваются."""
    import asyncio

    from app.core import App
    from app.models import AlertRule

    async def go():
        app = App()
        now, day = time.time(), 86400
        app.certs.list = lambda: [
            {"name": "short", "domains": ["a.example.com"], "days_left": 0.6, "not_before": now - 0.4 * day,
             "not_after": now + 0.6 * day, "used_by": ["A"]},
            {"name": "long", "domains": ["b.example.com"], "days_left": 60, "not_before": now - 30 * day,
             "not_after": now + 60 * day, "used_by": ["B"]}]
        v1, _ = app.metric(AlertRule(name="c", metric="cert_expiry", operator="<", threshold=14))
        app.certs.list = lambda: [
            {"name": "short", "domains": ["a.example.com"], "days_left": 0.1, "not_before": now - 0.9 * day,
             "not_after": now + 0.1 * day, "used_by": ["A"]}]
        v2, msg = app.metric(AlertRule(name="c", metric="cert_expiry", operator="<", threshold=14))
        app.db.close()
        return v1, v2, msg
    v1, v2, msg = asyncio.run(go())
    assert v1 == 60                     # короткий в норме — значение по длинному
    assert v2 == 0.1 and "short" in msg  # короткий не продлился — тревога
