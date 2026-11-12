"""Сертификаты: самоподписанные, загрузка PEM (с проверкой пары и формата), файлы на диске, удаление."""
import os
import shutil
import subprocess
import time

import pytest

from app.config import settings
from app.db import Database
from app.models import CertificateRequest, PanelSettings
from app.services.certs import CertificateService, domain_covered

TMP = os.environ["NM_TEST_TMP"]
pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="нужен openssl")


@pytest.fixture(scope="module")
def svc():
    settings.ensure_dirs()
    db = Database(f"{TMP}/certs.db")
    yield CertificateService(db, lambda: PanelSettings())
    db.close()


def make_pair(name, days=30, key="ec"):
    d = f"{TMP}/pem-{name}"
    os.makedirs(d, exist_ok=True)
    args = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"] if key == "ec" else ["-newkey", "rsa:2048"]
    subprocess.run(["openssl", "req", "-x509", "-nodes", *args, "-days", str(days), "-keyout", f"{d}/key.pem",
                    "-out", f"{d}/cert.pem", "-subj", f"/CN={name}.test", "-addext", f"subjectAltName=DNS:{name}.test"],
                   capture_output=True, check=True)
    return open(f"{d}/cert.pem").read(), open(f"{d}/key.pem").read(), d


def test_selfsigned(svc):
    for kt in ("ecdsa", "rsa"):
        cid = svc.create(CertificateRequest(type="selfsigned", domains=["a.test", "*.a.test"], key_type=kt, days=90), "t")
        c = svc.get(cid)
        assert c["status"] == "valid" and set(c["domains"]) == {"a.test", "*.a.test"}
        assert 88 < c["days_left"] <= 90 and c["data"]["self_signed"] is True
        assert oct(os.stat(c["key_path"]).st_mode)[-3:] == "600"
        svc.delete(cid)
        assert svc.get(cid) is None and not os.path.exists(c["cert_path"])
    with pytest.raises(ValueError):
        svc.create(CertificateRequest(type="selfsigned", domains=[]), "t")


def test_upload_valid_and_invalid(svc):
    cert, key, _ = make_pair("up")
    cid = svc.create(CertificateRequest(type="upload", name="Свой", cert_pem=cert, key_pem=key), "t")
    assert svc.get(cid)["status"] == "valid" and svc.get(cid)["domains"] == ["up.test"]
    _, other_key, _ = make_pair("other")
    before = len(svc.list())
    for bad, msg in ((dict(cert_pem=cert, key_pem=other_key), "не соответствует"),
                     (dict(cert_pem="garbage", key_pem=key), "PEM"),
                     (dict(cert_pem=cert, key_pem="-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n"), "зашифрован")):
        with pytest.raises(ValueError, match=msg):
            svc.create(CertificateRequest(type="upload", **bad), "t")
    assert len(svc.list()) == before  # неудачные попытки не оставляют записей
    svc.delete(cid)


def test_path_and_expiry(svc):
    cert, key, d = make_pair("old", days=1)
    cid = svc.create(CertificateRequest(type="path", cert_path=f"{d}/cert.pem", key_path=f"{d}/key.pem"), "t")
    c = svc.get(cid)
    assert c["status"] == "valid" and 0 < c["days_left"] <= 1
    with pytest.raises(ValueError, match="не найден"):
        svc.create(CertificateRequest(type="path", cert_path="/nonexistent.pem", key_path=f"{d}/key.pem"), "t")
    os.remove(f"{d}/cert.pem")
    svc.refresh_all()
    assert svc.get(cid)["status"] == "missing"
    svc.delete(cid)


def test_delete_refused_when_in_use(svc):
    cid = svc.create(CertificateRequest(type="selfsigned", domains=["used.test"]), "t")
    svc.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                   ("Сайт", 1, '{"name": "Сайт", "ssl": {"enabled": true, "certificate_id": %d}}' % cid, time.time(), 0))
    with pytest.raises(ValueError, match="используется"):
        svc.delete(cid)
    svc.db.execute("DELETE FROM sites")
    svc.delete(cid)


def test_domain_covered():
    assert domain_covered("a.example.com", ["*.example.com"]) and domain_covered("EXAMPLE.com", ["example.com"])
    assert not domain_covered("a.b.example.com", ["*.example.com"]) and not domain_covered("example.com", ["*.example.com"])
