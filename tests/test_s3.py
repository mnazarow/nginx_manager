"""S3-выгрузка резервных копий: подпись SigV4 (сверка с botocore) и полный цикл против эмулятора S3 (moto)."""
import datetime
import os
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

from app.services import s3

T = datetime.datetime(2026, 11, 12, 10, 30, 0, tzinfo=datetime.timezone.utc)
AK, SK = "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


def _botocore_auth(method, url, headers, body):
    botocore = pytest.importorskip("botocore")
    from unittest import mock

    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials
    req = AWSRequest(method=method, url=url, headers=dict(headers), data=body)
    auth = S3SigV4Auth(Credentials(AK, SK), "s3", "ru-central1")

    class FakeDT(datetime.datetime):
        @classmethod
        def utcnow(cls):
            return T.replace(tzinfo=None)

        @classmethod
        def now(cls, tz=None):
            return T if tz else T.replace(tzinfo=None)
    with mock.patch.object(botocore.auth.datetime, "datetime", FakeDT):
        auth.add_auth(req)
    return req.headers["Authorization"]


@pytest.mark.parametrize("method,url,headers,body", [
    ("PUT", "http://storage.example.com/bucket/nginx-manager/nginx-manager-20261112-030000-auto.json",
     {"Content-Type": "application/json", "Content-Length": "17"}, b'{"format": "x"}\n\n'),
    ("GET", "http://storage.example.com/bucket/?list-type=2&prefix=nginx-manager%2Fsrv%20one%2F", {}, b""),
    ("DELETE", "http://bucket.storage.example.com/a%20b/%D1%84%D0%B0%D0%B9%D0%BB.db.gz", {}, b""),
])
def test_signature_matches_botocore(method, url, headers, body):
    import hashlib
    payload = hashlib.sha256(body).hexdigest()
    ours = s3.sign(method, url, headers, payload, AK, SK, "ru-central1", now=T)["Authorization"]
    assert ours == _botocore_auth(method, url, headers, body)


def test_url_styles():
    c = s3.S3Client("https://storage.yandexcloud.net/", "ru-central1", "my-bkt", AK, SK)
    assert c.url("nm/файл 1.db") == "https://storage.yandexcloud.net/my-bkt/nm/%D1%84%D0%B0%D0%B9%D0%BB%201.db"
    c.path_style = False
    assert c.url("k", {"list-type": "2", "prefix": "a/"}) == "https://my-bkt.storage.yandexcloud.net/k?list-type=2&prefix=a%2F"


# ----------------------------------------------------------------------------- moto
@pytest.fixture(scope="module")
def moto():
    exe = shutil.which("moto_server")
    if not exe:
        pytest.skip("moto_server не установлен (pip install 'moto[server]')")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    env = dict(os.environ, NO_PROXY="*", no_proxy="*")
    p = subprocess.Popen([exe, "-H", "127.0.0.1", "-p", str(port)], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, env=env)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    yield url
    p.terminate()
    p.wait(5)


def test_offsite_cycle(moto, monkeypatch, tmp_path):
    """Копия → gzip → шифрование → выгрузка → хранение N копий → список → скачивание с расшифровкой и распаковкой."""
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    from app.config import settings
    from app.core import App
    from app.models import PanelSettings
    from app.services import backup
    app = App()
    cl = s3.S3Client(moto, "us-east-1", "nm-backups", AK, SK)
    cl.request("PUT", "")  # создать бакет
    p = PanelSettings(s3_enabled=True, s3_endpoint=moto, s3_bucket="nm-backups", s3_prefix="srv1",
                      s3_access_key=AK, s3_secret_key=SK, s3_keep=2, s3_encrypt_password="Pa$$ шифра")
    app.save_panel(p)
    assert backup.offsite_check(app)["ok"]
    made = []
    for label in ("auto", "manual", "auto"):
        db_path = backup.db_backup(app, label)
        made.append(db_path)
        res = backup.offsite_upload(app, db_path)
        assert res["ok"], res
        time.sleep(1.1)  # отметка времени в имени — с точностью до секунды
    names = [o["name"] for o in backup.offsite_list(app)]
    assert len(names) == 4 and all(n.endswith(".enc") for n in names), names   # 2 копии × (json + db.gz)
    assert not any(made[0].name.split(".")[0] in n for n in names)              # старейшая удалена
    assert app.db.kv_get("offsite_last")["ok"]
    # скачать: файл расшифровывается и распаковывается в каталог копий
    db_name = next(n for n in names if ".db.gz" in n)
    os.unlink(settings.backups_dir / db_name.replace(".gz.enc", ""))
    local = backup.offsite_download(app, db_name)
    assert local == db_name.replace(".gz.enc", "")
    with open(settings.backups_dir / local, "rb") as f:
        assert f.read(16) == b"SQLite format 3\x00"
    js_name = next(n for n in names if n.endswith(".json.enc"))
    original = (settings.backups_dir / js_name[:-4]).read_text()
    os.unlink(settings.backups_dir / js_name[:-4])
    assert (settings.backups_dir / backup.offsite_download(app, js_name)).read_text() == original
    # неверный пароль — понятная ошибка, мусор не остаётся
    app.save_panel(p.model_copy(update={"s3_encrypt_password": "не тот"}))
    with pytest.raises(ValueError, match="расшифровать"):
        backup.offsite_download(app, js_name)
    assert not (settings.backups_dir / js_name).exists()
    # недоступное хранилище — ошибка в журнале и kv, копия на сервере остаётся
    app.save_panel(p.model_copy(update={"s3_endpoint": "http://127.0.0.1:9"}))
    res = backup.offsite_upload(app, made[-1])
    assert not res["ok"] and app.db.kv_get("offsite_last")["error"]
    ev = app.db.one("SELECT * FROM events WHERE source='backup' ORDER BY id DESC LIMIT 1")
    assert ev["level"] == "error" and "Не удалось выгрузить" in ev["message"]
    app.save_panel(PanelSettings())
    app.db.close()
