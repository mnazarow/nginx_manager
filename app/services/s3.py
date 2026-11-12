"""Минимальный клиент S3-совместимого хранилища (AWS S3, MinIO, Yandex Object Storage, VK Cloud, Selectel,
Cloudflare R2, Backblaze B2) для выгрузки резервных копий: PUT, GET, DELETE, ListObjectsV2.

Подпись AWS Signature Version 4 реализована здесь же, без boto3: панель не тянет лишних зависимостей. Тесты сверяют
подпись с botocore и прогоняют выгрузку против moto (эмулятор S3).
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple, Union

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class S3Error(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"HTTP {status} {code}: {message}".strip())
        self.status, self.code = status, code


def _q(s: str, safe: str = "-_.~") -> str:
    return urllib.parse.quote(s, safe=safe)


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def file_sha256(path: Union[str, Path]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign(method: str, url: str, headers: Dict[str, str], payload_hash: str, access_key: str, secret_key: str,
         region: str, now: Optional[datetime.datetime] = None, service: str = "s3") -> Dict[str, str]:
    """Заголовки запроса с подписью SigV4 (x-amz-date, x-amz-content-sha256, Authorization)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amz_date, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    u = urllib.parse.urlsplit(url)
    host = u.netloc
    if (u.scheme == "https" and host.endswith(":443")) or (u.scheme == "http" and host.endswith(":80")):
        host = host.rsplit(":", 1)[0]
    hdrs = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    hdrs.update({"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash})
    signed = ";".join(sorted(hdrs))
    canonical_headers = "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs))
    query = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    canonical_query = "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(query))
    canonical_uri = _q(urllib.parse.unquote(u.path or "/"), safe="/-_.~")
    canonical = "\n".join([method, canonical_uri, canonical_query, canonical_headers, signed, payload_hash])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode(), day), region), service), "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {k: v for k, v in headers.items()}
    out.update({"x-amz-date": amz_date, "x-amz-content-sha256": payload_hash,
                "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, "
                                 f"Signature={signature}"})
    return out


class S3Client:
    def __init__(self, endpoint: str, region: str, bucket: str, access_key: str, secret_key: str,
                 path_style: bool = True, timeout: float = 120):
        self.endpoint = endpoint.rstrip("/")
        self.region = region or "us-east-1"
        self.bucket = bucket
        self.ak, self.sk = access_key, secret_key
        self.path_style = path_style
        self.timeout = timeout

    def url(self, key: str = "", query: Optional[Dict[str, str]] = None) -> str:
        u = urllib.parse.urlsplit(self.endpoint)
        path = _q(key, safe="/-_.~")
        if self.path_style:
            base = f"{u.scheme}://{u.netloc}{u.path}/{self.bucket}/{path}"
        else:
            base = f"{u.scheme}://{self.bucket}.{u.netloc}{u.path}/{path}"
        if query:
            base += "?" + "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(query.items()))
        return base

    def request(self, method: str, key: str = "", query: Optional[Dict[str, str]] = None,
                body: Union[None, bytes, BinaryIO] = None, payload_hash: str = EMPTY_SHA256,
                headers: Optional[Dict[str, str]] = None, out: Optional[BinaryIO] = None) -> Tuple[int, bytes]:
        url = self.url(key, query)
        hdrs = dict(headers or {})
        if isinstance(body, bytes):
            payload_hash = hashlib.sha256(body).hexdigest()
            hdrs["Content-Length"] = str(len(body))
        signed = sign(method, url, hdrs, payload_hash, self.ak, self.sk, self.region)
        rq = urllib.request.Request(url, data=body, method=method, headers=signed)
        try:
            with urllib.request.urlopen(rq, timeout=self.timeout) as r:
                if out is not None:
                    for chunk in iter(lambda: r.read(1 << 20), b""):
                        out.write(chunk)
                    return r.status, b""
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            data = e.read()
            code, msg = "", data[:300].decode(errors="replace")
            try:
                x = ET.fromstring(data)
                code = x.findtext("Code") or ""
                msg = x.findtext("Message") or msg
            except ET.ParseError:
                pass
            raise S3Error(e.code, code, msg) from None

    # ---- операции ---------------------------------------------------------
    def put_file(self, key: str, path: Union[str, Path], content_type: str = "application/octet-stream") -> None:
        size = os.path.getsize(path)
        digest = file_sha256(path)
        with open(path, "rb") as f:
            self.request("PUT", key, body=f, payload_hash=digest,
                         headers={"Content-Length": str(size), "Content-Type": content_type})

    def put_bytes(self, key: str, data: bytes, content_type: str = "text/plain") -> None:
        self.request("PUT", key, body=data, headers={"Content-Type": content_type})

    def get_to_file(self, key: str, dest: Union[str, Path]) -> None:
        tmp = Path(str(dest) + ".part")
        with open(tmp, "wb") as f:
            self.request("GET", key, out=f)
        os.replace(tmp, dest)

    def delete(self, key: str) -> None:
        self.request("DELETE", key)

    def list(self, prefix: str = "") -> List[Dict[str, Any]]:
        """Все объекты с префиксом (ListObjectsV2, с продолжением для больших списков)."""
        items: List[Dict[str, Any]] = []
        token = ""
        while True:
            q = {"list-type": "2", "prefix": prefix}
            if token:
                q["continuation-token"] = token
            _, data = self.request("GET", "", query=q)
            x = ET.fromstring(data)
            ns = x.tag[: x.tag.index("}") + 1] if x.tag.startswith("{") else ""
            for c in x.findall(f"{ns}Contents"):
                items.append({"key": c.findtext(f"{ns}Key"), "size": int(c.findtext(f"{ns}Size") or 0),
                              "last_modified": c.findtext(f"{ns}LastModified") or ""})
            token = x.findtext(f"{ns}NextContinuationToken") or ""
            if (x.findtext(f"{ns}IsTruncated") or "false").lower() != "true" or not token:
                return items
