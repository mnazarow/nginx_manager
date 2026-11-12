#!/usr/bin/env python3
"""Сквозная проверка выпуска сертификатов через работающую панель против настоящего ACME-сервера.

Нужны: ACME-сервер Pebble (https://github.com/letsencrypt/pebble) и DNS-сервер с зоной тестового домена,
принимающий динамические обновления по ключу TSIG (BIND), которого Pebble использует для проверок
(pebble -dnsserver 127.0.0.1:53). Домены зоны должны указывать на этот сервер (для HTTP-проверки).

Что проверяется:
  1. HTTP-проверка: обычный сертификат для --http-domain;
  2. DNS-проверка через RFC 2136: wildcard *.<зона> + <зона>;
  3. wildcard-сертификат подключается к временному сайту, конфигурация применяется, nginx отдаёт этот сертификат;
  4. продление: новый сертификат с новым серийным номером;
  5. всё временное удаляется, настройки панели восстанавливаются (--keep — оставить для осмотра).

python3 tools/acme_e2e.py --password '...' --directory https://127.0.0.1:14000/dir --ca-bundle /opt/acme-test/ca.pem \\
    --zone example.com --http-domain blog.example.com --tsig-name nm-acme-key --tsig-secret '...' --tsig-alg HMAC-SHA256
"""
import argparse
import json
import socket
import ssl
import sys
import time
import urllib.request
from http.cookiejar import CookieJar


class Panel:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()),
                                              urllib.request.ProxyHandler({}))

    def call(self, method, path, body=None, ok=(200,)):
        data = json.dumps(body).encode() if body is not None else None
        rq = urllib.request.Request(self.url + "/api" + path, data=data, method=method,
                                    headers={"Content-Type": "application/json", "X-NM-CSRF": "1"})
        try:
            with self.op.open(rq, timeout=120) as r:
                code, text = r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            code, text = e.code, e.read().decode()
        if code not in ok:
            raise SystemExit(f"✗ {method} {path}: HTTP {code} {text[:600]}")
        return json.loads(text) if text else None


def step(msg):
    print(f"• {msg}", flush=True)


def wait_cert(p, cid, prev_serial=None, timeout=300):
    t0 = time.time()
    while time.time() - t0 < timeout:
        c = next(x for x in p.call("GET", "/certs")["items"] if x["id"] == cid)
        job = c.get("job") or {}
        if job.get("state") == "error":
            raise SystemExit("✗ выпуск не удался: " + job.get("error", "") + "\n" + "\n".join(job.get("log", [])[-25:]))
        if job.get("state") == "done" and c["status"] == "valid" and (prev_serial is None or
                                                                       c["data"].get("serial") != prev_serial):
            return c
        time.sleep(2)
    raise SystemExit(f"✗ сертификат #{cid} не выпущен за {timeout} с")


def served_cert(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        der = t.getpeercert(binary_form=True)
    import subprocess
    pem = ssl.DER_cert_to_PEM_cert(der)
    out = subprocess.run(["openssl", "x509", "-noout", "-issuer", "-serial", "-ext", "subjectAltName"],
                         input=pem, capture_output=True, text=True).stdout
    return out


def create_account(p, a, created):
    step("Учётная запись DNS (RFC 2136)")
    acc = {"name": f"BIND: {a.zone}", "provider": "rfc2136", "rfc_server": a.dns_server, "rfc_port": 53,
           "rfc_key_name": a.tsig_name, "rfc_key_secret": a.tsig_secret, "rfc_algorithm": a.tsig_alg,
           "propagation_seconds": 3}
    aid = created["account"] = p.call("POST", "/dns-accounts", acc)["id"]
    chk = p.call("POST", f"/dns-accounts/{aid}/check")
    assert chk["ok"], chk
    step("  проверка: " + "; ".join(i["text"] for i in chk["items"]))
    return aid


def main(a):
    p = Panel(a.url)
    p.call("POST", "/auth/login", {"username": a.user, "password": a.password})
    panel0 = p.call("GET", "/settings/panel")
    created = {"certs": [], "account": None, "site": None}
    try:
        step("Настройки панели: свой ACME-сервер " + a.directory)
        panel = dict(panel0, acme_ca="custom", acme_directory=a.directory, acme_ca_bundle=a.ca_bundle,
                     letsencrypt_email="ops@" + a.zone, acme_eab_kid=a.eab_kid, acme_eab_hmac=a.eab_hmac)
        p.call("PUT", "/settings/panel", panel)
        assert a.directory.split("/")[2] in p.call("GET", "/certs")["ca"]

        aid = 0
        if a.tsig_name:
            aid = create_account(p, a, created)

        step(f"HTTP-проверка: сертификат для {a.http_domain}")
        cid = p.call("POST", "/certs", {"type": "letsencrypt", "name": "e2e-http", "domains": [a.http_domain],
                                        "challenge": "http"})["id"]
        created["certs"].append(cid)
        c = wait_cert(p, cid)
        assert "Pebble" in c["issuer"] and c["domains"] == [a.http_domain], c
        step(f"  ✓ выпущен: {c['issuer']}, до {time.strftime('%d.%m.%Y', time.localtime(c['not_after']))}")
        if a.eab_kid:
            log = "\n".join(c["job"]["log"])
            assert "--eab-kid" in log and a.eab_hmac not in log, "ключ EAB не передан или виден в журнале"
            step("  ✓ аккаунт зарегистрирован с привязкой EAB, HMAC-ключ в журнале скрыт")
        if a.only_http:
            print("\n✓ Проверка HTTP-выпуска пройдена")
            return 0

        if not aid:
            raise SystemExit("✗ для DNS-проверки нужны --tsig-name и --tsig-secret")
        step(f"DNS-проверка: wildcard *.{a.zone} и {a.zone}")
        r = p.call("POST", "/certs", {"type": "letsencrypt", "name": "e2e-wildcard", "domains": [f"*.{a.zone}"]},
                   ok=(422,))
        assert "DNS" in json.dumps(r, ensure_ascii=False)
        wid = p.call("POST", "/certs", {"type": "letsencrypt", "name": "e2e-wildcard",
                                        "domains": [f"*.{a.zone}", a.zone], "challenge": "dns",
                                        "dns_account_id": aid})["id"]
        created["certs"].append(wid)
        w = wait_cert(p, wid)
        assert sorted(w["domains"]) == sorted([f"*.{a.zone}", a.zone]) and w["data"]["challenge"] == "dns", w
        step(f"  ✓ выпущен: {', '.join(w['domains'])}")
        log = "\n".join(w["job"]["log"])
        assert "--dns-rfc2136-credentials" in log and a.tsig_secret not in log

        host = f"e2e-{int(time.time()) % 100000}.{a.zone}"
        step(f"Сайт {host} с wildcard-сертификатом, применение")
        created["site"] = p.call("POST", "/sites", {
            "name": "ACME e2e", "domains": [host], "type": "proxy",
            "backends": [{"address": "127.0.0.1", "port": a.backend_port}],
            "ssl": {"enabled": True, "certificate_id": wid, "force_https": True}})["id"]
        res = p.call("POST", "/config/apply", {"comment": "acme e2e: сайт с wildcard"})
        assert res.get("ok", True), res
        time.sleep(1)
        out = served_cert(host)
        assert "Pebble" in out and f"*.{a.zone}" in out, out
        step("  ✓ nginx отдаёт wildcard-сертификат: " + " ".join(out.split())[:160])

        step("Продление wildcard-сертификата")
        serial = w["data"].get("serial")
        p.call("POST", f"/certs/{wid}/renew")
        w2 = wait_cert(p, wid, prev_serial=serial)
        assert w2["data"]["serial"] != serial
        time.sleep(2)
        out2 = served_cert(host)
        assert w2["data"]["serial"].replace(":", "").lstrip("0").upper() in out2.replace(":", "").upper(), out2
        step(f"  ✓ новый серийный номер {w2['data']['serial']}; nginx перечитал сертификат")

        diag = p.call("POST", "/diagnostics/run")
        bad = [r for r in diag["results"] if r["group"] == "SSL" and r["status"] == "fail"]
        assert not bad, bad
        step("Диагностика SSL: без ошибок")
        print("\n✓ Сквозная проверка ACME пройдена")
        return 0
    finally:
        if not a.keep:
            if created["site"]:
                p.call("DELETE", f"/sites/{created['site']}", ok=(200, 404))
                p.call("POST", "/config/apply", {"comment": "acme e2e: уборка"}, ok=(200, 409))
            for cid in created["certs"]:
                p.call("DELETE", f"/certs/{cid}", ok=(200, 400, 404))
            if created["account"]:
                p.call("DELETE", f"/dns-accounts/{created['account']}", ok=(200, 400, 404))
            if panel0.get("acme_eab_hmac") == "••••••••":
                panel0.pop("acme_eab_hmac")
            p.call("PUT", "/settings/panel", panel0)
            step("Временные объекты удалены, настройки панели восстановлены")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8088")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--directory", required=True, help="каталог ACME (Pebble: https://127.0.0.1:14000/dir)")
    ap.add_argument("--ca-bundle", default="", help="корневой сертификат TLS ACME-сервера")
    ap.add_argument("--zone", default="example.com")
    ap.add_argument("--http-domain", required=True)
    ap.add_argument("--dns-server", default="127.0.0.1")
    ap.add_argument("--tsig-name", default="")
    ap.add_argument("--tsig-secret", default="")
    ap.add_argument("--tsig-alg", default="HMAC-SHA256")
    ap.add_argument("--backend-port", type=int, default=9001)
    ap.add_argument("--eab-kid", default="", help="ACME-сервер требует EAB (Pebble: externalAccountBindingRequired)")
    ap.add_argument("--eab-hmac", default="")
    ap.add_argument("--only-http", action="store_true", help="только HTTP-выпуск (например, для проверки EAB)")
    ap.add_argument("--keep", action="store_true", help="не удалять созданное (для осмотра и скриншотов)")
    sys.exit(main(ap.parse_args()))
