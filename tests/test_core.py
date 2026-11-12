"""Автотесты ядра: проверка значений, генератор конфигурации, разбор журналов, криптография.

Запуск: python3 -m pytest -q tests/   (тесты с nginx -t пропускаются, если nginx не установлен)
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("NM_CONF_FILE", "/nonexistent")
TMP = Path(tempfile.mkdtemp(prefix="nm-tests-"))
os.environ.update(NM_DATA_DIR=str(TMP / "data"), NM_MANAGED_DIR=str(TMP / "managed"),
                  NM_NGINX_CONF=str(TMP / "nginx.conf"), NM_LOG_DIR=str(TMP / "logs"), NM_CACHE_DIR=str(TMP / "cache"))

from app import validators as V  # noqa: E402
from app.models import (Backend, BasicAuthUser, CacheSettings, GlobalSettings, Location, PanelSettings,  # noqa: E402
                        SecuritySettings, Site, SSLSettings, Stream)
from app.nginx.generator import CertInfo, Generator, NginxCaps, Paths, State  # noqa: E402
from app.stats.collector import percentile  # noqa: E402
from app.stats.parsing import categorize, classify_ua, parse_access, parse_error  # noqa: E402
from app.utils import apr1, hash_password, totp_code, totp_verify, verify_password  # noqa: E402


# ---------------------------------------------------------------- validators
@pytest.mark.parametrize("v,ok", [("30s", True), ("500ms", True), ("1h", True), ("10", True), ("1 h", False),
                                  ("10x", False), ("", True)])
def test_duration(v, ok):
    if ok:
        assert V.duration(v) == v
    else:
        with pytest.raises(V.ValidationError):
            V.duration(v)


def test_domain_idn_and_wildcard():
    assert V.domain("Пример.РФ") == "xn--e1afmkfd.xn--p1ai"
    assert V.domain("*.Example.com.") == "*.example.com"
    assert V.domain("~^(.+)\\.example\\.com$").startswith("~")
    for bad in ("exa mple.com", "a;b.com", "-bad.com", "x" * 70 + ".com"):
        with pytest.raises(V.ValidationError):
            V.domain(bad)


def test_injection_blocked():
    with pytest.raises(Exception):
        Site(name="x", domains=["a.com"], backends=[Backend(address="127.0.0.1;evil", port=80)])
    with pytest.raises(Exception):
        SecuritySettings(rate="10r/s; return 200")
    assert V.quote('a"b\\c') == '"a\\"b\\\\c"'


def test_cidr():
    assert V.cidr("10.0.0.1/8") == "10.0.0.0/8"
    assert V.cidr("2001:db8::1") == "2001:db8::1"
    with pytest.raises(V.ValidationError):
        V.cidr("300.1.1.1")


def test_site_rules():
    with pytest.raises(Exception):
        Site(name="x", domains=["a.com"])  # нет бэкендов
    with pytest.raises(Exception):
        Site(name="x", domains=["a.com"], backends=[Backend()], ssl=SSLSettings(enabled=True))  # нет сертификата
    with pytest.raises(Exception):
        Site(name="x", domains=["a.com"], balancing="ip_hash", backends=[Backend(), Backend(port=81, backup=True)])
    with pytest.raises(Exception):
        Location(path="/a/", match="regex", proxy_path="/")


# ---------------------------------------------------------------- crypto
def test_apr1_matches_openssl_vector():
    assert apr1("secret", "abcdefgh") == "$apr1$abcdefgh$h9FWgUz3n9YxylKLlR5SQ/"


def test_password_hash():
    h = hash_password("Pa55word!")
    assert verify_password("Pa55word!", h) and not verify_password("wrong", h)


def test_totp_rfc6238():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
    assert totp_code(secret, 59, digits=8) == "94287082"
    assert totp_verify(secret, totp_code(secret))


# ---------------------------------------------------------------- parsing
def test_parse_access_and_multi_upstream():
    line = ('{"t":"1700000000.123","site":"3","host":"a.com","ip":"1.2.3.4","m":"GET","u":"/x?y=1","p":"HTTP/2.0",'
            '"s":"502","b":"10","bs":"200","rl":"80","rt":"0.250","ua":"10.0.0.1:80, 10.0.0.2:80","us":"502, 200",'
            '"urt":"0.100, 0.120","uct":"-","uht":"-","ref":"","agent":"curl/8","cache":"-","sch":"https",'
            '"tls":"TLSv1.3","rid":"abc","cr":"1"}')
    r = parse_access(line)
    assert r["status"] == 502 and r["path"] == "/x" and r["upstream"] == "10.0.0.2:80"
    assert abs(r["urt"] - 0.22) < 1e-9 and r["cache"] == ""
    assert parse_access("not json") is None


def test_parse_error_categories():
    e = parse_error('2024/01/01 10:00:00 [error] 1#1: *5 upstream timed out (110: Connection timed out) while reading '
                    'response header from upstream, client: 1.2.3.4, server: a.com, request: "GET / HTTP/1.1", '
                    'upstream: "http://10.0.0.1:80/", host: "a.com"')
    assert e["category"] == "upstream_timeout" and e["client"] == "1.2.3.4" and e["upstream"] == "http://10.0.0.1:80/"
    assert categorize("no live upstreams while connecting to upstream") == "no_live_upstreams"
    assert categorize("client intended to send too large body: 2000000 bytes") == "body_too_large"


def test_ua_classification():
    assert classify_ua("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Mobile/15E148 Safari/604.1")[1:3] == \
        ("iOS", "Мобильный")
    assert classify_ua("Mozilla/5.0 (compatible; Googlebot/2.1)")[3] is True


def test_percentile_histogram():
    hist = [0] * 12
    hist[4] = 100  # все в корзине 50..100 мс
    assert 0.05 <= percentile(hist, 0.5) <= 0.1


# ---------------------------------------------------------------- generator
def make_state():
    site = Site(name="Shop", domains=["shop.test", "www.shop.test"], canonical_redirect=True,
                backends=[Backend(address="127.0.0.1", port=9001, weight=3),
                          Backend(address="127.0.0.1", port=9002, backup=True)],
                balancing="least_conn", ssl=SSLSettings(enabled=True, certificate_id=1, hsts=True),
                cache=CacheSettings(enabled=True, bypass_cookie_pattern="session"),
                security=SecuritySettings(rate_limit=True, basic_auth=True, block_bad_bots=True, block_exploits=True,
                                          basic_auth_users=[BasicAuthUser(username="u", password_hash=apr1("x"))]),
                locations=[Location(path="/api/", use_site_backends=False, backends=[Backend(port=9003)],
                                    proxy_path="/", rate_limit="custom", rate="5r/s"),
                           Location(path="\\.php$", match="regex_ci", action="deny"),
                           Location(path="/robots.txt", match="exact", action="return",
                                    return_body="User-agent: *\nDisallow: /a")])
    stream = Stream(name="PG", listen_port=15432, backends=[Backend(port=5432)], allow=["10.0.0.0/8"])
    cert = TMP / "c.pem", TMP / "k.pem"
    return State([(1, site)], [(1, stream)], GlobalSettings(), PanelSettings(),
                 {1: CertInfo(1, str(cert[0]), str(cert[1]), True)})


def render(state, caps=None):
    bans = TMP / "bans.conf"
    bans.write_text("203.0.113.7 1;\n198.51.100.0/24 1;\n2001:db8::/32 1;\n")
    p = Paths(str(TMP / "managed" / "stage"), str(TMP / "managed" / "live"), "/var/acme", str(TMP / "logs"),
              str(TMP / "cache"), 8089, 8088, str(TMP / "data"), bans_file=str(bans))
    return Generator(state, caps or NginxCaps(version=(1, 24, 0), ipv6=False), p).render()


def test_generator_content():
    files = render(make_state())
    site = next(v for k, v in files.items() if k.startswith("sites/site-1"))
    assert "least_conn;" in site and "backup;" in site and "zone=nm_rl_1_l0" in site
    assert "proxy_pass http://nm_site_1_l0/;" in site
    assert "return 301 https://$host$request_uri;" in site
    assert '"User-agent: *\\nDisallow: /a"' in site
    assert "error_page 502 @nm_err_502;" in site and "auth_basic_user_file" in site
    assert "map $http_cookie $nm_nocache_1" in site
    assert "listen 443 ssl http2;" in site  # nginx < 1.25.1
    assert files["auth/site-1.htpasswd"].startswith("u:$apr1$")
    assert "ssl_reject_handshake on;" in files["http.d/10-default.conf"]
    assert "proxy_pass nm_stream_1;" in next(v for k, v in files.items() if k.startswith("streams/"))


def test_generator_new_nginx_http2_directive():
    files = render(make_state(), NginxCaps(version=(1, 27, 0), ipv6=True))
    site = next(v for k, v in files.items() if k.startswith("sites/site-1"))
    assert "http2 on;" in site and "listen [::]:443 ssl;" in site


@pytest.mark.skipif(not shutil.which("nginx") or os.geteuid() != 0, reason="нужен nginx и root")
def test_generated_config_passes_nginx_t():
    import subprocess
    os.makedirs(TMP / "logs", exist_ok=True)
    os.makedirs(TMP / "cache" / "default", exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(TMP / "k.pem"),
                    "-out", str(TMP / "c.pem"), "-days", "2", "-subj", "/CN=shop.test"], capture_output=True, check=True)
    from app.nginx.manager import NginxManager
    from app.db import Database
    mgr = NginxManager(Database(TMP / "t.db"))
    caps = mgr.caps()
    files = render(make_state(), caps)
    stage = TMP / "managed" / "stage"
    for rel, content in files.items():
        (stage / rel).parent.mkdir(parents=True, exist_ok=True)
        (stage / rel).write_text(content)
    ok, out = mgr.test_config(stage / "nginx.conf")
    assert ok, out


# ---------------------------------------------------------------- блокировки IP
def test_normalize_net():
    from app.services.bans import normalize_net
    assert normalize_net(" 203.0.113.7 ") == "203.0.113.7"
    assert normalize_net("198.51.100.77/24") == "198.51.100.0/24"
    assert normalize_net("2001:db8::1/128") == "2001:db8::1"
    for bad in ("", "999.1.1.1", "10.0.0.0/4", "abc"):
        with pytest.raises(ValueError):
            normalize_net(bad)


def test_ban_detector_rules():
    from app.services.bans import BanDetector, SCAN_RE
    ps = PanelSettings(autoban_scan=3, autoban_auth=5, autoban_4xx=0, autoban_default_host=0)
    d = BanDetector(lambda: ps)
    t = 1_700_000_000.0
    for uri in ("/.env", "/.git/config", "/index.php?id=1%20union%20select%201", "/wp-config.php.bak"):
        assert SCAN_RE.search(uri.lower()), uri
    for uri in ("/", "/products/42?page=2", "/static/app.css", "/wp-login.php", "/api/v1/users"):
        assert not SCAN_RE.search(uri.lower()), uri
    d.observe("1.2.3.4", t, 404, "/.env", "1", False, False)
    d.observe("1.2.3.4", t + 1, 404, "/.git/HEAD", "1", False, False)
    assert not d.candidates
    d.observe("1.2.3.4", t + 2, 404, "/phpmyadmin/", "1", False, False)
    c = d.take()
    assert len(c) == 1 and c[0]["rule"] == "scan" and c[0]["count"] == 3
    d.observe("1.2.3.4", t + 3, 404, "/.aws/credentials", "1", False, False)
    assert not d.take()  # повторно в том же окне не помечается
    for i in range(5):
        d.observe("5.6.7.8", t + i, 401, "/admin", "2", False, False)
    assert d.take()[0]["rule"] == "auth"
    # новое окно — счётчики сбрасываются
    d.observe("9.9.9.9", t, 404, "/.env", "1", False, False)
    d.observe("9.9.9.9", t + ps.autoban_window + 1, 404, "/.env", "1", False, False)
    assert d.win["9.9.9.9"][4] == 1
    d.observe("9.9.9.9", t, 444, "/", "1", False, True)
    assert d.blocked_total == 1 and d.blocked_hits["9.9.9.9"] == 1


def test_generator_bans():
    files = render(make_state())
    base = files["http.d/00-base.conf"]
    assert "geo $nm_banned" in base and '"bn":"$nm_banned"' in base and "bans.conf;" in base
    site = next(v for k, v in files.items() if k.startswith("sites/site-1"))
    assert site.count("if ($nm_banned)") == 2  # HTTP→HTTPS и основной server
    assert "return 444;" in site
    assert "if ($nm_banned)" in files["http.d/10-default.conf"]


def test_metrics_format():
    from app.services.metrics import Out, labels, num
    assert labels({"a": 'x"y\\z\n'}) == '{a="x\\"y\\\\z\\n"}'
    assert num(float("nan")) == "NaN" and num(3.0) == "3" and num(0.25) == "0.25"
    o = Out()
    o.metric("m_total", "counter", "help", [({"s": "1"}, 5)])
    assert o.text() == '# HELP m_total help\n# TYPE m_total counter\nm_total{s="1"} 5\n'


def test_tailer_reads_in_chunks(tmp_path):
    import asyncio
    from app.db import Database
    from app.stats.collector import LogTailer
    log = tmp_path / "a.log"
    lines = [f'{{"n":{i},"pad":"{"x" * 200}"}}' for i in range(20000)]
    log.write_text("\n".join(lines) + "\n")
    got = []
    t = LogTailer(log, "test", Database(tmp_path / "t.db"), got.extend)
    t._open(from_start=True)
    chunks = 0
    while t._read(budget=256 * 1024):
        chunks += 1
    assert len(got) == 20000 and chunks > 10
    asyncio.run(asyncio.sleep(0))


def test_every_form_field_has_doc_anchor():
    """Ссылка «подробнее» из подсказки каждого поля ведёт на существующий якорь справочника."""
    from app.schema import full_schema
    docs = {p.name: p.read_text(encoding="utf-8") for p in (ROOT / "docs").glob("*.md")}
    missing = []

    def walk(fields):
        for f in fields:
            if f.get("ui") == "hidden":
                continue
            if f.get("doc_page") and f'id="{f["anchor"]}"' not in docs.get(f["doc_page"], ""):
                missing.append(f"{f['doc_page']}#{f['anchor']}")
            walk(f.get("fields") or [])
    for fields in full_schema()["models"].values():
        walk(fields)
    assert not missing, missing[:10]


def test_docs_links_resolve():
    """Ссылки между главами документации указывают на существующие файлы."""
    import re as _re
    names = {p.name for p in (ROOT / "docs").glob("*.md")}
    bad = []
    for p in (ROOT / "docs").glob("*.md"):
        for m in _re.finditer(r"\]\(([\w.-]+\.md)(#[^)]*)?\)", p.read_text(encoding="utf-8")):
            if m.group(1) not in names:
                bad.append(f"{p.name} → {m.group(1)}")
    assert not bad, bad


def _slug(text):
    import re as _re
    return _re.sub(r"\s", "-", _re.sub(r"[^\w\s-]", "", text.strip().lower()))


def test_insights_catalog_integrity():
    """Каждый сценарий и показатель описан полностью, а ссылки на документацию ведут на существующие разделы."""
    import re as _re
    from app.services.insights import METRICS, SCENARIOS, assess
    docs = {p.name: p.read_text(encoding="utf-8") for p in (ROOT / "docs").glob("*.md")}

    def sections(page):
        out = set()
        for line in docs[page].splitlines():
            m = _re.match(r"^#{1,6}\s+(.*)$", line)
            if m:
                out.add(_slug(_re.sub(r"[`*]", "", m.group(1))))
        return out | set(_re.findall(r'id="([^"]+)"', docs[page]))
    for sid, sc in SCENARIOS.items():
        assert sc.title and sc.when and sc.what, sid
        if sc.group != "errorlog":
            assert sc.causes and sc.actions, sid
        page, sec = sc.doc
        assert page in docs, (sid, page)
        assert not sec or sec in sections(page), (sid, page, sec)
    for mid, m in METRICS.items():
        assert m["desc"] and m["how"] and m["norm"] and m["advice"], mid
        page, sec = m["doc"]
        assert sec in sections(page), (mid, sec)
    assert assess("err5", 6, requests=100) == "crit" and assess("err5", 2, requests=100) == "warn"
    assert assess("err5", 50, requests=5) == "ok"          # мало данных
    assert assess("hit_ratio", 10, requests=500) == "warn" and assess("hit_ratio", 80, requests=500) == "ok"
    assert assess("connections", 950, extra={"capacity": 1000}) == "crit"
