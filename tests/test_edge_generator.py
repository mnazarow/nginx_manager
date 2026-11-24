"""Генератор конфигурации и проверка значений — свойства на случайных данных (hypothesis):

* любое значение, принятое проверками полей, не ломает синтаксис nginx и не добавляет директив;
* строка в кавычках доходит до клиента ровно такой, какой её ввели (проверка на запущенном nginx);
* любая комбинация переключателей сайта и глобальных настроек, которую принимают модели, даёт конфигурацию,
  которую принимает nginx -t (или понятный отказ генератора, а не ошибку nginx).
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import time
import typing
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings as hsettings, strategies as st
from pydantic import BaseModel, ValidationError

from app import validators as V
from app.models import Backend, GlobalSettings, Location, PanelSettings, Site, Stream
from app.nginx import manager as M
from app.nginx.generator import CertInfo, State
from tests.test_edge_nginx import mgr  # noqa: F401 — фикстура менеджера с изолированными каталогами

NGINX = bool(shutil.which("nginx")) and os.geteuid() == 0
needs_nginx = pytest.mark.skipif(not NGINX, reason="нужен nginx и root")
FAST = hsettings(max_examples=150, deadline=None, derandomize=True)

# печатаемые символы, включая все спецсимволы конфигурации nginx
PRINTABLE = st.characters(categories=("L", "N", "P", "S", "Zs"), exclude_characters="\x85\u2028\u2029")


# =============================================================================
#  Проверки полей: свойства
# =============================================================================
@FAST
@given(st.text(PRINTABLE, max_size=40))
def test_safe_token_never_lets_syntax_through(v):
    try:
        out = V.safe_token(v)
    except V.ValidationError:
        return
    assert not any(c in out for c in ";{}\"'\\`\n\r\0 \t#"[:-1]) and not out.startswith("#")


@FAST
@given(st.text(st.characters(categories=("L", "N"), exclude_characters="\x85") | st.sampled_from(list(".-_*~;{} ")),
               max_size=60))
def test_domain_normalization_is_stable(v):
    try:
        d = V.domain(v)
    except V.ValidationError:
        return
    assert V.domain(d) == d  # повторная проверка ничего не меняет
    if not d.startswith("~"):
        assert d == d.lower() and not any(c in d for c in ";{} \"'\n") and d.isascii()


@FAST
@given(st.text(PRINTABLE, max_size=60))
def test_quote_is_one_token(v):
    """Значение в кавычках — один аргумент директивы, что бы ни было внутри (разбор как у nginx)."""
    q = V.quote(v)
    stmts = list(V._raw_statements(f"add_header X-Test {q};"))
    assert stmts == [("add_header", ["X-Test", v])]
    assert list(V._raw_statements(f"add_header X-Test {V.quote_if_needed(v)};"))[0][1][1] == (v or "")


@FAST
@given(st.text(st.sampled_from(list("0123456789smhdwMyk")), max_size=8))
def test_duration_and_size_parsers_agree(v):
    try:
        V.duration(v, allow_empty=False)
        ok = True
    except V.ValidationError:
        ok = False
    assert ok == (V.parse_duration_seconds(v) > 0 or v.strip("0") in ("", "s", "ms", "m", "h", "d", "w", "M", "y")
                  and v[:1].isdigit())
    try:
        V.size(v, allow_empty=False)
        assert V.parse_size_bytes(v) >= 0 and v[:1].isdigit()
    except V.ValidationError:
        assert V.parse_size_bytes(v) == 0


@FAST
@given(st.integers(0, 2 ** 32 - 1), st.integers(0, 32))
def test_cidr_roundtrip(addr, prefix):
    import ipaddress
    raw = f"{ipaddress.IPv4Address(addr)}/{prefix}"
    out = V.cidr(raw)
    assert ipaddress.ip_network(out) == ipaddress.ip_network(raw, strict=False) and V.cidr(out) == out


@pytest.mark.parametrize("text,hidden", [
    ("add_header X a;}\ninclude /etc/shadow;", "include"),
    ("set $a 'x;'; load_module x.so;", "load_module"),
    ("# include /etc/passwd;\nreturn 200;", None),
    ("return 200 \"#\";include /x;", "include"),
    ("location / {} } } lua_code_cache off;", "lua_code_cache"),
    ("add_header X \"a\\\"b\"; env PATH;", "env"),
])
def test_raw_statements_cannot_hide_directives(text, hidden):
    names = [n for n, _ in V._raw_statements(text)]
    assert (hidden in names) if hidden else "include" not in names


# =============================================================================
#  Значения в кавычках доходят до клиента без изменений (настоящий nginx)
# =============================================================================
def _run_nginx(tmp: Path, body: str) -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    for d in ("logs", "tmp"):
        (tmp / d).mkdir(exist_ok=True)
    (tmp / "nginx.conf").write_text(
        f"pid {tmp}/nginx.pid;\nerror_log {tmp}/logs/error.log;\nevents {{}}\nhttp {{\n access_log off;\n"
        + "".join(f" {k}_temp_path {tmp}/tmp/{k};\n" for k in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        + f" server {{\n  listen 127.0.0.1:{port};\n{body}\n }}\n}}\n")
    r = subprocess.run(["nginx", "-p", str(tmp), "-c", str(tmp / "nginx.conf")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return port


@needs_nginx
@hsettings(max_examples=4, deadline=None, derandomize=True, suppress_health_check=list(HealthCheck))
@given(st.lists(st.text(PRINTABLE.filter(lambda c: c != "$"), min_size=1, max_size=40).map(str.strip)
                .filter(bool), min_size=25, max_size=25),
       st.lists(st.text(PRINTABLE.filter(lambda c: c != "$") | st.just("\n"), max_size=60), min_size=10,
                max_size=10))
def test_quoted_values_reach_client_unchanged(tmp_path_factory, headers, bodies):
    tmp = tmp_path_factory.mktemp("ngx")
    locs = [f"  location = /h{i} {{ add_header X-V {V.quote(v)}; return 204; }}" for i, v in enumerate(headers)]
    locs += [f"  location = /b{i} {{ default_type text/plain; return 200 {V.quote_multiline(v)}; }}"
             for i, v in enumerate(bodies)]
    port = _run_nginx(tmp, "\n".join(locs))
    try:
        for i, v in enumerate(headers):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", f"/h{i}")
            r = c.getresponse()
            got = r.getheader("X-V").encode("latin-1").decode("utf-8")
            r.read()
            assert got == v, (v, got)
        for i, v in enumerate(bodies):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", f"/b{i}")
            assert c.getresponse().read().decode() == v
    finally:
        subprocess.run(["nginx", "-p", str(tmp), "-c", str(tmp / "nginx.conf"), "-s", "stop"], capture_output=True)


# =============================================================================
#  Случайные комбинации переключателей → nginx -t
# =============================================================================
# include_*: системные каталоги этой машины (их содержимое проверяется отдельным тестом ниже)
SKIP = {"enabled", "default_server", "use_site_backends", "redirect", "static", "protection", "health",
        "ip_access", "maintenance", "ssl_dhparam", "include_conf_d", "include_sites_enabled"}


def _toggles(draw, cls: type, depth: int = 0) -> dict:
    """Случайные значения всех флагов и вариантов выбора модели (вложенные модели — на один уровень)."""
    out: dict = {}
    for name, f in cls.model_fields.items():
        if name in SKIP:
            continue
        a = f.annotation
        origin, args = typing.get_origin(a), typing.get_args(a)
        if a is bool:
            out[name] = draw(st.booleans())
        elif origin is typing.Literal:
            out[name] = draw(st.sampled_from(args))
        elif origin in (list, typing.List) and args and typing.get_origin(args[0]) is typing.Literal:
            out[name] = draw(st.lists(st.sampled_from(typing.get_args(args[0])), unique=True, max_size=3))
        elif depth == 0 and isinstance(a, type) and issubclass(a, BaseModel):
            out[name] = _toggles(draw, a, depth + 1)
    return out


@st.composite
def site_states(draw):
    base = {"name": "Fuzz", "domains": ["fuzz.test", "www.fuzz.test"],
            "backends": [{"address": "127.0.0.1", "port": 9001}, {"address": "127.0.0.1", "port": 9002,
                                                                  "backup": draw(st.booleans())}],
            "redirect": {"url": "https://example.com"}, "static": {"root": "/var/www/html"}}
    data = {**base, **_toggles(draw, Site)}
    data["ssl"] = {**data.get("ssl", {}), "certificate_id": 1}
    sec = data.setdefault("security", {})
    sec.update(allow=["10.0.0.0/8"], deny=["203.0.113.0/24"], bad_bots=["sqlmap", "evil bot"],
               basic_auth_users=[{"username": "u", "password_hash": "$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1"}])
    data["headers"] = [{"name": "X-Fuzz", "value": draw(st.text(PRINTABLE.filter(lambda c: c != "$"), max_size=20))}]
    locs = []
    for i in range(draw(st.integers(0, 3))):
        loc = _toggles(draw, Location)
        loc.update(path=["/api/", "/static/", r"\.php$", "/exact"][i], use_site_backends=draw(st.booleans()),
                   backends=[{"address": "127.0.0.1", "port": 9100 + i}], redirect_url="https://example.com/x",
                   static_root="/var/www/html", return_body="ok", rate="5r/s")
        if loc["match"] in ("regex", "regex_ci") and not loc["path"].startswith("\\"):
            loc["path"] = r"\.php$"
        elif loc["match"] not in ("regex", "regex_ci") and loc["path"].startswith("\\"):
            loc["path"] = "/php/"
        locs.append(loc)
    data["locations"] = locs
    glob = _toggles(draw, GlobalSettings)
    # списки, которые переключателями не задаются: DNS для бэкендов по имени, реальный IP за прокси, своё http
    glob.update(resolver=draw(st.sampled_from([[], ["1.1.1.1", "8.8.8.8"]])),
                real_ip_from=draw(st.sampled_from([[], ["10.0.0.0/8", "2001:db8::/32"]])),
                custom_http=draw(st.sampled_from(["", "# своё\nmerge_slashes on;"])))
    panel = {"panel_domain": draw(st.sampled_from(["", "panel.fuzz.test"])),
             "panel_certificate_id": draw(st.sampled_from([None, 1, 99])),
             "panel_allow": draw(st.sampled_from([[], ["10.0.0.0/8"]]))}
    try:
        site = Site.model_validate(data)
        g = GlobalSettings.model_validate(glob)
        p = PanelSettings.model_validate(panel)
    except ValidationError:
        assume(False)
    return site, g, p


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    d = tmp_path_factory.mktemp("cert")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"),
                    "-out", str(d / "c.pem"), "-days", "2", "-subj", "/CN=fuzz.test"], capture_output=True, check=True)
    return CertInfo(1, str(d / "c.pem"), str(d / "k.pem"), True)


@needs_nginx
@hsettings(max_examples=int(os.environ.get("NM_FUZZ", "60")), deadline=None, derandomize=not os.environ.get("NM_FUZZ"),
           suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much,
                                  HealthCheck.too_slow])
@given(site_states())
def test_random_site_and_global_settings_pass_nginx_t(mgr, cert, sg):  # noqa: F811
    site, g, panel = sg
    stream = Stream(name="PG", listen_port=25432, backends=[Backend(port=5432)])
    state = State([(1, site)], [(1, stream)], g, panel, {1: cert})
    try:
        mgr.apply_sync(state, "fuzz")
    except M.ApplyError as e:
        # понятный отказ генератора (противоречивые настройки) допустим; ошибка nginx -t — нет
        emerg = [ln for ln in e.output.splitlines() if "[emerg]" in ln]
        assert not e.output, ("\n".join(emerg) or e.output[-1500:],
                              json.dumps(site.model_dump(exclude_defaults=True), ensure_ascii=False)[:3000],
                              json.dumps(g.model_dump(exclude_defaults=True), ensure_ascii=False)[:1500])


@needs_nginx
def test_many_sites_same_ports_and_defaults(mgr, cert):  # noqa: F811
    """Двадцать сайтов на одних портах, у части свой listen_ip, один — сервер по умолчанию; IDN-домены и
    шаблоны; сайты-перенаправления и статика."""
    sites = []
    for i in range(20):
        kind = ["proxy", "redirect", "static"][i % 3]
        sites.append((i + 1, Site(name=f"Сайт {i}", type=kind, domains=[f"s{i}.test", f"*.w{i}.test",
                                                                         f"пример{i}.рф"],
                                  backends=[Backend(address="127.0.0.1", port=9000 + i)],
                                  redirect={"url": "https://example.com"}, static={"root": "/var/www/html"},
                                  default_server=(i == 4), listen_ip="127.0.0.1" if i % 5 == 0 else "",
                                  ssl={"enabled": i % 2 == 0, "certificate_id": 1})))
    mgr.apply_sync(State(sites, [], GlobalSettings(), PanelSettings(), {1: cert}), "fuzz")
    conf = "".join(Path(p).read_text() for p in Path(os.path.realpath(M.settings.live_dir)).rglob("*.conf"))
    assert "xn--" in conf and conf.count("default_server") >= 1
    # два «сервера по умолчанию» на одном порту — понятный отказ
    sites[1] = (2, sites[1][1].model_copy(update={"default_server": True}))
    with pytest.raises(M.ApplyError, match="по умолчанию"):
        mgr.apply_sync(State(sites, [], GlobalSettings(), PanelSettings(), {1: cert}), "fuzz")


def test_system_default_server_in_included_dirs(mgr, cert, tmp_path, monkeypatch):  # noqa: F811
    """Подключён sites-enabled, где default (Debian) — сервер по умолчанию на 80: заглушка панели уступает ему
    порт с предупреждением; сайт, отмеченный «по умолчанию» на том же порту, — понятный отказ, а не nginx -t."""
    from app.nginx import generator as G
    d = tmp_path / "sites-enabled"
    d.mkdir()
    (d / "default").write_text("server {\n\tlisten 80 default_server;\n\t# listen 443 ssl default_server;\n"
                               "\tlisten 127.0.0.1:8080 default_server;\n\tserver_name _;\n\treturn 204;\n}\n")
    (d / "broken").mkdir()  # каталог вместо файла — пропускается
    monkeypatch.setattr(G, "EXTERNAL_INCLUDES", {"include_conf_d": str(tmp_path / "conf.d/*.conf"),
                                                 "include_sites_enabled": str(d / "*")})
    g = GlobalSettings(include_sites_enabled=True)
    site = Site(name="A", domains=["a.test"], backends=[Backend(port=9001)])
    if NGINX:
        (d / "broken").rmdir()
        res = mgr.apply_sync(State([(1, site)], [], g, PanelSettings(), {1: cert}), "x")
        assert any("Порт 80: сервер по умолчанию задан" in w for w in res["warnings"])
        assert not any("8080" in w or "443" in w for w in res["warnings"])
    with pytest.raises(M.ApplyError, match="Порт 80: сервер по умолчанию уже задан") as e:
        mgr.apply_sync(State([(1, site.model_copy(update={"default_server": True}))], [], g, PanelSettings(),
                             {1: cert}), "x")
    assert not e.value.output and "«A»" in str(e.value)


def test_missing_certificate_and_stream_module(mgr, cert):  # noqa: F811
    site = Site(name="A", domains=["a.test"], backends=[Backend(port=80)], ssl={"enabled": True,
                                                                                 "certificate_id": 99})
    with pytest.raises(M.ApplyError, match="сертификат не найден") as e:
        mgr.apply_sync(State([(5, site)], [], GlobalSettings(), PanelSettings(), {1: cert}), "x")
    assert e.value.site_id == 5
    # сертификат ещё не выпущен — сайт работает по HTTP с предупреждением
    pending = CertInfo(1, cert.cert_path, cert.key_path, False)
    if NGINX:
        res = mgr.apply_sync(State([(5, site.model_copy(update={"ssl": site.ssl.model_copy(
            update={"certificate_id": 1})}))], [], GlobalSettings(), PanelSettings(), {1: pending}), "x")
        assert any("сертификат не выпущен" in w for w in res["warnings"])
    # потоки включены, а модуля stream нет
    caps = mgr.caps()
    no_stream = caps.__class__(**{**caps.__dict__, "stream_available": False, "stream_load": ""})
    mgr.caps = lambda refresh=False: no_stream
    with pytest.raises(M.ApplyError, match="модуль stream"):
        mgr.apply_sync(State([], [(1, Stream(name="S", listen_port=2000, backends=[Backend(port=1)]))],
                             GlobalSettings(), PanelSettings(), {}), "x")
    time.sleep(0)
