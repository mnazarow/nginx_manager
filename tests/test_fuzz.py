"""Фаззинг генератора: опасные строки во всех строковых полях сайта, потока и глобальных настроек.

Каждое значение должно быть либо отклонено проверкой модели, либо попасть в конфигурацию так,
что токенизатор nginx не увидит в ней новой директивы. Поля custom_* (сырые директивы для
администратора) пропускаются: они намеренно вставляются как есть.
"""
import copy
import shutil
import os
from pathlib import Path

import pytest
from pydantic import ValidationError as PVE

from app.models import (Backend, BasicAuthUser, CacheSettings, GlobalSettings, Location, PanelSettings,
                        SecuritySettings, Site, SSLSettings, Stream)
from app.nginx.generator import CertInfo, Generator, NginxCaps, Paths, State
from app.utils import apr1

TMP = Path(os.environ["NM_TEST_TMP"])
MARK = "nm_injected"
PAYLOADS = [f"x; {MARK} on", f'x" ; {MARK} on; "', f"x\n{MARK} on;", f"x}} {MARK} on; {{", "a\\",
            f"x' {MARK} on '", "x\\;" + MARK + " on", f"x\t{MARK}", "#x", '"', "'"]


def directives(text: str) -> set:
    """Имена директив по правилам токенизатора nginx: кавычки, обратная косая черта, # в начале токена."""
    names, toks, tok, started, quote, i, n = set(), [], "", False, None, 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                tok += text[i + 1]
                i += 2
                continue
            if ch == quote:
                quote = None
            else:
                tok += ch
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            tok, started, i = tok + text[i + 1], True, i + 2
            continue
        if ch in "\"'" and not started:
            quote, started, i = ch, True, i + 1
            continue
        if ch == "#" and not started:
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch.isspace() or ch in ";{}":
            if started:
                toks.append(tok)
            tok, started = "", False
            if ch in ";{}":
                if toks:
                    names.add(toks[0])
                toks = []
        else:
            tok, started = tok + ch, True
        i += 1
    return names


def base_site() -> Site:
    return Site(name="Shop", domains=["shop.test"], backends=[Backend(address="127.0.0.1", port=9001)],
                ssl=SSLSettings(enabled=True, certificate_id=1, hsts=True),
                cache=CacheSettings(enabled=True, bypass_cookie_pattern="session"),
                security=SecuritySettings(rate_limit=True, basic_auth=True,
                                          basic_auth_users=[BasicAuthUser(username="u", password_hash=apr1("x"))]),
                locations=[Location(path="/api/"), Location(path="/r", action="return", return_body="ok"),
                           Location(path="/old", action="redirect", redirect_url="https://x.test/")])


def render(site=None, stream=None, glob=None):
    st = State([(1, site or base_site())], [(1, stream)] if stream else [], glob or GlobalSettings(), PanelSettings(),
               {1: CertInfo(1, "/tmp/c.pem", "/tmp/k.pem", True)})
    p = Paths(str(TMP / "fz" / "stage"), str(TMP / "fz" / "live"), "/var/acme", str(TMP / "logs"), str(TMP / "cache"),
              8089, 8088, str(TMP / "data"), bans_file=str(TMP / "fz-bans.conf"))
    return Generator(st, NginxCaps(version=(1, 24, 0), ipv6=True), p).render()


def walk(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, path + (k,))
    elif isinstance(obj, list):
        if obj and all(isinstance(x, str) for x in obj):
            yield path + (0,)
        for i, v in enumerate(obj):
            if not isinstance(v, str):
                yield from walk(v, path + (i,))
    elif isinstance(obj, str):
        yield path


def test_no_directive_injection_through_fields():
    targets = [("site", base_site().model_dump(), Site),
               ("stream", Stream(name="PG", listen_port=15432, backends=[Backend(port=5432)]).model_dump(), Stream),
               ("glob", GlobalSettings().model_dump(), GlobalSettings)]
    checked, problems = 0, []
    for kind, base, model in targets:
        for path in walk(base):
            if any(str(p).startswith("custom") for p in path):
                continue
            for payload in PAYLOADS:
                d = copy.deepcopy(base)
                ref = d
                for k in path[:-1]:
                    ref = ref[k]
                ref[path[-1]] = payload
                try:
                    m = model.model_validate(d)
                    files = render(**{kind: m})
                except (PVE, ValueError):
                    continue
                checked += 1
                for name, text in files.items():
                    if name.endswith(".htpasswd"):
                        if any(":" not in ln or ln.count(":") != 1 for ln in text.splitlines()):
                            problems.append((kind, path, payload, name))
                    elif MARK in directives(text):
                        problems.append((kind, path, payload, name))
    assert checked > 100
    assert not problems, problems[:10]


def test_tokenizer_sees_real_injection():
    assert MARK in directives(f'add_header X "a"; {MARK} on;')
    assert MARK not in directives(f'add_header X "a; {MARK} on";')
    assert MARK not in directives(f"# {MARK} on;\nlisten 80;")


@pytest.mark.skipif(not shutil.which("nginx") or os.geteuid() != 0, reason="нужен nginx и root")
def test_accepted_values_pass_nginx_t():
    """Значения, которые модель принимает, не должны ломать конфигурацию (обратная косая черта, #, кавычки)."""
    import subprocess
    from app.db import Database
    from app.nginx.manager import NginxManager
    for d in ("logs", "cache/default", "data"):
        (TMP / d).mkdir(parents=True, exist_ok=True)
    if not (TMP / "fz-c.pem").exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(TMP / "fz-k.pem"),
                        "-out", str(TMP / "fz-c.pem"), "-days", "2", "-subj", "/CN=shop.test"],
                       capture_output=True, check=True)
    (TMP / "fz-bans.conf").write_text("")
    mgr = NginxManager(Database(TMP / "fz.db"))
    caps = mgr.caps()
    stage = TMP / "fz" / "stage"
    failures = []
    targets = [("site", base_site().model_dump(), Site),
               ("glob", GlobalSettings().model_dump(), GlobalSettings)]
    for kind, base, model in targets:
        for path in walk(base):
            if any(str(p).startswith("custom") for p in path):
                continue
            for payload in ("a\\", "#x", "x # y", "тест значение", '"', "'"):
                d = copy.deepcopy(base)
                ref = d
                for k in path[:-1]:
                    ref = ref[k]
                ref[path[-1]] = payload
                try:
                    m = model.model_validate(d)
                except (PVE, ValueError):
                    continue
                st = State([(1, m if kind == "site" else base_site())], [], m if kind == "glob" else GlobalSettings(),
                           PanelSettings(), {1: CertInfo(1, str(TMP / "fz-c.pem"), str(TMP / "fz-k.pem"), True)})
                p = Paths(str(stage), str(TMP / "fz" / "live"), "/var/acme", str(TMP / "logs"), str(TMP / "cache"),
                          8089, 8088, str(TMP / "data"), bans_file=str(TMP / "fz-bans.conf"))
                try:
                    files = Generator(st, caps, p).render()
                except ValueError:
                    continue
                shutil.rmtree(stage, ignore_errors=True)
                for rel, content in files.items():
                    (stage / rel).parent.mkdir(parents=True, exist_ok=True)
                    (stage / rel).write_text(content)
                ok, out = mgr.test_config(stage / "nginx.conf")
                if not ok:
                    failures.append((kind, path, payload, out.strip().splitlines()[:1]))
    mgr.db.close()
    assert not failures, failures[:10]
