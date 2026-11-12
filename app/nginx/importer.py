"""Импорт существующих конфигураций nginx (из nginx -T) в сайты панели.

Разбирает server-блоки, upstream-группы, proxy_pass, сертификаты, редиректы и статические локации.
Всё, что не удалось сопоставить с полями формы, сохраняется в «Свои директивы» или заметки.
"""
from __future__ import annotations

import fnmatch
import os
import re
from typing import Any, Dict, List, Optional, Tuple

Node = Dict[str, Any]


def split_dump(text: str) -> Dict[str, str]:
    files: Dict[str, str] = {}
    cur, buf = None, []
    for line in text.splitlines():
        m = re.match(r"^# configuration file (.+):$", line)
        if m:
            if cur:
                files[cur] = "\n".join(buf)
            cur, buf = m.group(1), []
        elif cur:
            buf.append(line)
    if cur:
        files[cur] = "\n".join(buf)
    return files


def tokenize(src: str) -> List[str]:
    toks: List[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
        elif c == "#":
            while i < n and src[i] != "\n":
                i += 1
        elif c in "{};":
            toks.append(c)
            i += 1
        elif c in "\"'":
            q, j, buf = c, i + 1, []
            while j < n and src[j] != q:
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j + 1])
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            toks.append("".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and not src[j].isspace() and src[j] not in "{};":
                if src[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            toks.append(src[i:j])
            i = j
    return toks


def parse(toks: List[str]) -> List[Node]:
    pos = 0

    def block() -> List[Node]:
        nonlocal pos
        nodes: List[Node] = []
        args: List[str] = []
        while pos < len(toks):
            t = toks[pos]
            pos += 1
            if t == ";":
                if args:
                    nodes.append({"name": args[0], "args": args[1:], "block": None})
                args = []
            elif t == "{":
                nodes.append({"name": args[0] if args else "", "args": args[1:], "block": block()})
                args = []
            elif t == "}":
                return nodes
            else:
                args.append(t)
        return nodes

    return block()


def expand(nodes: List[Node], files: Dict[str, str], conf_dir: str, depth: int = 0) -> List[Node]:
    out: List[Node] = []
    for n in nodes:
        if n["name"] == "include" and n["args"] and depth < 10:
            pat = n["args"][0]
            if not pat.startswith("/"):
                pat = os.path.join(conf_dir, pat)
            for path in sorted(p for p in files if fnmatch.fnmatch(p, pat)):
                out.extend(expand(parse(tokenize(files[path])), files, conf_dir, depth + 1))
        else:
            if n["block"] is not None:
                n = {**n, "block": expand(n["block"], files, conf_dir, depth)}
            out.append(n)
    return out


def find(nodes: List[Node], name: str) -> List[Node]:
    return [n for n in nodes if n["name"] == name]


def first_a(nodes: List[Node], name: str) -> Optional[Node]:
    """Первая директива с аргументами (директивы без аргументов — ошибка в исходной конфигурации, их пропускаем)."""
    return next((n for n in nodes if n["name"] == name and n["args"]), None)


def first(nodes: List[Node], name: str) -> Optional[Node]:
    r = find(nodes, name)
    return r[0] if r else None


def parse_server_addr(s: str) -> Tuple[str, Optional[int]]:
    if s.startswith("unix:"):
        return s, None
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", s)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else 80
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h, int(p) if p.isdigit() else 80
    return s, 80


def upstream_backends(node: Node) -> Tuple[List[Dict[str, Any]], str]:
    backends = []
    balancing = "round_robin"
    for d in node["block"] or []:
        if d["name"] == "server" and d["args"]:
            addr, port = parse_server_addr(d["args"][0])
            b: Dict[str, Any] = {"address": addr, "port": port}
            for a in d["args"][1:]:
                if a.startswith("weight="):
                    b["weight"] = int(a[7:])
                elif a.startswith("max_fails="):
                    b["max_fails"] = int(a[10:])
                elif a.startswith("fail_timeout="):
                    b["fail_timeout"] = a[13:]
                elif a == "backup":
                    b["backup"] = True
                elif a == "down":
                    b["down"] = True
                elif a.startswith("max_conns="):
                    b["max_conns"] = int(a[10:])
            backends.append(b)
        elif d["name"] in ("least_conn", "ip_hash", "random"):
            balancing = d["name"]
        elif d["name"] == "hash":
            balancing = "hash"
    return backends, balancing


def proxy_target(url: str, upstreams: Dict[str, Node]) -> Optional[Dict[str, Any]]:
    m = re.match(r"^(https?)://([^/]+)(/.*)?$", url)
    if not m:
        return None
    scheme, host, path = m.group(1), m.group(2), m.group(3) or ""
    if "$" in host:
        return None
    if host in upstreams:
        backends, bal = upstream_backends(upstreams[host])
        return {"scheme": scheme, "backends": backends, "balancing": bal, "path": path}
    addr, port = parse_server_addr(host)
    if port == 80 and scheme == "https" and ":" not in host:
        port = 443
    return {"scheme": scheme, "backends": [{"address": addr, "port": port}], "balancing": "round_robin", "path": path}


HANDLED = {"listen", "server_name", "ssl_certificate", "ssl_certificate_key", "location", "access_log", "error_log",
           "return", "root", "index", "client_max_body_size", "ssl_protocols", "ssl_ciphers", "http2",
           "ssl_session_cache", "ssl_session_timeout", "ssl_prefer_server_ciphers", "include", "add_header",
           "ssl_dhparam", "ssl_session_tickets", "ssl_stapling", "ssl_stapling_verify", "gzip"}


def import_config(dump: str, conf_path: str) -> Dict[str, Any]:
    files = split_dump(dump)
    if conf_path not in files and files:
        conf_path = next(iter(files))
    root = expand(parse(tokenize(files.get(conf_path, ""))), files, os.path.dirname(conf_path))
    http = first(root, "http")
    if not http:
        return {"sites": [], "certificates": [], "warnings": ["Блок http не найден"]}
    hb = http["block"]
    upstreams = {u["args"][0]: u for u in find(hb, "upstream") if u["args"]}
    servers = find(hb, "server")
    groups: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    certs: Dict[Tuple[str, str], str] = {}
    warnings: List[str] = []
    for srv in servers:
        b = srv["block"] or []
        names = tuple(sorted(a for n in find(b, "server_name") for a in n["args"])) or ("_",)
        if names == ("_",) or names == ("localhost",):
            continue
        listens = [n["args"] for n in find(b, "listen")]
        ssl = any("ssl" in a or (a and a[0].endswith("443")) for a in listens)
        g = groups.setdefault(names, {"name": names[0], "domains": list(names), "http": None, "https": None})
        g["https" if ssl else "http"] = srv
    sites = []
    for names, g in groups.items():
        main = g["https"] or g["http"]
        b = main["block"] or []
        site: Dict[str, Any] = {"name": g["name"], "domains": g["domains"], "enabled": False, "type": "proxy",
                                "tags": ["импорт"], "locations": [], "backends": []}
        notes = []
        custom = []
        if g["https"]:
            cert = first_a(b, "ssl_certificate")
            key = first_a(b, "ssl_certificate_key")
            if cert and key:
                pair = (cert["args"][0], key["args"][0])
                certs[pair] = g["name"]
                site["ssl"] = {"enabled": True, "certificate_ref": list(pair),
                               "force_https": bool(g["http"] and _is_https_redirect(g["http"]))}
        for ln in find(b, "listen"):
            if ln["args"]:
                port = re.sub(r"^.*:", "", ln["args"][0])
                if port.isdigit():
                    p = int(port)
                    if "ssl" in ln["args"] and p != 443:
                        site["https_port"] = p
                    elif "ssl" not in ln["args"] and p != 80 and not ln["args"][0].endswith("443"):
                        site["http_port"] = p
        cmb = first_a(b, "client_max_body_size")
        if cmb:
            site["performance"] = {"client_max_body_size": cmb["args"][0]}
        ret = first_a(b, "return")
        if ret and len(ret["args"]) >= 2 and ret["args"][0] in ("301", "302", "307", "308"):
            site["type"] = "redirect"
            url = ret["args"][1]
            site["redirect"] = {"url": url.replace("$request_uri", ""), "code": int(ret["args"][0]),
                                "preserve_path": "$request_uri" in url}
        for loc in find(b, "location"):
            args = loc["args"]
            if not args:
                continue
            mod, path = ("", args[0]) if len(args) == 1 else (args[0], args[1])
            match = {"": "prefix", "=": "exact", "^~": "prefix_priority", "~": "regex", "~*": "regex_ci"}.get(mod)
            if not match or path.startswith("@") or "/.well-known/acme-challenge" in path:
                continue
            lb = loc["block"] or []
            pp = first_a(lb, "proxy_pass")
            r = first_a(lb, "return")
            root = first_a(lb, "root") or first_a(lb, "alias")
            if path == "/" and match == "prefix" and pp:
                t = proxy_target(pp["args"][0], upstreams)
                if t:
                    site["backends"] = t["backends"]
                    site["backend_scheme"] = t["scheme"]
                    site["balancing"] = t["balancing"]
                    rt = first_a(lb, "proxy_read_timeout")
                    site.setdefault("proxy", {})
                    if rt:
                        site["proxy"]["read_timeout"] = rt["args"][0]
                    ct = first_a(lb, "proxy_connect_timeout")
                    if ct:
                        site["proxy"]["connect_timeout"] = ct["args"][0]
                    if not first(lb, "proxy_set_header") or not any(
                            h["args"][:1] == ["Upgrade"] for h in find(lb, "proxy_set_header")):
                        site["proxy"]["websocket"] = False
                else:
                    notes.append(f"location / proxy_pass {pp['args'][0]} не распознан")
                continue
            if path == "/" and match == "prefix" and root and not pp and site["type"] == "proxy":
                site["type"] = "static"
                site["static"] = {"root": root["args"][0]}
                tf = first_a(lb, "try_files")
                if tf and "/index.html" in tf["args"]:
                    site["static"]["spa"] = True
                continue
            item: Dict[str, Any] = {"path": path, "match": match}
            if pp:
                t = proxy_target(pp["args"][0], upstreams)
                if not t:
                    notes.append(f"location {path}: proxy_pass {pp['args'][0]} не распознан")
                    continue
                item.update(action="proxy", use_site_backends=False, backends=t["backends"],
                            backend_scheme=t["scheme"])
                if t["path"] and match not in ("regex", "regex_ci"):
                    item["proxy_path"] = t["path"]
            elif r and r["args"]:
                code = r["args"][0]
                if code in ("301", "302", "307", "308") and len(r["args"]) > 1:
                    item.update(action="redirect", redirect_code=int(code), redirect_url=r["args"][1])
                elif code == "403":
                    item.update(action="deny")
                else:
                    item.update(action="return", return_code=int(code) if code.isdigit() else 200,
                                return_body=r["args"][1] if len(r["args"]) > 1 else "")
            elif root:
                item.update(action="static", static_root=root["args"][0])
            elif find(lb, "deny"):
                item.update(action="deny")
            else:
                notes.append(f"location {mod} {path}: не распознан, перенесён в «Свои директивы»")
                custom.append(_render(loc))
                continue
            site["locations"].append(item)
        for d in b:
            if d["name"] not in HANDLED and d["name"] not in ("proxy_set_header", "proxy_pass"):
                custom.append(_render(d))
        if site["type"] == "proxy" and not site["backends"] and not any(
                lc.get("path") == "/" for lc in site["locations"]):
            warnings.append(f"«{g['name']}»: не найден proxy_pass в location / — сайт импортирован как статический")
            site["type"] = "static"
        if custom:
            site["custom_server"] = "\n".join(custom)
        if notes:
            site["notes"] = "Импорт: " + "; ".join(notes)
        sites.append(site)
    return {"sites": sites, "certificates": [{"cert": c, "key": k, "name": n} for (c, k), n in certs.items()],
            "warnings": warnings}


def _is_https_redirect(srv: Node) -> bool:
    for n in (srv["block"] or []):
        if n["name"] == "return" and len(n["args"]) > 1 and n["args"][1].startswith("https://"):
            return True
        if n["name"] == "location" and n["block"]:
            if _is_https_redirect(n):
                return True
    return False


def _render(n: Node, ind: int = 0) -> str:
    pad = "    " * ind
    args = " ".join(_q(a) for a in n["args"])
    if n["block"] is None:
        return f"{pad}{n['name']} {args};".replace(" ;", ";")
    inner = "\n".join(_render(c, ind + 1) for c in n["block"])
    return f"{pad}{n['name']} {args} {{\n{inner}\n{pad}}}".replace("  {", " {")


def _q(a: str) -> str:
    return f'"{a}"' if (not a or any(c.isspace() or c in ";{}" for c in a)) else a
