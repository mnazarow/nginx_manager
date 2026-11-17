"""Списки разрешённых адресов по ссылке («Доступ по IP» сайта → «Списки адресов по ссылке»).

Панель скачивает файл по расписанию (интервал — у списка), находит в нём IPv4/IPv6-адреса и подсети (подходят
текст «по строке», CSV и JSON — например, диапазоны сервиса из его API) и добавляет их в тот же файл, что и доступ
по ссылке (ip-grants.conf: geo $nm_ipgrant, адрес → «,номера сайтов,»). nginx перечитывает файл без новой версии
конфигурации. Если список не скачался, действуют адреса из последней удачной загрузки.
"""
from __future__ import annotations

import ipaddress
import re
import ssl
import time
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

KV = "iplists"
MAX_BYTES = 4 << 20
MAX_NETS = 50000
_RE = re.compile(r"(?<![\w:.])((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+(?:/\d{1,3})?)(?![\w:.])")


def parse(text: str) -> List[str]:
    """Все адреса и подсети в тексте (комментарии после # игнорируются), без повторов, нормализованные."""
    out: List[str] = []
    seen: Set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        for m in _RE.finditer(line):
            raw = m.group(1)
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                continue
            if net.prefixlen == 0:
                continue  # «все адреса» из списка не принимаем
            v = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
            if v not in seen:
                seen.add(v)
                out.append(v)
                if len(out) >= MAX_NETS:
                    return out
    return out


def fetch(url: str, timeout: float = 20) -> List[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "NginxManager-IpList/1.0", "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:  # noqa: S310
        blob = r.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        raise ValueError("список больше 4 МБ")
    nets = parse(blob.decode("utf-8", "replace"))
    if not nets:
        raise ValueError("в файле не найдено ни одного IP-адреса или подсети")
    return nets


def sources(state) -> Dict[str, Dict[str, Any]]:
    """{url: {hours, sites: [номер]}} по включённым сайтам применённой версии."""
    out: Dict[str, Dict[str, Any]] = {}
    for sid, s in state.sites:
        if not (s.enabled and s.ip_access.enabled):
            continue
        for src in s.ip_access.lists:
            d = out.setdefault(src.url, {"hours": src.hours, "sites": []})
            d["hours"] = min(d["hours"], src.hours)
            d["sites"].append(sid)
    return out


def refresh(db, state, force_urls: Optional[List[str]] = None, fetcher=None) -> Tuple[bool, Dict[str, Any]]:
    """Скачать списки, у которых подошёл срок (или указанные). (изменились ли адреса, итоги по спискам)."""
    fetcher = fetcher or fetch
    st: Dict[str, Any] = db.kv_get(KV, {}) or {}
    srcs = sources(state)
    changed = False
    done: Dict[str, Any] = {}
    now = time.time()
    for url, d in srcs.items():
        cur = st.get(url) or {}
        due = force_urls is not None and url in force_urls or \
            force_urls is None and now - float(cur.get("tried") or 0) >= d["hours"] * 3600
        if not due:
            continue
        try:
            nets = fetcher(url)
            if nets != cur.get("nets"):
                changed = True
            st[url] = {"nets": nets, "at": now, "tried": now, "ok": True, "error": "", "count": len(nets)}
        except Exception as e:  # noqa: BLE001
            st[url] = {**cur, "tried": now, "ok": False, "error": str(e)[:300]}
        done[url] = st[url]
    for url in [u for u in st if u not in srcs]:  # список больше нигде не используется
        st.pop(url)
        changed = True
    db.kv_set(KV, st)
    return changed, done


def site_nets(db, state) -> Dict[str, Set[int]]:
    """{сеть: {номера сайтов}} из последних удачных загрузок."""
    st = db.kv_get(KV, {}) or {}
    out: Dict[str, Set[int]] = {}
    for url, d in sources(state).items():
        for net in (st.get(url) or {}).get("nets") or []:
            out.setdefault(net, set()).update(d["sites"])
    return out


def status(db, state, sid: int) -> List[Dict[str, Any]]:
    st = db.kv_get(KV, {}) or {}
    out = []
    for sid_, s in state.sites:
        if sid_ != sid:
            continue
        for src in s.ip_access.lists:
            d = st.get(src.url) or {}
            out.append({"url": src.url, "comment": src.comment, "hours": src.hours, "ok": d.get("ok"),
                        "error": d.get("error", ""), "count": d.get("count", 0), "at": d.get("at"),
                        "tried": d.get("tried"), "sample": (d.get("nets") or [])[:12]})
    return out


def merge(entries: Dict[str, Set[int]]) -> Dict[str, Set[int]]:
    """geo выбирает самую точную подсеть: каждой сети добавляются сайты всех сетей, в которые она входит, —
    иначе адрес, выданный по ссылке для одного сайта, «закрыл» бы подсеть из списка другого."""
    nets = []
    for k in entries:
        try:
            nets.append((ipaddress.ip_network(k, strict=False), k))
        except ValueError:
            continue
    by_len: Dict[Tuple[int, int], Dict[Any, Set[int]]] = {}
    for n, k in nets:
        by_len.setdefault((n.version, n.prefixlen), {})[n.network_address] = entries[k]
    lens = sorted(by_len)
    out: Dict[str, Set[int]] = {}
    for n, k in nets:
        sites = set(entries[k])
        for ver, plen in lens:
            if ver != n.version or plen >= n.prefixlen:
                continue
            sup = n.supernet(new_prefix=plen).network_address
            sites |= by_len[(ver, plen)].get(sup, set())
        out[k] = sites
    return out
