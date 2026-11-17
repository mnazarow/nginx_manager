"""Списки разрешённых адресов по ссылке («Доступ по IP» сайта → «Списки адресов по ссылке»).

Панель скачивает файл по расписанию (интервал — у списка), находит в нём IPv4/IPv6-адреса и подсети (подходят
текст «по строке», CSV и JSON — например, диапазоны сервиса из его API) и добавляет их в тот же файл, что и доступ
по ссылке (ip-grants.conf: geo $nm_ipgrant, адрес → «,номера сайтов,»). nginx перечитывает файл без новой версии
конфигурации. Если список не скачался, действуют адреса из последней удачной загрузки.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

KV = "iplists"
KV_TRUSTED = "trusted_lists"
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


def fetch(url: str, timeout: float = 20, sha256: str = "") -> List[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "NginxManager-IpList/1.0", "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:  # noqa: S310
        blob = r.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        raise ValueError("список больше 4 МБ")
    if sha256 and hashlib.sha256(blob).hexdigest() != sha256:
        raise ValueError("контрольная сумма SHA-256 не совпадает — файл изменён, загрузка отклонена")
    nets = parse(blob.decode("utf-8", "replace"))
    if not nets:
        raise ValueError("в файле не найдено ни одного IP-адреса или подсети")
    return nets


def _opts(src) -> Dict[str, Any]:
    return {"hours": src.hours, "min_prefix": getattr(src, "min_prefix", 16), "max_change": getattr(src, "max_change", 50),
            "sha256": getattr(src, "sha256", ""), "comment": src.comment, "sites": []}


def _merge_opts(d: Dict[str, Any], src) -> None:
    """Один список у нескольких сайтов: самый частый интервал и самые строгие проверки."""
    d["hours"] = min(d["hours"], src.hours)
    d["min_prefix"] = max(d["min_prefix"], getattr(src, "min_prefix", 16))
    mc = getattr(src, "max_change", 50)
    d["max_change"] = min(x for x in (d["max_change"], mc) if x) if (d["max_change"] or mc) else 0
    d["sha256"] = d["sha256"] or getattr(src, "sha256", "")


def sources(state) -> Dict[str, Dict[str, Any]]:
    """{url: {hours, проверки, sites: [номер]}} по включённым сайтам применённой версии."""
    out: Dict[str, Dict[str, Any]] = {}
    for sid, s in state.sites:
        if not (s.enabled and s.ip_access.enabled):
            continue
        for src in s.ip_access.lists:
            if src.url in out:
                _merge_opts(out[src.url], src)
            else:
                out[src.url] = _opts(src)
            out[src.url]["sites"].append(sid)
    return out


def trusted_sources(panel) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for src in getattr(panel, "trusted_lists", []) or []:
        if src.url in out:
            _merge_opts(out[src.url], src)
        else:
            out[src.url] = _opts(src)
    return out


def guard(nets: List[str], old: Optional[List[str]], opts: Dict[str, Any]) -> Tuple[List[str], int, Optional[int]]:
    """Отбросить слишком широкие подсети; посчитать, на сколько процентов список изменился.
    (сети, отброшено, процент изменений — если превышен порог подтверждения, иначе None)."""
    mp = int(opts.get("min_prefix") or 0)
    keep, dropped = [], 0
    for n in nets:
        net = ipaddress.ip_network(n, strict=False)
        if mp and net.prefixlen < (mp if net.version == 4 else min(128, mp + 16)):
            dropped += 1
            continue
        keep.append(n)
    if not keep:
        raise ValueError(f"все {len(nets)} записей шире разрешённой подсети /{mp} — список отклонён")
    mc = int(opts.get("max_change") or 0)
    if old and mc:
        a, b = set(old), set(keep)
        pct = round(100 * len(a ^ b) / max(len(a | b), 1))  # доля изменившихся среди всех встреченных адресов
        if pct > mc:
            return keep, dropped, pct
    return keep, dropped, None


def _refresh(db, kv: str, srcs: Dict[str, Dict[str, Any]], force_urls: Optional[List[str]], fetcher,
             accept: Optional[List[str]] = None) -> Tuple[bool, Dict[str, Any]]:
    fetcher = fetcher or fetch
    st: Dict[str, Any] = db.kv_get(kv, {}) or {}
    changed = False
    done: Dict[str, Any] = {}
    now = time.time()
    for url in accept or []:  # «Принять изменения»: отложенная загрузка становится действующей
        cur = st.get(url) or {}
        if cur.get("pending"):
            nets = cur["pending"]["nets"]
            st[url] = {**cur, "nets": nets, "count": len(nets), "at": cur["pending"]["at"], "ok": True, "error": "",
                       "pending": None}
            changed = True
            done[url] = st[url]
    for url, d in srcs.items():
        cur = st.get(url) or {}
        due = force_urls is not None and url in force_urls or \
            force_urls is None and now - float(cur.get("tried") or 0) >= d["hours"] * 3600
        if not due or url in done:
            continue
        try:
            raw = fetcher(url, sha256=d["sha256"]) if d.get("sha256") else fetcher(url)
            nets, dropped, pct = guard(raw, cur.get("nets"), d)
            if pct is not None:
                st[url] = {**cur, "tried": now, "ok": False, "dropped": dropped,
                           "error": f"изменилось {pct}% адресов (порог {d['max_change']}%) — ждёт подтверждения",
                           "pending": {"nets": nets, "at": now, "pct": pct}}
            else:
                if nets != cur.get("nets"):
                    changed = True
                st[url] = {"nets": nets, "at": now, "tried": now, "ok": True, "error": "", "count": len(nets),
                           "dropped": dropped, "pending": None}
        except Exception as e:  # noqa: BLE001
            st[url] = {**cur, "tried": now, "ok": False, "error": str(e)[:300]}
        done[url] = st[url]
    for url in [u for u in st if u not in srcs]:  # список больше нигде не используется
        st.pop(url)
        changed = True
    db.kv_set(kv, st)
    return changed, done


def refresh(db, state, force_urls: Optional[List[str]] = None, fetcher=None,
            accept: Optional[List[str]] = None) -> Tuple[bool, Dict[str, Any]]:
    """Скачать списки сайтов, у которых подошёл срок (или указанные). (изменились ли адреса, итоги по спискам)."""
    return _refresh(db, KV, sources(state), force_urls, fetcher, accept)


def refresh_trusted(db, panel, force_urls: Optional[List[str]] = None, fetcher=None,
                    accept: Optional[List[str]] = None) -> Tuple[bool, Dict[str, Any]]:
    return _refresh(db, KV_TRUSTED, trusted_sources(panel), force_urls, fetcher, accept)


def site_nets(db, state) -> Dict[str, Set[int]]:
    """{сеть: {номера сайтов}} из последних удачных загрузок."""
    st = db.kv_get(KV, {}) or {}
    out: Dict[str, Set[int]] = {}
    for url, d in sources(state).items():
        for net in (st.get(url) or {}).get("nets") or []:
            out.setdefault(net, set()).update(d["sites"])
    return out


def trusted_entries(db, panel) -> List[Tuple[str, str]]:
    """[(сеть, комментарий)] доверенных адресов из списков по ссылке (последние принятые загрузки)."""
    st = db.kv_get(KV_TRUSTED, {}) or {}
    out, seen = [], set()
    for url, d in trusted_sources(panel).items():
        label = d["comment"] or urllib.parse.urlparse(url).netloc
        for net in (st.get(url) or {}).get("nets") or []:
            if net not in seen:
                seen.add(net)
                out.append((net, f"из списка «{label}»"[:120]))
    return out


def _status_item(src, d: Dict[str, Any]) -> Dict[str, Any]:
    pend = d.get("pending") or None
    return {"url": src.url, "comment": src.comment, "hours": src.hours, "ok": d.get("ok"),
            "error": d.get("error", ""), "count": d.get("count", 0), "at": d.get("at"), "tried": d.get("tried"),
            "dropped": d.get("dropped", 0), "sample": (d.get("nets") or [])[:12],
            "pending": {"count": len(pend["nets"]), "pct": pend["pct"], "at": pend["at"],
                        "added": sorted(set(pend["nets"]) - set(d.get("nets") or []))[:10],
                        "removed": sorted(set(d.get("nets") or []) - set(pend["nets"]))[:10]} if pend else None}


def status(db, state, sid: int) -> List[Dict[str, Any]]:
    st = db.kv_get(KV, {}) or {}
    out = []
    for sid_, s in state.sites:
        if sid_ != sid:
            continue
        for src in s.ip_access.lists:
            out.append(_status_item(src, st.get(src.url) or {}))
    return out


def trusted_status(db, panel) -> List[Dict[str, Any]]:
    st = db.kv_get(KV_TRUSTED, {}) or {}
    return [_status_item(src, st.get(src.url) or {}) for src in getattr(panel, "trusted_lists", []) or []]


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
