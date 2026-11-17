"""Доверенные адреса: свой список (настройки панели), полученные с других серверов и временные записи.

Свой список хранится в настройках панели (trusted_ips), полученные — в kv «peers_trusted»
({id сервера: {name, at, entries}}). Для генерации конфигурации и проверок защиты используется объединение:
свои действующие записи + полученные (если приём включён). У полученных записей заполнено поле origin."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..models import IpEntry

KV = "peers_trusted"
MAX_PER_PEER = 5000


def active(entries: List[IpEntry], now: Optional[float] = None) -> List[IpEntry]:
    now = now or time.time()
    return [e for e in entries if e.active(now)]


def received(db, now: Optional[float] = None) -> List[IpEntry]:
    """Действующие записи, полученные с других серверов (origin — имя сервера)."""
    now = now or time.time()
    out: List[IpEntry] = []
    for oid, d in sorted((db.kv_get(KV, {}) or {}).items()):
        name = str((d or {}).get("name") or oid)[:80]
        for raw in (d or {}).get("entries", [])[:MAX_PER_PEER]:
            try:
                e = IpEntry.model_validate({**raw, "origin": name})
            except Exception:  # noqa: BLE001 — запись с ошибкой пропускаем
                continue
            if e.active(now):
                out.append(e)
    return out


def effective(db, panel) -> List[IpEntry]:
    """Свои действующие + из списков по ссылке + полученные (без повторов адресов; своя запись важнее)."""
    from .iplists import trusted_entries
    own = active([e for e in panel.trusted_ips if not e.origin])
    out = list(own)
    have = {e.address for e in own}
    for net, comment in trusted_entries(db, panel):
        if net not in have:
            have.add(net)
            out.append(IpEntry.model_construct(address=net, comment=comment, expires=None, origin=""))
    if getattr(panel, "peers_accept_trusted", True):
        for e in received(db):
            if e.address not in have:
                have.add(e.address)
                out.append(e)
    return out


def with_effective(db, panel):
    """Копия настроек панели, где trusted_ips — действующий объединённый список (для генератора конфигурации)."""
    return panel.model_copy(update={"trusted_ips": effective(db, panel)})


def store(db, oid: str, name: str, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Сохранить список, полученный от сервера oid. Возвращает {changed, count, added, removed}."""
    clean: List[Dict[str, Any]] = []
    seen = set()
    for raw in entries[:MAX_PER_PEER]:
        if not isinstance(raw, dict):
            continue
        try:
            e = IpEntry.model_validate({"address": raw.get("address", ""), "comment": str(raw.get("comment") or "")[:120],
                                        "expires": raw.get("expires")})
        except Exception:  # noqa: BLE001
            continue
        if e.address in seen or not e.active():
            continue
        if e.address in ("0.0.0.0/0", "::/0"):
            continue  # «доверять всем» с другого сервера не принимаем
        seen.add(e.address)
        clean.append({"address": e.address, "comment": e.comment, "expires": e.expires})
    st = db.kv_get(KV, {}) or {}
    old = (st.get(oid) or {}).get("entries", [])
    old_set = {(x["address"], x.get("expires")) for x in old}
    new_set = {(x["address"], x.get("expires")) for x in clean}
    changed = old_set != new_set
    if clean:
        st[oid] = {"name": name, "at": time.time(), "entries": clean}
    else:
        st.pop(oid, None)
    db.kv_set(KV, st)
    oa = {a for a, _ in old_set}
    na = {a for a, _ in new_set}
    return {"changed": changed, "count": len(clean), "added": len(na - oa), "removed": len(oa - na)}


def by_peer(db) -> List[Dict[str, Any]]:
    """Для страницы «Доверенные адреса»: полученные списки по серверам."""
    now = time.time()
    out = []
    for oid, d in sorted((db.kv_get(KV, {}) or {}).items(), key=lambda x: str((x[1] or {}).get("name"))):
        entries = [e for e in (d or {}).get("entries", []) if not e.get("expires") or e["expires"] > now]
        out.append({"id": oid, "name": d.get("name") or oid, "at": d.get("at"), "entries": entries})
    return out
