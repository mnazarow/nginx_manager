"""API раздела «Доверенные адреса»: общий список IP и подсетей, которые никогда не блокируются, и проверка адреса
(доверенный ли, заблокирован ли, какие сайты с доступом по IP его пускают)."""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Dict

from fastapi import Body, Depends, HTTPException, Query, Request

from ..auth import admin, viewer
from ..models import LOOPBACK_NETS, PRIVATE_NETS, PanelSettings
from .routes import audit, router


def _nm(request: Request):
    return request.app.state.nm


def _net(x: str):
    return ipaddress.ip_network(x, strict=False)


def _in(ip: str, nets) -> str:
    try:
        a = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return ""
    for n in nets:
        try:
            t = _net(n)
        except ValueError:
            continue
        if a.version == t.version and a.subnet_of(t):
            return n
    return ""


@router.get("/trusted")
async def trusted_get(request: Request, user=Depends(viewer)):
    """Доверенные адреса, всегда доверенные (сервер, доступ к панели) и ваш адрес."""
    app = _nm(request)
    p = app.panel()
    return {"entries": [e.model_dump() for e in p.trusted_ips], "always": LOOPBACK_NETS + list(p.panel_allow),
            "your_ip": app.auth.client_ip(request)}


@router.put("/trusted")
async def trusted_put(request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                      user=Depends(admin)):
    """Сохранить список: {entries: [{address, comment}]}. Блокировки адресов, вошедших в список, снимаются.
    ?apply=1 — применить конфигурацию nginx (доверенные адреса в проверках защиты, ограничениях частоты, доступе по
    странам и на сайтах с доступом по IP)."""
    app = _nm(request)
    raw = body.get("entries")
    if not isinstance(raw, list) or len(raw) > 5000:
        raise HTTPException(400, "Ожидается список entries (не больше 5000 записей)")
    raw = [e if isinstance(e, dict) else {"address": str(e)} for e in raw]
    # проверка — моделью настроек панели (ошибки с указанием строки: trusted_ips.N.address)
    checked = PanelSettings.model_validate({**app.panel().model_dump(), "trusted_ips": raw})
    entries, seen = [], set()
    for item in checked.trusted_ips:
        if item.address not in seen:
            seen.add(item.address)
            entries.append(item)
    if any(_net(e.address).prefixlen == 0 for e in entries):
        raise HTTPException(400, "Нельзя сделать доверенными все адреса (0.0.0.0/0 или ::/0)")
    old = {e.address for e in app.panel().trusted_ips}
    app.save_panel(app.panel().model_copy(update={"trusted_ips": entries}))
    unbanned = await asyncio.to_thread(app.bans.drop_trusted)
    await app.bans.sync(force=True)
    new = {e.address for e in entries}
    audit(request, user, "trusted_updated", f"{len(entries)} адресов",
          {"added": sorted(new - old)[:50], "removed": sorted(old - new)[:50], "unbanned": unbanned})
    res = await app.apply(user["username"], "Изменены доверенные адреса") if apply else None
    return {"ok": True, "count": len(entries), "unbanned": unbanned, "applied": res}


@router.get("/trusted/check")
async def trusted_check(request: Request, ip: str = Query(...), user=Depends(viewer)):
    """Проверить адрес: доверенный ли (какой записью), заблокирован ли, на каких сайтах с доступом по IP открыт."""
    app = _nm(request)
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(400, f"«{ip}» — не IP-адрес")
    a = str(addr)
    p = app.panel()
    entry = next((e for e in p.trusted_ips if _in(a, [e.address])), None)
    always = _in(a, LOOPBACK_NETS + list(p.panel_allow))
    ban = None
    for r in app.db.query("SELECT net, reason, expires_at FROM bans"):
        if _in(a, [r["net"]]):
            ban = dict(r)
            break
    sites = []
    for sid, s in app.nginx.load_state().sites:
        x = s.ip_access
        if not x.enabled:
            continue
        by = next((e.address + (f" ({e.comment})" if e.comment else "") for e in x.entries if _in(a, [e.address])),
                  "")
        if not by and x.allow_trusted and entry:
            by = "доверенные адреса"
        if not by and x.allow_private and _in(a, PRIVATE_NETS):
            by = "локальные сети"
        if not by and _in(a, LOOPBACK_NETS):
            by = "сам сервер"
        sites.append({"id": sid, "name": s.name, "allowed": bool(by), "by": by})
    return {"ip": a, "trusted": entry.model_dump() if entry else None, "always": always,
            "banned": ban, "sites": sites}
