"""API раздела «Доверенные адреса»: общий список IP и подсетей, которые никогда не блокируются, и проверка адреса
(доверенный ли, заблокирован ли, какие сайты с доступом по IP его пускают)."""
from __future__ import annotations

import asyncio
import time
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
    from ..services.iplists import trusted_status
    from ..services.trusted import by_peer
    return {"entries": [e.model_dump() for e in p.trusted_ips if not e.origin],
            "lists": [x.model_dump() for x in p.trusted_lists], "lists_status": trusted_status(app.db, p),
            "always": LOOPBACK_NETS + list(p.panel_allow), "your_ip": app.auth.client_ip(request),
            "received": by_peer(app.db), "accept": p.peers_accept_trusted,
            "share": [{"id": x.id, "name": x.name, "trusted": x.trusted} for x in p.peers if x.enabled]}


@router.put("/trusted")
async def trusted_put(request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                      user=Depends(admin)):
    """Сохранить список: {entries: [{address, comment}], lists: [{url, comment, hours, …}] (необязательно)}.
    Блокировки адресов, вошедших в список, снимаются.
    ?apply=1 — применить конфигурацию nginx (доверенные адреса в проверках защиты, ограничениях частоты, доступе по
    странам и на сайтах с доступом по IP)."""
    app = _nm(request)
    raw = body.get("entries")
    if not isinstance(raw, list) or len(raw) > 5000:
        raise HTTPException(400, "Ожидается список entries (не больше 5000 записей)")
    raw = [e if isinstance(e, dict) else {"address": str(e)} for e in raw]
    # полученные с других серверов записи здесь не редактируются (поле origin ставит только синхронизация)
    raw = [{k: v for k, v in e.items() if k != "origin"} for e in raw]
    # проверка — моделью настроек панели (ошибки с указанием строки: trusted_ips.N.address)
    upd: Dict[str, Any] = {"trusted_ips": raw}
    if isinstance(body.get("lists"), list):
        upd["trusted_lists"] = body["lists"][:50]
    checked = PanelSettings.model_validate({**app.panel().model_dump(), **upd})
    entries, seen = [], set()
    for item in checked.trusted_ips:
        if item.address not in seen:
            seen.add(item.address)
            entries.append(item)
    if any(_net(e.address).prefixlen == 0 for e in entries):
        raise HTTPException(400, "Нельзя сделать доверенными все адреса (0.0.0.0/0 или ::/0)")
    entries = [e for e in entries if e.active()]  # истёкшие временные записи не сохраняем
    old = {e.address for e in app.panel().trusted_ips}
    app.save_panel(app.panel().model_copy(update={"trusted_ips": entries, "trusted_lists": checked.trusted_lists}))
    unbanned = await asyncio.to_thread(app.bans.drop_trusted)
    await app.bans.sync(force=True)
    new = {e.address for e in entries}
    audit(request, user, "trusted_updated", f"{len(entries)} адресов",
          {"added": sorted(new - old)[:50], "removed": sorted(old - new)[:50], "unbanned": unbanned})
    app.peers.mark()  # другим серверам — со следующей отправкой блокировок
    res = await app.apply(user["username"], "Изменены доверенные адреса") if apply else None
    return {"ok": True, "count": len(entries), "unbanned": unbanned, "applied": res}


@router.post("/trusted/lists/refresh")
async def trusted_lists_refresh(request: Request, body: Dict[str, Any] = Body(default={}), user=Depends(admin)):
    """Скачать списки доверенных адресов сейчас ({accept: [url]} — принять отложенные изменения); если адреса
    изменились — переприменить последнюю применённую версию конфигурации."""
    from ..services import iplists
    app = _nm(request)
    p = app.panel()
    accept = [str(u) for u in (body.get("accept") or [])]
    changed, done = await asyncio.to_thread(iplists.refresh_trusted, app.db, p,
                                            None if accept else [x.url for x in p.trusted_lists], None, accept)
    applied = None
    if changed:
        applied = await app.trusted_lists_changed("Списки доверенных адресов обновлены вручную")
    audit(request, user, "trusted_lists_refresh", f"{len(done)} списков", {"accept": accept})
    return {"changed": changed, "applied": (applied or {}).get("version"), "lists": iplists.trusted_status(app.db, p),
            "errors": {u: d["error"] for u, d in done.items() if not d.get("ok")}}


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
    entry = next((e for e in app.trusted_entries() if _in(a, [e.address])), None)
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
        by = next((e.address + (f" ({e.comment})" if e.comment else "") for e in x.entries
                   if e.active() and _in(a, [e.address])), "")
        if not by and x.allow_trusted and entry:
            by = "доверенные адреса"
        if not by and x.allow_private and _in(a, PRIVATE_NETS):
            by = "локальные сети"
        if not by and _in(a, LOOPBACK_NETS):
            by = "сам сервер"
        sites.append({"id": sid, "name": s.name, "allowed": bool(by), "by": by})
    return {"ip": a, "trusted": entry.model_dump() if entry else None, "always": always,
            "banned": ban, "sites": sites}


@router.get("/sites/{sid}/ip-denials")
async def site_ip_denials(request: Request, sid: int, hours: int = Query(24, ge=1, le=24 * 30), user=Depends(viewer)):
    """Отказы «Доступа по IP» сайта: ряд по времени, самые частые адреса (с последним путём и страной)."""
    app = _nm(request)
    now = time.time()
    since = int(now - hours * 3600) // 60 * 60
    step = 300 if hours <= 6 else 3600 if hours <= 168 else 86400
    rows = app.db.query("SELECT (ts / ?) * ? AS b, SUM(n) AS n FROM ipdeny_minute WHERE site=? AND ts>=? "
                        "GROUP BY b ORDER BY b", (step, step, str(sid), since))
    by = {r["b"]: r["n"] for r in rows}
    start = since // step * step
    series = [[t, by.get(t, 0)] for t in range(start, int(now) // step * step + step, step)]
    top = app.db.query("SELECT ip, SUM(n) AS n, MAX(ts) AS last, MIN(ts) AS first, country FROM ipdeny_minute "
                       "WHERE site=? AND ts>=? GROUP BY ip ORDER BY n DESC LIMIT 50", (str(sid), since))
    out = []
    for r in top:
        last = app.db.one("SELECT uri FROM ipdeny_minute WHERE site=? AND ip=? AND ts=?", (str(sid), r["ip"], r["last"]))
        out.append({**r, "uri": (last or {}).get("uri", ""),
                    "trusted": bool(app.bans.trusted_entry(r["ip"]))})
    total = sum(r["n"] for r in rows)
    ips = (app.db.one("SELECT COUNT(DISTINCT ip) AS n FROM ipdeny_minute WHERE site=? AND ts>=?",
                      (str(sid), since)) or {}).get("n", 0)
    return {"hours": hours, "step": step, "total": total, "ips": ips, "series": series, "top": out}
