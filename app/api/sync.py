"""API нескольких серверов: приём блокировок и настроек защиты от других серверов с Nginx Manager, состояние
связи, проверка и отправка вручную."""
from __future__ import annotations

import asyncio
from typing import Any, Dict

from fastapi import Body, Depends, HTTPException, Request

from ..auth import admin, operator, viewer
from ..config import VERSION
from ..models import ProtectionSettings
from .routes import audit
from .routes import router


def _nm(request: Request):
    return request.app.state.nm


@router.get("/sync/hello")
async def sync_hello(request: Request, user=Depends(viewer)):
    """Проверка связи другим сервером: имя, версия и идентификатор этого сервера."""
    app = _nm(request)
    o = app.peers.origin()
    return {**o, "version": VERSION, "role": user["role"]}


@router.post("/sync/bans")
async def sync_bans(request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    """Принять полный список блокировок другого сервера: {origin: {id, name}, bans: [{net, expires_at, reason}]}."""
    app = _nm(request)
    bans = body.get("bans")
    if not isinstance(bans, list) or not isinstance(body.get("origin"), dict):
        raise HTTPException(400, "Нужны origin и bans")
    try:
        res = await asyncio.to_thread(app.peers.receive_bans, body["origin"], bans, user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    if res["added"] or res["removed"] or res["updated"]:
        await app.bans.sync(force=True)
    return res


@router.post("/sync/protection")
async def sync_protection(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Принять настройки защиты от другого сервера и применить последнюю применённую конфигурацию с ними."""
    app = _nm(request)
    origin = body.get("origin") or {}
    if str(origin.get("id")) == app.peers.origin()["id"]:
        raise HTTPException(400, "Это этот же сервер")
    old = app.protection.settings()
    data = dict(body.get("settings") or {})
    # правила, привязанные к сайтам, — свои: номера сайтов на серверах разные; CrowdSec — свой агент и ключ
    data["custom_rules"] = [r for r in data.get("custom_rules") or [] if not r.get("sites")] + \
        [r.model_dump() for r in old.custom_rules if r.sites]
    data["rate_rules"] = [r for r in data.get("rate_rules") or [] if not r.get("sites")] + \
        [r.model_dump() for r in old.rate_rules if r.sites]
    for k in ("crowdsec_url", "crowdsec_key", "crowdsec_action", "crowdsec_minutes"):
        data[k] = getattr(old, k)
    try:
        p = ProtectionSettings.model_validate(data)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"Настройки защиты не приняты: {e}"[:500])
    app.protection.save(p)
    name = str(origin.get("name") or "")[:80]
    state = app.last_applied_state()
    res = None
    if state is not None:
        state.protection = p
        try:
            res = await app.apply("sync", f"Настройки защиты с сервера «{name}»", "sync", state)
        except Exception as e:  # noqa: BLE001 — nginx -t не принял: вернуть прежние настройки
            app.protection.save(old)
            return {"ok": False, "error": str(e)[:500]}
    audit(request, user, "protection_settings_synced", name)
    app.db.event("info", "protection", f"Настройки защиты получены с сервера «{name}»"
                 + (" и применены" if res else ""))
    if p.vulndb_enabled:
        asyncio.get_running_loop().create_task(app.protection.vulndb.write_map())
    return {"ok": True, "applied": bool(res), "version": (res or {}).get("version")}


@router.get("/peers")
async def peers_status(request: Request, user=Depends(viewer)):
    """Другие серверы: настройки (без токенов), состояние отправки, полученные блокировки."""
    app = _nm(request)
    st = app.peers.status()
    out = []
    for peer in app.panel().peers:
        out.append({"id": peer.id, "name": peer.name, "url": peer.url, "enabled": peer.enabled, "bans": peer.bans,
                    "protection": peer.protection, **(st.get(peer.id) or {})})
    incoming = app.db.kv_get("peers_incoming", {}) or {}
    counts = {r["source"]: r["n"] for r in app.db.query("SELECT source, COUNT(*) AS n FROM bans WHERE source LIKE "
                                                         "'sync:%' GROUP BY source")}
    inc = [{"id": k, **v, "active": counts.get(f"sync:{k}", 0)} for k, v in incoming.items()]
    return {"peers": out, "incoming": inc, "me": app.peers.origin()}


@router.post("/peers/{pid}/test")
async def peers_test(request: Request, pid: str, user=Depends(admin)):
    """Проверить связь с сервером (адрес, токен, версия)."""
    app = _nm(request)
    peer = next((x for x in app.panel().peers if x.id == pid), None)
    if not peer:
        raise HTTPException(404, "Сервер не найден")
    return await asyncio.to_thread(app.peers.test, peer)


@router.post("/peers/push")
async def peers_push(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Отправить другим серверам сейчас: {what: "bans" | "protection", peer: id (необязательно)}."""
    app = _nm(request)
    what = body.get("what")
    if what == "bans":
        res = await asyncio.to_thread(app.peers.push_bans)
    elif what == "protection":
        res = await asyncio.to_thread(app.peers.push_protection, body.get("peer"))
    else:
        raise HTTPException(400, "what: bans или protection")
    audit(request, user, "peers_push", what)
    return {"results": res}
