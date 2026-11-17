"""API нескольких серверов: приём блокировок и настроек защиты от других серверов с Nginx Manager, состояние
связи, проверка и отправка вручную."""
from __future__ import annotations

import asyncio
import time
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
    trusted = body.get("trusted")
    if isinstance(trusted, list):
        # доверенные адреса отправителя: снимают защиту — только с токеном администратора и если приём включён
        if user["role"] != "admin":
            res["trusted"] = {"skipped": "нужен токен администратора"}
        elif not app.panel().peers_accept_trusted:
            res["trusted"] = {"skipped": "приём выключен на сервере-получателе"}
        else:
            res["trusted"] = await app.peers.receive_trusted(body["origin"], trusted, user["username"])
            if res["trusted"].get("changed"):
                await app.bans.sync(force=True)
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
    # правила, привязанные к сайтам: номера сайтов на серверах разные — сопоставляем по доменам; не нашли сайта —
    # правило не переносится. Свои правила получателя, которых нет у отправителя, остаются. CrowdSec — свой.
    sender = {str(k): [str(d).lower() for d in v] for k, v in (body.get("sites") or {}).items()
              if isinstance(v, list)}
    local: Dict[str, int] = {}
    for sid, site in app.nginx.load_state().sites:
        for d in site.domains:
            local.setdefault(d.lower(), sid)
    mapped = dropped = 0

    def remap(rules, own):
        nonlocal mapped, dropped
        out = []
        for r in rules or []:
            if not isinstance(r, dict):
                continue
            ids = r.get("sites") or []
            if ids:
                new_ids = []
                for i in ids:
                    hit = next((local[d] for d in sender.get(str(i), []) if d in local), None)
                    if hit is not None and hit not in new_ids:
                        new_ids.append(hit)
                if not new_ids:
                    dropped += 1
                    continue
                mapped += 1
                r = {**r, "sites": new_ids}
            out.append(r)
        ids_in = {r.get("id") for r in out}
        return out + [r.model_dump() for r in own if r.sites and r.id not in ids_in]
    data["custom_rules"] = remap(data.get("custom_rules"), old.custom_rules)
    data["rate_rules"] = remap(data.get("rate_rules"), old.rate_rules)
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
    return {"ok": True, "applied": bool(res), "version": (res or {}).get("version"), "mapped": mapped,
            "dropped": dropped}


@router.get("/peers")
async def peers_status(request: Request, user=Depends(viewer)):
    """Другие серверы: настройки (без токенов), состояние отправки, полученные блокировки."""
    app = _nm(request)
    st = app.peers.status()
    cmp = app.db.kv_get("peers_compare", {}) or {}
    out = []
    for peer in app.panel().peers:
        out.append({"id": peer.id, "name": peer.name, "url": peer.url, "enabled": peer.enabled, "bans": peer.bans,
                    "protection": peer.protection, "trusted": peer.trusted, "sites": peer.sites,
                    "sites_tag": peer.sites_tag, "compare": cmp.get(peer.id), **(st.get(peer.id) or {})})
    incoming = app.db.kv_get("peers_incoming", {}) or {}
    counts = {r["source"]: r["n"] for r in app.db.query("SELECT source, COUNT(*) AS n FROM bans WHERE source LIKE "
                                                         "'sync:%' GROUP BY source")}
    from ..services.trusted import by_peer
    tr = {x["id"]: len(x["entries"]) for x in by_peer(app.db)}
    inc = [{"id": k, **v, "active": counts.get(f"sync:{k}", 0), "trusted": tr.get(k, 0)} for k, v in incoming.items()]
    mk = app.db.kv_get("synced_sites", {}) or {}
    mirrors = [{"id": k, "name": v.get("name") or k, "sites": len(v.get("map") or {}), "at": v.get("at")}
               for k, v in mk.items()]
    return {"peers": out, "incoming": inc, "me": app.peers.origin(), "accept_trusted": app.panel().peers_accept_trusted,
            "transfers": app.db.kv_get("transfers_in", []) or [], "mirrors": mirrors,
            "last_version": (app.nginx.last_applied() or {}).get("id")}


@router.get("/sync/summary")
async def sync_summary(request: Request, user=Depends(operator)):
    """Сводка применённой конфигурации для сравнения с другим сервером: только хеши разделов, без содержимого."""
    from ..services.compare import summary
    return await asyncio.to_thread(summary, _nm(request))


@router.post("/peers/{pid}/compare")
async def peers_compare(request: Request, pid: str, user=Depends(operator)):
    """Сравнить применённую конфигурацию этого сервера с другим: какие сайты, потоки и настройки различаются."""
    from ..services.compare import compare
    app = _nm(request)
    peer = next((x for x in app.panel().peers if x.id == pid), None)
    if not peer:
        raise HTTPException(404, "Сервер не найден")
    res = await asyncio.to_thread(compare, app, peer)
    if res.get("ok"):
        st = app.db.kv_get("peers_compare", {}) or {}
        st[pid] = {"at": time.time(), "total": res["total"]}
        app.db.kv_set("peers_compare", st)
    return res


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
    elif what == "sites":  # синхронизировать сайты заново (сброс отметки отправленной версии)
        for peer in app.panel().peers:
            app.peers._set(peer.id, sites_version=None, sites_tried_version=None)
        res = await asyncio.to_thread(app.peers.sites_tick)
    else:
        raise HTTPException(400, "what: bans, protection или sites")
    audit(request, user, "peers_push", what)
    return {"results": res}


@router.post("/sync/sites")
async def sync_sites(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Принять сайты и сертификаты с другого сервера: {origin, sites: [{src_id, name, enabled, data}],
    certs: [{src_id, name, cert_pem, key_pem, fingerprint}], overwrite, apply}. Сайты с теми же доменами обновляются
    (overwrite) или пропускаются; сертификаты сохраняются как загруженные и обновляются при повторной отправке."""
    from ..nginx.manager import ApplyError
    from ..services import transfer as TF
    app = _nm(request)
    origin = body.get("origin") or {}
    oid = str(origin.get("id") or "")[:32]
    if not oid or oid == app.peers.origin()["id"]:
        raise HTTPException(400, "Неверный источник (это этот же сервер?)")
    origin = {"id": oid, "name": str(origin.get("name") or oid)[:80]}
    sites = body.get("sites") or []
    certs = body.get("certs") or []
    if not isinstance(sites, list) or not isinstance(certs, list):
        raise HTTPException(400, "sites и certs — списки")
    want_apply = bool(body.get("apply"))
    mirror = bool(body.get("mirror"))
    if mirror and not app.panel().peers_accept_sites:
        raise HTTPException(403, "Приём синхронизации сайтов выключен на этом сервере (Настройки панели → Другие серверы)")
    pending_before = (bool(sites) or mirror) and want_apply and bool(app.pending().get("pending"))
    res: Dict[str, Any] = {"name": app.peers.origin()["name"]}
    overwrite = bool(body.get("overwrite")) or mirror
    if sites or mirror:  # сертификаты — только для сайтов, которые будут созданы или обновлены
        only = await asyncio.to_thread(TF.needed_certs, app, sites, overwrite)
        res["certs"] = await asyncio.to_thread(TF.receive_certs, app, origin, certs, user["username"], only)
        res["sites"] = await asyncio.to_thread(TF.receive_sites, app, origin, sites, res["certs"]["map"],
                                               overwrite, user["username"], mirror)
    else:  # только сертификаты: продление на источнике — обновляем уже перенесённые
        res["certs"] = await asyncio.to_thread(TF.receive_certs, app, origin, certs, user["username"], None, False)
    app.touch()
    changed = sum(res.get("sites", {}).get(k, 0) for k in ("created", "updated", "deleted")) + \
        (len(res["certs"]["changed_ids"]) if mirror else 0)
    if changed and want_apply:
        if pending_before:
            res["apply_error"] = "на этом сервере есть неприменённые изменения — примените конфигурацию вручную"
        else:
            try:
                r = await app.apply(user["username"], f"{'Синхронизация' if mirror else 'Перенос'} сайтов с сервера "
                                    f"«{origin['name']}»", "transfer")
                res["applied"] = r.get("version")
            except ApplyError as e:
                res["apply_error"] = str(e)[:500]
    elif res["certs"]["changed_ids"]:
        # только обновлённые сертификаты (продление на источнике) — переприменить, если они используются
        for cid in res["certs"]["changed_ids"]:
            await app.after_cert_issued(cid)
    res["certs"].pop("map", None)
    if mirror and not changed:
        return res  # синхронизация без изменений — не засоряем журнал событий
    TF.log_incoming(app.db, origin, res, user["username"])
    s_ = res.get("sites") or {}
    c_ = res["certs"]
    app.db.event("info", "peers", f"Сервер «{origin['name']}»: сайты — создано {s_.get('created', 0)}, обновлено "
                 f"{s_.get('updated', 0)}, пропущено {s_.get('skipped', 0)}; сертификаты — новых {c_['created']}, "
                 f"обновлено {c_['updated']}", {"user": user["username"]})
    audit(request, user, "sites_received", origin["name"], {"sites": s_.get("items", [])[:50],
                                                            "certs": {k: c_[k] for k in ("created", "updated")}})
    return res


@router.post("/peers/{pid}/transfer")
async def peers_transfer(request: Request, pid: str, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Перенести сайты на другой сервер: {sites: [id], certs: true, overwrite: false, apply: true}."""
    app = _nm(request)
    peer = next((x for x in app.panel().peers if x.id == pid), None)
    if not peer:
        raise HTTPException(404, "Сервер не найден")
    ids = [int(x) for x in (body.get("sites") or []) if str(x).isdigit()]
    if not ids:
        raise HTTPException(400, "Выберите сайты")
    try:
        res = await asyncio.to_thread(app.peers.transfer, peer, ids, bool(body.get("certs", True)),
                                      bool(body.get("overwrite")), bool(body.get("apply", True)))
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(request, user, "sites_sent", peer.name, {"sites": ids, "certs": bool(body.get("certs", True))})
    return res
