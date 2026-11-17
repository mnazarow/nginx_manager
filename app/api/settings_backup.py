"""API копии всех настроек: создать, проверить, восстановить (по разделам, с автоматическим откатом)."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict

from fastapi import Body, Depends, HTTPException, Request

from ..auth import admin
from ..config import settings
from ..services import settings_backup as SB
from .routes import audit, router


def _nm(request: Request):
    return request.app.state.nm


def _file(name: str) -> Path:
    p = settings.backups_dir / Path(str(name)).name
    if not p.name.startswith("nginx-manager-") or not SB.is_settings_file(p.name) or not p.is_file():
        raise HTTPException(404, "Копия настроек не найдена")
    return p


@router.get("/backup/settings/sections")
async def settings_sections(user=Depends(admin)):
    """Разделы копии настроек."""
    return [{"id": k, "title": v} for k, v in SB.SECTIONS.items()]


@router.post("/backup/settings")
async def settings_create(request: Request, body: Dict[str, Any] = Body(default={}), user=Depends(admin)):
    """Создать копию всех настроек: {password (необязательно), sections (необязательно — все)}. Файл —
    в списке копий; скачать — /backup/download/<имя>."""
    app = _nm(request)
    password = str(body.get("password") or "")
    if password and len(password) < 8:
        raise HTTPException(400, "Пароль копии — не короче 8 символов")
    sections = body.get("sections") or None
    try:
        p = await asyncio.to_thread(SB.create, app, "all", sections, password)
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    audit(request, user, "settings_backup_created", p.name, {"encrypted": bool(password), "sections": sections})
    return {"name": p.name, "size": p.stat().st_size, "encrypted": bool(password)}


@router.post("/backup/settings/inspect")
async def settings_inspect(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Проверить копию настроек: {name, password} → разделы с числом записей, версия, предупреждения."""
    p = _file(body.get("name", ""))
    try:
        return await asyncio.to_thread(SB.inspect, p, str(body.get("password") or ""))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/backup/settings/restore")
async def settings_restore(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Восстановить разделы из копии: {name, password, sections, apply}. Перед этим сохраняются текущие настройки
    (копия before-settings-restore); если nginx не принял конфигурацию — настройки возвращаются из неё."""
    from ..nginx.manager import ApplyError
    app = _nm(request)
    p = _file(body.get("name", ""))
    sections = [s for s in (body.get("sections") or []) if s in SB.SECTIONS]
    if not sections:
        raise HTTPException(400, "Выберите разделы для восстановления")
    if app.nginx.lock.locked():
        raise HTTPException(409, "Сейчас применяется конфигурация — повторите через несколько секунд")
    password = str(body.get("password") or "")
    try:
        await asyncio.to_thread(SB.read, p, password)  # пароль и целостность — до создания страховочной копии
        safety = await asyncio.to_thread(SB.create, app, "before-settings-restore")
        res = await asyncio.to_thread(SB.restore, app, p, sections, password, user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    res["safety"] = safety.name
    if "bans" in sections or "panel" in sections:
        await app.bans.sync(force=True)
    await app.grants.sync(force=True)
    if body.get("apply", True) and res["nginx"]:
        try:
            r = await app.apply(user["username"], f"Восстановление настроек из копии {p.name}", "restore")
            res["applied"] = r.get("version")
        except ApplyError as e:
            # nginx не принял — возвращаем прежние настройки этих разделов (работающий nginx не менялся)
            await asyncio.to_thread(SB.restore, app, safety, sections, "", user["username"])
            await app.bans.sync(force=True)
            res.update(rolled_back=True, apply_error=str(e)[:1000], applied=None)
            app.db.event("error", "backup", f"Восстановление настроек из {p.name} отменено: nginx не принял "
                                            f"конфигурацию — {str(e)[:300]}")
    audit(request, user, "settings_restored", p.name, {"sections": sections, "applied": res.get("applied"),
                                                       "rolled_back": res.get("rolled_back", False)})
    return res
