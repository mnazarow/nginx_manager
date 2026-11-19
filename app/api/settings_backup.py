"""API копии всех настроек: создать, проверить, восстановить (по разделам, с автоматическим откатом)."""
from __future__ import annotations

import asyncio
import json
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
    """Восстановить разделы из копии: {name, password, sections, apply} или отдельные сайты: {name, password,
    sites: [номера сайтов в копии], apply}. Перед этим сохраняются текущие настройки (копия
    before-settings-restore); если nginx не принял конфигурацию — настройки возвращаются из неё."""
    from ..nginx.manager import ApplyError
    app = _nm(request)
    p = _file(body.get("name", ""))
    only_sites = [int(x) for x in (body.get("sites") or []) if str(x).isdigit()]
    sections = ["sites"] if only_sites else [s for s in (body.get("sections") or []) if s in SB.SECTIONS]
    if not sections:
        raise HTTPException(400, "Выберите разделы для восстановления")
    if app.nginx.lock.locked():
        raise HTTPException(409, "Сейчас применяется конфигурация — повторите через несколько секунд")
    password = str(body.get("password") or "")
    try:
        await asyncio.to_thread(SB.read, p, password)  # пароль и целостность — до создания страховочной копии
        safety = await asyncio.to_thread(SB.create, app, "before-settings-restore")
        if only_sites:
            res = await asyncio.to_thread(SB.restore_sites, app, p, only_sites, password, user["username"])
        else:
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
            back = ["sites", "certificates"] if only_sites else sections
            await asyncio.to_thread(SB.restore, app, safety, back, "", user["username"])
            await app.bans.sync(force=True)
            res.update(rolled_back=True, apply_error=str(e)[:1000], applied=None)
            app.db.event("error", "backup", f"Восстановление настроек из {p.name} отменено: nginx не принял "
                                            f"конфигурацию — {str(e)[:300]}")
    audit(request, user, "settings_restored", p.name, {"sections": sections, "sites": only_sites,
                                                       "applied": res.get("applied"),
                                                       "rolled_back": res.get("rolled_back", False)})
    return res


@router.get("/backup/settings/job")
async def settings_job_status(request: Request, user=Depends(admin)):
    """Копия настроек по расписанию: настройки (куда отправляется) и итог последнего запуска."""
    from ..services import settings_job as SJ
    app = _nm(request)
    p = app.panel()
    names = {r["id"]: json.loads(r["data"]).get("name") for r in app.db.query("SELECT id, data FROM alert_channels")}
    return {"hours": p.sb_hours, "only_changed": p.sb_only_changed, "encrypted": bool(SJ.password(p)),
            "targets": ([{"id": "s3", "name": f"основное хранилище {p.s3_bucket}"}] if p.s3_enabled and p.sb_main_s3
                        else []) + ([{"id": "s3_second", "name": f"второе хранилище {p.sb_s3_bucket}"}]
                                    if p.sb_s3 else [])
            + [{"id": f"channel:{c}", "name": names.get(c) or f"канал #{c}"} for c in p.sb_channels],
            "last": app.db.kv_get(SJ.KV_LAST) or None, "verify_days": p.sb_verify_days,
            "verify": app.db.kv_get(SJ.KV_VERIFY) or None}


@router.post("/backup/settings/job")
async def settings_job_run(request: Request, user=Depends(admin)):
    """Сделать копию настроек и отправить её во все выбранные места сейчас (без проверки «изменились ли»)."""
    from ..services import settings_job as SJ
    app = _nm(request)
    res = await asyncio.to_thread(SJ.run, app, True, "manual")
    audit(request, user, "settings_backup_sent", res.get("name", ""),
          {"ok": res["ok"], "targets": {k: v.get("ok") for k, v in res.get("targets", {}).items()}})
    return res


@router.post("/backup/settings/s3-check")
async def settings_s3_check(request: Request, user=Depends(admin)):
    """Проверить второе хранилище копий настроек: запись, чтение списка, удаление маленького объекта."""
    from ..services.backup import offsite_check
    app = _nm(request)
    if not app.panel().sb_s3:
        raise HTTPException(400, "Второе хранилище не включено («Настройки панели → Копия настроек»)")
    try:
        return await asyncio.to_thread(offsite_check, app, True)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:500]}


@router.get("/backup/settings/s3")
async def settings_s3_list(request: Request, user=Depends(admin)):
    """Копии настроек во втором хранилище (новые сверху)."""
    from ..services.settings_job import second_s3
    app = _nm(request)
    p = app.panel()
    if not p.sb_s3:
        raise HTTPException(400, "Второе хранилище не включено («Настройки панели → Копия настроек»)")
    try:
        objs = await asyncio.to_thread(second_s3(p).list, p.sb_s3_prefix)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Хранилище недоступно: {str(e)[:300]}")
    out = []
    for o in objs:
        name = o["key"][len(p.sb_s3_prefix):]
        if "/" in name or ".settings.tar.gz" not in name:
            continue
        out.append({"name": name, "size": o.get("size", 0), "modified": o.get("last_modified", "")})
    out.sort(key=lambda x: x["name"], reverse=True)
    return {"bucket": p.sb_s3_bucket, "prefix": p.sb_s3_prefix, "items": out}


@router.post("/backup/settings/s3/download")
async def settings_s3_download(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Скачать копию настроек из второго хранилища в каталог копий сервера (как есть — пароль спросит окно
    восстановления)."""
    from ..services.settings_job import second_s3
    app = _nm(request)
    p = app.panel()
    name = Path(str(body.get("name") or "")).name
    if not p.sb_s3 or not name.startswith("nginx-manager-") or ".settings.tar.gz" not in name:
        raise HTTPException(400, "Это не копия настроек Nginx Manager")
    dest = settings.backups_dir / name
    try:
        await asyncio.to_thread(second_s3(p).get_to_file, p.sb_s3_prefix + name, dest)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Не удалось скачать: {str(e)[:300]}")
    dest.chmod(0o600)
    audit(request, user, "settings_s3_downloaded", name)
    return {"name": name, "encrypted": name.endswith(".enc"), "size": dest.stat().st_size}


@router.post("/backup/settings/verify")
async def settings_verify(request: Request, user=Depends(admin)):
    """Проверить последнюю копию настроек на сервере и во внешних хранилищах сейчас."""
    from ..services import settings_job as SJ
    app = _nm(request)
    res = await asyncio.to_thread(SJ.verify, app, "manual")
    audit(request, user, "settings_verified", "", {"ok": res["ok"]})
    return res
