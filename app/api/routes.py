"""REST API и WebSocket веб-панели. Документация OpenAPI: /api/docs-ui."""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from ..auth import COOKIE, ROLE_LABELS, ROLES, admin, operator, viewer
from ..config import DOCS_DIR, VERSION, settings
from ..models import (CLOUDFLARE_IPS, DNS_PROVIDERS, DNS_SECRET_FIELDS, AlertChannel, AlertRule, CertificateRequest,
                      DnsAccount, GlobalSettings, PanelSettings, Site, Stream)
from ..nginx.generator import State, slug
from ..schema import full_schema
from ..utils import apr1, totp_secret, totp_verify, verify_password

router = APIRouter(prefix="/api")
MASK = "••••••••"
PANEL_SECRETS = ("acme_eab_hmac", "s3_secret_key", "s3_encrypt_password")


def nm(request: Request):
    return request.app.state.nm


def audit(request: Request, user: Dict[str, Any], action: str, target: str = "", details: Any = None) -> None:
    nm(request).db.audit(user["username"], user.get("ip"), action, target, details)
    nm(request).touch()


def rng(frm: Optional[float], to: Optional[float], default: int = 3600):
    end = to or time.time()
    start = frm or end - default
    if start >= end:
        raise HTTPException(400, "Начало периода должно быть раньше конца")
    return start, end


# =============================================================================
#  Аутентификация
# =============================================================================
class LoginBody(BaseModel):
    username: str
    password: str
    otp: str = ""
    remember: bool = True


@router.post("/auth/login")
async def login(body: LoginBody, request: Request, response: Response):
    """Вход: {username, password, otp?, remember}. Ставит cookie сессии; при включённой 2FA без кода отвечает {totp_required: true}."""
    app = nm(request)
    ip = app.auth.client_ip(request)
    if not app.auth.ip_allowed(ip):
        raise HTTPException(403, "Доступ к панели с вашего IP запрещён")
    left = app.auth.locked(ip)
    if left:
        raise HTTPException(429, f"Слишком много неудачных попыток. Повторите через {left // 60 + 1} мин.")
    try:
        u = await asyncio.to_thread(app.auth.authenticate, body.username, body.password, body.otp)
    except LookupError:
        return {"totp_required": True}
    except PermissionError as e:
        app.auth.fail(ip)
        app.db.audit(body.username, ip, "login_failed", "", None)
        if app.auth.locked(ip):
            p = app.panel()
            app.db.event("warning", "auth", f"Вход с {ip} заблокирован на {p.login_lock_minutes} мин: "
                                            f"{p.login_max_attempts} неудачных попыток (последнее имя «{body.username[:60]}»)",
                         {"ip": ip, "username": body.username[:60]})
        await asyncio.sleep(0.5)
        raise HTTPException(401, str(e))
    if app.panel().require_2fa_admin and u["role"] == "admin" and not u["totp_enabled"]:
        pass  # пользователь будет перенаправлен на настройку 2FA
    seen = app.db.one("SELECT 1 FROM audit_log WHERE username=? AND action='login' AND ip=? LIMIT 1", (u["username"], ip))
    if not seen and app.db.one("SELECT 1 FROM audit_log WHERE username=? AND action='login' LIMIT 1", (u["username"],)):
        # первый вход с этого адреса (но не самый первый вход вообще) — повод проверить, что это вы
        app.db.event("warning" if u["role"] == "admin" else "info", "auth",
                     f"Вход пользователя «{u['username']}» ({ROLE_LABELS.get(u['role'], u['role'])}) с нового адреса "
                     f"{ip}", {"ip": ip, "user_agent": request.headers.get("user-agent", "")[:200]})
    token = app.auth.create_session(u["id"], ip, request.headers.get("user-agent", ""))
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure,
                        max_age=app.panel().session_hours * 3600 if body.remember else None, path="/")
    app.db.audit(u["username"], ip, "login", "", None)
    return {"ok": True, "must_change_password": bool(u["must_change_password"]),
            "require_2fa": app.panel().require_2fa_admin and u["role"] == "admin" and not u["totp_enabled"]}


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    """Выход: завершает текущую сессию."""
    tok = request.cookies.get(COOKIE)
    if tok:
        nm(request).auth.destroy_session(tok)
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/me")
async def me(user=Depends(viewer)):
    """Текущий пользователь: имя, роль, 2FA, нужно ли сменить пароль."""
    return {k: user[k] for k in ("id", "username", "role", "totp_enabled", "must_change_password")} | \
        {"role_label": ROLE_LABELS[user["role"]]}


class PasswordBody(BaseModel):
    current: str
    new: str


@router.post("/auth/password")
async def change_password(body: PasswordBody, request: Request, user=Depends(viewer)):
    """Сменить свой пароль: {current, new}. Все сессии пользователя завершаются."""
    if not verify_password(body.current, user["password_hash"]):
        raise HTTPException(400, "Текущий пароль неверен")
    try:
        nm(request).auth.set_password(user["id"], body.new)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(request, user, "password_changed")
    return {"ok": True, "relogin": True}


@router.post("/auth/totp/setup")
async def totp_setup(user=Depends(viewer)):
    """Начать настройку 2FA: новый секрет и otpauth-ссылка для QR-кода."""
    sec = totp_secret()
    uri = f"otpauth://totp/NginxManager:{user['username']}?secret={sec}&issuer=NginxManager"
    return {"secret": sec, "uri": uri}


@router.post("/auth/totp/enable")
async def totp_enable(request: Request, secret: str = Body(...), code: str = Body(...), user=Depends(viewer)):
    """Включить 2FA: {secret, code} — код из приложения подтверждает секрет."""
    if not totp_verify(secret, code):
        raise HTTPException(400, "Неверный код. Проверьте время на телефоне и сервере")
    nm(request).db.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", (secret, user["id"]))
    audit(request, user, "2fa_enabled")
    return {"ok": True}


@router.post("/auth/totp/disable")
async def totp_disable(request: Request, password: str = Body(..., embed=True), user=Depends(viewer)):
    """Отключить 2FA: {password}."""
    if not verify_password(password, user["password_hash"]):
        raise HTTPException(400, "Неверный пароль")
    nm(request).db.execute("UPDATE users SET totp_secret='', totp_enabled=0 WHERE id=?", (user["id"],))
    audit(request, user, "2fa_disabled")
    return {"ok": True}


@router.get("/auth/sessions")
async def sessions(request: Request, user=Depends(viewer)):
    """Активные сессии текущего пользователя (браузеры, IP, время)."""
    rows = nm(request).db.query("SELECT id, created_at, last_seen, expires_at, ip, user_agent FROM sessions "
                                "WHERE user_id=? ORDER BY last_seen DESC", (user["id"],))
    cur = user.get("sid")
    for r in rows:
        r["current"] = r["id"] == cur
        r["id"] = r["id"][:16]
    return rows


@router.delete("/auth/sessions/{sid}")
async def kill_session(sid: str, request: Request, user=Depends(viewer)):
    """Завершить свою сессию по идентификатору."""
    nm(request).db.execute("DELETE FROM sessions WHERE user_id=? AND id LIKE ?", (user["id"], sid + "%"))
    return {"ok": True}


@router.get("/auth/tokens")
async def tokens(request: Request, user=Depends(viewer)):
    """API-токены текущего пользователя."""
    return nm(request).db.query("SELECT id, name, prefix, created_at, expires_at, last_used, role FROM api_tokens "
                                "WHERE user_id=? ORDER BY id", (user["id"],))


@router.post("/auth/tokens")
async def create_token(request: Request, name: str = Body(...), days: int = Body(0), role: str = Body(""),
                       user=Depends(viewer)):
    """Создать API-токен: {name, days (0 — бессрочно), role}. role = viewer | operator | admin — не выше своей роли;
    пусто — как у пользователя. Токен показывается один раз."""
    if user.get("via") == "token":  # иначе утёкший токен мог бы выпустить себе «запасной», переживающий отзыв
        raise HTTPException(403, "Создавать токены можно только из браузерной сессии («Мой профиль»)")
    if role and role not in ROLE_LABELS:
        raise HTTPException(400, "Роль токена: viewer, operator или admin")
    if role and ROLES[role] > ROLES.get(user["role"], 0):
        raise HTTPException(403, f"Роль токена не может быть выше вашей («{ROLE_LABELS.get(user['role'], user['role'])}»)")
    if not 0 <= days <= 3650:
        raise HTTPException(400, "Срок токена — от 0 (бессрочно) до 3650 дней")
    # иначе токен стал бы обходом политики входа: временный пароль или обязательная 2FA администратора
    if user.get("must_change_password"):
        raise HTTPException(403, "Сначала смените временный пароль")
    if user["role"] == "admin" and not user.get("totp_enabled") and nm(request).panel().require_2fa_admin:
        raise HTTPException(403, "Политика панели требует двухфакторную аутентификацию для администраторов — "
                                 "включите её, затем создайте токен")
    tok = nm(request).auth.create_token(user["id"], name, days, role)
    audit(request, user, "token_created", name, {"role": role or "как у пользователя", "days": days})
    return {"token": tok}


@router.delete("/auth/tokens/{tid}")
async def delete_token(tid: int, request: Request, user=Depends(viewer)):
    """Удалить свой API-токен."""
    nm(request).db.execute("DELETE FROM api_tokens WHERE id=? AND user_id=?", (tid, user["id"]))
    audit(request, user, "token_deleted", str(tid))
    return {"ok": True}


# =============================================================================
#  Общее состояние
# =============================================================================
@router.get("/state")
async def state(request: Request, user=Depends(viewer)):
    """Сводное состояние для верхней панели: nginx, неприменённые изменения, оповещения, анализ, тишина."""
    return await asyncio.to_thread(nm(request).state_summary, user)


@router.get("/schema")
async def schema(user=Depends(viewer)):
    """Схема форм: поля моделей с подписями, подсказками, значениями по умолчанию; списки стран и диапазоны Cloudflare."""
    from ..services.geoblock import COUNTRY_CODES, EU
    s = full_schema()
    s["cloudflare_ips"] = CLOUDFLARE_IPS
    s["countries"] = list(COUNTRY_CODES)
    s["country_groups"] = {"eu": list(EU)}
    return s


@router.get("/overview")
async def overview(request: Request, user=Depends(viewer)):
    """Данные дашборда: сайты, бэкенды, сертификаты, последние события."""
    app = nm(request)
    sites = await list_sites(request, user)
    certs = app.certs.list()
    events = app.db.query("SELECT * FROM events ORDER BY id DESC LIMIT 15")
    return {
        "sites": sites, "health": app.health.list(),
        "certs": [{"id": c["id"], "name": c["name"], "days_left": c["days_left"], "status": c["status"]}
                  for c in certs],
        "events": events, "snapshot": app.stats.snapshot(),
        "summary_24h": await asyncio.to_thread(app.stats.summary, time.time() - 86400, time.time(), "*", False),
        "alerts": [{"id": rid, **st} for rid, st in app.alerts.status().items() if st.get("state") != "ok"],
    }


# =============================================================================
#  Сайты
# =============================================================================
def _site_row(app, r: Dict[str, Any], live: Dict[str, Any], health: Dict[str, List]) -> Dict[str, Any]:
    d = json.loads(r["data"])
    sid = str(r["id"])
    lv = live.get(sid, {})
    hs = health.get(f"site:{sid}", [])
    return {"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]), "type": d.get("type"),
            "domains": d.get("domains", []), "ssl": (d.get("ssl") or {}).get("enabled", False),
            "certificate_id": (d.get("ssl") or {}).get("certificate_id"),
            "backends": [f"{b['address']}:{b.get('port') or ''}".rstrip(":") for b in d.get("backends", [])],
            "health": hs, "tags": d.get("tags", []), "maintenance": (d.get("maintenance") or {}).get("enabled"),
            "cache": (d.get("cache") or {}).get("enabled"), "rps": lv.get("rps", 0), "bps": lv.get("bps", 0),
            "err5_pct": lv.get("err5_pct", 0), "rt_avg": lv.get("rt_avg", 0), "updated_at": r["updated_at"],
            "locations": len(d.get("locations", [])),
            "geo": {"mode": (d.get("security") or {}).get("geo_mode", "off"),
                    "countries": (d.get("security") or {}).get("geo_countries", [])}}


@router.get("/sites")
async def list_sites(request: Request, user=Depends(viewer)):
    """Список сайтов с доменами, состоянием бэкендов и нагрузкой за последние секунды."""
    app = nm(request)
    live = app.stats.agg.per_site_now(10)
    health: Dict[str, List] = {}
    for t in app.health.targets.values():
        health.setdefault(t.owner, []).append({"addr": f"{t.address}:{t.port}", "state": t.state,
                                               "latency_ms": round(t.last_latency * 1000, 1), "error": t.last_error})
    return [_site_row(app, r, live, health) for r in app.db.query("SELECT * FROM sites ORDER BY name COLLATE NOCASE")]


@router.get("/sites/{sid}")
async def get_site(sid: int, request: Request, user=Depends(viewer)):
    """Настройки сайта. Пароли и хеши Basic Auth не возвращаются."""
    r = nm(request).db.one("SELECT * FROM sites WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Сайт не найден")
    data = json.loads(r["data"])
    for u in (data.get("security") or {}).get("basic_auth_users", []):
        u["password"] = ""
        u["password_hash"] = ""  # хранится только на сервере; при сохранении без пароля берётся прежний
    return {"id": r["id"], "data": data, "created_at": r["created_at"], "updated_at": r["updated_at"]}


def app_nginx_masked(files: Dict[str, str]) -> Dict[str, str]:
    from ..nginx.manager import NginxManager
    return NginxManager.masked(files)


def _raw_texts(d: Dict[str, Any]) -> List[str]:
    """Тексты «Своих директив» сайта (на уровне http, server, location / и в каждой локации)."""
    return [d.get("custom_http") or "", d.get("custom_server") or "", d.get("custom_location") or ""] + \
        [(loc or {}).get("custom") or "" for loc in d.get("locations") or [] if isinstance(loc, dict)]


def _guard_raw(user: Optional[Dict[str, Any]], site: Site, old: Optional[Dict[str, Any]]) -> None:
    """Опасные директивы в «Своих директивах» добавляет только администратор (см. validators.RISKY_DIRECTIVES).
    Уже существующие (добавленные администратором) не мешают оператору менять остальные поля сайта."""
    from ..validators import risky_raw_directives
    if not user or user["role"] == "admin":
        return
    had = {x for t in _raw_texts(old or {}) for x in risky_raw_directives(t)}
    new = sorted({x for t in _raw_texts(site.model_dump()) for x in risky_raw_directives(t)} - had)
    if new:
        raise HTTPException(403, "Только администратор может добавить в «Свои директивы»: " + "; ".join(new[:5])
                            + ". Такие директивы читают или создают файлы от имени root (include, журналы вне "
                              "/var/log/nginx, временные каталоги) или выполняют код (Lua, Perl, njs).")


def _prepare_site(app, data: Dict[str, Any], sid: Optional[int] = None,
                  user: Optional[Dict[str, Any]] = None) -> Site:
    old_users = {}
    old: Optional[Dict[str, Any]] = None
    if sid:
        r = app.db.one("SELECT data FROM sites WHERE id=?", (sid,))
        if r:
            old = json.loads(r["data"])
            for u in old.get("security", {}).get("basic_auth_users", []):
                old_users[u["username"]] = u.get("password_hash", "")
    site = Site.model_validate(data)
    _guard_raw(user, site, old)
    for u in site.security.basic_auth_users:
        if u.password:
            if len(u.password) < 4:
                raise ValueError(f"Пароль пользователя «{u.username}» слишком короткий")
            u.password_hash = apr1(u.password)
            u.password = ""
        elif not u.password_hash:
            u.password_hash = old_users.get(u.username, "")
            if not u.password_hash:
                raise ValueError(f"Укажите пароль для пользователя «{u.username}»")
    if site.ssl.enabled and site.ssl.certificate_id and \
            not app.db.one("SELECT 1 FROM certificates WHERE id=?", (site.ssl.certificate_id,)):
        raise ValueError("Выбранный сертификат не существует")
    return site


async def _maybe_apply(app, user, apply: bool, comment: str) -> Optional[Dict[str, Any]]:
    if not apply:
        return None
    return await app.apply(user["username"], comment)


@router.post("/sites")
async def create_site(request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                      user=Depends(operator)):
    """Создать сайт (тело — модель Site). ?apply=1 — применить конфигурацию сразу."""
    app = nm(request)
    site = _prepare_site(app, body, user=user)
    now = time.time()
    sid = app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                         (site.name, int(site.enabled), json.dumps(site.model_dump(), ensure_ascii=False), now, now))
    audit(request, user, "site_created", site.name, {"id": sid})
    res = await _maybe_apply(app, user, apply, f"Создан сайт «{site.name}»")
    return {"id": sid, "applied": res}


@router.put("/sites/{sid}")
async def update_site(sid: int, request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                      user=Depends(operator)):
    """Изменить сайт. Пустой пароль пользователя Basic Auth — оставить прежний. ?apply=1 — применить сразу."""
    app = nm(request)
    if not app.db.one("SELECT 1 FROM sites WHERE id=?", (sid,)):
        raise HTTPException(404, "Сайт не найден")
    site = _prepare_site(app, body, sid, user)
    app.db.execute("UPDATE sites SET name=?, enabled=?, data=?, updated_at=? WHERE id=?",
                   (site.name, int(site.enabled), json.dumps(site.model_dump(), ensure_ascii=False), time.time(), sid))
    audit(request, user, "site_updated", site.name, {"id": sid})
    res = await _maybe_apply(app, user, apply, f"Изменён сайт «{site.name}»")
    return {"id": sid, "applied": res}


@router.post("/sites/{sid}/toggle")
async def toggle_site(sid: int, request: Request, apply: bool = Query(False), user=Depends(operator)):
    """Включить или выключить сайт. ?apply=1 — применить сразу."""
    app = nm(request)
    r = app.db.one("SELECT * FROM sites WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Сайт не найден")
    d = json.loads(r["data"])
    d["enabled"] = not d.get("enabled", True)
    app.db.execute("UPDATE sites SET enabled=?, data=?, updated_at=? WHERE id=?",
                   (int(d["enabled"]), json.dumps(d, ensure_ascii=False), time.time(), sid))
    audit(request, user, "site_enabled" if d["enabled"] else "site_disabled", r["name"])
    res = await _maybe_apply(app, user, apply, f"Сайт «{r['name']}» {'включён' if d['enabled'] else 'выключен'}")
    return {"enabled": d["enabled"], "applied": res}


@router.post("/sites/{sid}/maintenance")
async def site_maintenance(sid: int, request: Request, enabled: bool = Body(..., embed=True), user=Depends(operator)):
    """Режим обслуживания: {enabled}. Применяется сразу."""
    app = nm(request)
    r = app.db.one("SELECT * FROM sites WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Сайт не найден")
    d = json.loads(r["data"])
    d.setdefault("maintenance", {})["enabled"] = enabled
    app.db.execute("UPDATE sites SET data=?, updated_at=? WHERE id=?", (json.dumps(d, ensure_ascii=False),
                                                                       time.time(), sid))
    audit(request, user, "maintenance_on" if enabled else "maintenance_off", r["name"])
    res = await app.apply(user["username"], f"Обслуживание «{r['name']}»: {'вкл' if enabled else 'выкл'}")
    return {"ok": True, "applied": res}


class BulkBody(BaseModel):
    ids: List[int]
    action: str
    tag: str = ""
    apply: bool = False


BULK_ACTIONS = {"enable": "включены", "disable": "выключены", "maintenance_on": "переведены в обслуживание",
                "maintenance_off": "выведены из обслуживания", "delete": "удалены", "tag_add": "метка добавлена",
                "tag_remove": "метка убрана"}


@router.post("/sites/bulk")
async def sites_bulk(body: BulkBody, request: Request, user=Depends(operator)):
    """Одно действие над несколькими сайтами: {ids, action, tag?, apply}. action = enable | disable | maintenance_on | maintenance_off | tag_add | tag_remove | delete. Обслуживание применяется сразу, остальное — по флагу apply."""
    app = nm(request)
    if body.action not in BULK_ACTIONS:
        raise HTTPException(400, "Неизвестное действие")
    ids = sorted({int(i) for i in body.ids})[:1000]
    if not ids:
        raise HTTPException(400, "Не выбраны сайты")
    tag = body.tag.strip()[:40]
    if body.action.startswith("tag_") and (not tag or any(c in tag for c in "\r\n\0")):
        raise HTTPException(400, "Укажите метку")
    rows = app.db.query(f"SELECT * FROM sites WHERE id IN ({','.join('?' * len(ids))})", ids)
    if not rows:
        raise HTTPException(404, "Сайты не найдены")
    changed: List[str] = []
    now = time.time()
    for r in rows:
        if body.action == "delete":
            app.db.execute("DELETE FROM sites WHERE id=?", (r["id"],))
            changed.append(r["name"])
            continue
        d = json.loads(r["data"])
        before = json.dumps(d, sort_keys=True)
        if body.action in ("enable", "disable"):
            d["enabled"] = body.action == "enable"
        elif body.action.startswith("maintenance_"):
            d.setdefault("maintenance", {})["enabled"] = body.action == "maintenance_on"
        elif body.action == "tag_add":
            d["tags"] = list(dict.fromkeys(list(d.get("tags") or []) + [tag]))
        else:
            d["tags"] = [t for t in d.get("tags") or [] if t != tag]
        if json.dumps(d, sort_keys=True) == before:
            continue
        site = Site.model_validate(d)
        app.db.execute("UPDATE sites SET enabled=?, data=?, updated_at=? WHERE id=?",
                       (int(site.enabled), json.dumps(d, ensure_ascii=False), now, r["id"]))
        changed.append(r["name"])
    # в аудит — не более 50 имён: запись о действии над сотнями сайтов не должна раздувать журнал
    audit(request, user, "sites_bulk", body.action, {"requested": len(ids), "changed": len(changed),
                                                     "sites": changed[:50], "tag": tag or None})
    if changed:
        app.touch()
    need_apply = bool(changed) and (body.apply or body.action.startswith("maintenance_"))
    res = await _maybe_apply(app, user, need_apply,
                             f"Массово ({len(changed)}): {BULK_ACTIONS[body.action]} — " + ", ".join(changed[:5])
                             + ("…" if len(changed) > 5 else ""))
    return {"changed": len(changed), "sites": changed, "applied": res}


@router.post("/sites/{sid}/clone")
async def clone_site(sid: int, request: Request, user=Depends(operator)):
    """Копия сайта (выключенная, с пометкой «копия»)."""
    app = nm(request)
    r = app.db.one("SELECT * FROM sites WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Сайт не найден")
    d = json.loads(r["data"])
    d["name"] = d["name"] + " (копия)"
    d["enabled"] = False
    now = time.time()
    new = app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                         (d["name"], 0, json.dumps(d, ensure_ascii=False), now, now))
    audit(request, user, "site_cloned", r["name"], {"new_id": new})
    return {"id": new}


@router.delete("/sites/{sid}")
async def delete_site(sid: int, request: Request, apply: bool = Query(False), user=Depends(operator)):
    """Удалить сайт. ?apply=1 — применить сразу."""
    app = nm(request)
    r = app.db.one("SELECT name FROM sites WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Сайт не найден")
    app.db.execute("DELETE FROM sites WHERE id=?", (sid,))
    audit(request, user, "site_deleted", r["name"], {"id": sid})
    res = await _maybe_apply(app, user, apply, f"Удалён сайт «{r['name']}»")
    return {"ok": True, "applied": res}


def _render_with(app, site: Optional[Site] = None, sid: Optional[int] = None,
                 stream: Optional[Stream] = None, stid: Optional[int] = None):
    st = app.nginx.load_state()
    if site is not None:
        sid = sid or 0
        st.sites = [(i, s) for i, s in st.sites if i != sid] + [(sid, site)]
    if stream is not None:
        stid = stid or 0
        st.streams = [(i, s) for i, s in st.streams if i != stid] + [(stid, stream)]
    return st, sid, stid


@router.post("/sites/preview")
async def preview_site(request: Request, body: Dict[str, Any] = Body(...), sid: int = Query(0),
                       test: bool = Query(False), user=Depends(viewer)):
    """Конфигурация nginx для черновика сайта без сохранения. ?sid — для существующего, ?test=1 — проверить nginx -t (оператор и администратор)."""
    app = nm(request)
    if test and ROLES.get(user["role"], 0) < ROLES["operator"]:
        # nginx -t читает конфигурацию от root: проверка черновика — право того, кто может менять сайты
        raise HTTPException(403, "Проверка черновика через nginx -t доступна оператору и администратору")
    site = _prepare_site(app, body, sid or None, user)
    st, sid, _ = _render_with(app, site, sid)
    site.enabled = True
    st.sites = [(i, s) for i, s in st.sites if i != sid] + [(sid, site)]
    files, warnings = await asyncio.to_thread(app.nginx.render, st)
    name = f"sites/site-{sid}-{slug(site.name)}.conf"
    res: Dict[str, Any] = {"config": files.get(name, ""), "warnings": warnings}
    if test:
        res["test"] = await asyncio.to_thread(_test_state, app, st)
    return res


def _test_state(app, st: State) -> Dict[str, Any]:
    import shutil
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="nm-test-", dir=str(settings.managed_dir)))
    try:
        files, _ = app.nginx.render(st, include_root=str(tmp))
        for rel, content in files.items():
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        ok, out = app.nginx.test_config(tmp / "nginx.conf")
        return {"ok": ok, "output": out.replace(str(tmp), "…"), "errors": app.nginx.parse_errors(out, files, str(tmp))}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@router.get("/sites/{sid}/config")
async def site_config(sid: int, request: Request, user=Depends(viewer)):
    """Действующая сгенерированная конфигурация сайта."""
    app = nm(request)
    files, warnings = await asyncio.to_thread(app.nginx.render, app.nginx.load_state())
    for k, v in files.items():
        if k.startswith(f"sites/site-{sid}-"):
            return {"file": k, "config": v, "warnings": warnings}
    return {"file": "", "config": "# Сайт выключен — конфигурация не генерируется", "warnings": warnings}


# =============================================================================
#  Потоки TCP/UDP
# =============================================================================
@router.get("/streams")
async def list_streams(request: Request, user=Depends(viewer)):
    """Список TCP/UDP-потоков."""
    app = nm(request)
    health: Dict[str, List] = {}
    for t in app.health.targets.values():
        health.setdefault(t.owner, []).append({"addr": f"{t.address}:{t.port}", "state": t.state,
                                               "latency_ms": round(t.last_latency * 1000, 1), "error": t.last_error})
    out = []
    for r in app.db.query("SELECT * FROM streams ORDER BY name COLLATE NOCASE"):
        d = json.loads(r["data"])
        out.append({"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]), "data": d,
                    "health": health.get(f"stream:{r['id']}", [])})
    return out


@router.get("/streams/{sid}")
async def get_stream(sid: int, request: Request, user=Depends(viewer)):
    """Настройки потока."""
    r = nm(request).db.one("SELECT * FROM streams WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Поток не найден")
    return {"id": r["id"], "data": json.loads(r["data"])}


def _check_stream_port(app, s: Stream, sid: Optional[int]) -> None:
    st = app.nginx.load_state()
    for i, o in st.streams:
        if i != sid and o.enabled and o.listen_port == s.listen_port and \
                (o.protocol == s.protocol or "both" in (o.protocol, s.protocol)):
            raise ValueError(f"Порт {s.listen_port} уже используется потоком «{o.name}»")
    http_ports = {x.http_port for _, x in st.sites} | {x.https_port for _, x in st.sites} | {80, 443}
    if s.protocol != "udp" and s.listen_port in http_ports:
        raise ValueError(f"Порт {s.listen_port} используется HTTP-сайтами")
    if s.listen_port in (settings.bind_port, settings.stub_status_port):
        raise ValueError(f"Порт {s.listen_port} занят панелью")


@router.post("/streams")
async def create_stream(request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                        user=Depends(operator)):
    """Создать поток (тело — модель Stream). ?apply=1 — применить сразу."""
    app = nm(request)
    s = Stream.model_validate(body)
    _check_stream_port(app, s, None)
    now = time.time()
    sid = app.db.execute("INSERT INTO streams(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                         (s.name, int(s.enabled), json.dumps(s.model_dump(), ensure_ascii=False), now, now))
    audit(request, user, "stream_created", s.name)
    return {"id": sid, "applied": await _maybe_apply(app, user, apply, f"Создан поток «{s.name}»")}


@router.put("/streams/{sid}")
async def update_stream(sid: int, request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                        user=Depends(operator)):
    """Изменить поток. ?apply=1 — применить сразу."""
    app = nm(request)
    s = Stream.model_validate(body)
    _check_stream_port(app, s, sid)
    app.db.execute("UPDATE streams SET name=?, enabled=?, data=?, updated_at=? WHERE id=?",
                   (s.name, int(s.enabled), json.dumps(s.model_dump(), ensure_ascii=False), time.time(), sid))
    audit(request, user, "stream_updated", s.name)
    return {"id": sid, "applied": await _maybe_apply(app, user, apply, f"Изменён поток «{s.name}»")}


@router.delete("/streams/{sid}")
async def delete_stream(sid: int, request: Request, apply: bool = Query(False), user=Depends(operator)):
    """Удалить поток. ?apply=1 — применить сразу."""
    app = nm(request)
    r = app.db.one("SELECT name FROM streams WHERE id=?", (sid,))
    app.db.execute("DELETE FROM streams WHERE id=?", (sid,))
    audit(request, user, "stream_deleted", r["name"] if r else str(sid))
    return {"ok": True, "applied": await _maybe_apply(app, user, apply, "Удалён поток")}


@router.post("/streams/preview")
async def preview_stream(request: Request, body: Dict[str, Any] = Body(...), sid: int = Query(0),
                         user=Depends(viewer)):
    """Конфигурация nginx для черновика потока без сохранения."""
    app = nm(request)
    s = Stream.model_validate(body)
    s.enabled = True
    st, _, stid = _render_with(app, stream=s, stid=sid)
    files, warnings = await asyncio.to_thread(app.nginx.render, st)
    return {"config": files.get(f"streams/stream-{stid}-{slug(s.name)}.conf", ""), "warnings": warnings}


# =============================================================================
#  Конфигурация, версии, настройки
# =============================================================================
@router.get("/config/pending")
async def pending(request: Request, user=Depends(viewer)):
    """Неприменённые изменения: сравнение с последней применённой версией (хеши паролей скрыты)."""
    app = nm(request)
    try:
        diff = await asyncio.to_thread(app.nginx.pending_diff)
    except Exception as e:
        return {"error": str(e), "diff": []}
    return {"diff": diff, "pending": bool(diff)}


@router.post("/config/apply")
async def apply_config(request: Request, comment: str = Body("", embed=True), user=Depends(operator)):
    """Применить конфигурацию: проверка nginx -t → переключение → reload; при ошибке — откат. {comment}."""
    app = nm(request)
    res = await app.apply(user["username"], comment)
    audit(request, user, "config_applied", f"v{res['version']}", {"comment": comment})
    return res


@router.post("/config/test")
async def test_config(request: Request, user=Depends(viewer)):
    """Проверить текущую конфигурацию из базы через nginx -t, ничего не применяя."""
    app = nm(request)
    st = app.nginx.load_state()
    return await asyncio.to_thread(_test_state, app, st)


@router.get("/config/versions")
async def versions(request: Request, limit: int = 100, user=Depends(viewer)):
    """История версий конфигурации. ?limit."""
    rows = nm(request).db.query("SELECT id, ts, username, comment, source, status, checksum, "
                                "length(files) size FROM config_versions ORDER BY id DESC LIMIT ?", (limit,))
    applied = nm(request).db.kv_get("applied_version")
    for r in rows:
        r["current"] = r["id"] == applied
    return rows


@router.get("/config/versions/{vid}")
async def version(vid: int, request: Request, user=Depends(viewer)):
    """Файлы версии конфигурации (хеши паролей скрыты) и список сайтов и потоков в ней."""
    r = nm(request).db.one("SELECT * FROM config_versions WHERE id=?", (vid,))
    if not r:
        raise HTTPException(404, "Версия не найдена")
    r["files"] = app_nginx_masked(json.loads(r["files"]))
    st = json.loads(r["state"])
    r["state_summary"] = {"sites": [{"id": s["id"], "name": s["data"]["name"], "enabled": s["data"].get("enabled")}
                                    for s in st.get("sites", [])],
                          "streams": [{"id": s["id"], "name": s["data"]["name"]} for s in st.get("streams", [])]}
    del r["state"]
    return r


@router.get("/config/versions/{vid}/diff")
async def version_diff(vid: int, request: Request, against: str = "prev", user=Depends(viewer)):
    """Отличия версии от предыдущей применённой; ?against=current — от действующей."""
    app = nm(request)
    r = app.db.one("SELECT files FROM config_versions WHERE id=?", (vid,))
    if not r:
        raise HTTPException(404, "Версия не найдена")
    new = json.loads(r["files"])
    if against == "current":
        cur = app.nginx.last_applied()
        old = json.loads(cur["files"]) if cur else {}
        return app.nginx.diff(new, old)
    prev = app.db.one("SELECT files FROM config_versions WHERE id<? AND status='applied' ORDER BY id DESC LIMIT 1",
                      (vid,))
    return app.nginx.diff(json.loads(prev["files"]) if prev else {}, new)


@router.post("/config/versions/{vid}/rollback")
async def rollback(vid: int, request: Request, user=Depends(operator)):
    """Откат к версии: настройки сайтов и потоков восстанавливаются из неё и применяются."""
    app = nm(request)
    r = app.db.one("SELECT state FROM config_versions WHERE id=?", (vid,))
    if not r:
        raise HTTPException(404, "Версия не найдена")
    st_json = json.loads(r["state"])
    State.from_json(st_json)  # проверка
    await asyncio.to_thread(app.nginx.restore_state_to_db, st_json)
    app.touch()
    res = await app.apply(user["username"], f"Откат к версии {vid}", source="rollback")
    audit(request, user, "config_rollback", f"v{vid}", {"new_version": res["version"]})
    return res


@router.get("/config/files")
async def config_files(request: Request, user=Depends(viewer)):
    """Файлы действующей конфигурации (хеши паролей скрыты)."""
    last = nm(request).nginx.last_applied()
    return app_nginx_masked(json.loads(last["files"])) if last else {}


@router.get("/config/dump", response_class=PlainTextResponse)
async def config_dump(request: Request, user=Depends(admin)):
    """Полный вывод nginx -T (только администратор)."""
    return await asyncio.to_thread(nm(request).nginx.dump_config)


@router.get("/settings/global")
async def get_global(request: Request, user=Depends(viewer)):
    """Глобальные настройки nginx."""
    return nm(request).global_settings().model_dump()


@router.put("/settings/global")
async def put_global(request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                     user=Depends(admin)):
    """Изменить глобальные настройки nginx. ?apply=1 — применить сразу."""
    app = nm(request)
    g = GlobalSettings.model_validate(body)
    app.db.kv_set("global_settings", g.model_dump())
    audit(request, user, "global_settings_updated")
    return {"ok": True, "applied": await _maybe_apply(app, user, apply, "Изменены глобальные настройки")}


@router.get("/settings/panel")
async def get_panel(request: Request, user=Depends(viewer)):
    """Настройки панели (секреты — ключ EAB, ключ и пароль шифрования S3 — не возвращаются, вместо них маска)."""
    d = nm(request).panel().model_dump()
    for k in PANEL_SECRETS:
        if d.get(k):
            d[k] = MASK
    return d


@router.put("/settings/panel")
async def put_panel(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Изменить настройки панели (только администратор)."""
    app = nm(request)
    old = app.panel()
    for k in PANEL_SECRETS:
        if body.get(k) == MASK:  # секрет не менялся
            body[k] = getattr(old, k)
    p = PanelSettings.model_validate(body)
    ip = user.get("ip", "")
    if p.require_2fa_admin and not old.require_2fa_admin and not user.get("totp_enabled"):
        raise HTTPException(400, "Сначала включите двухфакторную аутентификацию для себя (раздел «Мой профиль») — "
                                 "иначе политика сразу ограничит ваши права")
    app.save_panel(p)
    if p.panel_allow and not app.auth.ip_allowed(ip):
        app.save_panel(old)
        raise HTTPException(400, f"Ваш текущий IP {ip} не входит в список разрешённых — вы потеряете доступ")
    app.stats.reload_geoip()
    audit(request, user, "panel_settings_updated")
    needs_apply = (old.panel_domain != p.panel_domain or old.panel_certificate_id != p.panel_certificate_id or
                   old.panel_allow != p.panel_allow)
    return {"ok": True, "needs_apply": needs_apply}


@router.get("/nginx/info")
async def nginx_info(request: Request, user=Depends(viewer)):
    """Сведения о nginx: версия, модули, параметры сборки, поддержка HTTP/2, HTTP/3, stream."""
    app = nm(request)
    info = await asyncio.to_thread(app.nginx.info)
    info["status"] = app.nginx.status()
    return info


@router.post("/nginx/{action}")
async def nginx_action(action: str, request: Request, user=Depends(operator)):
    """Управление nginx: reload, restart, start, stop, reopen (переоткрыть журналы)."""
    app = nm(request)
    fn = {"start": app.nginx.start, "stop": app.nginx.stop, "restart": app.nginx.restart,
          "reload": app.nginx.reload_or_start, "reopen": app.nginx.reopen_logs}.get(action)
    if not fn:
        raise HTTPException(404, "Неизвестное действие")
    if action == "stop" and user["role"] != "admin":
        raise HTTPException(403, "Остановить nginx может только администратор")
    ok, out = await asyncio.to_thread(fn)
    audit(request, user, f"nginx_{action}", "", {"ok": ok})
    if not ok:
        raise HTTPException(500, out.strip() or f"Не удалось выполнить {action}")
    return {"ok": ok, "output": out}


# =============================================================================
#  Сертификаты
# =============================================================================
@router.get("/certs")
async def certs(request: Request, user=Depends(viewer)):
    """Сертификаты: домены, срок действия, статус, где используются, ход выпуска."""
    app = nm(request)
    from ..services import acme
    p = app.panel()
    server = acme.directory_for(p)
    items = app.certs.list()
    for c in items:
        if c["type"] == "letsencrypt":
            srv = c["data"].get("server") or acme.CA_DIRECTORIES[
                "letsencrypt-staging" if c["data"].get("staging") else "letsencrypt"]
            c["ca"] = acme.ca_title(srv)
            c["data"].pop("eab", None)
    return {"items": items, "certbot": bool(app.certs.certbot()), "email": p.letsencrypt_email,
            "webroot": str(settings.acme_webroot), "ca": acme.ca_title(server) if server else "не настроен",
            "renew_days": p.renew_days_before}


@router.post("/certs")
async def create_cert(request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    """Новый сертификат: Let's Encrypt, загрузка PEM, самоподписанный или файлы на сервере (модель CertificateRequest)."""
    app = nm(request)
    req = CertificateRequest.model_validate(body)
    if req.type == "letsencrypt":
        cid = await app.certs.issue_letsencrypt(req, user["username"], after=app.after_cert_issued)
    else:
        cid = await asyncio.to_thread(app.certs.create, req, user["username"])
    audit(request, user, "cert_created", req.name or ",".join(req.domains), {"type": req.type, "id": cid})
    app.touch()
    return {"id": cid}


@router.post("/certs/{cid}/renew")
async def renew_cert(cid: int, request: Request, user=Depends(operator)):
    """Продлить или перевыпустить сертификат Let's Encrypt."""
    app = nm(request)
    await app.certs.renew(cid, after=app.after_cert_issued)
    audit(request, user, "cert_renew", str(cid))
    return {"ok": True}


@router.delete("/certs/{cid}")
async def delete_cert(cid: int, request: Request, user=Depends(operator)):
    """Удалить сертификат (нельзя, пока он используется сайтом или панелью)."""
    app = nm(request)
    await asyncio.to_thread(app.certs.delete, cid)
    audit(request, user, "cert_deleted", str(cid))
    return {"ok": True}


# =============================================================================
#  Учётные записи DNS (DNS-проверка ACME)
# =============================================================================
def _mask_dns(d: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(d)
    for k in DNS_SECRET_FIELDS:
        if d.get(k):
            d[k] = MASK
    return d


def _dns_from(app, body: Dict[str, Any], aid: Optional[int] = None) -> DnsAccount:
    if aid:
        old = app.db.one("SELECT data FROM dns_accounts WHERE id=?", (aid,))
        if not old:
            raise HTTPException(404, "Учётная запись не найдена")
        od = json.loads(old["data"])
        for k in DNS_SECRET_FIELDS:
            if body.get(k) == MASK:
                body[k] = od.get(k, "")
    return DnsAccount.model_validate(body)


@router.get("/dns-accounts")
async def dns_accounts(request: Request, user=Depends(viewer)):
    """Учётные записи DNS-провайдеров (секреты не возвращаются): провайдер, где используется, установлен ли плагин certbot."""
    from ..services import acme
    app = nm(request)
    usage = app.certs.dns_accounts_usage()
    plugins = await asyncio.to_thread(acme.installed_plugins)
    out = []
    for r in app.db.query("SELECT * FROM dns_accounts ORDER BY name"):
        d = json.loads(r["data"])
        auth = acme.PLUGINS[d["provider"]]["auth"]
        out.append({"id": r["id"], "data": _mask_dns(d), "provider_title": DNS_PROVIDERS[d["provider"]],
                    "used_by": usage.get(r["id"], []),
                    "plugin": True if d["provider"] == "hook" else (None if plugins is None else auth in plugins),
                    "package": acme.PLUGINS[d["provider"]].get("pkg", "")})
    return {"items": out, "certbot": plugins is not None}


@router.post("/dns-accounts")
async def create_dns_account(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Создать учётную запись DNS (модель DnsAccount; только администратор — в ней секреты)."""
    app = nm(request)
    acc = _dns_from(app, body)
    now = time.time()
    aid = app.db.execute("INSERT INTO dns_accounts(name,provider,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                         (acc.name, acc.provider, json.dumps(acc.model_dump(), ensure_ascii=False), now, now))
    audit(request, user, "dns_account_created", acc.name, {"provider": acc.provider})
    return {"id": aid}


@router.put("/dns-accounts/{aid}")
async def update_dns_account(aid: int, request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Изменить учётную запись DNS. Секрет «••••••••» — оставить прежний; файлы учётных данных для продления
    переписываются сразу."""
    app = nm(request)
    acc = _dns_from(app, body, aid)
    app.db.execute("UPDATE dns_accounts SET name=?, provider=?, data=?, updated_at=? WHERE id=?",
                   (acc.name, acc.provider, json.dumps(acc.model_dump(), ensure_ascii=False), time.time(), aid))
    await asyncio.to_thread(app.certs.sync_dns_credentials, aid)
    audit(request, user, "dns_account_updated", acc.name, {"provider": acc.provider})
    return {"id": aid}


@router.delete("/dns-accounts/{aid}")
async def delete_dns_account(aid: int, request: Request, user=Depends(admin)):
    """Удалить учётную запись DNS (нельзя, пока по ней продлеваются сертификаты)."""
    from ..services import acme
    app = nm(request)
    used = app.certs.dns_accounts_usage().get(aid)
    if used:
        raise HTTPException(400, f"Учётная запись используется сертификатами: {', '.join(used[:5])}. "
                                 "Удалите их или выпустите заново с другой учётной записью")
    r = app.db.one("SELECT name FROM dns_accounts WHERE id=?", (aid,))
    if not r:
        raise HTTPException(404, "Учётная запись не найдена")
    app.db.execute("DELETE FROM dns_accounts WHERE id=?", (aid,))
    acme.remove_credentials(aid)
    audit(request, user, "dns_account_deleted", r["name"])
    return {"ok": True}


@router.post("/dns-accounts/{aid}/check")
async def check_dns_account(aid: int, request: Request, user=Depends(operator)):
    """Проверить учётную запись без выпуска: установлен ли плагин certbot, существуют ли скрипты."""
    from ..services import acme
    acc = nm(request).certs.dns_account(aid)
    if not acc:
        raise HTTPException(404, "Учётная запись не найдена")
    return await asyncio.to_thread(acme.check_account, acc)


@router.post("/certs/selftest")
async def cert_selftest(request: Request, domain: str = Body(..., embed=True), user=Depends(operator)):
    """Проверка домена перед выпуском Let's Encrypt: DNS, доступность /.well-known/acme-challenge по HTTP. {domain}."""
    from ..validators import domain as vd
    return await asyncio.to_thread(nm(request).certs.http01_selftest, vd(domain))


# =============================================================================
#  Статистика
# =============================================================================
@router.get("/stats/realtime")
async def stats_realtime(request: Request, seconds: int = 300, site: str = "*", user=Depends(viewer)):
    """Посекундные ряды за последние минуты: запросы по классам, трафик, перцентили. ?seconds, ?site."""
    return nm(request).stats.agg.realtime(min(600, max(10, seconds)), site)


@router.get("/stats/snapshot")
async def stats_snapshot(request: Request, user=Depends(viewer)):
    """Текущие показатели: окна 1/10/60 секунд, соединения nginx, система, сайты."""
    return nm(request).stats.snapshot()


@router.get("/stats/timeseries")
async def stats_ts(request: Request, frm: Optional[float] = Query(None, alias="from"), to: Optional[float] = None,
                   site: str = "*", points: int = 240, user=Depends(viewer)):
    """Временные ряды за период (поминутно до 48 часов, дальше почасово). ?from, ?to, ?site, ?points."""
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.timeseries, s, e, site, min(1000, points))


@router.get("/stats/summary")
async def stats_summary(request: Request, frm: Optional[float] = Query(None, alias="from"), to: Optional[float] = None,
                        site: str = "*", user=Depends(viewer)):
    """Сводка за период: запросы, коды, перцентили, кэш, боты, блокировки, ошибки nginx. ?from, ?to, ?site."""
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.summary, s, e, site)


@router.get("/stats/top")
async def stats_top(request: Request, kind: str, frm: Optional[float] = Query(None, alias="from"),
                    to: Optional[float] = None, site: str = "*", limit: int = 30, user=Depends(viewer)):
    """Топ за период: ?kind = uri, ip, ua, referer, browser, os, device, country, upstream, e4xx, e5xx, slow, host."""
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.tops, s, e, site, kind, min(500, limit))


@router.get("/stats/sites")
async def stats_sites(request: Request, frm: Optional[float] = Query(None, alias="from"), to: Optional[float] = None,
                      user=Depends(viewer)):
    """Сравнение сайтов за период: доля трафика, ошибки, время ответа."""
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.compare_sites, s, e)


@router.get("/stats/sla")
async def stats_sla(request: Request, days: int = 30, slo: float = 99.9, user=Depends(viewer)):
    """Доступность сайтов (доля ответов без 5xx) по дням и бюджет ошибок. ?days (по умолчанию 30), ?slo (цель, %, по умолчанию 99.9)."""
    from ..services.metrics import site_names
    app = nm(request)
    days = min(max(days, 7), 90)
    slo = min(max(slo, 90.0), 99.999)
    res = await asyncio.to_thread(app.stats.sla, days, slo)
    names = site_names(app)
    names["*"] = "Все сайты"
    res["sites"] = [dict(x, name=names.get(x["site"], x["site"])) for x in res["sites"]
                    if x["site"] == "*" or x["site"] in names and x["site"] not in ("-", "panel")]
    res["sites"].sort(key=lambda x: (x["site"] != "*", x["a30"] if x["a30"] is not None else 101, x["name"]))
    return res


@router.get("/stats/heatmap")
async def stats_heatmap(request: Request, weeks: int = 4, site: str = "*", user=Depends(viewer)):
    """Почасовые значения за последние недели для тепловой карты. ?weeks, ?site."""
    return await asyncio.to_thread(nm(request).stats.heatmap, min(max(weeks, 1), 26), site)


@router.get("/stats/system")
async def stats_system(request: Request, frm: Optional[float] = Query(None, alias="from"),
                       to: Optional[float] = None, user=Depends(viewer)):
    """Ресурсы сервера и процессов nginx за период."""
    s, e = rng(frm, to, 600)
    return await asyncio.to_thread(nm(request).stats.system_series, s, e)


@router.get("/stats/streams")
async def stats_streams(request: Request, frm: Optional[float] = Query(None, alias="from"),
                        to: Optional[float] = None, user=Depends(viewer)):
    """Статистика TCP/UDP-потоков за период."""
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.stream_series, s, e)


@router.get("/requests")
async def requests_search(request: Request, limit: int = 100, offset: int = 0, user=Depends(viewer)):
    """Поиск по журналу запросов: ?site, status (код или 5xx), ip, method, uri, host, ua, upstream, country, rid, min_rt (мс), start, end (unix-время), sort = rt | bytes, limit, offset."""
    f = dict(request.query_params)
    return await asyncio.to_thread(nm(request).stats.search_requests, f, min(1000, limit), offset)


@router.get("/requests/live")
async def requests_live(request: Request, seq: int = 0, limit: int = 200, user=Depends(viewer)):
    """Последние запросы из памяти; ?seq — только новее этого номера (живой журнал без WebSocket)."""
    return nm(request).stats.agg.live_since(seq, min(1000, limit))


@router.get("/errors")
async def errors_search(request: Request, limit: int = 100, offset: int = 0, user=Depends(viewer)):
    """Поиск по журналу ошибок nginx: ?level, category, site, q, start, end, limit, offset; счётчики по категориям."""
    f = dict(request.query_params)
    return await asyncio.to_thread(nm(request).stats.search_errors, f, min(1000, limit), offset)


@router.get("/errors/raw", response_class=PlainTextResponse)
async def errors_raw(request: Request, lines: int = 200, user=Depends(viewer)):
    """Последние строки журнала ошибок nginx как есть."""
    return "\n".join(nm(request).nginx.recent_error_log(min(5000, lines)))


# =============================================================================
#  Бэкенды, диагностика, события
# =============================================================================
@router.get("/health")
async def health(request: Request, user=Depends(viewer)):
    """Активные проверки бэкендов: состояние, задержка, доступность, история; пассивные ошибки из журнала nginx."""
    app = nm(request)
    return {"targets": app.health.list(), "passive": dict(app.stats.agg.passive_upstream.most_common(50))}


@router.post("/health/check")
async def health_check(request: Request, key: Optional[str] = Body(None, embed=True), user=Depends(viewer)):
    """Проверить бэкенды сейчас: {key} — один сервер или группа, null — все."""
    return await nm(request).health.check_now(key)


@router.get("/health/history")
async def health_history(request: Request, key: str, frm: Optional[float] = Query(None, alias="from"),
                         to: Optional[float] = None, user=Depends(viewer)):
    """Поминутная история проверок сервера. ?key, ?from, ?to."""
    s, e = rng(frm, to, 86400)
    return await asyncio.to_thread(nm(request).health.history, key, s, e)


@router.get("/diagnostics")
async def diagnostics(request: Request, user=Depends(viewer)):
    """Результаты последней диагностики."""
    return nm(request).diag.last


@router.post("/diagnostics/run")
async def diagnostics_run(request: Request, user=Depends(viewer)):
    """Запустить диагностику сейчас."""
    return await nm(request).diag.run_all()


@router.post("/diagnostics/fix")
async def diagnostics_fix(request: Request, action: str = Body(...), args: Dict[str, Any] = Body({}),
                          user=Depends(operator)):
    """Выполнить исправление из диагностики: {action, args}."""
    app = nm(request)
    res = await app.diag.fix(action, args, user["username"])
    audit(request, user, "diag_fix", action, {"args": args, "ok": res.get("ok")})
    return res


@router.get("/diagnostics/collector")
async def collector(request: Request, user=Depends(viewer)):
    """Состояние сборщика статистики: журналы, отставание, ошибки разбора."""
    return nm(request).stats.collector_info()


# =============================================================================
#  Встроенный анализ и подсказки
# =============================================================================
@router.get("/insights")
async def insights(request: Request, frm: Optional[float] = Query(None, alias="from"),
                   to: Optional[float] = None, site: str = "*", user=Depends(viewer)):
    """Встроенный анализ за период: найденные проблемы с причинами и шагами. ?from, ?to, ?site."""
    start, end = rng(frm, to, 900)
    return await asyncio.to_thread(nm(request).insights.evaluate, start, end, site or "*")


@router.get("/insights/catalog")
async def insights_catalog(request: Request, user=Depends(viewer)):
    """Справочник анализа: все показатели с порогами и все сценарии."""
    return nm(request).insights.catalog()


class ThresholdsBody(BaseModel):
    thresholds: Dict[str, Optional[Dict[str, float]]]


@router.put("/insights/thresholds")
async def insights_thresholds(body: ThresholdsBody, request: Request, user=Depends(admin)):
    """Свои пороги показателей: {metric: {warn, crit}} или {metric: null} — вернуть значения по умолчанию."""
    from ..services.insights import METRICS
    app = nm(request)
    p = app.panel()
    cur = dict(p.insight_thresholds or {})
    for k, v in body.thresholds.items():
        m = METRICS.get(k)
        if not m or m.get("warn") is None or m.get("fixed"):
            raise HTTPException(400, f"Показатель «{k}» не имеет настраиваемых порогов")
        if v is None:
            cur.pop(k, None)
            continue
        w, c = float(v.get("warn", m["warn"])), float(v.get("crit", m["crit"]))
        if w < 0 or c < 0:
            raise HTTPException(400, f"{m['label']}: пороги не могут быть отрицательными")
        if m["dir"] == "above" and c < w:
            raise HTTPException(400, f"{m['label']}: порог «проблема» должен быть не меньше порога «внимание»")
        if m["dir"] == "below" and c > w:
            raise HTTPException(400, f"{m['label']}: порог «проблема» должен быть не больше порога «внимание»")
        if w == m["warn"] and c == m["crit"]:
            cur.pop(k, None)
        else:
            cur[k] = {"warn": w, "crit": c}
    app.save_panel(p.model_copy(update={"insight_thresholds": cur}))
    app.insights._cache.clear()
    audit(request, user, "insight_thresholds", ", ".join(body.thresholds), cur)
    return {"ok": True, "thresholds": app.insights.thresholds()}


@router.post("/insights/mute")
async def insights_mute(request: Request, id: str = Body(..., embed=True), mute: bool = Body(True, embed=True),
                        user=Depends(operator)):
    """Скрыть или вернуть тип подсказок: {id, mute}."""
    from ..services.insights import SCENARIOS
    app = nm(request)
    if id not in SCENARIOS:
        raise HTTPException(404, "Неизвестный сценарий")
    p = app.panel()
    muted = [x for x in p.insights_muted if x != id] + ([id] if mute else [])
    app.save_panel(p.model_copy(update={"insights_muted": muted}))
    app.insights._cache.clear()
    audit(request, user, "insight_muted" if mute else "insight_unmuted", id)
    return {"ok": True, "muted": muted}


# =============================================================================
#  Регулярные отчёты
# =============================================================================
@router.get("/reports/preview")
async def report_preview(request: Request, period: str = "day", user=Depends(viewer)):
    """Текст регулярного отчёта за ?period = day | week (без отправки)."""
    from ..services import reports
    if period not in ("day", "week"):
        raise HTTPException(400, "period: day | week")
    return await asyncio.to_thread(reports.build, nm(request), period)


@router.post("/reports/send")
async def report_send(request: Request, period: str = Body("day", embed=True),
                      channels: Optional[List[int]] = Body(None, embed=True), user=Depends(operator)):
    """Отправить отчёт сейчас: {period, channels}."""
    from ..services import reports
    app = nm(request)
    if period not in ("day", "week"):
        raise HTTPException(400, "period: day | week")
    ids = channels if channels is not None else list(app.panel().report_channels)
    if not ids:
        raise HTTPException(400, "Не выбраны каналы: укажите их в «Настройки панели → Отчёты»")
    rep = await asyncio.to_thread(reports.build, app, period)
    res = await reports.send(app, rep, ids)
    audit(request, user, "report_sent", rep["title"], {"channels": ids, "results": res})
    return {"title": rep["title"], "results": res}


# =============================================================================
#  Блокировки IP
# =============================================================================
class BanBody(BaseModel):
    nets: List[str]
    minutes: Optional[int] = 60      # None — бессрочно
    reason: str = ""
    force: bool = False              # разрешить блокировку доверенных адресов (кроме своего)


@router.get("/bans")
async def bans_list(request: Request, user=Depends(viewer)):
    """Блокировки IP, подозрительные адреса, нарушители, статистика и настройки автоблокировки."""
    app = nm(request)
    p = app.panel()
    items = app.bans.active()
    active = {b["net"] for b in items}
    suspicious = [{**x, "banned": x["ip"] in active} for x in reversed(app.bans.detector.suspicious.values())]
    return {"items": items, "stats": app.bans.stats(), "suspicious": suspicious,
            "offenders": app.bans.detector.top_offenders(30),
            "settings": {k: getattr(p, k) for k in PanelSettings.model_fields if k.startswith(("autoban", "ban_"))},
            "file": str(settings.bans_file)}


@router.post("/bans")
async def bans_add(body: BanBody, request: Request, user=Depends(operator)):
    """Заблокировать адреса и подсети: {nets, minutes (null — бессрочно), reason, force}."""
    from ..services.bans import in_any, normalize_net
    app = nm(request)
    if body.minutes is not None and not (1 <= body.minutes <= 525600 * 5):
        raise HTTPException(400, "Срок блокировки: от 1 минуты до 5 лет или бессрочно")
    nets, errors = [], []
    for raw in body.nets:
        for part in raw.replace(",", " ").split():
            try:
                nets.append(normalize_net(part))
            except ValueError as e:
                errors.append(f"{part}: {e}")
    if errors:
        raise HTTPException(400, "Некорректные адреса: " + "; ".join(errors[:10]))
    if not nets:
        raise HTTPException(400, "Укажите IP-адрес или подсеть")
    if len(nets) > 10000:
        raise HTTPException(400, "Не более 10 000 адресов за раз")
    own = user.get("ip") or ""
    trusted = app.bans.trusted_nets()
    for n in nets:
        if own and in_any(own, [n]):
            raise HTTPException(400, f"{n}: в этот диапазон входит ваш собственный адрес ({own}) — вы потеряете доступ")
        if not body.force and (in_any(n, trusted) or in_any(n.split("/")[0], trusted)):
            raise HTTPException(400, f"{n}: адрес в списке доверенных (localhost, «Никогда не блокировать» или "
                                     "доступ к панели). Уберите его оттуда или подтвердите блокировку")
    country = ""
    for n in nets:
        if "/" not in n and app.stats.geoip.reader:
            country = app.stats.geoip.country(n)
        app.bans.add(n, body.minutes, body.reason.strip()[:300], "manual", user["username"], "manual",
                     country=country)
    audit(request, user, "ip_banned", ", ".join(nets[:20]) + (f" (+{len(nets) - 20})" if len(nets) > 20 else ""),
          {"minutes": body.minutes, "reason": body.reason})
    ok, out = await app.bans.sync(force=True)
    return {"ok": ok, "count": len(nets), "nets": nets[:100], "output": out if not ok else ""}


@router.delete("/bans/{ban_id}")
async def bans_remove(ban_id: int, request: Request, user=Depends(operator)):
    """Снять блокировку."""
    app = nm(request)
    row = app.bans.remove(ban_id)
    if not row:
        raise HTTPException(404, "Блокировка не найдена")
    audit(request, user, "ip_unbanned", row["net"])
    app.db.event("info", "bans", f"Разблокирован {row['net']} ({user['username']})")
    ok, out = await app.bans.sync(force=True)
    return {"ok": ok, "output": out if not ok else ""}


@router.get("/geo")
async def geo_status(request: Request, user=Depends(viewer)):
    """Доступ по странам: база GeoIP, файл сетей, сайты с правилами."""
    app = nm(request)
    g = app.stats.geoip
    st = app.nginx.geo_status()
    applied = app.last_applied_state()
    live = {sid for sid, s in applied.sites if s.security.geo_mode != "off"} if applied else set()
    sites = []
    for r in app.db.query("SELECT id, name, enabled, data FROM sites ORDER BY name COLLATE NOCASE"):
        sec = (json.loads(r["data"]).get("security") or {})
        if sec.get("geo_mode", "off") == "off":
            continue
        sites.append({"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]), "mode": sec["geo_mode"],
                      "countries": sec.get("geo_countries", []), "status": sec.get("geo_status", 403),
                      "exceptions": len(sec.get("geo_exceptions", [])), "applied": r["id"] in live})
    import importlib.util
    has_pkg = importlib.util.find_spec("maxminddb") is not None
    hits = app.stats.agg.geo_hits
    by_country: Dict[str, int] = {}
    by_site: Dict[str, int] = {}
    for (site, cc), n in hits.items():
        by_country[cc] = by_country.get(cc, 0) + n
        by_site[site] = by_site.get(site, 0) + n
    now = time.time()

    def day_blocked(sid: int) -> int:
        return int(app.stats.summary(now - 86400, now, str(sid), exact_uniq=False)["blocked"]["geo"])
    for s in sites:
        s["blocked"] = by_site.get(str(s["id"]), 0)
        s["blocked_24h"] = await asyncio.to_thread(day_blocked, s["id"])
    return {"db": {"path": g.path, "loaded": g.reader is not None, "error": g.error, "package": has_pkg,
                   "mtime": g.mtime or None},
            "file": st, "sites": sites, "active": bool(st["db"]),
            "blocked": {"total": sum(by_country.values()), "since": app.stats.started,
                        "countries": sorted(([k, v] for k, v in by_country.items()), key=lambda x: -x[1])[:30]}}


@router.post("/geo/rebuild")
async def geo_rebuild(request: Request, user=Depends(operator)):
    """Пересобрать сети стран из базы GeoIP и перечитать nginx."""
    app = nm(request)
    app.stats.reload_geoip()
    await app.refresh_geo(force=True)
    audit(request, user, "geo_rebuild")
    return await geo_status(request, user)


@router.post("/bans/clear")
async def bans_clear(request: Request, source: str = Body("auto", embed=True), user=Depends(admin)):
    """Снять блокировки: {source: auto | manual | all} (только администратор)."""
    app = nm(request)
    if source not in ("auto", "manual", "all"):
        raise HTTPException(400, "source: auto | manual | all")
    where = "" if source == "all" else " WHERE source=?"
    params = () if source == "all" else (source,)
    n = app.db.scalar("SELECT COUNT(*) FROM bans" + where, params) or 0
    app.db.execute("DELETE FROM bans" + where, params)
    app.bans.dirty = True
    audit(request, user, "bans_cleared", source, {"count": n})
    ok, out = await app.bans.sync(force=True)
    return {"ok": ok, "removed": n}


@router.post("/events/notify-test")
async def events_notify_test(request: Request, user=Depends(operator)):
    """Отправить проверочное уведомление о событии в каналы подписки (настройки панели → «Уведомления о событиях»)."""
    app = nm(request)
    p = app.panel()
    if not p.event_channels:
        raise HTTPException(400, "Не выбраны каналы — уведомления о событиях выключены")
    res = await app.events.deliver("warning", "panel", f"Проверка уведомлений о событиях ({user['username']}). "
                                                        "Так будут выглядеть сообщения о сбоях.",
                                   force_channels=list(p.event_channels))
    if not res:
        raise HTTPException(400, "Выбранные каналы выключены или удалены")
    return {"results": res}


@router.get("/events")
async def events(request: Request, limit: int = 200, level: str = "", source: str = "", user=Depends(viewer)):
    """Журнал событий панели. ?level, ?source, ?limit."""
    where, params = [], []
    if level:
        where.append("level=?")
        params.append(level)
    if source:
        where.append("source=?")
        params.append(source)
    sql = "SELECT * FROM events" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
    return nm(request).db.query(sql, params + [min(max(1, limit), 5000)])


@router.get("/audit")
async def audit_log(request: Request, limit: int = 300, q: str = "", user=Depends(admin)):
    """Аудит действий пользователей (только администратор). ?q — поиск по пользователю, действию и объекту; ?limit."""
    if q:
        return nm(request).db.query("SELECT * FROM audit_log WHERE username LIKE ? OR action LIKE ? OR target LIKE ? "
                                    "ORDER BY id DESC LIMIT ?", (f"%{q}%",) * 3 + (limit,))
    return nm(request).db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


# =============================================================================
#  Оповещения
# =============================================================================
def _mask_channel(d: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(d)
    for k in ("telegram_token", "smtp_password"):
        if d.get(k):
            d[k] = MASK
    return d


@router.get("/alerts/rules")
async def alert_rules(request: Request, user=Depends(viewer)):
    """Правила оповещений с текущим состоянием и значением метрики."""
    app = nm(request)
    st = app.alerts.status()
    return [{"id": r["id"], "data": json.loads(r["data"]), "status": st.get(r["id"], {})}
            for r in app.db.query("SELECT * FROM alert_rules ORDER BY id")]


@router.post("/alerts/rules")
async def create_rule(request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    """Создать правило оповещения (модель AlertRule)."""
    r = AlertRule.model_validate(body)
    now = time.time()
    rid = nm(request).db.execute("INSERT INTO alert_rules(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                                 (r.name, int(r.enabled), json.dumps(r.model_dump(), ensure_ascii=False), now, now))
    audit(request, user, "alert_rule_created", r.name)
    return {"id": rid}


@router.put("/alerts/rules/{rid}")
async def update_rule(rid: int, request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    """Изменить правило оповещения."""
    r = AlertRule.model_validate(body)
    nm(request).db.execute("UPDATE alert_rules SET name=?, enabled=?, data=?, updated_at=? WHERE id=?",
                           (r.name, int(r.enabled), json.dumps(r.model_dump(), ensure_ascii=False), time.time(), rid))
    audit(request, user, "alert_rule_updated", r.name)
    return {"id": rid}


@router.delete("/alerts/rules/{rid}")
async def delete_rule(rid: int, request: Request, user=Depends(operator)):
    """Удалить правило оповещения."""
    nm(request).db.execute("DELETE FROM alert_rules WHERE id=?", (rid,))
    audit(request, user, "alert_rule_deleted", str(rid))
    return {"ok": True}


@router.get("/alerts/channels")
async def alert_channels(request: Request, user=Depends(viewer)):
    """Каналы уведомлений (секреты не возвращаются)."""
    return [{"id": r["id"], "data": _mask_channel(json.loads(r["data"]))}
            for r in nm(request).db.query("SELECT * FROM alert_channels ORDER BY id")]


def _channel_from(app, body: Dict[str, Any], cid: Optional[int]) -> AlertChannel:
    if cid:
        old = app.db.one("SELECT data FROM alert_channels WHERE id=?", (cid,))
        if old:
            od = json.loads(old["data"])
            for k in ("telegram_token", "smtp_password"):
                if body.get(k) == MASK:
                    body[k] = od.get(k, "")
    return AlertChannel.model_validate(body)


@router.post("/alerts/channels")
async def create_channel(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Создать канал: Telegram, Slack, Discord, e-mail, webhook (модель AlertChannel; только администратор)."""
    ch = _channel_from(nm(request), body, None)
    now = time.time()
    cid = nm(request).db.execute("INSERT INTO alert_channels(name,type,enabled,data,created_at,updated_at) "
                                 "VALUES(?,?,?,?,?,?)", (ch.name, ch.type, int(ch.enabled),
                                                         json.dumps(ch.model_dump(), ensure_ascii=False), now, now))
    audit(request, user, "alert_channel_created", ch.name)
    return {"id": cid}


@router.put("/alerts/channels/{cid}")
async def update_channel(cid: int, request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    """Изменить канал. Пустой секрет — оставить прежний."""
    ch = _channel_from(nm(request), body, cid)
    nm(request).db.execute("UPDATE alert_channels SET name=?, type=?, enabled=?, data=?, updated_at=? WHERE id=?",
                           (ch.name, ch.type, int(ch.enabled), json.dumps(ch.model_dump(), ensure_ascii=False),
                            time.time(), cid))
    audit(request, user, "alert_channel_updated", ch.name)
    return {"id": cid}


@router.delete("/alerts/channels/{cid}")
async def delete_channel(cid: int, request: Request, user=Depends(admin)):
    """Удалить канал."""
    nm(request).db.execute("DELETE FROM alert_channels WHERE id=?", (cid,))
    audit(request, user, "alert_channel_deleted", str(cid))
    return {"ok": True}


@router.post("/alerts/channels/test")
async def test_channel(request: Request, body: Dict[str, Any] = Body(...), cid: int = Query(0),
                       user=Depends(operator)):
    """Отправить тестовое сообщение: {id} сохранённого канала или {data} черновика."""
    from ..services.alerts import send
    ch = _channel_from(nm(request), body, cid or None)
    try:
        await asyncio.to_thread(send, ch, "Тестовое уведомление", "Канал настроен правильно 👍", "info")
    except Exception as e:
        raise HTTPException(400, f"Не удалось отправить: {e}")
    return {"ok": True}


class SilenceBody(BaseModel):
    minutes: int = 60
    starts_at: Optional[float] = None      # None — сейчас; иначе плановые работы
    rule_ids: List[int] = []               # пусто — все правила
    reason: str = ""


@router.get("/alerts/silences")
async def silences_list(request: Request, user=Depends(viewer)):
    """Периоды тишины оповещений: действующие, запланированные и завершённые."""
    now = time.time()
    rows = nm(request).db.query("SELECT * FROM silences WHERE ends_at>? ORDER BY starts_at", (now - 7 * 86400,))
    for r in rows:
        r["rule_ids"] = json.loads(r["rule_ids"] or "[]")
        r["state"] = "active" if r["starts_at"] <= now < r["ends_at"] else "planned" if r["starts_at"] > now else "ended"
    return rows


@router.post("/alerts/silences")
async def silences_add(body: SilenceBody, request: Request, user=Depends(operator)):
    """Тишина на время работ: {minutes, starts_at?, rule_ids?, reason}."""
    if not 5 <= body.minutes <= 30 * 24 * 60:
        raise HTTPException(400, "Длительность тишины: от 5 минут до 30 суток")
    now = time.time()
    start = body.starts_at or now
    if start < now - 60 or start > now + 90 * 86400:
        raise HTTPException(400, "Начало — сейчас или в ближайшие 90 дней")
    app = nm(request)
    known = {r["id"] for r in app.db.query("SELECT id FROM alert_rules")}
    bad = [i for i in body.rule_ids if i not in known]
    if bad:
        raise HTTPException(400, f"Неизвестные правила: {bad}")
    sid = app.db.execute("INSERT INTO silences(created_at, starts_at, ends_at, rule_ids, reason, username) "
                         "VALUES(?,?,?,?,?,?)", (now, start, start + body.minutes * 60, json.dumps(body.rule_ids),
                                                 body.reason.strip()[:300], user["username"]))
    when = time.strftime("%d.%m %H:%M", time.localtime(start))
    till = time.strftime("%d.%m %H:%M", time.localtime(start + body.minutes * 60))
    scope = "все правила" if not body.rule_ids else f"правил: {len(body.rule_ids)}"
    app.db.event("info", "alerts", f"Тишина оповещений {when} — {till} ({scope}), {user['username']}"
                 + (f": {body.reason}" if body.reason else ""))
    audit(request, user, "alerts_silenced", f"{when} — {till}", body.model_dump())
    await app.broadcast({"type": "state"})
    return {"id": sid}


@router.delete("/alerts/silences/{sid}")
async def silences_end(sid: int, request: Request, user=Depends(operator)):
    """Завершить или отменить период тишины."""
    app = nm(request)
    row = app.db.one("SELECT * FROM silences WHERE id=?", (sid,))
    if not row:
        raise HTTPException(404, "Не найдено")
    now = time.time()
    if row["starts_at"] > now:
        app.db.execute("DELETE FROM silences WHERE id=?", (sid,))
    else:
        app.db.execute("UPDATE silences SET ends_at=? WHERE id=?", (min(row["ends_at"], now), sid))
    app.db.event("info", "alerts", f"Тишина оповещений завершена ({user['username']}); не отправлено уведомлений: "
                                   f"{row['suppressed']}")
    audit(request, user, "alerts_unsilenced", str(sid))
    return {"ok": True}


@router.get("/alerts/events")
async def alert_events(request: Request, limit: int = 200, user=Depends(viewer)):
    """История срабатываний и восстановлений правил."""
    return nm(request).db.query("SELECT * FROM alert_events ORDER BY id DESC LIMIT ?", (limit,))


# =============================================================================
#  Пользователи
# =============================================================================
@router.get("/users")
async def users(request: Request, user=Depends(admin)):
    """Пользователи панели (только администратор)."""
    rows = nm(request).auth.users()
    for r in rows:
        r["role_label"] = ROLE_LABELS.get(r["role"], r["role"])
    return rows


@router.post("/users")
async def create_user(request: Request, username: str = Body(...), password: str = Body(...),
                      role: str = Body("viewer"), user=Depends(admin)):
    """Создать пользователя: {username, password, role}. При первом входе он должен сменить пароль."""
    uid = nm(request).auth.create_user(username, password, role, must_change=True)
    audit(request, user, "user_created", username, {"role": role})
    return {"id": uid}


@router.put("/users/{uid}")
async def update_user(uid: int, request: Request, role: Optional[str] = Body(None), disabled: Optional[bool] = Body(None),
                      password: Optional[str] = Body(None), user=Depends(admin)):
    """Изменить пользователя: {role?, disabled?, password?}. Последнего администратора лишить прав нельзя."""
    app = nm(request)
    u = app.db.one("SELECT * FROM users WHERE id=?", (uid,))
    if not u:
        raise HTTPException(404, "Пользователь не найден")
    admins = app.db.scalar("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0")
    if u["role"] == "admin" and admins <= 1 and ((role and role != "admin") or disabled):
        raise HTTPException(400, "Нельзя лишить прав последнего администратора")
    if role:
        if role not in ROLE_LABELS:
            raise HTTPException(400, "Неизвестная роль")
        app.db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    if disabled is not None:
        app.db.execute("UPDATE users SET disabled=? WHERE id=?", (int(disabled), uid))
        if disabled:
            app.db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    if password:
        app.auth.set_password(uid, password)
        app.db.execute("UPDATE users SET must_change_password=1 WHERE id=?", (uid,))
    audit(request, user, "user_updated", u["username"], {"role": role, "disabled": disabled,
                                                         "password_reset": bool(password)})
    return {"ok": True}


@router.post("/users/{uid}/reset-2fa")
async def reset_2fa(uid: int, request: Request, user=Depends(admin)):
    """Сбросить 2FA пользователя (потерян телефон)."""
    nm(request).db.execute("UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?", (uid,))
    audit(request, user, "user_2fa_reset", str(uid))
    return {"ok": True}


@router.delete("/users/{uid}")
async def delete_user(uid: int, request: Request, user=Depends(admin)):
    """Удалить пользователя."""
    app = nm(request)
    if uid == user["id"]:
        raise HTTPException(400, "Нельзя удалить самого себя")
    u = app.db.one("SELECT * FROM users WHERE id=?", (uid,))
    if u and u["role"] == "admin" and app.db.scalar("SELECT COUNT(*) FROM users WHERE role='admin'") <= 1:
        raise HTTPException(400, "Нельзя удалить последнего администратора")
    app.db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    app.db.execute("DELETE FROM api_tokens WHERE user_id=?", (uid,))
    app.db.execute("DELETE FROM users WHERE id=?", (uid,))
    audit(request, user, "user_deleted", u["username"] if u else str(uid))
    return {"ok": True}


# =============================================================================
#  Резервные копии, импорт
# =============================================================================
@router.get("/backup/export")
async def backup_export(request: Request, users: bool = False, certs: bool = True, user=Depends(admin)):
    """Экспорт настроек в JSON: сайты, потоки, настройки, оповещения, сертификаты; ?users=1 — с пользователями."""
    from ..services.backup import export_config
    data = await asyncio.to_thread(export_config, nm(request), users, certs)
    audit(request, user, "config_exported")
    fn = f"nginx-manager-export-{time.strftime('%Y%m%d-%H%M%S')}.json"
    return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="{fn}"'})


@router.post("/backup/import")
async def backup_import(request: Request, data: Dict[str, Any] = Body(...), mode: str = Query("replace"),
                        user=Depends(admin)):
    """Импорт настроек из JSON. ?mode = replace (с прежними номерами) | merge (новые номера, ссылки переносятся)."""
    from ..services.backup import db_backup, import_config
    app = nm(request)
    await asyncio.to_thread(db_backup, app, "before-import")
    stats = await asyncio.to_thread(import_config, app, data, mode)
    audit(request, user, "config_imported", mode, stats)
    return {"ok": True, "stats": stats}


@router.get("/backup/list")
async def backup_list(user=Depends(admin)):
    """Резервные копии базы и кода на сервере."""
    from ..services.backup import list_backups
    return list_backups()


@router.post("/backup/create")
async def backup_create(request: Request, user=Depends(admin)):
    """Создать резервную копию базы сейчас (и выгрузить в S3, если выгрузка включена)."""
    from ..services.backup import db_backup, offsite_upload
    app = nm(request)
    p = await asyncio.to_thread(db_backup, app, "manual")
    audit(request, user, "backup_created", p.name)
    offsite = await asyncio.to_thread(offsite_upload, app, p) if app.panel().s3_enabled else None
    return {"name": p.name, "offsite": offsite}


def _need_s3(app):
    if not app.panel().s3_enabled:
        raise HTTPException(400, "Выгрузка в S3 выключена — включите и сохраните настройки (вкладка «Резервные копии»)")


@router.post("/backup/s3/check")
async def backup_s3_check(request: Request, user=Depends(admin)):
    """Проверить доступ к S3-хранилищу: записать, найти в списке и удалить маленький объект."""
    from ..services.backup import offsite_check
    from ..services.s3 import S3Error
    app = nm(request)
    _need_s3(app)
    try:
        return await asyncio.to_thread(offsite_check, app)
    except S3Error as e:
        hint = {403: "доступ запрещён: проверьте ключи и права на бакет (PutObject, ListBucket, DeleteObject)",
                404: "бакет не найден: проверьте имя, регион и способ адресации (path-style)",
                301: "бакет в другом регионе — укажите его регион"}.get(e.status, "")
        raise HTTPException(400, f"Хранилище ответило: {e}" + (f" — {hint}" if hint else ""))
    except OSError as e:
        raise HTTPException(400, f"Нет связи с хранилищем: {e}")


@router.get("/backup/s3/list")
async def backup_s3_list(request: Request, user=Depends(admin)):
    """Копии в S3-хранилище и результат последней выгрузки."""
    from ..services.backup import offsite_list
    app = nm(request)
    _need_s3(app)
    try:
        items = await asyncio.to_thread(offsite_list, app)
    except Exception as e:
        raise HTTPException(400, f"Не удалось получить список: {e}")
    return {"items": items, "last": app.db.kv_get("offsite_last")}


@router.post("/backup/s3/download")
async def backup_s3_download(request: Request, name: str = Body(..., embed=True), user=Depends(admin)):
    """Скачать копию из S3 в каталог копий сервера (расшифровать и распаковать базу): {name}."""
    from ..services.backup import offsite_download
    app = nm(request)
    _need_s3(app)
    try:
        local = await asyncio.to_thread(offsite_download, app, name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(400, f"Не удалось скачать: {e}")
    audit(request, user, "backup_downloaded_s3", name)
    return {"name": local}


def _backup_file(name: str) -> Path:
    p = settings.backups_dir / Path(name).name
    if not p.name.startswith("nginx-manager-") or not p.is_file():
        raise HTTPException(404, "Копия не найдена")
    return p


@router.get("/backup/inspect/{name}")
async def backup_inspect(name: str, user=Depends(admin)):
    """Проверить копию базы перед восстановлением: целостность, версия схемы, сайты, пользователи."""
    from ..services.backup import inspect_db
    p = _backup_file(name)
    try:
        return await asyncio.to_thread(inspect_db, p)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/backup/restore")
async def backup_restore_status(user=Depends(admin)):
    """Запланированное восстановление (если есть), итог последнего и может ли панель перезапуститься сама."""
    from .. import process
    from ..services.backup import RESTORE_LAST, _read_json, restore_pending
    return {"pending": restore_pending(), "last": _read_json(settings.data_dir / RESTORE_LAST),
            "can_restart": process.can_restart()}


@router.post("/backup/restore")
async def backup_restore(request: Request, name: str = Body(..., embed=True), user=Depends(admin)):
    """Восстановить базу из копии на сервере: {name}. Текущая база сохраняется (before-restore), панель
    перезапускается и при старте заменяет файл базы. Пользователи, настройки и статистика — как в копии."""
    from .. import process
    from ..services.backup import restore_pending, schedule_restore
    app = nm(request)
    p = _backup_file(name)
    if restore_pending() is not None:
        raise HTTPException(409, "Восстановление уже запланировано — дождитесь перезапуска панели или отмените его")
    if app.nginx.lock.locked():
        raise HTTPException(409, "Сейчас применяется конфигурация — повторите через несколько секунд")
    try:
        res = await asyncio.to_thread(schedule_restore, app, p, user["username"], app.auth.client_ip(request))
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(request, user, "backup_restore_scheduled", p.name, {"safety": res["safety"]})
    restart = process.can_restart()
    if restart:  # ответ должен успеть уйти до остановки сервера
        asyncio.get_running_loop().call_later(0.8, process.request_restart)
    return {"ok": True, "safety": res["safety"], "restart": restart, "info": res["info"]}


@router.delete("/backup/restore")
async def backup_restore_cancel(request: Request, user=Depends(admin)):
    """Отменить запланированное восстановление (пока панель не перезапущена)."""
    from ..services.backup import cancel_restore
    found = cancel_restore()
    if found:
        audit(request, user, "backup_restore_cancelled")
    return {"ok": True, "cancelled": found}


@router.post("/backup/upload")
async def backup_upload(request: Request, filename: str = Query(...), user=Depends(admin)):
    """Загрузить копию на сервер (тело запроса — файл): база .db или .db.gz, экспорт .json. Файл проверяется;
    база потом восстанавливается кнопкой «Восстановить»."""
    import gzip
    import shutil
    from ..services.backup import inspect_db
    base = Path(filename).name
    low = base.lower()
    if not (low.endswith(".db") or low.endswith(".db.gz") or low.endswith(".json")):
        raise HTTPException(400, "Можно загрузить базу (.db, .db.gz) или экспорт настроек (.json). Зашифрованную "
                                 "копию (.enc) сначала расшифруйте — команда есть в документации")
    ext = ".json" if low.endswith(".json") else ".db.gz" if low.endswith(".gz") else ".db"
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    if stem.startswith("nginx-manager-"):  # копия этой или другой панели — имя сохраняется
        dest = settings.backups_dir / stem
        if dest.exists() or (dest.suffix == ".gz" and dest.with_suffix("").exists()):
            raise HTTPException(409, f"Копия {dest.name} уже есть на сервере")
    else:  # произвольное имя: отметка времени + исходное имя (для поиска в списке)
        orig = re.sub(r"[^a-z0-9]+", "-", base.lower()[:-len(ext)]).strip("-")[:40]
        prefix = f"nginx-manager-{time.strftime('%Y%m%d-%H%M%S')}-uploaded" + (f"-{orig}" if orig else "")
        n = 1
        dest = settings.backups_dir / (prefix + ext)
        while dest.exists() or dest.with_name(dest.name[:-3]).exists() and ext == ".db.gz":
            n += 1
            dest = settings.backups_dir / f"{prefix}-{n}{ext}"
    tmp = dest.with_name(dest.name + ".part")
    size = 0
    limit = 4 << 30
    try:
        with open(tmp, "wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, "Файл больше 4 ГБ")
                f.write(chunk)
        tmp.chmod(0o600)
        if not size:
            raise HTTPException(400, "Пустой файл")
        if dest.name.endswith(".gz"):
            out = dest.with_suffix("")

            def _gunzip():
                with gzip.open(tmp, "rb") as fi, open(out, "wb") as fo:
                    shutil.copyfileobj(fi, fo, 1 << 20)
            try:
                await asyncio.to_thread(_gunzip)
            except (OSError, EOFError) as e:
                out.unlink(missing_ok=True)
                raise HTTPException(400, f"Не удалось распаковать .gz: {e}")
            out.chmod(0o600)
            tmp.unlink(missing_ok=True)
            dest = out
        else:
            tmp.rename(dest)
        if dest.suffix == ".db":
            try:
                info = await asyncio.to_thread(inspect_db, dest)
            except ValueError as e:
                dest.unlink(missing_ok=True)
                raise HTTPException(400, str(e))
        else:
            try:
                data = json.loads(dest.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or data.get("format") != "nginx-manager-export":
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                dest.unlink(missing_ok=True)
                raise HTTPException(400, "Это не файл экспорта Nginx Manager")
            info = None
    finally:
        tmp.unlink(missing_ok=True)
    audit(request, user, "backup_uploaded", dest.name, {"size": size})
    return {"name": dest.name, "size": dest.stat().st_size, "info": info}


@router.get("/backup/download/{name}")
async def backup_download(name: str, user=Depends(admin)):
    """Скачать резервную копию."""
    p = settings.backups_dir / Path(name).name
    if not p.exists() or not p.name.startswith("nginx-manager-"):
        raise HTTPException(404, "Файл не найден")
    return FileResponse(p, filename=p.name)


@router.delete("/backup/{name}")
async def backup_delete(name: str, request: Request, user=Depends(admin)):
    """Удалить резервную копию."""
    p = settings.backups_dir / Path(name).name
    if p.exists() and p.name.startswith("nginx-manager-"):
        p.unlink()
    audit(request, user, "backup_deleted", name)
    return {"ok": True}


@router.get("/metrics/grafana-dashboard")
async def grafana_dashboard(user=Depends(viewer)):
    """Дашборд Grafana для метрик Prometheus панели (JSON для импорта в Grafana 9+)."""
    from ..config import ROOT_DIR
    p = ROOT_DIR / "packaging" / "grafana" / "nginx-manager.json"
    if not p.is_file():
        raise HTTPException(404, "Файл дашборда не найден (packaging/grafana/nginx-manager.json)")
    return FileResponse(p, media_type="application/json", filename="nginx-manager-grafana.json")


@router.post("/import/nginx/preview")
async def import_preview(request: Request, path: str = Body("", embed=True), user=Depends(admin)):
    """Разобрать существующую конфигурацию nginx (nginx -T) и показать, какие сайты будут созданы. {path}."""
    from ..nginx.importer import import_config
    from ..utils import run
    app = nm(request)
    conf = path or str(settings.nginx_conf.with_name(settings.nginx_conf.name + ".nm-orig"))
    if not Path(conf).exists():
        raise HTTPException(404, f"Файл {conf} не найден")
    code, out = await asyncio.to_thread(run, [app.nginx.binary, "-T", "-c", conf], 60)
    if "# configuration file" not in out:
        raise HTTPException(400, "nginx -T не смог прочитать конфигурацию:\n" + out[-2000:])
    res = import_config(out, conf)
    for s in res["sites"]:
        try:
            data = dict(s)
            data.pop("ssl", None)
            Site.model_validate(data)
            s["_valid"] = True
        except Exception as e:
            s["_valid"] = False
            s["_error"] = str(e)[:300]
    return res


@router.post("/import/nginx/commit")
async def import_commit(request: Request, sites: List[Dict[str, Any]] = Body(...),
                        certificates: List[Dict[str, Any]] = Body([]), user=Depends(admin)):
    """Создать сайты (выключенными) и сертификаты из результата разбора: {sites, certificates}."""
    app = nm(request)
    cert_ids: Dict[str, int] = {}
    for c in certificates:
        if Path(c["cert"]).exists() and Path(c["key"]).exists():
            existing = app.db.one("SELECT id FROM certificates WHERE cert_path=?", (c["cert"],))
            if existing:
                cert_ids[c["cert"]] = existing["id"]
                continue
            cid = await asyncio.to_thread(app.certs.create, CertificateRequest(
                type="path", name=c.get("name", c["cert"]), cert_path=c["cert"], key_path=c["key"]), user["username"])
            cert_ids[c["cert"]] = cid
    created, errors = [], []
    now = time.time()
    for s in sites:
        data = {k: v for k, v in s.items() if not k.startswith("_")}
        ssl = data.pop("ssl", None)
        if ssl and ssl.get("certificate_ref"):
            cid = cert_ids.get(ssl["certificate_ref"][0])
            if cid:
                data["ssl"] = {"enabled": True, "certificate_id": cid, "force_https": ssl.get("force_https", True)}
        try:
            site = Site.model_validate(data)
            sid = app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                                 (site.name, 0, json.dumps(site.model_dump(), ensure_ascii=False), now, now))
            created.append(sid)
        except Exception as e:
            errors.append(f"{data.get('name')}: {e}")
    audit(request, user, "nginx_imported", "", {"created": len(created)})
    return {"created": created, "errors": errors}


# =============================================================================
#  Встроенная документация
# =============================================================================
@router.get("/docs")
async def docs_list(user=Depends(viewer)):
    """Список глав документации."""
    out = []
    for p in sorted(DOCS_DIR.glob("*.md")):
        title = p.stem
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break
        out.append({"name": p.name, "title": title})
    return out


@router.get("/docs/{name}", response_class=PlainTextResponse)
async def docs_get(name: str, user=Depends(viewer)):
    """Текст главы документации (Markdown)."""
    p = DOCS_DIR / Path(name).name
    if not p.exists() or p.suffix != ".md":
        raise HTTPException(404, "Документ не найден")
    return p.read_text(encoding="utf-8")


@router.get("/version")
async def version_info():
    """Версия панели (доступно без входа)."""
    return {"version": VERSION, "name": "Nginx Manager"}


# =============================================================================
#  WebSocket
# =============================================================================
def _live_filter(f: Any) -> Dict[str, Any]:
    """Фильтр живого журнала от браузера: только известные поля и типы (иначе сравнение упадёт в общем цикле)."""
    if not isinstance(f, dict):
        return {}
    out: Dict[str, Any] = {k: str(f[k])[:300] for k in ("site", "status", "ip", "q")
                           if isinstance(f.get(k), (str, int)) and str(f[k]) != ""}
    try:
        out["min_rt"] = max(0.0, float(f.get("min_rt") or 0))
    except (TypeError, ValueError):
        pass
    out["hide_bots"] = bool(f.get("hide_bots"))
    return out


@router.websocket("/ws")
async def ws(websocket: WebSocket):
    from ..core import WSClient
    app = websocket.app.state.nm
    tok = websocket.cookies.get(COOKIE)
    user = app.auth.user_by_session(tok) if tok else None
    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    if not user or (origin and host and origin.split("://", 1)[-1] != host) \
            or not app.auth.ip_allowed(app.auth.client_ip(websocket)):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    client = WSClient(websocket, user)
    app.clients.add(client)
    try:
        while True:
            try:
                msg = json.loads(await websocket.receive_text())
            except ValueError:
                continue  # не JSON — пропускаем сообщение, соединение остаётся
            if not isinstance(msg, dict):
                continue
            t = msg.get("type")
            if t == "live":
                client.live = bool(msg.get("on"))
                client.live_filter = _live_filter(msg.get("filter"))
                if client.live:
                    client.live_seq = max(0, app.stats.agg.live_seq - 100)
            elif t == "errors":
                client.errors = bool(msg.get("on"))
                if client.errors:
                    client.err_seq = max(0, app.stats.agg.err_seq - 50)
            elif t == "ping":
                await websocket.send_text('{"type":"pong"}')
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        app.clients.discard(client)
