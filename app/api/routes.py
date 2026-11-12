"""REST API и WebSocket веб-панели. Документация OpenAPI: /api/docs-ui."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from ..auth import COOKIE, ROLE_LABELS, admin, operator, viewer
from ..config import DOCS_DIR, VERSION, settings
from ..models import (CLOUDFLARE_IPS, AlertChannel, AlertRule, CertificateRequest, GlobalSettings, PanelSettings,
                      Site, Stream)
from ..nginx.generator import State, slug
from ..schema import full_schema
from ..utils import apr1, totp_secret, totp_verify, verify_password

router = APIRouter(prefix="/api")
MASK = "••••••••"


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
        await asyncio.sleep(0.5)
        raise HTTPException(401, str(e))
    if app.panel().require_2fa_admin and u["role"] == "admin" and not u["totp_enabled"]:
        pass  # пользователь будет перенаправлен на настройку 2FA
    token = app.auth.create_session(u["id"], ip, request.headers.get("user-agent", ""))
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure,
                        max_age=app.panel().session_hours * 3600 if body.remember else None, path="/")
    app.db.audit(u["username"], ip, "login", "", None)
    return {"ok": True, "must_change_password": bool(u["must_change_password"]),
            "require_2fa": app.panel().require_2fa_admin and u["role"] == "admin" and not u["totp_enabled"]}


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    tok = request.cookies.get(COOKIE)
    if tok:
        nm(request).auth.destroy_session(tok)
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/me")
async def me(user=Depends(viewer)):
    return {k: user[k] for k in ("id", "username", "role", "totp_enabled", "must_change_password")} | \
        {"role_label": ROLE_LABELS[user["role"]]}


class PasswordBody(BaseModel):
    current: str
    new: str


@router.post("/auth/password")
async def change_password(body: PasswordBody, request: Request, user=Depends(viewer)):
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
    sec = totp_secret()
    uri = f"otpauth://totp/NginxManager:{user['username']}?secret={sec}&issuer=NginxManager"
    return {"secret": sec, "uri": uri}


@router.post("/auth/totp/enable")
async def totp_enable(request: Request, secret: str = Body(...), code: str = Body(...), user=Depends(viewer)):
    if not totp_verify(secret, code):
        raise HTTPException(400, "Неверный код. Проверьте время на телефоне и сервере")
    nm(request).db.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", (secret, user["id"]))
    audit(request, user, "2fa_enabled")
    return {"ok": True}


@router.post("/auth/totp/disable")
async def totp_disable(request: Request, password: str = Body(..., embed=True), user=Depends(viewer)):
    if not verify_password(password, user["password_hash"]):
        raise HTTPException(400, "Неверный пароль")
    nm(request).db.execute("UPDATE users SET totp_secret='', totp_enabled=0 WHERE id=?", (user["id"],))
    audit(request, user, "2fa_disabled")
    return {"ok": True}


@router.get("/auth/sessions")
async def sessions(request: Request, user=Depends(viewer)):
    rows = nm(request).db.query("SELECT id, created_at, last_seen, expires_at, ip, user_agent FROM sessions "
                                "WHERE user_id=? ORDER BY last_seen DESC", (user["id"],))
    cur = user.get("sid")
    for r in rows:
        r["current"] = r["id"] == cur
        r["id"] = r["id"][:16]
    return rows


@router.delete("/auth/sessions/{sid}")
async def kill_session(sid: str, request: Request, user=Depends(viewer)):
    nm(request).db.execute("DELETE FROM sessions WHERE user_id=? AND id LIKE ?", (user["id"], sid + "%"))
    return {"ok": True}


@router.get("/auth/tokens")
async def tokens(request: Request, user=Depends(viewer)):
    return nm(request).db.query("SELECT id, name, prefix, created_at, expires_at, last_used FROM api_tokens "
                                "WHERE user_id=? ORDER BY id", (user["id"],))


@router.post("/auth/tokens")
async def create_token(request: Request, name: str = Body(...), days: int = Body(0), user=Depends(viewer)):
    tok = nm(request).auth.create_token(user["id"], name, days)
    audit(request, user, "token_created", name)
    return {"token": tok}


@router.delete("/auth/tokens/{tid}")
async def delete_token(tid: int, request: Request, user=Depends(viewer)):
    nm(request).db.execute("DELETE FROM api_tokens WHERE id=? AND user_id=?", (tid, user["id"]))
    audit(request, user, "token_deleted", str(tid))
    return {"ok": True}


# =============================================================================
#  Общее состояние
# =============================================================================
@router.get("/state")
async def state(request: Request, user=Depends(viewer)):
    return await asyncio.to_thread(nm(request).state_summary, user)


@router.get("/schema")
async def schema(user=Depends(viewer)):
    s = full_schema()
    s["cloudflare_ips"] = CLOUDFLARE_IPS
    return s


@router.get("/overview")
async def overview(request: Request, user=Depends(viewer)):
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
            "locations": len(d.get("locations", []))}


@router.get("/sites")
async def list_sites(request: Request, user=Depends(viewer)):
    app = nm(request)
    live = app.stats.agg.per_site_now(10)
    health: Dict[str, List] = {}
    for t in app.health.targets.values():
        health.setdefault(t.owner, []).append({"addr": f"{t.address}:{t.port}", "state": t.state,
                                               "latency_ms": round(t.last_latency * 1000, 1), "error": t.last_error})
    return [_site_row(app, r, live, health) for r in app.db.query("SELECT * FROM sites ORDER BY name COLLATE NOCASE")]


@router.get("/sites/{sid}")
async def get_site(sid: int, request: Request, user=Depends(viewer)):
    r = nm(request).db.one("SELECT * FROM sites WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Сайт не найден")
    data = json.loads(r["data"])
    for u in (data.get("security") or {}).get("basic_auth_users", []):
        u["password"] = ""
    return {"id": r["id"], "data": data, "created_at": r["created_at"], "updated_at": r["updated_at"]}


def _prepare_site(app, data: Dict[str, Any], sid: Optional[int] = None) -> Site:
    old_users = {}
    if sid:
        r = app.db.one("SELECT data FROM sites WHERE id=?", (sid,))
        if r:
            for u in json.loads(r["data"]).get("security", {}).get("basic_auth_users", []):
                old_users[u["username"]] = u.get("password_hash", "")
    site = Site.model_validate(data)
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
    app = nm(request)
    site = _prepare_site(app, body)
    now = time.time()
    sid = app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                         (site.name, int(site.enabled), json.dumps(site.model_dump(), ensure_ascii=False), now, now))
    audit(request, user, "site_created", site.name, {"id": sid})
    res = await _maybe_apply(app, user, apply, f"Создан сайт «{site.name}»")
    return {"id": sid, "applied": res}


@router.put("/sites/{sid}")
async def update_site(sid: int, request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                      user=Depends(operator)):
    app = nm(request)
    if not app.db.one("SELECT 1 FROM sites WHERE id=?", (sid,)):
        raise HTTPException(404, "Сайт не найден")
    site = _prepare_site(app, body, sid)
    app.db.execute("UPDATE sites SET name=?, enabled=?, data=?, updated_at=? WHERE id=?",
                   (site.name, int(site.enabled), json.dumps(site.model_dump(), ensure_ascii=False), time.time(), sid))
    audit(request, user, "site_updated", site.name, {"id": sid})
    res = await _maybe_apply(app, user, apply, f"Изменён сайт «{site.name}»")
    return {"id": sid, "applied": res}


@router.post("/sites/{sid}/toggle")
async def toggle_site(sid: int, request: Request, apply: bool = Query(False), user=Depends(operator)):
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


@router.post("/sites/{sid}/clone")
async def clone_site(sid: int, request: Request, user=Depends(operator)):
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
    app = nm(request)
    site = _prepare_site(app, body, sid or None)
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
    app = nm(request)
    s = Stream.model_validate(body)
    _check_stream_port(app, s, sid)
    app.db.execute("UPDATE streams SET name=?, enabled=?, data=?, updated_at=? WHERE id=?",
                   (s.name, int(s.enabled), json.dumps(s.model_dump(), ensure_ascii=False), time.time(), sid))
    audit(request, user, "stream_updated", s.name)
    return {"id": sid, "applied": await _maybe_apply(app, user, apply, f"Изменён поток «{s.name}»")}


@router.delete("/streams/{sid}")
async def delete_stream(sid: int, request: Request, apply: bool = Query(False), user=Depends(operator)):
    app = nm(request)
    r = app.db.one("SELECT name FROM streams WHERE id=?", (sid,))
    app.db.execute("DELETE FROM streams WHERE id=?", (sid,))
    audit(request, user, "stream_deleted", r["name"] if r else str(sid))
    return {"ok": True, "applied": await _maybe_apply(app, user, apply, "Удалён поток")}


@router.post("/streams/preview")
async def preview_stream(request: Request, body: Dict[str, Any] = Body(...), sid: int = Query(0),
                         user=Depends(viewer)):
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
    app = nm(request)
    try:
        diff = await asyncio.to_thread(app.nginx.pending_diff)
    except Exception as e:
        return {"error": str(e), "diff": []}
    return {"diff": diff, "pending": bool(diff)}


@router.post("/config/apply")
async def apply_config(request: Request, comment: str = Body("", embed=True), user=Depends(operator)):
    app = nm(request)
    res = await app.apply(user["username"], comment)
    audit(request, user, "config_applied", f"v{res['version']}", {"comment": comment})
    return res


@router.post("/config/test")
async def test_config(request: Request, user=Depends(viewer)):
    app = nm(request)
    st = app.nginx.load_state()
    return await asyncio.to_thread(_test_state, app, st)


@router.get("/config/versions")
async def versions(request: Request, limit: int = 100, user=Depends(viewer)):
    rows = nm(request).db.query("SELECT id, ts, username, comment, source, status, checksum, "
                                "length(files) size FROM config_versions ORDER BY id DESC LIMIT ?", (limit,))
    applied = nm(request).db.kv_get("applied_version")
    for r in rows:
        r["current"] = r["id"] == applied
    return rows


@router.get("/config/versions/{vid}")
async def version(vid: int, request: Request, user=Depends(viewer)):
    r = nm(request).db.one("SELECT * FROM config_versions WHERE id=?", (vid,))
    if not r:
        raise HTTPException(404, "Версия не найдена")
    r["files"] = json.loads(r["files"])
    st = json.loads(r["state"])
    r["state_summary"] = {"sites": [{"id": s["id"], "name": s["data"]["name"], "enabled": s["data"].get("enabled")}
                                    for s in st.get("sites", [])],
                          "streams": [{"id": s["id"], "name": s["data"]["name"]} for s in st.get("streams", [])]}
    del r["state"]
    return r


@router.get("/config/versions/{vid}/diff")
async def version_diff(vid: int, request: Request, against: str = "prev", user=Depends(viewer)):
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
    last = nm(request).nginx.last_applied()
    return json.loads(last["files"]) if last else {}


@router.get("/config/dump", response_class=PlainTextResponse)
async def config_dump(request: Request, user=Depends(admin)):
    return await asyncio.to_thread(nm(request).nginx.dump_config)


@router.get("/settings/global")
async def get_global(request: Request, user=Depends(viewer)):
    return nm(request).global_settings().model_dump()


@router.put("/settings/global")
async def put_global(request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                     user=Depends(admin)):
    app = nm(request)
    g = GlobalSettings.model_validate(body)
    app.db.kv_set("global_settings", g.model_dump())
    audit(request, user, "global_settings_updated")
    return {"ok": True, "applied": await _maybe_apply(app, user, apply, "Изменены глобальные настройки")}


@router.get("/settings/panel")
async def get_panel(request: Request, user=Depends(viewer)):
    return nm(request).panel().model_dump()


@router.put("/settings/panel")
async def put_panel(request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    app = nm(request)
    old = app.panel()
    p = PanelSettings.model_validate(body)
    ip = user.get("ip", "")
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
    app = nm(request)
    info = await asyncio.to_thread(app.nginx.info)
    info["status"] = app.nginx.status()
    return info


@router.post("/nginx/{action}")
async def nginx_action(action: str, request: Request, user=Depends(operator)):
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
    app = nm(request)
    return {"items": app.certs.list(), "certbot": bool(app.certs.certbot()),
            "email": app.panel().letsencrypt_email, "webroot": str(settings.acme_webroot)}


@router.post("/certs")
async def create_cert(request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
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
    app = nm(request)
    await app.certs.renew(cid, after=app.after_cert_issued)
    audit(request, user, "cert_renew", str(cid))
    return {"ok": True}


@router.delete("/certs/{cid}")
async def delete_cert(cid: int, request: Request, user=Depends(operator)):
    app = nm(request)
    await asyncio.to_thread(app.certs.delete, cid)
    audit(request, user, "cert_deleted", str(cid))
    return {"ok": True}


@router.post("/certs/selftest")
async def cert_selftest(request: Request, domain: str = Body(..., embed=True), user=Depends(viewer)):
    from ..validators import domain as vd
    return await asyncio.to_thread(nm(request).certs.http01_selftest, vd(domain))


# =============================================================================
#  Статистика
# =============================================================================
@router.get("/stats/realtime")
async def stats_realtime(request: Request, seconds: int = 300, site: str = "*", user=Depends(viewer)):
    return nm(request).stats.agg.realtime(min(600, max(10, seconds)), site)


@router.get("/stats/snapshot")
async def stats_snapshot(request: Request, user=Depends(viewer)):
    return nm(request).stats.snapshot()


@router.get("/stats/timeseries")
async def stats_ts(request: Request, frm: Optional[float] = Query(None, alias="from"), to: Optional[float] = None,
                   site: str = "*", points: int = 240, user=Depends(viewer)):
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.timeseries, s, e, site, min(1000, points))


@router.get("/stats/summary")
async def stats_summary(request: Request, frm: Optional[float] = Query(None, alias="from"), to: Optional[float] = None,
                        site: str = "*", user=Depends(viewer)):
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.summary, s, e, site)


@router.get("/stats/top")
async def stats_top(request: Request, kind: str, frm: Optional[float] = Query(None, alias="from"),
                    to: Optional[float] = None, site: str = "*", limit: int = 30, user=Depends(viewer)):
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.tops, s, e, site, kind, min(500, limit))


@router.get("/stats/sites")
async def stats_sites(request: Request, frm: Optional[float] = Query(None, alias="from"), to: Optional[float] = None,
                      user=Depends(viewer)):
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.compare_sites, s, e)


@router.get("/stats/system")
async def stats_system(request: Request, frm: Optional[float] = Query(None, alias="from"),
                       to: Optional[float] = None, user=Depends(viewer)):
    s, e = rng(frm, to, 600)
    return await asyncio.to_thread(nm(request).stats.system_series, s, e)


@router.get("/stats/streams")
async def stats_streams(request: Request, frm: Optional[float] = Query(None, alias="from"),
                        to: Optional[float] = None, user=Depends(viewer)):
    s, e = rng(frm, to)
    return await asyncio.to_thread(nm(request).stats.stream_series, s, e)


@router.get("/requests")
async def requests_search(request: Request, limit: int = 100, offset: int = 0, user=Depends(viewer)):
    f = dict(request.query_params)
    return await asyncio.to_thread(nm(request).stats.search_requests, f, min(1000, limit), offset)


@router.get("/requests/live")
async def requests_live(request: Request, limit: int = 200, user=Depends(viewer)):
    return nm(request).stats.agg.live_since(0, limit)


@router.get("/errors")
async def errors_search(request: Request, limit: int = 100, offset: int = 0, user=Depends(viewer)):
    f = dict(request.query_params)
    return await asyncio.to_thread(nm(request).stats.search_errors, f, min(1000, limit), offset)


@router.get("/errors/raw", response_class=PlainTextResponse)
async def errors_raw(request: Request, lines: int = 200, user=Depends(viewer)):
    return "\n".join(nm(request).nginx.recent_error_log(min(5000, lines)))


# =============================================================================
#  Бэкенды, диагностика, события
# =============================================================================
@router.get("/health")
async def health(request: Request, user=Depends(viewer)):
    app = nm(request)
    return {"targets": app.health.list(), "passive": dict(app.stats.agg.passive_upstream.most_common(50))}


@router.post("/health/check")
async def health_check(request: Request, key: Optional[str] = Body(None, embed=True), user=Depends(viewer)):
    return await nm(request).health.check_now(key)


@router.get("/health/history")
async def health_history(request: Request, key: str, frm: Optional[float] = Query(None, alias="from"),
                         to: Optional[float] = None, user=Depends(viewer)):
    s, e = rng(frm, to, 86400)
    return await asyncio.to_thread(nm(request).health.history, key, s, e)


@router.get("/diagnostics")
async def diagnostics(request: Request, user=Depends(viewer)):
    return nm(request).diag.last


@router.post("/diagnostics/run")
async def diagnostics_run(request: Request, user=Depends(viewer)):
    return await nm(request).diag.run_all()


@router.post("/diagnostics/fix")
async def diagnostics_fix(request: Request, action: str = Body(...), args: Dict[str, Any] = Body({}),
                          user=Depends(operator)):
    app = nm(request)
    res = await app.diag.fix(action, args, user["username"])
    audit(request, user, "diag_fix", action, {"args": args, "ok": res.get("ok")})
    return res


@router.get("/diagnostics/collector")
async def collector(request: Request, user=Depends(viewer)):
    return nm(request).stats.collector_info()


# =============================================================================
#  Встроенный анализ и подсказки
# =============================================================================
@router.get("/insights")
async def insights(request: Request, frm: Optional[float] = Query(None, alias="from"),
                   to: Optional[float] = None, site: str = "*", user=Depends(viewer)):
    start, end = rng(frm, to, 900)
    return await asyncio.to_thread(nm(request).insights.evaluate, start, end, site or "*")


@router.get("/insights/catalog")
async def insights_catalog(request: Request, user=Depends(viewer)):
    return nm(request).insights.catalog()


@router.post("/insights/mute")
async def insights_mute(request: Request, id: str = Body(..., embed=True), mute: bool = Body(True, embed=True),
                        user=Depends(operator)):
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
#  Блокировки IP
# =============================================================================
class BanBody(BaseModel):
    nets: List[str]
    minutes: Optional[int] = 60      # None — бессрочно
    reason: str = ""
    force: bool = False              # разрешить блокировку доверенных адресов (кроме своего)


@router.get("/bans")
async def bans_list(request: Request, user=Depends(viewer)):
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
    app = nm(request)
    row = app.bans.remove(ban_id)
    if not row:
        raise HTTPException(404, "Блокировка не найдена")
    audit(request, user, "ip_unbanned", row["net"])
    app.db.event("info", "bans", f"Разблокирован {row['net']} ({user['username']})")
    ok, out = await app.bans.sync(force=True)
    return {"ok": ok, "output": out if not ok else ""}


@router.post("/bans/clear")
async def bans_clear(request: Request, source: str = Body("auto", embed=True), user=Depends(admin)):
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


@router.get("/events")
async def events(request: Request, limit: int = 200, level: str = "", source: str = "", user=Depends(viewer)):
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
    app = nm(request)
    st = app.alerts.status()
    return [{"id": r["id"], "data": json.loads(r["data"]), "status": st.get(r["id"], {})}
            for r in app.db.query("SELECT * FROM alert_rules ORDER BY id")]


@router.post("/alerts/rules")
async def create_rule(request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    r = AlertRule.model_validate(body)
    now = time.time()
    rid = nm(request).db.execute("INSERT INTO alert_rules(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                                 (r.name, int(r.enabled), json.dumps(r.model_dump(), ensure_ascii=False), now, now))
    audit(request, user, "alert_rule_created", r.name)
    return {"id": rid}


@router.put("/alerts/rules/{rid}")
async def update_rule(rid: int, request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    r = AlertRule.model_validate(body)
    nm(request).db.execute("UPDATE alert_rules SET name=?, enabled=?, data=?, updated_at=? WHERE id=?",
                           (r.name, int(r.enabled), json.dumps(r.model_dump(), ensure_ascii=False), time.time(), rid))
    audit(request, user, "alert_rule_updated", r.name)
    return {"id": rid}


@router.delete("/alerts/rules/{rid}")
async def delete_rule(rid: int, request: Request, user=Depends(operator)):
    nm(request).db.execute("DELETE FROM alert_rules WHERE id=?", (rid,))
    audit(request, user, "alert_rule_deleted", str(rid))
    return {"ok": True}


@router.get("/alerts/channels")
async def alert_channels(request: Request, user=Depends(viewer)):
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
    ch = _channel_from(nm(request), body, None)
    now = time.time()
    cid = nm(request).db.execute("INSERT INTO alert_channels(name,type,enabled,data,created_at,updated_at) "
                                 "VALUES(?,?,?,?,?,?)", (ch.name, ch.type, int(ch.enabled),
                                                         json.dumps(ch.model_dump(), ensure_ascii=False), now, now))
    audit(request, user, "alert_channel_created", ch.name)
    return {"id": cid}


@router.put("/alerts/channels/{cid}")
async def update_channel(cid: int, request: Request, body: Dict[str, Any] = Body(...), user=Depends(admin)):
    ch = _channel_from(nm(request), body, cid)
    nm(request).db.execute("UPDATE alert_channels SET name=?, type=?, enabled=?, data=?, updated_at=? WHERE id=?",
                           (ch.name, ch.type, int(ch.enabled), json.dumps(ch.model_dump(), ensure_ascii=False),
                            time.time(), cid))
    audit(request, user, "alert_channel_updated", ch.name)
    return {"id": cid}


@router.delete("/alerts/channels/{cid}")
async def delete_channel(cid: int, request: Request, user=Depends(admin)):
    nm(request).db.execute("DELETE FROM alert_channels WHERE id=?", (cid,))
    audit(request, user, "alert_channel_deleted", str(cid))
    return {"ok": True}


@router.post("/alerts/channels/test")
async def test_channel(request: Request, body: Dict[str, Any] = Body(...), cid: int = Query(0),
                       user=Depends(operator)):
    from ..services.alerts import send
    ch = _channel_from(nm(request), body, cid or None)
    try:
        await asyncio.to_thread(send, ch, "Тестовое уведомление", "Канал настроен правильно 👍", "info")
    except Exception as e:
        raise HTTPException(400, f"Не удалось отправить: {e}")
    return {"ok": True}


@router.get("/alerts/events")
async def alert_events(request: Request, limit: int = 200, user=Depends(viewer)):
    return nm(request).db.query("SELECT * FROM alert_events ORDER BY id DESC LIMIT ?", (limit,))


# =============================================================================
#  Пользователи
# =============================================================================
@router.get("/users")
async def users(request: Request, user=Depends(admin)):
    rows = nm(request).auth.users()
    for r in rows:
        r["role_label"] = ROLE_LABELS.get(r["role"], r["role"])
    return rows


@router.post("/users")
async def create_user(request: Request, username: str = Body(...), password: str = Body(...),
                      role: str = Body("viewer"), user=Depends(admin)):
    uid = nm(request).auth.create_user(username, password, role, must_change=True)
    audit(request, user, "user_created", username, {"role": role})
    return {"id": uid}


@router.put("/users/{uid}")
async def update_user(uid: int, request: Request, role: Optional[str] = Body(None), disabled: Optional[bool] = Body(None),
                      password: Optional[str] = Body(None), user=Depends(admin)):
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
    nm(request).db.execute("UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?", (uid,))
    audit(request, user, "user_2fa_reset", str(uid))
    return {"ok": True}


@router.delete("/users/{uid}")
async def delete_user(uid: int, request: Request, user=Depends(admin)):
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
    from ..services.backup import export_config
    data = await asyncio.to_thread(export_config, nm(request), users, certs)
    audit(request, user, "config_exported")
    fn = f"nginx-manager-export-{time.strftime('%Y%m%d-%H%M%S')}.json"
    return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="{fn}"'})


@router.post("/backup/import")
async def backup_import(request: Request, data: Dict[str, Any] = Body(...), mode: str = Query("replace"),
                        user=Depends(admin)):
    from ..services.backup import db_backup, import_config
    app = nm(request)
    await asyncio.to_thread(db_backup, app, "before-import")
    stats = await asyncio.to_thread(import_config, app, data, mode)
    audit(request, user, "config_imported", mode, stats)
    return {"ok": True, "stats": stats}


@router.get("/backup/list")
async def backup_list(user=Depends(admin)):
    from ..services.backup import list_backups
    return list_backups()


@router.post("/backup/create")
async def backup_create(request: Request, user=Depends(admin)):
    from ..services.backup import db_backup
    p = await asyncio.to_thread(db_backup, nm(request), "manual")
    audit(request, user, "backup_created", p.name)
    return {"name": p.name}


@router.get("/backup/download/{name}")
async def backup_download(name: str, user=Depends(admin)):
    p = settings.backups_dir / Path(name).name
    if not p.exists() or not p.name.startswith("nginx-manager-"):
        raise HTTPException(404, "Файл не найден")
    return FileResponse(p, filename=p.name)


@router.delete("/backup/{name}")
async def backup_delete(name: str, request: Request, user=Depends(admin)):
    p = settings.backups_dir / Path(name).name
    if p.exists() and p.name.startswith("nginx-manager-"):
        p.unlink()
    audit(request, user, "backup_deleted", name)
    return {"ok": True}


@router.post("/import/nginx/preview")
async def import_preview(request: Request, path: str = Body("", embed=True), user=Depends(admin)):
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
    p = DOCS_DIR / Path(name).name
    if not p.exists() or p.suffix != ".md":
        raise HTTPException(404, "Документ не найден")
    return p.read_text(encoding="utf-8")


@router.get("/version")
async def version_info():
    return {"version": VERSION, "name": "Nginx Manager"}


# =============================================================================
#  WebSocket
# =============================================================================
@router.websocket("/ws")
async def ws(websocket: WebSocket):
    from ..core import WSClient
    app = websocket.app.state.nm
    tok = websocket.cookies.get(COOKIE)
    user = app.auth.user_by_session(tok) if tok else None
    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    if not user or (origin and host and origin.split("://", 1)[-1] != host):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    client = WSClient(websocket, user)
    app.clients.add(client)
    try:
        while True:
            msg = json.loads(await websocket.receive_text())
            t = msg.get("type")
            if t == "live":
                client.live = bool(msg.get("on"))
                client.live_filter = msg.get("filter") or {}
                if client.live:
                    client.live_seq = max(0, app.stats.agg.live_seq - 100)
            elif t == "errors":
                client.errors = bool(msg.get("on"))
                if client.errors:
                    client.err_seq = max(0, app.stats.agg.err_seq - 50)
            elif t == "ping":
                await websocket.send_text('{"type":"pong"}')
    except (WebSocketDisconnect, RuntimeError, ValueError):
        pass
    finally:
        app.clients.discard(client)
