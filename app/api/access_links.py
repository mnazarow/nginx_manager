"""Временный доступ к сайту по ссылке: API ссылок для панели и страница для посетителя (через nginx сайта)."""
from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import time
from typing import Any, Dict

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from ..auth import operator, viewer
from ..nginx.generator import LINK_PREFIX
from ..protection.challenge import _guard
from ..services import access_links as AL
from .routes import audit, router

public = APIRouter(include_in_schema=False)


def _nm(request: Request):
    return request.app.state.nm


def _site(app, sid: int) -> Dict[str, Any]:
    r = app.db.one("SELECT id, name, enabled, data FROM sites WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Сайт не найден")
    return {**r, "data": json.loads(r["data"])}


def link_url(site: Dict[str, Any], token: str) -> str:
    d = site["data"]
    host = next((x for x in d.get("domains", []) if "*" not in x and not x.startswith("~")), "") or "адрес-сайта"
    https = (d.get("ssl") or {}).get("enabled")
    port = d.get("https_port" if https else "http_port") or (443 if https else 80)
    default = 443 if https else 80
    return f"{'https' if https else 'http'}://{host}{'' if port == default else f':{port}'}{LINK_PREFIX}/{token}"


@router.get("/sites/{sid}/access-links")
async def links_list(request: Request, sid: int, user=Depends(viewer)):
    """Ссылки временного доступа сайта (без кодов) и выданный по ним доступ."""
    app = _nm(request)
    _site(app, sid)
    now = time.time()
    links = app.db.query("SELECT id, comment, hours, uses_left, uses_total, expires_at, created_by, created_at, notify "
                         "FROM ipaccess_links WHERE site=? AND (expires_at>? OR created_at>?) ORDER BY id DESC "
                         "LIMIT 100", (sid, now, now - 7 * 86400))
    for x in links:
        x["state"] = "expired" if x["expires_at"] <= now else "used" if x["uses_left"] <= 0 else "ok"
    return {"links": links, "grants": AL.active_grants(app.db, sid),
            "ready": bool(app.nginx.challenge_key())}


@router.post("/sites/{sid}/access-links")
async def links_create(request: Request, sid: int, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    """Создать ссылку: {hours, valid_hours, uses, comment}. Код возвращается один раз (в базе — только хеш)."""
    app = _nm(request)
    site = _site(app, sid)
    if not (site["data"].get("ip_access") or {}).get("enabled"):
        raise HTTPException(400, "Сначала включите «Доступ только с разрешённых адресов» и примените конфигурацию")
    try:
        lid, token = AL.create(app.db, sid, float(body.get("hours", 8)), float(body.get("valid_hours", 24)),
                               int(body.get("uses", 1)), str(body.get("comment") or ""), user["username"],
                               bool(body.get("notify", True)))
    except (TypeError, ValueError) as e:
        raise HTTPException(400, str(e))
    audit(request, user, "access_link_created", site["name"], {"id": lid, "hours": body.get("hours"),
                                                               "uses": body.get("uses"), "comment": body.get("comment")})
    return {"id": lid, "token": token, "url": link_url(site, token)}


@router.delete("/sites/{sid}/access-links/{lid}")
async def links_delete(request: Request, sid: int, lid: int, user=Depends(operator)):
    """Отозвать ссылку (уже выданный по ней доступ остаётся до срока — его отзывают отдельно)."""
    app = _nm(request)
    if not app.db.one("SELECT 1 FROM ipaccess_links WHERE id=? AND site=?", (lid, sid)):
        raise HTTPException(404, "Ссылка не найдена")
    app.db.execute("DELETE FROM ipaccess_links WHERE id=?", (lid,))
    audit(request, user, "access_link_deleted", str(sid), {"id": lid})
    return {"ok": True}


@router.delete("/sites/{sid}/access-grants/{gid}")
async def grants_revoke(request: Request, sid: int, gid: int, user=Depends(operator)):
    """Закрыть доступ, выданный по ссылке, досрочно (nginx перечитывает файл доступа сразу)."""
    app = _nm(request)
    g = app.db.one("SELECT * FROM ipaccess_grants WHERE id=? AND site=?", (gid, sid))
    if not g:
        raise HTTPException(404, "Доступ не найден")
    app.db.execute("UPDATE ipaccess_grants SET expires_at=? WHERE id=?", (time.time() - 1, gid))
    ok, out = await app.grants.sync()
    audit(request, user, "access_grant_revoked", g["ip"], {"site": sid})
    return {"ok": ok, "output": "" if ok else out[-500:]}


@router.get("/sites/{sid}/ip-lists")
async def iplists_status(request: Request, sid: int, user=Depends(viewer)):
    """Списки адресов по ссылке сайта (из применённой версии): когда скачаны, сколько адресов, ошибка."""
    from ..services import iplists
    app = _nm(request)
    _site(app, sid)
    state = app.last_applied_state()
    return {"lists": iplists.status(app.db, state, sid) if state else []}


@router.post("/sites/{sid}/ip-lists/refresh")
async def iplists_refresh(request: Request, sid: int, user=Depends(operator)):
    """Скачать списки сайта сейчас и обновить файл доступа."""
    from ..services import iplists
    app = _nm(request)
    _site(app, sid)
    state = app.last_applied_state()
    urls = [x["url"] for x in iplists.status(app.db, state, sid)] if state else []
    if not urls:
        raise HTTPException(400, "У сайта нет списков в применённой конфигурации — сохраните и примените сайт")
    _, done = await asyncio.to_thread(iplists.refresh, app.db, state, urls)
    ok, out = await app.grants.sync()
    audit(request, user, "iplists_refresh", str(sid), {"urls": urls})
    return {"ok": ok, "output": "" if ok else out[-500:], "lists": iplists.status(app.db, state, sid),
            "errors": {u: d["error"] for u, d in done.items() if not d.get("ok")}}


@router.post("/ip-lists/check")
async def iplists_check(request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    """Проверить ссылку на список до сохранения: скачать и показать, что в нём найдено."""
    from ..models import IpListSource
    from ..services import iplists
    try:
        url = IpListSource(url=str(body.get("url") or "")).url
    except Exception:
        raise HTTPException(400, "Адрес списка — https://…")
    try:
        nets = await asyncio.to_thread(iplists.fetch, url)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:300]}
    return {"ok": True, "count": len(nets), "sample": nets[:20],
            "v6": sum(1 for x in nets if ":" in x)}


# =============================================================================
#  Страница для посетителя: /.nm-access/<код> на сайте → nginx → /access-link/<код> панели
# =============================================================================
def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(AL.page(title, body), status_code=status,
                        headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex"})


def _ctx(request: Request, token: str):
    try:
        nm, ip = _guard(request)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    try:
        site = int(request.headers.get("x-nm-site", "0"))
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Некорректный запрос")
    return nm, ip, site, AL.find(nm.db, token)


def _already(nm, site: int, ip: str) -> str:
    """Есть ли у адреса доступ без ссылки: запись в списке сайта или ещё действующая выдача."""
    r = nm.db.one("SELECT data FROM sites WHERE id=?", (site,))
    if r:
        a = ipaddress.ip_address(ip)
        for e in (json.loads(r["data"]).get("ip_access") or {}).get("entries", []):
            if e.get("expires") and e["expires"] <= time.time():
                continue
            try:
                if a in ipaddress.ip_network(e["address"], strict=False):
                    return "list"
            except (ValueError, KeyError):
                continue
    g = nm.db.one("SELECT expires_at FROM ipaccess_grants WHERE site=? AND ip=? AND expires_at>?",
                  (site, ip, time.time()))
    return f"grant:{g['expires_at']}" if g else ""


@public.get("/access-link/{token}")
async def access_page(request: Request, token: str):
    nm, ip, site, link = _ctx(request, token)
    st = AL.state(link, site)
    host = html.escape(request.headers.get("host", "сайт"))
    if st != "ok":
        return _page("Ссылка недействительна", f"<h1>Ссылка недействительна</h1><p>{AL.REASONS[st]}</p>", 410)
    have = _already(nm, site, ip)
    note = ""
    if have == "list":
        note = "<p class='muted'>Ваш адрес уже есть в списке разрешённых — доступ у вас и так есть.</p>"
    elif have.startswith("grant:"):
        note = f"<p class='muted'>Доступ для вашего адреса уже открыт до {AL.when(float(have[6:]))} — ссылка продлит его.</p>"
    uses = f"<p class='muted'>Ссылкой можно воспользоваться ещё {link['uses_left']} раз(а), она действует до " \
           f"{AL.when(link['expires_at'])}.</p>" if link["uses_total"] > 1 else \
           "<p class='muted'>Ссылка одноразовая: после нажатия кнопки ею больше нельзя воспользоваться.</p>"
    body = (f"<h1>Доступ к {host}</h1><p>Сайт открыт только для разрешённых адресов. По этой ссылке можно открыть "
            f"доступ для вашего адреса <code>{html.escape(ip)}</code> на {AL.hours_text(link['hours'])}.</p>"
            f"{note}{uses}<form method='post'><button type='submit'>Открыть доступ</button></form>"
            f"<p class='muted'>Доступ привязан к адресу: при смене сети (мобильный интернет, VPN, другой Wi-Fi) "
            f"понадобится новая ссылка.</p>")
    return _page("Доступ к сайту", body)


@public.post("/access-link/{token}")
async def access_grant(request: Request, token: str):
    nm, ip, site, link = _ctx(request, token)
    st = AL.state(link, site)
    if st != "ok":
        return _page("Ссылка недействительна", f"<h1>Ссылка недействительна</h1><p>{AL.REASONS[st]}</p>", 410)
    g = await asyncio.to_thread(AL.grant, nm.db, link, ip, request.headers.get("user-agent", ""))
    ok, out = await nm.grants.sync()
    name = (nm.db.one("SELECT name FROM sites WHERE id=?", (site,)) or {}).get("name", site)
    msg = (f"Доступ по ссылке: {ip} — сайт «{name}» до {AL.when(g['expires_at'])}"
           + (f" (ссылка «{link['comment']}»)" if link["comment"] else "")
           + ("" if ok else " — nginx не перечитал файл доступа"))
    details = {"ip": ip, "site": site, "link": link["id"], "grant": g["id"],
               "ua": request.headers.get("user-agent", "")[:200]}
    p = nm.panel()
    if ok and link.get("notify", 1) and p.event_channels and not nm.alerts.silence_for(None):
        # сразу в каналы уведомлений о событиях — при любом «минимальном уровне» и выборе источников (уведомление
        # включено у самой ссылки); в Telegram — с кнопкой «Закрыть доступ»
        details["notified"] = True
        asyncio.get_running_loop().create_task(
            nm.events.deliver("info", "access", msg + f"\nБраузер: {details['ua'][:120] or '—'}", details,
                              force_channels=list(p.event_channels)))
    nm.db.event("info" if ok else "error", "access", msg, details)
    if not ok:
        return _page("Не получилось", "<h1>Не получилось открыть доступ</h1><p>Сервер не смог применить изменение. "
                     "Сообщите администратору сайта.</p>", 503)
    body = (f"<h1>Доступ открыт</h1><p>Адрес <code>{html.escape(ip)}</code> может открывать сайт до "
            f"<b>{AL.when(g['expires_at'])}</b>.</p><a class='btn' href='/'>Перейти на сайт</a>"
            f"<p class='muted'>Если сайт всё ещё не открывается, подождите несколько секунд и обновите страницу.</p>")
    return _page("Доступ открыт", body)
