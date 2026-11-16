"""API раздела «Защита от атак»: настройки, каталог правил, обзор и журнал атак, режим «Под атакой», списки
угроз, самопроверка, оценка защищённости, сетевые параметры ядра, быстрые исключения."""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from typing import Any, Dict, Optional

from fastapi import Body, Depends, HTTPException, Query, Request

from ..auth import admin, operator, viewer
from ..models import MODSEC_APPS, THREAT_PRESETS, VERIFIED_BOTS, GlobalSettings, ProtectionSettings, Site
from ..protection import rules as W
from ..protection.nginx import challenge_ready, modsec_ready, site_modes
from ..protection.service import ACTIONS, CRS_GROUPS, KINDS, SYSCTL, SYSCTL_FILE, TOOL_TITLES, sysctl_report

from .routes import audit as _audit_fn
from .routes import router  # маршруты регистрируются в общем роутере /api (модуль импортируется в конце routes.py)


def _nm(request: Request):
    return request.app.state.nm


def _audit(request, user, action, target="", details=None):
    _audit_fn(request, user, action, target, details)


def _sites(app):
    return [(r["id"], Site.model_validate(json.loads(r["data"]))) for r in
            app.db.query("SELECT id, data FROM sites ORDER BY id")]


@router.get("/protection/rules")
async def protection_rules(user=Depends(viewer)):
    """Каталог правил фильтра запросов: категории (режим по умолчанию, описание) и правила (уровень, поля, CVE)."""
    return {
        "categories": [{"id": k, **v} for k, v in W.CATEGORIES.items()],
        "rules": [{"id": r.id, "cat": r.cat, "title": r.title, "level": r.level, "cve": r.cve, "note": r.note,
                   "fields": [W.TARGETS[t][1] for t in r.targets], "example": (r.examples or [""])[0][:200]}
                  for r in W.RULES],
        "modes": W.MODES,
    }


@router.get("/protection/settings")
async def protection_get(request: Request, user=Depends(viewer)):
    """Общие настройки защиты, состояние списков угроз и режима «Под атакой», готовность nginx."""
    app = _nm(request)
    p = app.protection.settings()
    caps = app.nginx.caps()
    return {"settings": p.model_dump(), "effective_modes": {c: p.mode(c) for c in W.CATEGORIES},
            "feed_status": app.protection.feed_status(), "presets": THREAT_PRESETS, "bot_presets": VERIFIED_BOTS,
            "attack": app.protection.attack_state(), "challenge_ready": challenge_ready(caps),
            "modsec": _modsec_status(app), "kinds": KINDS, "actions": ACTIONS}


def _modsec_status(app) -> Dict[str, Any]:
    caps = app.nginx.caps()
    crs_dir, ver = app.nginx.crs()
    log = app.protection.modsec_log()
    try:
        size = log.stat().st_size
    except OSError:
        size = None
    return {"module": modsec_ready(caps), "crs_dir": crs_dir,
            "crs_version": ".".join(ver) if ver and len(ver) == 3 else ver, "audit_log": str(log), "audit_size": size,
            "apps": MODSEC_APPS, "groups": {k: v[1] for k, v in CRS_GROUPS.items()},
            "install": "apt install libnginx-mod-http-modsecurity modsecurity-crs"}


@router.put("/protection/settings")
async def protection_put(request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                         user=Depends(admin)):
    """Изменить общие настройки защиты (тело — ProtectionSettings). ?apply=1 — применить конфигурацию сразу."""
    app = _nm(request)
    p = ProtectionSettings.model_validate(body)
    old = app.protection.settings()
    app.protection.save(p)
    _audit(request, user, "protection_settings_updated")
    if p.crs_source != old.crs_source and p.crs_source == "package":
        app.protection.vulndb.use_package_crs()
    res = await app.apply(user["username"], "Изменены настройки защиты от атак") if apply else None
    loop = asyncio.get_running_loop()
    vuln_keys = ("vulndb_enabled", "vulndb_scope", "vulndb_skip_legit", "vulndb_exclude", "vulndb_exclude_paths")
    if any(getattr(p, k) != getattr(old, k) for k in vuln_keys) or p.mode("vuln") != old.mode("vuln"):
        loop.create_task(app.protection.vulndb.write_map())
    srcs = ("vulndb_enabled", "vulndb_kev", "vulndb_nuclei", "vulndb_epss", "vulndb_cvelist", "vulndb_exploitdb",
            "vulndb_scope")
    if any(getattr(p, k) != getattr(old, k) for k in srcs) and p.vulndb_enabled:
        loop.create_task(app.protection.vulndb.update(force=False))
    if p.crs_source == "github" and old.crs_source != "github":
        loop.create_task(app.protection.vulndb.update_crs(user=user["username"]))
    feeds_changed = [f.model_dump() for f in p.threat_feeds] != [f.model_dump() for f in old.threat_feeds] or \
        [b.model_dump() for b in p.verified_bots] != [b.model_dump() for b in old.verified_bots] or \
        (p.fake_bot_action, p.verified_skip_challenge) != (old.fake_bot_action, old.verified_skip_challenge)
    if feeds_changed:
        loop.create_task(app.protection.update_feeds(force=False))
    return {"ok": True, "applied": res}


@router.get("/protection/overview")
async def protection_overview(request: Request, hours: int = Query(24, ge=1, le=24 * 365), site: str = "",
                              user=Depends(viewer)):
    """Сводка атак за период: итоги по действиям и видам, ряды для графика, правила, сайты, IP, страны, URI."""
    app = _nm(request)
    await asyncio.to_thread(app.protection.flush)
    return await asyncio.to_thread(app.protection.overview, hours, site)


@router.get("/protection/events")
async def protection_events(request: Request, limit: int = Query(200, ge=1, le=2000), before: Optional[float] = None,
                            site: str = "", ip: str = "", kind: str = "", action: str = "", q: str = "",
                            rid: str = "", test: bool = False, user=Depends(viewer)):
    """Журнал атак: отдельные запросы (фильтры по сайту, IP, виду, действию, тексту и номеру запроса)."""
    app = _nm(request)
    await asyncio.to_thread(app.protection.flush)
    return await asyncio.to_thread(app.protection.events, limit, before, site, ip, kind, action, q, rid, test)


@router.get("/protection/live")
async def protection_live(request: Request, since: float = 0, user=Depends(viewer)):
    """Последние события защиты из памяти (для живой ленты)."""
    return [e for e in list(_nm(request).protection.recent) if e["ts"] > since][-100:]


@router.post("/protection/attack")
async def protection_attack(request: Request, body: Dict[str, Any] = Body(...), user=Depends(operator)):
    """Режим «Под атакой»: {site: id или null (все сайты), on: true/false, minutes: срок или null}."""
    app = _nm(request)
    site = body.get("site")
    on = bool(body.get("on"))
    minutes = body.get("minutes")
    if minutes is not None:
        minutes = int(minutes)
        if not 1 <= minutes <= 7 * 24 * 60:
            raise HTTPException(400, "Срок — от 1 минуты до 7 суток")
    if site is not None:
        site = int(site)
        if not app.db.one("SELECT 1 FROM sites WHERE id=?", (site,)):
            raise HTTPException(404, "Сайт не найден")
    if not challenge_ready(app.nginx.caps()):
        raise HTTPException(409, "Проверка браузера недоступна: в nginx нет модуля secure_link")
    res = await app.protection.set_attack(site, on, minutes, user["username"])
    _audit(request, user, "attack_mode_on" if on else "attack_mode_off", "все сайты" if site is None else str(site),
           {"minutes": minutes})
    if not res["ok"]:
        raise HTTPException(409, "nginx не принял файл режима «Под атакой»: " + res["output"])
    return res


@router.post("/protection/feeds/update")
async def protection_feeds_update(request: Request, body: Dict[str, Any] = Body(default={}), user=Depends(admin)):
    """Обновить списки угроз сейчас ({id} — только один список)."""
    app = _nm(request)
    res = await app.protection.update_feeds(force=True, only=body.get("id") or None)
    _audit(request, user, "threat_feeds_updated", body.get("id") or "все")
    return res


@router.post("/protection/selftest/{site_id}")
async def protection_selftest(request: Request, site_id: int, user=Depends(operator)):
    """Проверить защиту сайта: отправить в nginx на этом сервере набор атак и обычных запросов, сравнить итог с
    настройками (блокировка, запись в журнал, ложные срабатывания)."""
    app = _nm(request)
    try:
        res = await app.protection.selftest(site_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, user, "protection_selftest", str(site_id), res["summary"])
    return res


@router.get("/protection/selftest/{site_id}")
async def protection_selftest_last(request: Request, site_id: int, user=Depends(viewer)):
    """Итог последней самопроверки сайта."""
    return _nm(request).db.kv_get(f"selftest_{site_id}") or {}


@router.get("/protection/score")
async def protection_score(request: Request, user=Depends(viewer)):
    """Оценка защищённости каждого включённого сайта (0–100, A–F) с невыполненными пунктами."""
    app = _nm(request)
    out = []
    for sid, s in _sites(app):
        if s.enabled:
            sc = app.protection.score(sid, s)
            sc["modes"] = site_modes(app.protection.settings(), s.protection)
            sc["challenge"] = s.protection.challenge if s.protection.enabled else "off"
            sc["protection"] = s.protection.enabled
            out.append(sc)
    return out


@router.get("/protection/sysctl")
async def protection_sysctl(user=Depends(viewer)):
    """Сетевые параметры ядра, влияющие на устойчивость к SYN-флуду и подмене адресов."""
    return {"items": await asyncio.to_thread(sysctl_report), "file": str(SYSCTL_FILE),
            "installed": SYSCTL_FILE.exists()}


@router.post("/protection/sysctl/apply")
async def protection_sysctl_apply(request: Request, user=Depends(admin)):
    """Записать рекомендуемые значения в /etc/sysctl.d/90-nginx-manager.conf и применить (sysctl -p)."""
    lines = ["# Nginx Manager: сетевые параметры ядра (раздел «Защита → Сеть и сервер»)",
             "# Удалите файл и выполните sysctl --system, чтобы вернуть значения по умолчанию.", ""]
    for name, want, how, title in SYSCTL:
        lines.append(f"# {title}")
        lines.append(f"{name} = {want}")
    try:
        SYSCTL_FILE.write_text("\n".join(lines) + "\n")
    except OSError as e:
        raise HTTPException(409, f"Не удалось записать {SYSCTL_FILE}: {e}")
    try:
        r = await asyncio.to_thread(subprocess.run, ["sysctl", "-p", str(SYSCTL_FILE)], capture_output=True,
                                    text=True, timeout=30)
        out = (r.stdout + r.stderr)[-3000:]
    except (OSError, subprocess.TimeoutExpired) as e:
        out = str(e)
    _audit(request, user, "sysctl_applied")
    report = await asyncio.to_thread(sysctl_report)
    bad = [x["name"] for x in report if x["ok"] is False]
    return {"ok": not bad, "output": out, "items": report, "not_applied": bad}


SLOW_PROFILE = {"client_header_timeout": "10s", "client_body_timeout": "20s", "send_timeout": "20s",
                "keepalive_timeout": "30s", "reset_timedout_connection": True, "server_tokens": False,
                "large_client_header_buffers": "4 16k", "client_header_buffer_size": "1k"}


@router.get("/protection/slow-profile")
async def protection_slow_profile_get(request: Request, user=Depends(viewer)):
    """Текущие и рекомендуемые значения параметров nginx против медленных атак (Slowloris, R.U.D.Y.)."""
    g = _nm(request).global_settings().model_dump()
    return [{"key": k, "current": g.get(k), "recommended": v, "ok": g.get(k) == v} for k, v in SLOW_PROFILE.items()]


@router.post("/protection/slow-profile")
async def protection_slow_profile(request: Request, apply: bool = Query(False), user=Depends(admin)):
    """Установить рекомендуемые таймауты и буферы против медленных атак (глобальные настройки nginx)."""
    app = _nm(request)
    g = app.global_settings().model_dump()
    g.update(SLOW_PROFILE)
    app.db.kv_set("global_settings", GlobalSettings.model_validate(g).model_dump())
    app.touch()
    _audit(request, user, "slow_profile_applied")
    res = await app.apply(user["username"], "Защита от медленных атак: таймауты и буферы") if apply else None
    return {"ok": True, "applied": res}


@router.post("/protection/exclude")
async def protection_exclude(request: Request, body: Dict[str, Any] = Body(...), apply: bool = Query(False),
                             user=Depends(admin)):
    """Ложное срабатывание → исключение: {site, rule} отключает правило на сайте, {site, path} — проверку пути,
    {rule, all_sites: true} — правило на всех сайтах."""
    app = _nm(request)
    rule = (body.get("rule") or "").split("/")[-1]
    path = (body.get("path") or "").strip()
    if rule and rule not in W.RULE_BY_ID:
        raise HTTPException(400, f"Неизвестное правило «{rule}»")
    if body.get("all_sites"):
        p = app.protection.settings().model_copy(deep=True)
        if rule and rule not in p.waf_disabled_rules:
            p.waf_disabled_rules.append(rule)
        app.protection.save(ProtectionSettings.model_validate(p.model_dump()))
        target = "все сайты"
    else:
        sid = int(body.get("site") or 0)
        row = app.db.one("SELECT data FROM sites WHERE id=?", (sid,))
        if not row:
            raise HTTPException(404, "Сайт не найден")
        d = json.loads(row["data"])
        pr = d.setdefault("protection", {})
        if rule:
            pr.setdefault("waf_disabled_rules", [])
            if rule not in pr["waf_disabled_rules"]:
                pr["waf_disabled_rules"].append(rule)
        if path:
            pr.setdefault("waf_exclude_paths", [])
            if path not in pr["waf_exclude_paths"]:
                pr["waf_exclude_paths"].append(path)
        site = Site.model_validate(d)
        app.db.execute("UPDATE sites SET data=?, updated_at=? WHERE id=?",
                       (json.dumps(site.model_dump(), ensure_ascii=False), time.time(), sid))
        app.touch()
        target = site.name
    _audit(request, user, "protection_exclusion", target, {"rule": rule, "path": path})
    res = await app.apply(user["username"], f"Исключение защиты: {rule or path}") if apply else None
    return {"ok": True, "applied": res}


@router.post("/protection/test")
async def protection_test(body: Dict[str, Any] = Body(...), user=Depends(viewer)):
    """Какие правила сработали бы на значение: {uri, ua, referer, cookie} (проверка в Python, без nginx)."""
    vals = {"uri": body.get("uri"), "ua": body.get("ua"), "ref": body.get("referer"), "cookie": body.get("cookie")}
    vals = {k: str(v) for k, v in vals.items() if v is not None and v != ""}
    if not vals:
        raise HTTPException(400, "Укажите строку запроса или заголовок")
    level = int(body.get("level") or 2)
    hits = W.scan(vals, level)
    return [{"id": r.id, "cat": r.cat, "cat_title": W.CATEGORIES[r.cat]["title"], "title": r.title, "level": r.level,
             "cve": r.cve} for r in hits]


# ---------------------------------------------------------------------- аналитика
@router.get("/protection/analytics")
async def protection_analytics(request: Request, hours: int = Query(24, ge=1, le=24 * 365), site: str = "",
                               user=Depends(viewer)):
    """Аналитика атак за период и сравнение с предыдущим: ряды по механизмам, категориям, действиям и сайтам,
    доля атак в трафике, уникальные адреса, тепловая карта, инструменты атакующих, методы, коды ответа, цели,
    эффективность правил и списков угроз, ограничение частоты, воронка проверки браузера, роботы, периоды
    режима «Под атакой»."""
    app = _nm(request)
    await asyncio.to_thread(app.protection.flush)
    return await asyncio.to_thread(app.protection.analytics.analytics, hours, site)


@router.get("/protection/attackers")
async def protection_attackers(request: Request, hours: int = Query(24, ge=1, le=24 * 365), site: str = "",
                               q: str = "", limit: int = Query(200, ge=1, le=1000), user=Depends(viewer)):
    """Атакующие адреса за период: число атак, правила, сайты, инструмент по User-Agent, оценка угрозы 0–100."""
    app = _nm(request)
    await asyncio.to_thread(app.protection.flush)
    return await asyncio.to_thread(app.protection.analytics.attackers, hours, site, q, limit)


@router.get("/protection/ip/{ip}")
async def protection_ip(request: Request, ip: str, hours: int = Query(168, ge=1, le=24 * 365), user=Depends(viewer)):
    """Профиль адреса: атаки во времени, правила, сайты, пути, User-Agent, обычный трафик, блокировка, списки угроз."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Некорректный IP-адрес")
    app = _nm(request)
    await asyncio.to_thread(app.protection.flush)
    return await asyncio.to_thread(app.protection.analytics.ip_profile, ip, hours)


@router.get("/protection/rule")
async def protection_rule(request: Request, kind: str, rule: str, hours: int = Query(168, ge=1, le=24 * 365),
                          site: str = "", user=Depends(viewer)):
    """Карточка правила: описание, срабатывания во времени, сайты, адреса, пути, User-Agent, последние события."""
    app = _nm(request)
    if kind not in KINDS:
        raise HTTPException(400, "Неизвестный вид события")
    await asyncio.to_thread(app.protection.flush)
    return await asyncio.to_thread(app.protection.analytics.rule_detail, kind, rule[:120], hours, site)


@router.get("/protection/events.csv")
async def protection_events_csv(request: Request, limit: int = Query(10000, ge=1, le=100000), site: str = "",
                                ip: str = "", kind: str = "", action: str = "", q: str = "", user=Depends(viewer)):
    """Журнал атак в CSV (UTF-8 с BOM — открывается в Excel)."""
    import csv
    import io

    from fastapi.responses import Response
    app = _nm(request)
    await asyncio.to_thread(app.protection.flush)
    rows = await asyncio.to_thread(app.protection.events, min(limit, 100000), None, site, ip, kind, action, q, "",
                                   False)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Время", "Сайт", "IP", "Страна", "Механизм", "Правило", "Название правила", "Действие", "Метод",
                "Запрос", "User-Agent", "Код", "Номер запроса", "Host", "Инструмент"])
    from ..protection.service import classify_ua
    for r in rows:
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), r.get("site_name") or r["site"],
                    r["ip"], r["country"], KINDS.get(r["kind"], r["kind"]), r["rule"], r.get("title", ""),
                    ACTIONS.get(r["action"], r["action"]), r["method"], r["uri"], r["ua"], r["status"], r["rid"],
                    r["host"], TOOL_TITLES.get(classify_ua(r["ua"]), "")])
    _audit(request, user, "protection_events_export", details={"rows": len(rows)})
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="attacks-{time.strftime("%Y%m%d-%H%M")}.csv"'})


# =============================================================================
#  База уязвимостей и обновление баз
# =============================================================================
@router.get("/protection/vulns")
async def protection_vulns(request: Request, q: str = "", filter: str = "", sort: str = "kev",
                           limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), user=Depends(viewer)):
    """База уязвимостей: сводка (источники, охват) и страница списка с поиском и фильтром (kev, patched, covered,
    uncovered, ransomware, critical, epss, seen)."""
    app = _nm(request)
    db = app.protection.vulndb
    await asyncio.to_thread(db.record_seen)
    out = await asyncio.to_thread(db.search, q.strip()[:100], filter, sort, limit, offset)
    out["summary"] = await asyncio.to_thread(db.summary)
    out["map"] = app.db.kv_get("vulndb_map", {}) or {}
    out["new"] = app.db.kv_get("vulndb_new", {}) or {}
    return out


@router.get("/protection/vulns/{cve}")
async def protection_vuln(request: Request, cve: str, user=Depends(viewer)):
    """Карточка уязвимости: описание, источники, пути эксплойта, правила, попытки эксплуатации на сайтах."""
    app = _nm(request)
    await asyncio.to_thread(app.protection.flush)
    r = await asyncio.to_thread(app.protection.vulndb.get, cve)
    if not r:
        raise HTTPException(404, "Уязвимости нет в базе")
    return r


@router.post("/protection/vulns/update")
async def protection_vulns_update(request: Request, body: Dict[str, Any] = Body(default={}), user=Depends(admin)):
    """Обновить базы сейчас: {what: "all" | "vulns" | "feeds" | "crs"}. Без ожидания — ход виден в сводке."""
    app = _nm(request)
    what = body.get("what") or "all"
    loop = asyncio.get_running_loop()
    if what in ("all", "vulns"):
        if app.protection.vulndb.running:
            raise HTTPException(409, "Обновление базы уязвимостей уже идёт")
        loop.create_task(app.protection.vulndb.update(force=True, user=user["username"]))
    if what in ("all", "feeds"):
        loop.create_task(app.protection.update_feeds(force=True))
    if what == "crs":
        loop.create_task(app.protection.vulndb.update_crs(force=True, user=user["username"]))
    _audit(request, user, "protection_db_update", what)
    return {"ok": True, "started": what}


@router.post("/protection/vulns/{cve}/exclude")
async def protection_vuln_exclude(request: Request, cve: str, body: Dict[str, Any] = Body(default={}),
                                  user=Depends(admin)):
    """Исключить уязвимость из карты путей (ложное срабатывание) или вернуть: {exclude: true/false}."""
    app = _nm(request)
    p = app.protection.settings()
    cve = cve.upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        raise HTTPException(400, "Номер уязвимости — вида CVE-2021-44228")
    ex = [c for c in p.vulndb_exclude if c != cve] + ([cve] if body.get("exclude", True) else [])
    app.protection.save(p.model_copy(update={"vulndb_exclude": ex}))
    _audit(request, user, "vuln_excluded" if body.get("exclude", True) else "vuln_included", cve)
    ok, out = await app.protection.vulndb.write_map()
    return {"ok": ok, "output": "" if ok else out[-800:], "excluded": ex}


@router.get("/protection/sources")
async def protection_sources(request: Request, user=Depends(viewer)):
    """Все обновляемые базы защиты: списки угроз, диапазоны роботов, база уязвимостей, правила OWASP CRS."""
    app = _nm(request)
    p = app.protection.settings()
    st = app.protection.feed_status()
    db = app.protection.vulndb
    vs = db.status()
    crs_dir, ver = app.nginx.crs()
    rows = []
    for f in p.threat_feeds:
        s = st.get(f.id) or {}
        rows.append({"group": "threats", "id": f.id, "title": f.name or f.id, "enabled": f.enabled,
                     "ok": s.get("ok"), "count": s.get("count"), "updated": s.get("updated"),
                     "error": s.get("error", ""), "every": p.threat_update_hours})
    for b in p.verified_bots:
        s = st.get(f"bot:{b.id}") or {}
        rows.append({"group": "bots", "id": b.id, "title": b.name or b.id, "enabled": b.enabled, "ok": s.get("ok"),
                     "count": s.get("count"), "updated": s.get("updated"), "error": s.get("error", ""),
                     "every": p.threat_update_hours})
    from ..protection.vulndb import SOURCES
    for k, on in (("kev", p.vulndb_kev), ("nuclei", p.vulndb_nuclei), ("templates", p.vulndb_nuclei),
                  ("epss", p.vulndb_epss), ("cvelist", p.vulndb_cvelist), ("exploitdb", p.vulndb_exploitdb)):
        s = vs.get(k) or {}
        title = SOURCES.get(k, ("nuclei-templates: шаблоны эксплойтов", ""))[0]
        rows.append({"group": "vulns", "id": k, "title": title, "enabled": p.vulndb_enabled and on,
                     "ok": s.get("ok"), "count": s.get("count"), "updated": s.get("updated"),
                     "error": s.get("error", ""), "every": p.vulndb_update_hours})
    s = vs.get("crs") or {}
    rows.append({"group": "crs", "id": "crs", "title": "OWASP Core Rule Set", "enabled": p.modsec_enabled,
                 "ok": s.get("ok") if p.crs_source == "github" else bool(crs_dir), "count": None,
                 "updated": s.get("updated"), "error": s.get("error", "") if p.crs_source == "github" else "",
                 "every": p.vulndb_update_hours if p.crs_source == "github" else None,
                 "version": ".".join(ver) if ver and len(ver) == 3 else ver, "source": p.crs_source, "dir": crs_dir})
    return {"rows": rows, "running": db.running, "progress": db.progress}
