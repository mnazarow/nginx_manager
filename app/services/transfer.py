"""Перенос сайтов и сертификатов между серверами с Nginx Manager (кластер за одним доменом, переезд, резервный узел).

Отправитель собирает выбранные сайты (настройки целиком: локации, бэкенды, защита, доступ по IP, пользователи Basic
Auth — хеши паролей) и, по желанию, их сертификаты (fullchain + закрытый ключ) и отправляет POST /api/sync/sites на
сервер-получатель с его API-токеном администратора. Получатель:

* сертификаты сохраняет как загруженные (тип «upload») с отметкой источника; повторная отправка того же сертификата
  обновляет файлы на месте (так продлённый на источнике сертификат доезжает до получателя автоматически);
* сайт с теми же доменами обновляет (если разрешено) или пропускает, иначе создаёт новый; номер сертификата
  заменяется на местный; зона кэша, которой нет на получателе, заменяется первой существующей;
* применяет конфигурацию, если попросили и на получателе нет чужих неприменённых изменений.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import settings
from ..models import CertificateRequest, Site
from ..utils import atomic_write

log = logging.getLogger("nm.transfer")

MAX_SITES = 500
OUT_KV = "transfer_out"   # отправитель: {peer_id: {cert_id: fingerprint}} — кому пересылать продлённые сертификаты
IN_KV = "transfers_in"    # получатель: последние переносы (для страницы «Другие серверы»)
MIRROR_KV = "synced_sites"  # получатель синхронизации: {id источника: {"name", "map": {src_id: [местный id, создан]}}}


def _mid(v) -> Tuple[int, bool]:
    """Запись карты синхронизации: [местный id, создан синхронизацией] (прежний формат — просто id)."""
    return (int(v[0]), bool(v[1])) if isinstance(v, (list, tuple)) else (int(v), True)


# ====================================================================== отправитель
def read_cert(db, cid: int) -> Optional[Dict[str, Any]]:
    r = db.one("SELECT * FROM certificates WHERE id=?", (cid,))
    if not r or not r["cert_path"] or not r["key_path"]:
        return None
    try:
        cert = Path(r["cert_path"]).read_text()
        key = Path(r["key_path"]).read_text()
    except OSError:
        return None
    data = json.loads(r["data"] or "{}")
    return {"src_id": cid, "name": r["name"], "type": r["type"], "domains": json.loads(r["domains"] or "[]"),
            "cert_pem": cert, "key_pem": key, "fingerprint": data.get("fingerprint", ""),
            "not_after": r["not_after"]}


def build(db, site_ids: List[int], with_certs: bool) -> Dict[str, Any]:
    sites, certs = [], {}
    for sid in site_ids[:MAX_SITES]:
        r = db.one("SELECT id, name, enabled, data FROM sites WHERE id=?", (sid,))
        if not r:
            raise ValueError(f"Сайт #{sid} не найден")
        d = json.loads(r["data"])
        cid = (d.get("ssl") or {}).get("certificate_id")
        if with_certs and cid and cid not in certs:
            c = read_cert(db, cid)
            if c:
                certs[cid] = c
        sites.append({"src_id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]), "data": d})
    return {"sites": sites, "certs": list(certs.values())}


def build_mirror(db, state, tag: str, known: Dict[str, str]) -> Dict[str, Any]:
    """Синхронизация сайтов: сайты последней применённой версии (state) — с меткой tag или все, кроме полученных
    с других серверов; сертификаты — только новые или продлённые (known: {cert_id: отпечаток}, уже отправленные)."""
    skip = mirrored(db)
    sites, certs = [], {}
    for sid, site in state.sites:
        if sid in skip or (tag and tag not in site.tags):
            continue
        d = site.model_dump()
        sites.append({"src_id": sid, "name": site.name, "enabled": site.enabled, "data": d})
        cid = site.ssl.certificate_id
        if cid and cid not in certs:
            c = read_cert(db, cid)
            if c and known.get(str(cid)) != c.get("fingerprint"):
                certs[cid] = c
            elif c:
                certs[cid] = {"src_id": cid, "known": True}  # получатель уже знает этот сертификат
    return {"sites": sites, "certs": list(certs.values())}


def remember(db, peer_id: str, certs: List[Dict[str, Any]]) -> None:
    st = db.kv_get(OUT_KV, {}) or {}
    cur = st.setdefault(peer_id, {})
    for c in certs:
        cur[str(c["src_id"])] = c.get("fingerprint", "")
    db.kv_set(OUT_KV, st)


def peers_for_cert(db, cid: int) -> List[str]:
    return [pid for pid, m in (db.kv_get(OUT_KV, {}) or {}).items() if str(cid) in m]


# ====================================================================== получатель
def _cert_store(db, cid: int, cert: str, key: str) -> None:
    d = settings.certs_dir / str(cid)
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    atomic_write(d / "fullchain.pem", cert.strip() + "\n", 0o644)
    atomic_write(d / "privkey.pem", key.strip() + "\n", 0o600)
    db.execute("UPDATE certificates SET cert_path=?, key_path=?, updated_at=? WHERE id=?",
               (str(d / "fullchain.pem"), str(d / "privkey.pem"), time.time(), cid))


def _local_sites(app) -> List[tuple]:
    return [(r["id"], r["name"], {d.lower() for d in json.loads(r["data"]).get("domains", [])})
            for r in app.db.query("SELECT id, name, data FROM sites")]


def needed_certs(app, sites: List[Dict[str, Any]], overwrite: bool) -> set:
    """Номера сертификатов отправителя у сайтов, которые будут созданы или обновлены (пропущенным сайтам
    сертификаты не нужны — не оставляем на получателе лишних)."""
    local = _local_sites(app)
    out = set()
    for s in sites[:MAX_SITES]:
        d = s.get("data") or {}
        doms = {str(x).lower() for x in d.get("domains", [])}
        if not overwrite and any(x[2] & doms for x in local):
            continue
        cid = (d.get("ssl") or {}).get("certificate_id")
        if cid:
            out.add(str(cid))
    return out


def receive_certs(app, origin: Dict[str, str], certs: List[Dict[str, Any]], user: str,
                  only: Optional[set] = None, create: bool = True) -> Dict[str, Any]:
    """Сохранить сертификаты (only — только эти номера отправителя; create=False — только обновить уже
    перенесённые). Возвращает {map: {src_id: local_id}, created, updated, unchanged, errors, changed_ids}."""
    from .certs import key_matches
    oid, oname = origin["id"], origin["name"]
    have: Dict[str, Dict[str, Any]] = {}
    for r in app.db.query("SELECT id, data FROM certificates"):
        t = (json.loads(r["data"] or "{}").get("transfer") or {})
        if t.get("origin") == oid:
            have[str(t.get("src_id"))] = {"id": r["id"], "fp": json.loads(r["data"] or "{}").get("fingerprint", "")}
    out: Dict[str, Any] = {"map": {}, "created": 0, "updated": 0, "unchanged": 0, "errors": [], "changed_ids": [],
                           "missing": []}
    for c in certs[:MAX_SITES]:
        src = str(c.get("src_id"))
        if only is not None and src not in only:
            continue
        if c.get("known"):  # синхронизация: отправитель не пересылает сертификат, который здесь уже есть
            if src in have:
                out["map"][src] = have[src]["id"]
                out["unchanged"] += 1
            else:
                out["missing"].append(src)  # удалён здесь — отправитель пришлёт его целиком в следующий раз
            continue
        if not create and src not in have:
            continue  # продление сертификата, который здесь удалили, — не восстанавливаем
        name = str(c.get("name") or "")[:120] or "cert"
        cert, key = str(c.get("cert_pem") or ""), str(c.get("key_pem") or "")
        if "BEGIN CERTIFICATE" not in cert or "PRIVATE KEY" not in key:
            out["errors"].append(f"{name}: нет файлов сертификата или ключа")
            continue
        mark = {"origin": oid, "origin_name": oname, "src_id": c.get("src_id"), "src_type": c.get("type", ""),
                "at": time.time()}
        if src in have:
            cid = have[src]["id"]
            if c.get("fingerprint") and c["fingerprint"] == have[src]["fp"]:
                out["map"][src] = cid
                out["unchanged"] += 1
                continue
            r = app.db.one("SELECT cert_path, key_path FROM certificates WHERE id=?", (cid,))
            old = (Path(r["cert_path"]).read_text() if r and r["cert_path"] and Path(r["cert_path"]).exists() else "",
                   Path(r["key_path"]).read_text() if r and r["key_path"] and Path(r["key_path"]).exists() else "")
            _cert_store(app.db, cid, cert, key)
            d = settings.certs_dir / str(cid)
            if not key_matches(str(d / "fullchain.pem"), str(d / "privkey.pem")):
                if old[0] and old[1]:
                    _cert_store(app.db, cid, *old)  # вернуть прежние файлы
                out["errors"].append(f"{name}: закрытый ключ не соответствует сертификату")
                out["map"][src] = cid
                continue
            app.certs._update_from_file(cid)
            data = json.loads((app.db.one("SELECT data FROM certificates WHERE id=?", (cid,)) or {}).get("data") or "{}")
            data["transfer"] = mark
            app.db.execute("UPDATE certificates SET data=? WHERE id=?", (json.dumps(data), cid))
            out["map"][src] = cid
            out["updated"] += 1
            out["changed_ids"].append(cid)
            continue
        try:
            cid = app.certs.create(CertificateRequest(type="upload", name=f"{name} (с сервера «{oname}»)"[:120],
                                                      cert_pem=cert, key_pem=key), user)
        except ValueError as e:
            out["errors"].append(f"{name}: {e}")
            continue
        data = json.loads((app.db.one("SELECT data FROM certificates WHERE id=?", (cid,)) or {}).get("data") or "{}")
        data["transfer"] = mark
        app.db.execute("UPDATE certificates SET data=? WHERE id=?", (json.dumps(data), cid))
        out["map"][src] = cid
        out["created"] += 1
    return out


def _covering_cert(db, domains: List[str]) -> Optional[int]:
    from .certs import domain_covered
    best = None
    for r in db.query("SELECT id, domains, status, not_after FROM certificates WHERE status='valid' "
                      "ORDER BY not_after DESC"):
        cd = json.loads(r["domains"] or "[]")
        if domains and all(domain_covered(d, cd) for d in domains):
            best = r["id"]
            break
    return best


def mirrored(db) -> Dict[int, str]:
    """Местные сайты, которые обновляются синхронизацией с другого сервера: {номер сайта: имя сервера}."""
    out: Dict[int, str] = {}
    for _oid, d in (db.kv_get(MIRROR_KV, {}) or {}).items():
        for v in (d.get("map") or {}).values():
            out[_mid(v)[0]] = d.get("name") or _oid
    return out


def receive_sites(app, origin: Dict[str, str], sites: List[Dict[str, Any]], cert_map: Dict[str, int],
                  overwrite: bool, user: str, mirror: bool = False) -> Dict[str, Any]:
    """Создать или обновить сайты. Возвращает {items: [{name, action, id, notes}], created, updated, skipped, ...}.

    mirror (синхронизация сайтов): сайт ищется сначала по номеру у источника (домены могли поменяться), сайты,
    полученные от этого источника раньше, но пропавшие из списка, удаляются; неизменённые не трогаются."""
    glob = app.global_settings()
    zones = [z.name for z in glob.cache_zones]
    local = _local_sites(app)
    items: List[Dict[str, Any]] = []
    created = updated = skipped = unchanged = deleted = 0
    mk = app.db.kv_get(MIRROR_KV, {}) or {}
    smap: Dict[str, Tuple[int, bool]] = {k: _mid(v) for k, v in ((mk.get(origin["id"]) or {}).get("map") or {}).items()} \
        if mirror else {}
    seen: Dict[str, list] = {}  # src_id → [местный id, создан синхронизацией]
    for s in sites[:MAX_SITES]:
        raw = dict(s.get("data") or {})
        name = str(s.get("name") or raw.get("name") or "сайт")[:120]
        notes: List[str] = []
        ssl = dict(raw.get("ssl") or {})
        src_cid = ssl.get("certificate_id")
        if ssl.get("enabled"):
            if src_cid and str(src_cid) in cert_map:
                ssl["certificate_id"] = cert_map[str(src_cid)]
            else:
                cid = _covering_cert(app.db, [d for d in raw.get("domains", []) if d])
                if cid:
                    ssl["certificate_id"] = cid
                    notes.append(f"сертификат не передавался — выбран подходящий местный #{cid}")
                else:
                    ssl["enabled"] = False
                    ssl["certificate_id"] = None
                    notes.append("HTTPS выключен: сертификат не передан и подходящего на этом сервере нет")
        else:
            ssl["certificate_id"] = None if not src_cid or str(src_cid) not in cert_map else cert_map[str(src_cid)]
        raw["ssl"] = ssl
        cache = dict(raw.get("cache") or {})
        if cache.get("zone") and zones and cache["zone"] not in zones:
            notes.append(f"зоны кэша «{cache['zone']}» здесь нет — выбрана «{zones[0]}»")
            cache["zone"] = zones[0]
            raw["cache"] = cache
        try:
            site = Site.model_validate(raw)
        except Exception as e:  # noqa: BLE001
            items.append({"name": name, "action": "error", "notes": [str(e)[:300]]})
            skipped += 1
            continue
        doms = {d.lower() for d in site.domains}
        src = str(s.get("src_id", ""))
        match = next((x for x in local if mirror and src in smap and x[0] == smap[src][0]), None) or \
            next((x for x in local if x[2] & doms), None)
        now = time.time()
        payload = json.dumps(site.model_dump(), ensure_ascii=False)
        if mirror and match:
            # сайт, который уже был здесь до синхронизации, — «принятый»: при выходе из синхронизации не удаляется
            seen[src] = [match[0], smap[src][1] if src in smap and smap[src][0] == match[0] else False]
            old = app.db.one("SELECT name, enabled, data FROM sites WHERE id=?", (match[0],))
            if old and old["name"] == site.name and bool(old["enabled"]) == site.enabled and \
                    json.loads(old["data"]) == json.loads(payload):
                unchanged += 1
                continue
        if match and not overwrite:
            items.append({"name": site.name, "action": "skipped", "id": match[0],
                          "notes": [f"здесь уже есть сайт «{match[1]}» с теми же доменами"]})
            skipped += 1
            continue
        if match:
            app.db.execute("UPDATE sites SET name=?, enabled=?, data=?, updated_at=? WHERE id=?",
                           (site.name, int(site.enabled), payload, now, match[0]))
            items.append({"name": site.name, "action": "updated", "id": match[0], "notes": notes})
            updated += 1
        else:
            sid = app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                                 (site.name, int(site.enabled), payload, now, now))
            local.append((sid, site.name, doms))
            items.append({"name": site.name, "action": "created", "id": sid, "notes": notes})
            created += 1
            if mirror:
                seen[src] = [sid, True]
    if mirror:
        for src, (lid, made) in smap.items():
            if src in seen:
                continue
            r = app.db.one("SELECT name FROM sites WHERE id=?", (lid,))
            if r and made:
                app.db.execute("DELETE FROM sites WHERE id=?", (lid,))
                items.append({"name": r["name"], "action": "deleted", "id": lid,
                              "notes": ["удалён на сервере-источнике или исключён из синхронизации"]})
                deleted += 1
            elif r:  # был здесь до синхронизации — остаётся, но больше не обновляется
                items.append({"name": r["name"], "action": "released", "id": lid,
                              "notes": ["больше не синхронизируется (был на этом сервере до синхронизации)"]})
        mk[origin["id"]] = {"name": origin["name"], "map": seen, "at": time.time()}
        if not seen:
            mk.pop(origin["id"], None)
        app.db.kv_set(MIRROR_KV, mk)
    return {"items": items, "created": created, "updated": updated, "skipped": skipped, "unchanged": unchanged,
            "deleted": deleted}


def log_incoming(db, origin: Dict[str, str], res: Dict[str, Any], user: str) -> None:
    hist = db.kv_get(IN_KV, []) or []
    hist.insert(0, {"at": time.time(), "name": origin["name"], "user": user,
                    "sites": {k: res.get("sites", {}).get(k, 0) for k in ("created", "updated", "skipped")},
                    "certs": {k: res.get("certs", {}).get(k, 0) for k in ("created", "updated", "unchanged")},
                    "applied": bool(res.get("applied"))})
    db.kv_set(IN_KV, hist[:20])
