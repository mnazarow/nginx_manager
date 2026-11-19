"""Перенос TCP/UDP-потоков и общих настроек nginx между серверами («Сравнить» → «Отправить туда» / «Забрать сюда»).

Потоки сопоставляются по внешнему адресу, порту и протоколу (как в сравнении): поток с тем же ключом обновляется,
иначе создаётся. Общие настройки nginx переносятся целиком, кроме полей, которые у каждого сервера свои
(пользователь nginx, DNS-резолвер, файл DH-параметров, подключение conf.d и sites-enabled — зависят от дистрибутива).
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from ..models import GlobalSettings, Stream

GLOBAL_LOCAL = {"user", "resolver", "ssl_dhparam", "include_conf_d", "include_sites_enabled"}


def stream_key(s: Stream) -> str:
    return f"{s.listen_ip or '*'}:{s.listen_port}/{getattr(s, 'protocol', 'tcp')}"


def export_streams(app, keys: List[str]) -> List[Dict[str, Any]]:
    want = set(keys)
    state = app.last_applied_state() or app.nginx.load_state()
    return [{"key": stream_key(s), "src_id": sid, "name": s.name, "enabled": s.enabled,
             "data": s.model_dump(mode="json")} for sid, s in state.streams if stream_key(s) in want]


def export_global(app) -> Dict[str, Any]:
    state = app.last_applied_state() or app.nginx.load_state()
    return {k: v for k, v in state.glob.model_dump(mode="json").items() if k not in GLOBAL_LOCAL}


def receive_streams(app, items: List[Dict[str, Any]], overwrite: bool = True) -> Dict[str, Any]:
    res: Dict[str, Any] = {"created": 0, "updated": 0, "skipped": 0, "items": []}
    local = {}
    for r in app.db.query("SELECT id, data FROM streams"):
        try:
            local[stream_key(Stream.model_validate(json.loads(r["data"])))] = r["id"]
        except Exception:  # noqa: BLE001
            continue
    now = time.time()
    for it in items[:200]:
        try:
            s = Stream.model_validate(it.get("data") or {})
        except Exception as e:  # noqa: BLE001
            res["skipped"] += 1
            res["items"].append({"name": str(it.get("name") or "?")[:80], "action": "error",
                                 "notes": [f"неверные настройки: {str(e)[:200]}"]})
            continue
        key = stream_key(s)
        data = json.dumps(s.model_dump(mode="json"), ensure_ascii=False)
        if key in local:
            if not overwrite:
                res["skipped"] += 1
                res["items"].append({"name": s.name, "action": "skipped", "notes": ["такой поток уже есть"]})
                continue
            app.db.execute("UPDATE streams SET name=?, enabled=?, data=?, updated_at=? WHERE id=?",
                           (s.name, int(s.enabled), data, now, local[key]))
            res["updated"] += 1
            res["items"].append({"name": s.name, "id": local[key], "action": "updated"})
        else:
            sid = app.db.execute("INSERT INTO streams(name, enabled, data, created_at, updated_at) VALUES(?,?,?,?,?)",
                                 (s.name, int(s.enabled), data, now, now))
            local[key] = sid
            res["created"] += 1
            res["items"].append({"name": s.name, "id": sid, "action": "created"})
    return res


def receive_global(app, data: Dict[str, Any]) -> List[str]:
    """Принять общие настройки (свои поля сервера сохраняются). Список изменившихся полей (подписи)."""
    cur = app.global_settings().model_dump(mode="json")
    new = {**cur, **{k: v for k, v in (data or {}).items() if k not in GLOBAL_LOCAL and k in cur}}
    g = GlobalSettings.model_validate(new)
    dumped = g.model_dump(mode="json")
    changed = [k for k in dumped if dumped[k] != cur.get(k)]
    if changed:
        app.db.kv_set("global_settings", g.model_dump())
    labels = []
    for k in changed:
        f = GlobalSettings.model_fields.get(k)
        extra = (f.json_schema_extra if f else None) or {}
        labels.append(extra.get("label", k) if isinstance(extra, dict) else k)
    return labels
