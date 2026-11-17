"""Копия всех настроек по расписанию и её отправка во внешние места («Настройки панели → Копия настроек»).

Копия создаётся отдельно от ежедневной копии базы (каждые N часов, по желанию — только если настройки изменились)
или, при «0», берётся ежедневная. Затем она шифруется паролем копий настроек и отправляется: в каталог settings/
основного S3-хранилища, во второе S3-хранилище и в каналы оповещений (Telegram — файлом, e-mail — вложением).
Итог — в kv settings_job_last и в журнале «События» (ошибка — с уровнем «ошибка», уходит в уведомления о событиях).
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import settings

KV_LAST = "settings_job_last"
LABEL = "sched"
MAX_FILE = 20 << 20  # Telegram принимает до 50 МБ, почтовые серверы — обычно до 10–25 МБ
VOLATILE = {"updated_at", "last_used", "last_used_at", "last_login", "last_login_at", "last_ip", "last_seen",
            "not_after", "status", "last_error", "suppressed"}


def password(p) -> str:
    return p.sb_password or p.s3_encrypt_password or ""


def digest(app) -> str:
    """Отпечаток настроек без изменчивых полей (время входа, использование токенов, проверки сертификатов)."""
    from . import settings_backup as SB
    data, files, _ = SB.collect(app)
    h = hashlib.sha256()
    for sec in sorted(data):
        for key, part in sorted(data[sec].items()):
            if isinstance(part, dict) and "columns" in part:
                cols = part["columns"]
                keep = [i for i, c in enumerate(cols) if c not in VOLATILE]
                rows = sorted(json.dumps([r[i] for i in keep], default=str, ensure_ascii=False) for r in part["rows"])
                h.update(json.dumps([sec, key, [cols[i] for i in keep], rows], ensure_ascii=False).encode())
            else:
                h.update(json.dumps([sec, key, part], sort_keys=True, default=str, ensure_ascii=False).encode())
    for name in sorted(files):
        if name.startswith("letsencrypt/") and "/accounts/" not in name and not name.endswith(".conf"):
            continue  # файлы certbot меняются вместе с записями сертификатов — их хватает
        h.update(name.encode() + hashlib.sha256(files[name]).digest())
    return h.hexdigest()


def second_s3(p):
    from .s3 import S3Client
    return S3Client(p.sb_s3_endpoint, p.sb_s3_region, p.sb_s3_bucket, p.sb_s3_access_key, p.sb_s3_secret_key,
                    p.sb_s3_path_style)


def _prune(cl, prefix: str, keep: int) -> List[str]:
    if not keep:
        return []
    objs = sorted((o for o in cl.list(prefix) if ".settings.tar.gz" in o["key"]
                   and "/" not in o["key"][len(prefix):]), key=lambda o: o["key"])
    removed = []
    for o in objs[:-keep]:
        cl.delete(o["key"])
        removed.append(o["key"])
    return removed


def _prune_local(keep: int) -> None:
    files = sorted(settings.backups_dir.glob(f"nginx-manager-*-{LABEL}.settings.tar.gz*"))
    for old in files[:-keep] if keep > 0 else []:
        old.unlink(missing_ok=True)


def deliver(app, path: Path, main_s3: bool = True) -> Dict[str, Any]:
    """Отправить копию настроек во все выбранные места. {цель: {ok, error, key}}. main_s3=False — без основного
    хранилища (ежедневная копия уходит туда сама, вместе с базой)."""
    from . import alerts as AL
    from .backup import _encrypt, s3_client
    from ..models import AlertChannel
    p = app.panel()
    pw = password(p)
    out: Dict[str, Any] = {}
    tmp: Optional[Path] = None
    send = path
    if not path.name.endswith(".enc"):
        if not pw:
            if p.sb_s3 or p.sb_channels:
                out["encrypt"] = {"ok": False, "error": "не задан пароль шифрования — копия не отправлена"}
            return out
        tmp = send = _encrypt(path, pw)
    try:
        if p.s3_enabled and p.sb_main_s3 and main_s3:
            try:
                cl = s3_client(p)
                key = f"{p.s3_prefix}settings/{send.name}"
                cl.put_file(key, send)
                out["s3"] = {"ok": True, "key": key, "removed": len(_prune(cl, f"{p.s3_prefix}settings/",
                                                                         p.sb_remote_keep))}
            except Exception as e:  # noqa: BLE001
                out["s3"] = {"ok": False, "error": str(e)[:300]}
        if p.sb_s3:
            try:
                cl = second_s3(p)
                key = p.sb_s3_prefix + send.name
                cl.put_file(key, send)
                out["s3_second"] = {"ok": True, "key": key, "removed": len(_prune(cl, p.sb_s3_prefix,
                                                                                p.sb_remote_keep))}
            except Exception as e:  # noqa: BLE001
                out["s3_second"] = {"ok": False, "error": str(e)[:300]}
        if p.sb_channels:
            blob = send.read_bytes()
            for cid in p.sb_channels:
                row = app.db.one("SELECT id, data FROM alert_channels WHERE id=?", (cid,))
                if not row:
                    out[f"channel:{cid}"] = {"ok": False, "error": "канал удалён"}
                    continue
                ch = AlertChannel.model_validate(json.loads(row["data"]))
                try:
                    if len(blob) > MAX_FILE:
                        raise ValueError(f"файл больше {MAX_FILE >> 20} МБ")
                    AL.send_file(ch, "Копия всех настроек", f"{send.name} ({len(blob) // 1024 + 1} КБ), "
                                 "зашифрована паролем копий настроек. Восстановление: «Копии и импорт» → "
                                 "«Восстановить настройки» → «Загрузить копию…»", send.name, blob)
                    out[f"channel:{cid}"] = {"ok": True, "name": ch.name}
                except Exception as e:  # noqa: BLE001
                    out[f"channel:{cid}"] = {"ok": False, "name": ch.name, "error": str(e)[:300]}
    finally:
        if tmp:
            tmp.unlink(missing_ok=True)
    return out


def run(app, force: bool = False, source: str = "schedule", path: Optional[Path] = None) -> Dict[str, Any]:
    """Сделать (или взять готовую — path) копию настроек и отправить её. force — без проверки «изменились ли»."""
    from . import settings_backup as SB
    p = app.panel()
    res: Dict[str, Any] = {"at": time.time(), "source": source, "ok": True, "skipped": False, "name": "",
                           "targets": {}}
    try:
        dg = digest(app)
        last = app.db.kv_get(KV_LAST, {}) or {}
        if path is None:
            if p.sb_only_changed and not force and last.get("digest") == dg and last.get("ok"):
                res.update(skipped=True, name=last.get("name", ""), digest=dg)
                app.db.kv_set(KV_LAST, {**last, "checked_at": res["at"]})
                return res
            pw = password(p)
            path = SB.create(app, LABEL, None, pw)
            _prune_local(p.sb_keep)
        res["name"] = path.name
        res["digest"] = dg
        res["targets"] = deliver(app, path, main_s3=source != "daily")
        bad = {k: v for k, v in res["targets"].items() if not v.get("ok")}
        res["ok"] = not bad
        if bad:
            app.db.event("error", "backup", "Копия настроек не отправлена: "
                         + "; ".join(f"{v.get('name') or k}: {v.get('error')}" for k, v in bad.items()),
                         {"file": path.name})
        elif res["targets"]:
            app.db.event("info", "backup", f"Копия настроек {path.name} отправлена: "
                         + ", ".join(v.get("name") or {"s3": "основное хранилище", "s3_second": "второе хранилище"}
                                     .get(k, k) for k, v in res["targets"].items()))
    except Exception as e:  # noqa: BLE001
        res.update(ok=False, error=str(e)[:500])
        app.db.event("error", "backup", f"Копия настроек по расписанию не создана: {res['error']}")
    app.db.kv_set(KV_LAST, {k: v for k, v in res.items() if k != "skipped"})
    return res


def due(app, now: Optional[float] = None) -> bool:
    p = app.panel()
    if p.sb_hours <= 0:
        return False
    last = app.db.kv_get(KV_LAST, {}) or {}
    ts = max(float(last.get("at") or 0), float(last.get("checked_at") or 0))
    return (now or time.time()) - ts >= p.sb_hours * 3600
