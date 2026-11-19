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


# =============================================================================
#  Проверка копий: открывается ли последняя копия паролем и всё ли в ней на месте
# =============================================================================
KV_VERIFY = "settings_verify_last"


def verify_file(app, path: Path, pw: str) -> Dict[str, Any]:
    """Открыть копию (расшифровать, сверить SHA-256 всех файлов), проверить настройки моделями и пары
    «сертификат — ключ». {ok, problems, sections, certs, created_at, version}."""
    import tempfile
    from . import settings_backup as SB
    from .certs import key_matches
    out: Dict[str, Any] = {"name": path.name, "ok": False, "problems": []}
    if path.name.endswith(".enc") and not pw:
        out["problems"].append("копия зашифрована, а пароль копий настроек не задан — проверить нельзя")
        return out
    try:
        manifest, data, files = SB.read(path, pw)
    except Exception as e:  # noqa: BLE001
        out["problems"].append(f"не открывается: {str(e)[:300]}")
        return out
    out["created_at"] = manifest.get("created_at")
    out["version"] = manifest.get("version")
    try:
        SB._validate(data, list(data))
    except Exception as e:  # noqa: BLE001
        out["problems"].append(f"настройки не проходят проверку: {str(e)[:300]}")
    counts = {}
    for sec, part in data.items():
        counts[sec] = sum(len(t.get("rows") or []) for t in part.values() if isinstance(t, dict) and "rows" in t) \
            or len([v for v in part.values() if v])
    out["sections"] = counts
    if not counts.get("users"):
        out["problems"].append("в копии нет пользователей")
    pairs = sorted({n.split("/")[1] for n in files if n.startswith("certs/")})
    bad = []
    with tempfile.TemporaryDirectory() as td:
        for cid in pairs:
            c, k = files.get(f"certs/{cid}/fullchain.pem"), files.get(f"certs/{cid}/privkey.pem")
            if not c or not k:
                bad.append(cid)
                continue
            cp, kp = Path(td) / f"{cid}.crt", Path(td) / f"{cid}.key"
            cp.write_bytes(c)
            kp.write_bytes(k)
            kp.chmod(0o600)
            if not key_matches(str(cp), str(kp)):
                bad.append(cid)
    out["certs"] = len(pairs)
    if bad:
        out["problems"].append(f"сертификат не подходит к ключу или файла нет: #{', #'.join(bad[:10])}")
    out["ok"] = not out["problems"]
    return out


def latest_local() -> Optional[Path]:
    files = [f for f in settings.backups_dir.glob("nginx-manager-*.settings.tar.gz*")
             if "before-settings-restore" not in f.name and "-uploaded" not in f.name]
    return max(files, key=lambda f: f.stat().st_mtime) if files else None


def verify(app, source: str = "schedule") -> Dict[str, Any]:
    """Проверить последнюю копию на сервере и последние копии во внешних хранилищах."""
    import tempfile
    from .backup import s3_client
    p = app.panel()
    pw = password(p)
    res: Dict[str, Any] = {"at": time.time(), "source": source, "items": []}
    loc = latest_local()
    if not loc:
        res["items"].append({"where": "на сервере", "ok": False, "problems": ["копий всех настроек нет"]})
    else:
        it = verify_file(app, loc, pw if loc.name.endswith(".enc") else "")
        age = (time.time() - loc.stat().st_mtime) / 86400
        limit = max(2.0, 2 * p.sb_hours / 24) if p.sb_hours else 2.0
        if age > limit:
            it["problems"].append(f"последней копии {age:.0f} дн. — новые не создаются")
            it["ok"] = False
        res["items"].append({"where": "на сервере", **it})
    remotes = []
    if p.sb_s3:
        remotes.append(("второе хранилище", lambda: (second_s3(p), p.sb_s3_prefix)))
    if p.s3_enabled and p.sb_main_s3:
        remotes.append(("основное хранилище", lambda: (s3_client(p), p.s3_prefix + "settings/")))
    for where, mk in remotes:
        try:
            cl, prefix = mk()
            objs = sorted((o for o in cl.list(prefix) if ".settings.tar.gz" in o["key"]
                           and "/" not in o["key"][len(prefix):]), key=lambda o: o["key"])
            if not objs:
                if where == "основное хранилище":
                    continue  # копии по расписанию туда ещё не выгружались — ежедневная лежит рядом с базой
                res["items"].append({"where": where, "ok": False, "problems": ["копий настроек нет"]})
                continue
            key = objs[-1]["key"]
            with tempfile.TemporaryDirectory() as td:
                dest = Path(td) / Path(key).name
                cl.get_to_file(key, dest)
                it = verify_file(app, dest, pw)
            res["items"].append({"where": where, **it})
        except Exception as e:  # noqa: BLE001
            res["items"].append({"where": where, "ok": False, "problems": [f"хранилище недоступно: {str(e)[:200]}"]})
    res["ok"] = all(x["ok"] for x in res["items"])
    if res["ok"]:
        app.db.event("info", "backup", "Проверка копий настроек: " + "; ".join(
            f"{x['where']} — {x['name']} открывается, сертификатов {x.get('certs', 0)}" for x in res["items"]))
    else:
        app.db.event("error", "backup", "Проверка копий настроек: " + "; ".join(
            f"{x['where']}{' (' + x['name'] + ')' if x.get('name') else ''}: {'; '.join(x['problems'])}"
            for x in res["items"] if not x["ok"]))
    app.db.kv_set(KV_VERIFY, res)
    return res


def verify_due(app, now: Optional[float] = None) -> bool:
    days = app.panel().sb_verify_days
    if days <= 0:
        return False
    last = app.db.kv_get(KV_VERIFY) or {}
    return (now or time.time()) - float(last.get("at") or 0) >= days * 86400
