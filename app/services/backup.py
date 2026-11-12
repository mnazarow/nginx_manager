"""Резервное копирование: экспорт/импорт настроек в JSON и копии базы данных."""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import VERSION, settings


def export_config(app, include_users: bool = False, include_certs: bool = True) -> Dict[str, Any]:
    db = app.db
    out: Dict[str, Any] = {
        "format": "nginx-manager-export", "version": VERSION, "exported_at": time.time(),
        "global": db.kv_get("global_settings", {}), "panel": db.kv_get("panel_settings", {}),
        "sites": [{"id": r["id"], "data": json.loads(r["data"])} for r in db.query("SELECT * FROM sites ORDER BY id")],
        "streams": [{"id": r["id"], "data": json.loads(r["data"])} for r in db.query("SELECT * FROM streams")],
        "alert_rules": [{**json.loads(r["data"]), "_id": r["id"]} for r in db.query("SELECT * FROM alert_rules")],
        "alert_channels": [{"id": r["id"], "data": json.loads(r["data"])} for r in db.query("SELECT * FROM alert_channels")],
        "dns_accounts": [{"id": r["id"], "data": json.loads(r["data"])} for r in db.query("SELECT * FROM dns_accounts")],
        "certificates": [],
    }
    for c in db.query("SELECT * FROM certificates"):
        item = {k: c[k] for k in ("id", "name", "type", "domains", "cert_path", "key_path", "data", "status")}
        if include_certs and c["type"] in ("upload", "selfsigned"):
            try:
                item["cert_pem"] = Path(c["cert_path"]).read_text()
                item["key_pem_b64"] = base64.b64encode(Path(c["key_path"]).read_bytes()).decode()
            except OSError:
                pass
        out["certificates"].append(item)
    if include_users:
        out["users"] = db.query("SELECT username, password_hash, role, totp_secret, totp_enabled, disabled FROM users")
    return out


def import_config(app, data: Dict[str, Any], mode: str = "replace") -> Dict[str, Any]:
    """Импорт настроек из экспорта. Любая ошибка в данных — ValueError с понятным текстом; база при этом не меняется
    (всё пишется в одной транзакции)."""
    if not isinstance(data, dict) or data.get("format") != "nginx-manager-export":
        raise ValueError("Это не файл экспорта Nginx Manager")
    try:
        return _import_config(app, data, mode)
    except ValueError:
        raise
    except (KeyError, TypeError, AttributeError, binascii.Error) as e:
        raise ValueError(f"Файл экспорта повреждён: нет или неверно поле {e}") from e
    except sqlite3.IntegrityError as e:
        raise ValueError(f"Файл экспорта противоречив (повторяющиеся номера или имена): {e}") from e


def _import_config(app, data: Dict[str, Any], mode: str) -> Dict[str, Any]:
    from ..models import AlertChannel, AlertRule, DnsAccount, GlobalSettings, PanelSettings, Site, Stream
    db = app.db
    now = time.time()
    stats = {"sites": 0, "streams": 0, "certificates": 0, "rules": 0, "channels": 0}
    # валидация до записи
    sites = [(s.get("id"), Site.model_validate(s["data"])) for s in data.get("sites", [])]
    streams = [(s.get("id"), Stream.model_validate(s["data"])) for s in data.get("streams", [])]
    glob = GlobalSettings.model_validate(data.get("global", {}))
    dns = [(a.get("id"), DnsAccount.model_validate(a["data"])) for a in data.get("dns_accounts", [])]
    for u in data.get("users") or []:
        if u.get("role") not in ("viewer", "operator", "admin") or not str(u.get("username") or "").strip() \
                or not str(u.get("password_hash") or "").startswith("scrypt$"):
            raise ValueError(f"Неверная запись пользователя в файле экспорта: {u.get('username')!r}")
    cert_map: Dict[int, int] = {}
    with db.transaction() as c:
        if mode == "replace":
            for t in ("sites", "streams", "alert_rules", "alert_channels", "dns_accounts"):
                c.execute(f"DELETE FROM {t}")
        dns_map: Dict[int, int] = {}
        for aid, acc in dns:
            body = json.dumps(acc.model_dump(), ensure_ascii=False)
            if mode == "replace" and aid:
                c.execute("INSERT INTO dns_accounts(id,name,provider,data,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                          (aid, acc.name, acc.provider, body, now, now))
                dns_map[aid] = aid
            else:
                dns_map[aid or 0] = c.execute("INSERT INTO dns_accounts(name,provider,data,created_at,updated_at) "
                                              "VALUES(?,?,?,?,?)", (acc.name, acc.provider, body, now, now)).lastrowid
            stats["dns_accounts"] = stats.get("dns_accounts", 0) + 1
        for cert in data.get("certificates", []):
            cdata = json.loads(cert.get("data") or "{}") if isinstance(cert.get("data"), str) else (cert.get("data") or {})
            if cdata.get("dns_account_id") in dns_map:
                cdata["dns_account_id"] = dns_map[cdata["dns_account_id"]]
                cert = dict(cert, data=json.dumps(cdata, ensure_ascii=False))
            existing = c.execute("SELECT id FROM certificates WHERE name=? AND type=?",
                                 (cert["name"], cert["type"])).fetchone()
            if existing:
                cert_map[cert["id"]] = existing[0]
                continue
            cur = c.execute("INSERT INTO certificates(name,type,domains,cert_path,key_path,status,data,created_at,"
                            "updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                            (cert["name"], cert["type"], cert["domains"], cert["cert_path"], cert["key_path"],
                             "pending" if cert.get("cert_pem") else cert.get("status", "valid"), cert["data"], now, now))
            new_id = cur.lastrowid
            cert_map[cert["id"]] = new_id
            if cert.get("cert_pem") and cert.get("key_pem_b64"):
                d = settings.certs_dir / str(new_id)
                d.mkdir(parents=True, exist_ok=True)
                (d / "fullchain.pem").write_text(cert["cert_pem"])
                kp = d / "privkey.pem"
                kp.write_bytes(base64.b64decode(cert["key_pem_b64"]))
                kp.chmod(0o600)
                c.execute("UPDATE certificates SET cert_path=?, key_path=?, status='valid' WHERE id=?",
                          (str(d / "fullchain.pem"), str(kp), new_id))
            stats["certificates"] += 1
        keep_ids = mode == "replace"  # при замене номера сохраняются (история статистики и ссылки на них)
        site_map: Dict[str, str] = {}
        for sid, s in sites:
            if s.ssl.certificate_id in cert_map:
                s.ssl.certificate_id = cert_map[s.ssl.certificate_id]
            body = json.dumps(s.model_dump(), ensure_ascii=False)
            if keep_ids and sid:
                c.execute("INSERT INTO sites(id,name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                          (sid, s.name, int(s.enabled), body, now, now))
                new_id = sid
            else:
                new_id = c.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                                   (s.name, int(s.enabled), body, now, now)).lastrowid
            if sid:
                site_map[str(sid)] = str(new_id)
            stats["sites"] += 1
        for stid, s in streams:
            body = json.dumps(s.model_dump(), ensure_ascii=False)
            if keep_ids and stid:
                c.execute("INSERT INTO streams(id,name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                          (stid, s.name, int(s.enabled), body, now, now))
            else:
                c.execute("INSERT INTO streams(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                          (s.name, int(s.enabled), body, now, now))
            stats["streams"] += 1
        chan_map: Dict[int, int] = {}
        for ch in data.get("alert_channels", []):
            m = AlertChannel.model_validate(ch["data"])
            body = json.dumps(m.model_dump(), ensure_ascii=False)
            if keep_ids and ch.get("id"):
                c.execute("INSERT INTO alert_channels(id,name,type,enabled,data,created_at,updated_at) "
                          "VALUES(?,?,?,?,?,?,?)", (ch["id"], m.name, m.type, int(m.enabled), body, now, now))
                chan_map[ch["id"]] = ch["id"]
            else:
                cur = c.execute("INSERT INTO alert_channels(name,type,enabled,data,created_at,updated_at) "
                                "VALUES(?,?,?,?,?,?)", (m.name, m.type, int(m.enabled), body, now, now))
                chan_map[ch.get("id", 0)] = cur.lastrowid
            stats["channels"] += 1
        for r in data.get("alert_rules", []):
            r = dict(r)
            rid = r.pop("_id", None)
            m = AlertRule.model_validate(r)
            m.channels = [chan_map.get(x, x) for x in m.channels]
            m.site = site_map.get(m.site, m.site)  # правило по сайту — на новый номер сайта (режим «добавить»)
            body = json.dumps(m.model_dump(), ensure_ascii=False)
            if keep_ids and rid:
                c.execute("INSERT INTO alert_rules(id,name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                          (rid, m.name, int(m.enabled), body, now, now))
            else:
                c.execute("INSERT INTO alert_rules(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                          (m.name, int(m.enabled), body, now, now))
            stats["rules"] += 1
        c.execute("INSERT INTO kv(key,value) VALUES('global_settings',?) ON CONFLICT(key) DO UPDATE "
                  "SET value=excluded.value", (json.dumps(glob.model_dump(), ensure_ascii=False),))
        if data.get("panel"):
            pnl = PanelSettings.model_validate(data["panel"])
            if pnl.panel_certificate_id in cert_map:
                pnl.panel_certificate_id = cert_map[pnl.panel_certificate_id]
            pnl.report_channels = [chan_map.get(x, x) for x in pnl.report_channels]
            c.execute("INSERT INTO kv(key,value) VALUES('panel_settings',?) ON CONFLICT(key) DO UPDATE "
                      "SET value=excluded.value", (json.dumps(pnl.model_dump(), ensure_ascii=False),))
    if data.get("users"):
        for u in data["users"]:
            if not db.one("SELECT 1 FROM users WHERE username=?", (u["username"],)):
                db.execute("INSERT INTO users(username,password_hash,role,totp_secret,totp_enabled,disabled,created_at)"
                           " VALUES(?,?,?,?,?,?,?)", (u["username"], u["password_hash"], u["role"],
                                                       u.get("totp_secret", ""), u.get("totp_enabled", 0),
                                                       u.get("disabled", 0), now))
    app.certs.refresh_all()
    app._panel = None
    app.touch()
    return stats


def db_backup(app, label: str = "manual") -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    dest = settings.backups_dir / f"nginx-manager-{ts}-{label}.db"
    app.db.backup_to(dest)
    dest.chmod(0o600)
    js = settings.backups_dir / f"nginx-manager-{ts}-{label}.json"
    js.write_text(json.dumps(export_config(app, include_users=True), ensure_ascii=False, indent=1))
    js.chmod(0o600)
    return dest


def prune_backups(keep_auto: int, keep_update: int) -> List[str]:
    """Удалить старые копии: ежедневные (оставить keep_auto), сделанные при обновлениях, из консоли, перед импортом
    и восстановлением — базы, код прежних версий и nginx.conf (оставить keep_update каждого вида). Ручные копии из
    панели и скачанные из хранилища не трогаются."""
    d = settings.backups_dir
    removed: List[str] = []
    groups = [(sorted(d.glob("nginx-manager-*-auto.db")), keep_auto),
              (sorted(d.glob("nginx-manager-*-cli.db")), keep_update),
              (sorted(d.glob("nginx-manager-*-preupdate.db")), keep_update),
              (sorted(d.glob("nginx-manager-*-before-import.db")), keep_update),
              (sorted(d.glob("nginx-manager-*-before-restore.db")), keep_update),
              (sorted(d.glob("code-*.tar.gz"), key=lambda p: p.stat().st_mtime), keep_update),
              (sorted(d.glob("nginx.conf-*")), keep_update * 2)]
    for files, keep in groups:
        for old in files[:-keep] if keep > 0 else files:
            old.unlink(missing_ok=True)
            if old.suffix == ".db":
                old.with_suffix(".json").unlink(missing_ok=True)
            removed.append(old.name)
    return removed


def auto_backup(app) -> Path:
    p = db_backup(app, "auto")
    pnl = app.panel()
    removed = prune_backups(pnl.backup_keep, pnl.backup_keep_update)
    app.db.event("info", "backup", f"Автоматическая резервная копия: {p.name}"
                 + (f"; удалено старых копий: {len(removed)}" if removed else ""))
    if pnl.s3_enabled:
        offsite_upload(app, p)
    return p


# =============================================================================
#  Выгрузка во внешнее S3-хранилище
# =============================================================================
OPENSSL_ENC = ["-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt"]


def s3_client(p):
    from .s3 import S3Client
    return S3Client(p.s3_endpoint, p.s3_region, p.s3_bucket, p.s3_access_key, p.s3_secret_key, p.s3_path_style)


def _encrypt(src: Path, password: str) -> Path:
    from ..utils import run
    dest = src.with_name(src.name + ".enc")
    code, out = run(["openssl", "enc", *OPENSSL_ENC, "-in", str(src), "-out", str(dest), "-pass", "env:NM_BACKUP_PASS"],
                    timeout=600, env={"NM_BACKUP_PASS": password})
    if code != 0:
        dest.unlink(missing_ok=True)
        raise RuntimeError("шифрование не удалось: " + out[-300:])
    dest.chmod(0o600)
    return dest


def _decrypt(src: Path, password: str) -> Path:
    from ..utils import run
    dest = src.with_name(src.name[:-4])
    code, out = run(["openssl", "enc", "-d", *OPENSSL_ENC, "-in", str(src), "-out", str(dest),
                     "-pass", "env:NM_BACKUP_PASS"], timeout=600, env={"NM_BACKUP_PASS": password})
    if code != 0:
        dest.unlink(missing_ok=True)
        raise ValueError("Не удалось расшифровать: неверный пароль шифрования или файл повреждён")
    dest.chmod(0o600)
    return dest


def offsite_upload(app, db_path: Path) -> Dict[str, Any]:
    """Выгрузить копию (база в gzip + JSON-экспорт) в S3, при необходимости зашифровав, и удалить в хранилище
    копии сверх «Хранить копий в хранилище». Результат — в kv offsite_last и в журнале событий."""
    import gzip
    import shutil
    p = app.panel()
    files: List[Path] = []
    tmp: List[Path] = []
    res: Dict[str, Any] = {"ts": time.time(), "ok": False, "files": [], "error": ""}
    try:
        js = db_path.with_suffix(".json")
        if js.exists():
            files.append(js)
        if p.s3_include_db:
            gz = db_path.with_name(db_path.name + ".gz")
            with open(db_path, "rb") as fi, gzip.open(gz, "wb", compresslevel=6) as fo:
                shutil.copyfileobj(fi, fo, 1 << 20)
            gz.chmod(0o600)
            files.append(gz)
            tmp.append(gz)
        if p.s3_encrypt_password:
            enc = [_encrypt(f, p.s3_encrypt_password) for f in files]
            tmp += enc
            files = enc
        cl = s3_client(p)
        for f in files:
            cl.put_file(p.s3_prefix + f.name, f)
            res["files"].append({"key": p.s3_prefix + f.name, "size": f.stat().st_size})
        res["removed"] = prune_offsite(cl, p.s3_prefix, p.s3_keep) if p.s3_keep else []
        res["ok"] = True
        size = sum(x["size"] for x in res["files"])
        app.db.event("info", "backup", f"Копия выгружена в хранилище {p.s3_bucket}: {len(files)} файл(а), "
                                       f"{size / 1048576:.1f} МБ" + (", зашифровано" if p.s3_encrypt_password else "")
                     + (f"; удалено старых: {len(res['removed'])}" if res["removed"] else ""))
    except Exception as e:
        res["error"] = str(e)[:500]
        app.db.event("error", "backup", f"Не удалось выгрузить копию в хранилище {p.s3_bucket}: {res['error']}")
    finally:
        for f in tmp:
            f.unlink(missing_ok=True)
        app.db.kv_set("offsite_last", res)
    return res


def _stamp(key: str) -> str:
    """Отметка копии в имени: nginx-manager-20261112-030000-auto.db.gz → 20261112-030000-auto."""
    name = key.rsplit("/", 1)[-1]
    m = re.match(r"^nginx-manager-(\d{8}-\d{6}-[a-z-]+?)\.", name)
    return m.group(1) if m else ""


def prune_offsite(cl, prefix: str, keep: int) -> List[str]:
    """Оставить в хранилище `keep` последних копий (копия — все файлы одной отметки времени)."""
    objs = [o for o in cl.list(prefix) if _stamp(o["key"]) and "/" not in o["key"][len(prefix):]]
    stamps = sorted({_stamp(o["key"]) for o in objs}, reverse=True)
    old = set(stamps[keep:])
    removed = []
    for o in objs:
        if _stamp(o["key"]) in old:
            cl.delete(o["key"])
            removed.append(o["key"])
    return removed


def offsite_list(app) -> List[Dict[str, Any]]:
    p = app.panel()
    out = []
    for o in s3_client(p).list(p.s3_prefix):
        if "/" in o["key"][len(p.s3_prefix):]:
            continue
        o["name"] = o["key"][len(p.s3_prefix):]
        o["encrypted"] = o["name"].endswith(".enc")
        out.append(o)
    return sorted(out, key=lambda o: o["name"], reverse=True)


def offsite_download(app, name: str) -> str:
    """Скачать копию из хранилища в каталог копий сервера: расшифровать и распаковать базу. Возвращает имя файла."""
    import gzip
    import shutil
    p = app.panel()
    name = Path(name).name
    if not name.startswith("nginx-manager-"):
        raise ValueError("Это не копия Nginx Manager")
    dest = settings.backups_dir / name
    s3_client(p).get_to_file(p.s3_prefix + name, dest)
    dest.chmod(0o600)
    if dest.name.endswith(".enc"):
        if not p.s3_encrypt_password:
            raise ValueError("Копия зашифрована — укажите пароль шифрования в настройках, затем скачайте снова")
        try:
            plain = _decrypt(dest, p.s3_encrypt_password)
        finally:
            dest.unlink(missing_ok=True)
        dest = plain
    if dest.name.endswith(".gz"):
        out = dest.with_name(dest.name[:-3])
        with gzip.open(dest, "rb") as fi, open(out, "wb") as fo:
            shutil.copyfileobj(fi, fo, 1 << 20)
        out.chmod(0o600)
        dest.unlink(missing_ok=True)
        dest = out
    return dest.name


def offsite_check(app) -> Dict[str, Any]:
    """Проверка доступа: записать, прочитать список и удалить маленький объект."""
    import secrets
    p = app.panel()
    cl = s3_client(p)
    key = f"{p.s3_prefix}.nm-check-{secrets.token_hex(4)}"
    steps = []
    cl.put_bytes(key, b"nginx-manager check\n")
    steps.append("запись — ок")
    found = any(o["key"] == key for o in cl.list(p.s3_prefix))
    steps.append("чтение списка — ок" if found else "чтение списка — объект не найден (хранилище с задержкой?)")
    cl.delete(key)
    steps.append("удаление — ок")
    return {"ok": True, "steps": steps}


def list_backups() -> List[Dict[str, Any]]:
    out = []
    for p in sorted(settings.backups_dir.glob("nginx-manager-*"), reverse=True):
        if p.suffix not in (".db", ".json", ".gz", ".enc"):  # служебные файлы SQLite (-wal, -shm) и временные
            continue
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size, "mtime": st.st_mtime, "kind": p.suffix[1:]})
    return out


# =============================================================================
#  Восстановление базы из копии
# =============================================================================
#  Работающую базу нельзя подменить «на ходу»: её держат открытой сборщик статистики, фоновые задачи и запросы.
#  Поэтому восстановление двухшаговое: панель проверяет копию, сохраняет текущую базу (before-restore), кладёт
#  копию в data_dir/restore-pending.db и перезапускается; при старте, ДО открытия базы, apply_pending_restore()
#  ещё раз проверяет копию и заменяет ею файл базы. Итог пишется в журнал событий и аудита уже новой базы.
RESTORE_PENDING = "restore-pending.db"
RESTORE_META = "restore-pending.json"
RESTORE_RESULT = "restore-result.json"
RESTORE_LAST = "restore-last.json"
SQLITE_MAGIC = b"SQLite format 3\x00"


def _ro_connect(path: Path) -> sqlite3.Connection:
    """Открыть файл копии только для чтения, не создавая рядом -wal/-shm (immutable: файл никто не меняет)."""
    from urllib.request import pathname2url
    return sqlite3.connect(f"file:{pathname2url(str(Path(path).resolve()))}?immutable=1", uri=True)


def inspect_db(path: Path) -> Dict[str, Any]:
    """Проверить файл базы перед восстановлением и рассказать, что в нём. Любая проблема — ValueError с понятным
    текстом: не SQLite, повреждена, не база панели, сделана более новой версией, нет ни одного администратора."""
    from ..db import SCHEMA
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"Файл не найден: {path.name}")
    with open(path, "rb") as f:
        head = f.read(16)
    if head != SQLITE_MAGIC:
        hint = ""
        if head[:2] == b"\x1f\x8b":
            hint = " — это сжатый файл (.gz), сначала распакуйте его"
        elif head.startswith(b"Salted__"):
            hint = " — это зашифрованный файл (.enc), сначала расшифруйте его"
        elif head.lstrip()[:1] == b"{":
            hint = " — это экспорт настроек (JSON): загрузите его через «Импорт настроек»"
        raise ValueError(f"{path.name} не является файлом базы SQLite{hint}")
    con = None
    try:
        con = _ro_connect(path)
        chk = con.execute("PRAGMA quick_check").fetchone()[0]
        if chk != "ok":
            raise ValueError(f"База в копии повреждена (проверка целостности: {str(chk)[:200]})")
        ver = con.execute("PRAGMA user_version").fetchone()[0]
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if ver < 1 or not {"sites", "users", "kv", "config_versions"} <= tables:
            raise ValueError(f"{path.name} — база SQLite, но не база Nginx Manager")
        if ver > len(SCHEMA):
            raise ValueError(f"Копия сделана более новой версией панели (схема базы {ver}, эта версия знает схемы "
                             f"до {len(SCHEMA)}) — сначала обновите панель, затем восстанавливайте")
        users = [{"username": r[0], "role": r[1], "disabled": bool(r[2])}
                 for r in con.execute("SELECT username, role, disabled FROM users ORDER BY username")]
        admins = [u["username"] for u in users if u["role"] == "admin" and not u["disabled"]]
        if not admins:
            raise ValueError("В копии нет ни одного активного администратора — после восстановления войти в панель "
                             "было бы невозможно")

        def count(t: str) -> int:
            return con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] if t in tables else 0

        until = 0.0
        for t in ("events", "audit_log", "stats_minute"):
            if t in tables:
                until = max(until, con.execute(f"SELECT COALESCE(MAX(ts), 0) FROM {t}").fetchone()[0] or 0)
        last = con.execute("SELECT id, ts FROM config_versions WHERE status='applied' ORDER BY id DESC LIMIT 1") \
            .fetchone()
        st = path.stat()
        return {"name": path.name, "size": st.st_size, "mtime": st.st_mtime, "schema": ver,
                "schema_current": len(SCHEMA), "sites": count("sites"), "streams": count("streams"),
                "certificates": count("certificates"), "alert_rules": count("alert_rules"),
                "users": users, "admins": admins, "data_until": until or None,
                "last_applied": {"id": last[0], "ts": last[1]} if last else None}
    except sqlite3.DatabaseError as e:
        raise ValueError(f"Не удалось прочитать базу из копии: {e}") from e
    finally:
        if con is not None:
            con.close()


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
    tmp.chmod(0o600)
    os.replace(tmp, path)


def restore_pending() -> Optional[Dict[str, Any]]:
    """Запланированное, но ещё не выполненное восстановление (или None)."""
    if not (settings.data_dir / RESTORE_PENDING).exists():
        return None
    return _read_json(settings.data_dir / RESTORE_META) or {}


def schedule_restore(app, src: Path, user: str = "", ip: str = "") -> Dict[str, Any]:
    """Шаг 1 (работающая панель): проверить копию, сохранить текущую базу, положить копию на место ожидания.
    Сам файл базы заменит apply_pending_restore() при следующем запуске."""
    import shutil
    src = Path(src)
    info = inspect_db(src)
    safety = db_backup(app, "before-restore")
    pend = settings.data_dir / RESTORE_PENDING
    tmp = pend.with_name(pend.name + ".tmp")
    shutil.copyfile(src, tmp)
    tmp.chmod(0o600)
    os.replace(tmp, pend)
    meta = {"source": src.name, "user": user, "ip": ip, "ts": time.time(), "safety": safety.name}
    _write_json(settings.data_dir / RESTORE_META, meta)
    return {**meta, "info": info}


def cancel_restore() -> bool:
    found = (settings.data_dir / RESTORE_PENDING).exists()
    for n in (RESTORE_PENDING, RESTORE_META):
        (settings.data_dir / n).unlink(missing_ok=True)
    return found


def _running_config(db_path: Path) -> Optional[Dict[str, Any]]:
    """Последняя применённая версия конфигурации в текущей базе — то, что сейчас работает в nginx."""
    if not db_path.exists():
        return None
    con = sqlite3.connect(str(db_path), timeout=30)
    try:
        con.row_factory = sqlite3.Row
        r = con.execute("SELECT * FROM config_versions WHERE status='applied' ORDER BY id DESC LIMIT 1").fetchone()
        return dict(r) if r else None
    except sqlite3.DatabaseError:
        return None
    finally:
        con.close()


def _carry_running_config(db_path: Path, running: Optional[Dict[str, Any]]) -> Optional[int]:
    """Перенести в восстановленную базу версию конфигурации, которая реально работает в nginx. Тогда панель покажет
    честные «неприменённые изменения» (разницу между восстановленными настройками и работающим nginx), а к прежней
    конфигурации можно будет откатиться из «Истории версий»."""
    if not running:
        return None
    con = sqlite3.connect(str(db_path), timeout=30)
    try:
        last = con.execute("SELECT checksum FROM config_versions WHERE status='applied' ORDER BY id DESC LIMIT 1") \
            .fetchone()
        if last and last[0] and last[0] == running.get("checksum"):
            return None  # в nginx работает ровно то, что применено в копии
        cur = con.execute(
            "INSERT INTO config_versions(ts,username,comment,source,status,files,state,output,checksum) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (time.time(), running.get("username") or "system",
             f"Работавшая в nginx конфигурация на момент восстановления базы (в прежней базе — версия "
             f"{running['id']})", "restore", "applied", running["files"], running["state"], "",
             running.get("checksum")))
        vid = cur.lastrowid
        con.execute("INSERT INTO kv(key,value) VALUES('applied_version',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(vid),))
        con.commit()
        return vid
    finally:
        con.close()


def apply_pending_restore() -> Optional[Dict[str, Any]]:
    """Шаг 2 (запуск панели, база ещё не открыта): заменить файл базы запланированной копией.
    При любой ошибке остаётся прежняя база. Итог — в data_dir/restore-result.json (его прочтёт restore_report)."""
    d = settings.data_dir
    pend = d / RESTORE_PENDING
    if not pend.exists():
        return None
    res: Dict[str, Any] = dict(_read_json(d / RESTORE_META) or {}, ok=False, done_at=time.time(), error="")
    db = settings.db_path
    try:
        info = inspect_db(pend)
        running = _running_config(db)
        # сначала служебные файлы прежней базы: чужой журнал WAL нельзя оставлять рядом с новой базой
        for suf in ("-wal", "-shm", "-journal"):
            Path(str(db) + suf).unlink(missing_ok=True)
        os.replace(pend, db)
        os.chmod(db, 0o600)
        res.update(ok=True, schema=info["schema"], data_until=info["data_until"], sites=info["sites"],
                   carried_version=_carry_running_config(db, running))
    except Exception as e:  # noqa: BLE001 — панель должна запуститься с прежней базой при любой ошибке
        res["error"] = str(e).replace(RESTORE_PENDING, res.get("source") or RESTORE_PENDING)[:500]
        pend.unlink(missing_ok=True)
    (d / RESTORE_META).unlink(missing_ok=True)
    _write_json(d / RESTORE_RESULT, res)
    return res


def restore_report(app) -> Optional[Dict[str, Any]]:
    """После запуска: записать итог восстановления в журналы (уже восстановленной) базы и разослать уведомление."""
    d = settings.data_dir
    res = _read_json(d / RESTORE_RESULT)
    if res is None:
        return None
    who = res.get("user") or "nmctl"
    src = res.get("source") or "?"
    if res.get("ok"):
        try:
            pend = app.pending().get("pending")
        except Exception:  # noqa: BLE001
            pend = None
        res["pending"] = bool(pend)
        msg = (f"База восстановлена из копии {src} (запросил {who}); прежняя база сохранена как "
               f"{res.get('safety') or '—'}.")
        msg += (" Настройки в базе отличаются от работающей конфигурации nginx — проверьте изменения и примените."
                if pend else " Работающая конфигурация nginx совпадает с восстановленной.")
        app.db.event("warning", "backup", msg, res)
        app.db.audit(who, res.get("ip"), "backup_restored", src, {"safety": res.get("safety"),
                                                                 "carried_version": res.get("carried_version")})
    else:
        app.db.event("error", "backup", f"Восстановление базы из копии {src} не выполнено: {res.get('error')}. "
                                        "Панель работает с прежней базой.", res)
        app.db.audit(who, res.get("ip"), "backup_restore_failed", src, {"error": res.get("error")})
    app.db.kv_set("last_restore", res)
    os.replace(d / RESTORE_RESULT, d / RESTORE_LAST)
    return res
