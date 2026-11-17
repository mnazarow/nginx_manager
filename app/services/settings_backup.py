"""Резервная копия всех настроек и восстановление из неё.

Копия — архив tar.gz (по желанию зашифрованный паролем, AES-256 через openssl, как копии в S3):

    manifest.json        формат, версия панели, время, сервер, разделы с числом записей, контрольные суммы файлов
    settings.json        разделы: строки таблиц (сайты, потоки, сертификаты, учётные записи DNS, оповещения,
                         пользователи и API-токены, ручные блокировки) и настройки (nginx, панель, защита, секреты)
    certs/<id>/…         сертификат и закрытый ключ каждого сертификата (любого типа)
    letsencrypt/…        выпущенные по ACME сертификаты certbot (live, archive, renewal) и учётные записи ACME —
                         продление продолжится на новом сервере

Статистика, журналы и история версий в копию настроек не входят (для них — копия базы). Восстановление — по
выбранным разделам: каждый раздел заменяется целиком содержимым копии (номера сохраняются, ссылки сайтов на
сертификаты остаются верными). Перед восстановлением создаётся копия текущих настроек; если nginx не принял
новую конфигурацию, настройки возвращаются из неё автоматически.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import socket
import tarfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import VERSION, settings

FORMAT = "nginx-manager-settings"
LE_DIR = Path("/etc/letsencrypt")  # certbot (подменяется в тестах)
MAX_MEMBER = 64 << 20

SECTIONS: Dict[str, str] = {
    "sites": "Сайты (с доступом по IP и защитой сайтов)",
    "streams": "TCP/UDP-потоки",
    "certificates": "Сертификаты и закрытые ключи (с данными certbot для продления)",
    "dns": "Учётные записи DNS (для wildcard-сертификатов)",
    "global": "Настройки nginx",
    "panel": "Настройки панели (доверенные адреса, другие серверы, S3, отчёты, оповещения о событиях)",
    "protection": "Защита от атак",
    "alerts": "Оповещения: правила, каналы, тишина",
    "users": "Пользователи, 2FA и API-токены",
    "bans": "Ручные блокировки IP",
    "secrets": "Ключи проверки браузера и кнопок Telegram",
}
# таблицы разделов (строки копируются по общим столбцам — так копия старой версии восстанавливается в новой)
TABLES: Dict[str, List[Tuple[str, str]]] = {
    "sites": [("sites", "")],
    "streams": [("streams", "")],
    "certificates": [("certificates", "")],
    "dns": [("dns_accounts", "")],
    "alerts": [("alert_channels", ""), ("alert_rules", ""), ("silences", "WHERE ends_at > strftime('%s','now')")],
    "users": [("users", ""), ("api_tokens", "")],
    "bans": [("bans", "WHERE source='manual' AND (expires_at IS NULL OR expires_at > strftime('%s','now'))")],
}
KV: Dict[str, List[str]] = {"global": ["global_settings"], "panel": ["panel_settings"],
                            "protection": ["protection_settings"], "secrets": ["challenge_secret", "tg_actions_secret"]}
NGINX_SECTIONS = {"sites", "streams", "certificates", "global", "protection", "panel", "bans"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rows(db, table: str, where: str) -> Dict[str, Any]:
    cur = db.conn().execute(f"SELECT * FROM {table} {where}")  # noqa: S608 — имена таблиц из констант
    cols = [d[0] for d in cur.description]
    return {"columns": cols, "rows": [list(r) for r in cur.fetchall()]}


def _le_lineages(db) -> List[str]:
    out = []
    for r in db.query("SELECT data FROM certificates WHERE type='letsencrypt'"):
        name = (json.loads(r["data"] or "{}") or {}).get("cert_name")
        if name and re.match(r"^[A-Za-z0-9._-]+$", name):
            out.append(name)
    return out


# =============================================================================
#  Создание
# =============================================================================
def collect(app, sections: Optional[List[str]] = None) -> Tuple[Dict[str, Any], Dict[str, bytes], Dict[str, Any]]:
    """(settings.json, файлы архива {путь: содержимое}, сводка по разделам)."""
    db = app.db
    sections = [s for s in (sections or list(SECTIONS)) if s in SECTIONS]
    data: Dict[str, Any] = {}
    files: Dict[str, bytes] = {}
    summary: Dict[str, Any] = {}
    for sec in sections:
        part: Dict[str, Any] = {}
        for table, where in TABLES.get(sec, []):
            part[table] = _rows(db, table, where)
        for key in KV.get(sec, []):
            v = db.kv_get(key)
            if v is not None:
                part[key] = v
        data[sec] = part
        summary[sec] = sum(len(t["rows"]) for t in part.values() if isinstance(t, dict) and "rows" in t) \
            if TABLES.get(sec) else len(part)
    if "certificates" in sections:
        for c in db.query("SELECT id, cert_path, key_path FROM certificates"):
            for fname, path in (("fullchain.pem", c["cert_path"]), ("privkey.pem", c["key_path"])):
                try:
                    if path and Path(path).is_file():
                        files[f"certs/{c['id']}/{fname}"] = Path(path).read_bytes()
                except OSError:
                    pass
        names = _le_lineages(db)
        if names and LE_DIR.is_dir():
            roots = [LE_DIR / "accounts"] + [LE_DIR / d / n for n in names for d in ("live", "archive")]
            roots += [LE_DIR / "renewal" / f"{n}.conf" for n in names]
            for root in roots:
                if not root.exists():
                    continue
                for p in ([root] if root.is_file() else sorted(root.rglob("*"))):
                    rel = "letsencrypt/" + str(p.relative_to(LE_DIR))
                    if p.is_symlink():
                        files[rel] = ("@link:" + os.readlink(p)).encode()
                    elif p.is_file():
                        files[rel] = p.read_bytes()
        summary["certificate_files"] = sum(1 for k in files if k.startswith("certs/"))
        summary["letsencrypt_files"] = sum(1 for k in files if k.startswith("letsencrypt/"))
    return data, files, summary


def create(app, label: str = "manual", sections: Optional[List[str]] = None, password: str = "",
           dest_dir: Optional[Path] = None, ts: Optional[str] = None) -> Path:
    """Создать архив в каталоге копий: nginx-manager-<время>-<метка>.settings.tar.gz[.enc]."""
    from .backup import _encrypt
    data, files, summary = collect(app, sections)
    ts = ts or time.strftime("%Y%m%d-%H%M%S")
    dest_dir = dest_dir or settings.backups_dir
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"nginx-manager-{ts}-{label}.settings.tar.gz"
    n = 1
    while path.exists() or path.with_name(path.name + ".enc").exists():  # две копии в одну секунду
        n += 1
        path = dest_dir / f"nginx-manager-{ts}-{label}-{n}.settings.tar.gz"
    body = json.dumps(data, ensure_ascii=False, indent=1).encode()
    manifest = {"format": FORMAT, "version": VERSION, "schema": app.db.schema_version, "created_at": time.time(),
                "host": socket.gethostname(), "sections": summary, "label": label,
                "files": {"settings.json": _sha(body), **{k: _sha(v) for k, v in files.items()}}}
    tmp = path.with_name(path.name + ".part")
    with tarfile.open(tmp, "w:gz", compresslevel=6) as tar:
        for name, blob in [("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1).encode()),
                           ("settings.json", body), *sorted(files.items())]:
            info = tarfile.TarInfo(name)
            if blob.startswith(b"@link:") and name.startswith("letsencrypt/"):
                info.type = tarfile.SYMTYPE
                info.linkname = blob[6:].decode()
                tar.addfile(info)
                continue
            info.size = len(blob)
            info.mtime = int(time.time())
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(blob))
    tmp.chmod(0o600)
    tmp.rename(path)
    if password:
        enc = _encrypt(path, password)
        path.unlink(missing_ok=True)
        return enc
    return path


# =============================================================================
#  Чтение и проверка
# =============================================================================
def is_settings_file(name: str) -> bool:
    return name.endswith(".settings.tar.gz") or name.endswith(".settings.tar.gz.enc")


def _open(path: Path, password: str) -> Tuple[Path, Optional[Path]]:
    """Путь к tar.gz (расшифрованному во временный файл, если копия зашифрована) и временный файл для удаления."""
    from .backup import _decrypt
    if path.name.endswith(".enc"):
        if not password:
            raise ValueError("Копия зашифрована — укажите пароль")
        tmp = path.with_name(f".restore-{os.getpid()}-{int(time.time() * 1000)}-" + path.name)
        tmp.write_bytes(path.read_bytes())
        tmp.chmod(0o600)
        try:
            plain = _decrypt(tmp, password)
        finally:
            tmp.unlink(missing_ok=True)
        return plain, plain
    return path, None


def read(path: Path, password: str = "") -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, bytes]]:
    """(manifest, settings, файлы). Проверяет формат, контрольные суммы и имена файлов в архиве."""
    plain, tmp = _open(path, password)
    try:
        try:
            tar = tarfile.open(plain, "r:gz")
        except (tarfile.TarError, OSError, EOFError) as e:
            raise ValueError(f"Это не копия настроек Nginx Manager (архив не читается: {e})")
        manifest: Dict[str, Any] = {}
        data: Dict[str, Any] = {}
        files: Dict[str, bytes] = {}
        with tar:
            for m in tar.getmembers():
                name = m.name
                if name.startswith("/") or ".." in Path(name).parts or "\\" in name:
                    raise ValueError(f"Недопустимое имя в архиве: {name}")
                if m.issym():
                    if not name.startswith("letsencrypt/") or m.linkname.startswith("/") or \
                            not _inside(name, m.linkname):
                        raise ValueError(f"Недопустимая ссылка в архиве: {name} → {m.linkname}")
                    files[name] = ("@link:" + m.linkname).encode()
                    continue
                if not m.isfile():
                    continue
                if m.size > MAX_MEMBER:
                    raise ValueError(f"Слишком большой файл в архиве: {name}")
                blob = tar.extractfile(m).read()
                if name == "manifest.json":
                    manifest = json.loads(blob)
                elif name == "settings.json":
                    data = json.loads(blob)
                    files[name] = blob
                elif name.startswith(("certs/", "letsencrypt/")):
                    files[name] = blob
        if manifest.get("format") != FORMAT:
            raise ValueError("Это не копия настроек Nginx Manager (нет manifest.json нужного формата)")
        for name, digest in (manifest.get("files") or {}).items():
            blob = files.get(name)
            if blob is None or (not blob.startswith(b"@link:") and _sha(blob) != digest):
                raise ValueError(f"Копия повреждена: не совпадает контрольная сумма {name}")
        files.pop("settings.json", None)
        return manifest, data, files
    finally:
        if tmp:
            tmp.unlink(missing_ok=True)


def _inside(name: str, link: str) -> bool:
    base = Path("/x") / Path(name).parent
    return str(Path(os.path.normpath(base / link))).startswith("/x/")


def _vkey(v: str) -> Tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except ValueError:
        return (0,)


def inspect(path: Path, password: str = "") -> Dict[str, Any]:
    manifest, data, files = read(path, password)
    secs = []
    for key, title in SECTIONS.items():
        part = data.get(key)
        if part is None:
            continue
        item: Dict[str, Any] = {"id": key, "title": title, "count": 0, "names": []}
        for table, _ in TABLES.get(key, []):
            t = part.get(table) or {"columns": [], "rows": []}
            item["count"] += len(t["rows"])
            cols = t["columns"]
            for col in ("name", "net", "username"):
                if col in cols:
                    item["names"] += [str(r[cols.index(col)]) for r in t["rows"][:30]]
                    break
        if not TABLES.get(key):
            item["count"] = len(part)
        secs.append(item)
    warn = []
    if _vkey(str(manifest.get("version", ""))) > _vkey(VERSION):
        warn.append(f"Копия сделана более новой версией {manifest.get('version')} (здесь {VERSION}): новые "
                    "параметры, которых эта версия не знает, будут пропущены")
    pnl = ((data.get("panel") or {}).get("panel_settings") or {})
    if pnl.get("panel_allow"):
        warn.append("В настройках панели из копии включён доступ к панели только с адресов: "
                    + ", ".join(pnl["panel_allow"][:5]) + " — проверьте, что ваш адрес среди них")
    if manifest.get("host") and manifest["host"] != socket.gethostname():
        warn.append(f"Копия с другого сервера ({manifest['host']})")
    return {"manifest": {k: manifest.get(k) for k in ("version", "schema", "created_at", "host", "label")},
            "sections": secs, "files": {"certs": sum(1 for k in files if k.startswith("certs/")),
                                        "letsencrypt": sum(1 for k in files if k.startswith("letsencrypt/"))},
            "warnings": warn, "encrypted": path.name.endswith(".enc"), "size": path.stat().st_size,
            "name": path.name}


# =============================================================================
#  Восстановление
# =============================================================================
def _validate(data: Dict[str, Any], sections: List[str]) -> None:
    from ..models import (AlertChannel, AlertRule, DnsAccount, GlobalSettings, PanelSettings, ProtectionSettings,
                          Site, Stream)
    checks = {"sites": ("sites", Site), "streams": ("streams", Stream), "dns": ("dns_accounts", DnsAccount)}
    for sec in sections:
        part = data.get(sec)
        if part is None:
            raise ValueError(f"В копии нет раздела «{SECTIONS.get(sec, sec)}»")
        if sec in checks:
            table, model = checks[sec]
            t = part.get(table) or {"columns": [], "rows": []}
            for r in t["rows"]:
                row = dict(zip(t["columns"], r))
                try:
                    model.model_validate(json.loads(row["data"]))
                except Exception as e:  # noqa: BLE001
                    raise ValueError(f"{SECTIONS[sec]}: «{row.get('name')}» — {str(e)[:300]}")
        if sec == "alerts":
            for table, model in (("alert_rules", AlertRule), ("alert_channels", AlertChannel)):
                t = part.get(table) or {"columns": [], "rows": []}
                for r in t["rows"]:
                    model.model_validate(json.loads(dict(zip(t["columns"], r))["data"]))
        if sec == "users":
            t = part.get("users") or {"columns": [], "rows": []}
            users = [dict(zip(t["columns"], r)) for r in t["rows"]]
            if not any(u.get("role") == "admin" and not u.get("disabled") for u in users):
                raise ValueError("В копии нет ни одного включённого администратора — после восстановления в панель "
                                 "нельзя было бы войти")
            for u in users:
                if not str(u.get("password_hash") or "").startswith("scrypt$"):
                    raise ValueError(f"Неверная запись пользователя в копии: {u.get('username')!r}")
        for key, model in (("global_settings", GlobalSettings), ("panel_settings", PanelSettings),
                           ("protection_settings", ProtectionSettings)):
            if sec in KV and key in KV[sec] and key in part:
                model.model_validate(part[key])


def _table_cols(conn, table: str) -> List[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _restore_files(cert_rows: List[Dict[str, Any]], files: Dict[str, bytes], with_le: bool) -> Dict[int, Tuple[str, str]]:
    """Записать файлы сертификатов; вернуть {id: (cert_path, key_path)}."""
    paths: Dict[int, Tuple[str, str]] = {}
    if with_le:
        for name, blob in sorted(files.items()):
            if not name.startswith("letsencrypt/"):
                continue
            target = LE_DIR / name[len("letsencrypt/"):]
            target.parent.mkdir(parents=True, exist_ok=True)
            if blob.startswith(b"@link:"):
                if target.is_symlink() or target.exists():
                    target.unlink()
                os.symlink(blob[6:].decode(), target)
            else:
                target.write_bytes(blob)
                target.chmod(0o600 if "privkey" in target.name or "/accounts/" in name else 0o644)
    for row in cert_rows:
        cid = int(row["id"])
        cert, key = files.get(f"certs/{cid}/fullchain.pem"), files.get(f"certs/{cid}/privkey.pem")
        cp, kp = row.get("cert_path") or "", row.get("key_path") or ""
        le_ok = row.get("type") == "letsencrypt" and with_le and cp and Path(cp).is_file() and Path(kp).is_file()
        if le_ok or not (cert and key):
            paths[cid] = (cp, kp)
            continue
        d = settings.certs_dir / str(cid)
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        (d / "fullchain.pem").write_bytes(cert)
        (d / "privkey.pem").write_bytes(key)
        os.chmod(d / "privkey.pem", 0o600)
        paths[cid] = (str(d / "fullchain.pem"), str(d / "privkey.pem"))
    return paths


def restore(app, path: Path, sections: List[str], password: str = "", user: str = "") -> Dict[str, Any]:
    """Заменить выбранные разделы содержимым копии (одной транзакцией). Возвращает сводку и примечания."""
    manifest, data, files = read(path, password)
    sections = [s for s in sections if s in SECTIONS]
    if not sections:
        raise ValueError("Выберите хотя бы один раздел")
    _validate(data, sections)
    db = app.db
    notes: List[str] = []
    stats: Dict[str, int] = {}
    cert_rows: List[Dict[str, Any]] = []
    if "certificates" in sections:
        t = data["certificates"].get("certificates") or {"columns": [], "rows": []}
        cert_rows = [dict(zip(t["columns"], r)) for r in t["rows"]]
    paths = _restore_files(cert_rows, files, "certificates" in sections) if cert_rows else {}
    with db.transaction() as c:
        for sec in sections:
            part = data[sec]
            for table, where in TABLES.get(sec, []):
                t = part.get(table) or {"columns": [], "rows": []}
                cols = [x for x in t["columns"] if x in _table_cols(c, table)]
                c.execute(f"DELETE FROM {table} {where}")  # noqa: S608
                for r in t["rows"]:
                    row = dict(zip(t["columns"], r))
                    if table == "certificates" and int(row["id"]) in paths:
                        row["cert_path"], row["key_path"] = paths[int(row["id"])]
                    if table == "bans" and c.execute("SELECT 1 FROM bans WHERE net=?", (row["net"],)).fetchone():
                        c.execute("DELETE FROM bans WHERE net=?", (row["net"],))  # своя (автоматическая) — заменяется
                    c.execute(f"INSERT INTO {table}({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                              [row[x] for x in cols])
                stats[table] = len(t["rows"])
            for key in KV.get(sec, []):
                if key in part:
                    c.execute("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                              (key, json.dumps(part[key], ensure_ascii=False)))
                    stats[key] = 1
        if "users" in sections:
            c.execute("DELETE FROM sessions")  # все входят заново — пользователи и пароли теперь как в копии
        # ссылки на сертификаты: без раздела «Сертификаты» сайты из копии могли сослаться на чужие номера
        have = {r[0] for r in c.execute("SELECT id FROM certificates")}
        for sid, name, raw in c.execute("SELECT id, name, data FROM sites").fetchall():
            d = json.loads(raw)
            ssl = d.get("ssl") or {}
            if ssl.get("enabled") and ssl.get("certificate_id") not in have:
                ssl["enabled"] = False
                ssl["certificate_id"] = None
                d["ssl"] = ssl
                c.execute("UPDATE sites SET data=? WHERE id=?", (json.dumps(d, ensure_ascii=False), sid))
                notes.append(f"Сайт «{name}»: сертификата из копии нет на этом сервере — HTTPS выключен")
    _after(app, sections, notes)
    db.event("info", "backup", f"Настройки восстановлены из копии {path.name}: "
             + ", ".join(SECTIONS[s].split(" (")[0] for s in sections), {"user": user, "notes": notes[:20]})
    return {"sections": sections, "stats": stats, "notes": notes,
            "manifest": {k: manifest.get(k) for k in ("version", "created_at", "host")},
            "nginx": bool(NGINX_SECTIONS & set(sections)), "relogin": "users" in sections}


def _after(app, sections: List[str], notes: List[str]) -> None:
    """Сбросить кэши и пересобрать то, что зависит от восстановленных данных."""
    app._panel = None
    app.protection._settings = None
    if "dns" in sections:
        for r in app.db.query("SELECT id FROM dns_accounts"):
            try:
                app.certs.sync_dns_credentials(r["id"])
            except Exception as e:  # noqa: BLE001
                notes.append(f"Учётная запись DNS #{r['id']}: файл для certbot не записан — {e}")
    if "certificates" in sections:
        app.certs.refresh_all()
    if "bans" in sections or "panel" in sections:
        app.bans.dirty = True
    app.touch()
    try:
        app.refresh_runtime_maps()
    except Exception:  # noqa: BLE001
        pass


def latest_safety(label: str = "before-settings-restore") -> Optional[Path]:
    found = sorted(settings.backups_dir.glob(f"nginx-manager-*-{label}.settings.tar.gz"))
    return found[-1] if found else None


def list_settings_backups() -> List[Dict[str, Any]]:
    out = []
    for p in sorted(settings.backups_dir.glob("nginx-manager-*.settings.tar.gz*"), reverse=True):
        if p.name.endswith(".part") or not is_settings_file(p.name):
            continue
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size, "mtime": st.st_mtime, "encrypted": p.name.endswith(".enc")})
    return out

