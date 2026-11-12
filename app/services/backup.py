"""Резервное копирование: экспорт/импорт настроек в JSON и копии базы данных."""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from ..config import VERSION, settings


def export_config(app, include_users: bool = False, include_certs: bool = True) -> Dict[str, Any]:
    db = app.db
    out: Dict[str, Any] = {
        "format": "nginx-manager-export", "version": VERSION, "exported_at": time.time(),
        "global": db.kv_get("global_settings", {}), "panel": db.kv_get("panel_settings", {}),
        "sites": [{"id": r["id"], "data": json.loads(r["data"])} for r in db.query("SELECT * FROM sites ORDER BY id")],
        "streams": [{"id": r["id"], "data": json.loads(r["data"])} for r in db.query("SELECT * FROM streams")],
        "alert_rules": [json.loads(r["data"]) for r in db.query("SELECT * FROM alert_rules")],
        "alert_channels": [{"id": r["id"], "data": json.loads(r["data"])} for r in db.query("SELECT * FROM alert_channels")],
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
    if data.get("format") != "nginx-manager-export":
        raise ValueError("Это не файл экспорта Nginx Manager")
    from ..models import AlertChannel, AlertRule, GlobalSettings, PanelSettings, Site, Stream
    db = app.db
    now = time.time()
    stats = {"sites": 0, "streams": 0, "certificates": 0, "rules": 0, "channels": 0}
    # валидация до записи
    sites = [(s.get("id"), Site.model_validate(s["data"])) for s in data.get("sites", [])]
    streams = [(s.get("id"), Stream.model_validate(s["data"])) for s in data.get("streams", [])]
    glob = GlobalSettings.model_validate(data.get("global", {}))
    cert_map: Dict[int, int] = {}
    with db.transaction() as c:
        if mode == "replace":
            for t in ("sites", "streams", "alert_rules", "alert_channels"):
                c.execute(f"DELETE FROM {t}")
        for cert in data.get("certificates", []):
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
        for sid, s in sites:
            if s.ssl.certificate_id in cert_map:
                s.ssl.certificate_id = cert_map[s.ssl.certificate_id]
            if mode == "replace" and sid:
                c.execute("INSERT INTO sites(id,name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                          (sid, s.name, int(s.enabled), json.dumps(s.model_dump(), ensure_ascii=False), now, now))
            else:
                c.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                          (s.name, int(s.enabled), json.dumps(s.model_dump(), ensure_ascii=False), now, now))
            stats["sites"] += 1
        for sid, s in streams:
            c.execute("INSERT INTO streams(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                      (s.name, int(s.enabled), json.dumps(s.model_dump(), ensure_ascii=False), now, now))
            stats["streams"] += 1
        chan_map: Dict[int, int] = {}
        for ch in data.get("alert_channels", []):
            m = AlertChannel.model_validate(ch["data"])
            cur = c.execute("INSERT INTO alert_channels(name,type,enabled,data,created_at,updated_at) "
                            "VALUES(?,?,?,?,?,?)", (m.name, m.type, int(m.enabled),
                                                    json.dumps(m.model_dump(), ensure_ascii=False), now, now))
            chan_map[ch.get("id", 0)] = cur.lastrowid
            stats["channels"] += 1
        for r in data.get("alert_rules", []):
            m = AlertRule.model_validate(r)
            m.channels = [chan_map.get(x, x) for x in m.channels]
            c.execute("INSERT INTO alert_rules(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                      (m.name, int(m.enabled), json.dumps(m.model_dump(), ensure_ascii=False), now, now))
            stats["rules"] += 1
        c.execute("INSERT INTO kv(key,value) VALUES('global_settings',?) ON CONFLICT(key) DO UPDATE "
                  "SET value=excluded.value", (json.dumps(glob.model_dump(), ensure_ascii=False),))
        if data.get("panel"):
            pnl = PanelSettings.model_validate(data["panel"])
            if pnl.panel_certificate_id in cert_map:
                pnl.panel_certificate_id = cert_map[pnl.panel_certificate_id]
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
    """Удалить старые копии: ежедневные (оставить keep_auto), сделанные при обновлениях и из консоли — базы,
    код прежних версий и nginx.conf (оставить keep_update каждого вида). Ручные копии из панели не трогаются."""
    d = settings.backups_dir
    removed: List[str] = []
    groups = [(sorted(d.glob("nginx-manager-*-auto.db")), keep_auto),
              (sorted(d.glob("nginx-manager-*-cli.db")), keep_update),
              (sorted(d.glob("nginx-manager-*-preupdate.db")), keep_update),
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
    return p


def list_backups() -> List[Dict[str, Any]]:
    out = []
    for p in sorted(settings.backups_dir.glob("nginx-manager-*"), reverse=True):
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size, "mtime": st.st_mtime, "kind": p.suffix[1:]})
    return out
