"""SQLite-хранилище: схема, миграции, тонкая обёртка с потокобезопасным доступом.

Используется режим WAL: чтение не блокирует запись, а сборщик статистики
пишет пачками (одна транзакция в секунду).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

SCHEMA: List[str] = [
    # ---- v1 ---------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        data TEXT NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS streams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        data TEXT NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        domains TEXT NOT NULL DEFAULT '[]',
        cert_path TEXT NOT NULL DEFAULT '',
        key_path TEXT NOT NULL DEFAULT '',
        not_before REAL,
        not_after REAL,
        issuer TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        last_error TEXT DEFAULT '',
        data TEXT NOT NULL DEFAULT '{}',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        totp_secret TEXT DEFAULT '',
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        disabled INTEGER NOT NULL DEFAULT 0,
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL,
        last_login REAL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        last_seen REAL NOT NULL,
        ip TEXT DEFAULT '',
        user_agent TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS api_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        prefix TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL,
        last_used REAL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        username TEXT,
        ip TEXT,
        action TEXT NOT NULL,
        target TEXT,
        details TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
    CREATE TABLE IF NOT EXISTS config_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        username TEXT,
        comment TEXT,
        source TEXT NOT NULL DEFAULT 'user',
        status TEXT NOT NULL,
        files TEXT NOT NULL,
        state TEXT NOT NULL,
        output TEXT,
        checksum TEXT
    );
    CREATE TABLE IF NOT EXISTS stats_minute (
        ts INTEGER NOT NULL,
        site TEXT NOT NULL,
        req INTEGER NOT NULL DEFAULT 0,
        bout INTEGER NOT NULL DEFAULT 0,
        bin INTEGER NOT NULL DEFAULT 0,
        s1 INTEGER NOT NULL DEFAULT 0,
        s2 INTEGER NOT NULL DEFAULT 0,
        s3 INTEGER NOT NULL DEFAULT 0,
        s4 INTEGER NOT NULL DEFAULT 0,
        s5 INTEGER NOT NULL DEFAULT 0,
        rt_sum REAL NOT NULL DEFAULT 0,
        rt_max REAL NOT NULL DEFAULT 0,
        urt_sum REAL NOT NULL DEFAULT 0,
        urt_n INTEGER NOT NULL DEFAULT 0,
        uniq INTEGER NOT NULL DEFAULT 0,
        data TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (ts, site)
    );
    CREATE TABLE IF NOT EXISTS stats_hour (
        ts INTEGER NOT NULL,
        site TEXT NOT NULL,
        req INTEGER NOT NULL DEFAULT 0,
        bout INTEGER NOT NULL DEFAULT 0,
        bin INTEGER NOT NULL DEFAULT 0,
        s1 INTEGER NOT NULL DEFAULT 0,
        s2 INTEGER NOT NULL DEFAULT 0,
        s3 INTEGER NOT NULL DEFAULT 0,
        s4 INTEGER NOT NULL DEFAULT 0,
        s5 INTEGER NOT NULL DEFAULT 0,
        rt_sum REAL NOT NULL DEFAULT 0,
        rt_max REAL NOT NULL DEFAULT 0,
        urt_sum REAL NOT NULL DEFAULT 0,
        urt_n INTEGER NOT NULL DEFAULT 0,
        uniq INTEGER NOT NULL DEFAULT 0,
        data TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (ts, site)
    );
    CREATE TABLE IF NOT EXISTS top_hour (
        ts INTEGER NOT NULL,
        site TEXT NOT NULL,
        kind TEXT NOT NULL,
        key TEXT NOT NULL,
        cnt INTEGER NOT NULL,
        bytes INTEGER NOT NULL DEFAULT 0,
        extra REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (ts, site, kind, key)
    );
    CREATE TABLE IF NOT EXISTS top_day (
        ts INTEGER NOT NULL,
        site TEXT NOT NULL,
        kind TEXT NOT NULL,
        key TEXT NOT NULL,
        cnt INTEGER NOT NULL,
        bytes INTEGER NOT NULL DEFAULT 0,
        extra REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (ts, site, kind, key)
    );
    CREATE TABLE IF NOT EXISTS stream_minute (
        ts INTEGER NOT NULL,
        stream TEXT NOT NULL,
        sessions INTEGER NOT NULL DEFAULT 0,
        bytes_in INTEGER NOT NULL DEFAULT 0,
        bytes_out INTEGER NOT NULL DEFAULT 0,
        dur_sum REAL NOT NULL DEFAULT 0,
        errors INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (ts, stream)
    );
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        site TEXT,
        host TEXT,
        ip TEXT,
        method TEXT,
        uri TEXT,
        proto TEXT,
        status INTEGER,
        bytes INTEGER,
        rt REAL,
        urt REAL,
        upstream TEXT,
        ustatus TEXT,
        ref TEXT,
        ua TEXT,
        cache TEXT,
        tls TEXT,
        country TEXT,
        rid TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_req_ts ON requests(ts);
    CREATE INDEX IF NOT EXISTS idx_req_site_ts ON requests(site, ts);
    CREATE INDEX IF NOT EXISTS idx_req_status ON requests(status, ts);
    CREATE INDEX IF NOT EXISTS idx_req_ip ON requests(ip, ts);
    CREATE TABLE IF NOT EXISTS errors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        level TEXT,
        category TEXT,
        message TEXT,
        client TEXT,
        server TEXT,
        site TEXT,
        request TEXT,
        upstream TEXT,
        host TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_err_ts ON errors(ts);
    CREATE INDEX IF NOT EXISTS idx_err_cat ON errors(category, ts);
    CREATE TABLE IF NOT EXISTS system_minute (
        ts INTEGER PRIMARY KEY,
        cpu REAL, mem REAL, swap REAL, load1 REAL, load5 REAL, load15 REAL,
        disk REAL, net_rx REAL, net_tx REAL, disk_r REAL, disk_w REAL,
        conn_active REAL, conn_reading REAL, conn_writing REAL, conn_waiting REAL,
        nginx_rss REAL, nginx_cpu REAL, nginx_workers INTEGER, nginx_fds INTEGER
    );
    CREATE TABLE IF NOT EXISTS health_minute (
        ts INTEGER NOT NULL,
        target TEXT NOT NULL,
        checks INTEGER NOT NULL DEFAULT 0,
        fails INTEGER NOT NULL DEFAULT 0,
        lat_sum REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (ts, target)
    );
    CREATE TABLE IF NOT EXISTS alert_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        data TEXT NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alert_channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        data TEXT NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alert_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        rule_id INTEGER,
        rule_name TEXT,
        severity TEXT,
        state TEXT NOT NULL,
        message TEXT,
        value REAL,
        notified TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_alert_ts ON alert_events(ts);
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        level TEXT NOT NULL,
        source TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
    """,
    # ---- v2: блокировки IP ------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        net TEXT NOT NULL UNIQUE,
        reason TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'manual',
        rule TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL,
        expires_at REAL,
        offenses INTEGER NOT NULL DEFAULT 1,
        hits INTEGER NOT NULL DEFAULT 0,
        last_hit REAL,
        country TEXT NOT NULL DEFAULT '',
        details TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_bans_exp ON bans(expires_at);
    CREATE TABLE IF NOT EXISTS ban_offenses (
        ip TEXT PRIMARY KEY,
        count INTEGER NOT NULL DEFAULT 0,
        last_at REAL NOT NULL
    )
    """,
]


class Database:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self.write_lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    # ------------------------------------------------------------------
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(str(self.path), timeout=30, isolation_level=None,
                                check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=30000")
            self._local.conn = c
        return c

    def _migrate(self) -> None:
        c = self.conn()
        ver = c.execute("PRAGMA user_version").fetchone()[0]
        for i, script in enumerate(SCHEMA, start=1):
            if ver < i:
                with self.write_lock:
                    c.executescript("BEGIN;" + script + f"; PRAGMA user_version={i}; COMMIT;")
        try:
            import os
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @property
    def schema_version(self) -> int:
        return self.conn().execute("PRAGMA user_version").fetchone()[0]

    # ------------------------------------------------------------------
    def query(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        cur = self.conn().execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def one(self, sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        r = self.conn().execute(sql, params).fetchone()
        return dict(r) if r else None

    def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        r = self.conn().execute(sql, params).fetchone()
        return r[0] if r else None

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self.write_lock:
            cur = self.conn().execute(sql, params)
            return cur.lastrowid

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        with self.write_lock:
            c = self.conn()
            c.execute("BEGIN")
            try:
                c.executemany(sql, rows)
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise

    def transaction(self):
        return _Tx(self)

    # ---- key/value ----------------------------------------------------
    def kv_get(self, key: str, default: Any = None) -> Any:
        r = self.one("SELECT value FROM kv WHERE key=?", (key,))
        if not r:
            return default
        try:
            return json.loads(r["value"])
        except ValueError:
            return default

    def kv_set(self, key: str, value: Any) -> None:
        self.execute("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, json.dumps(value, ensure_ascii=False)))

    # ---- журналы ------------------------------------------------------
    def audit(self, username: Optional[str], ip: Optional[str], action: str,
              target: str = "", details: Any = None) -> None:
        self.execute("INSERT INTO audit_log(ts,username,ip,action,target,details) VALUES(?,?,?,?,?,?)",
                     (time.time(), username, ip, action, target,
                      json.dumps(details, ensure_ascii=False) if details is not None else None))

    def event(self, level: str, source: str, message: str, details: Any = None) -> None:
        self.execute("INSERT INTO events(ts,level,source,message,details) VALUES(?,?,?,?,?)",
                     (time.time(), level, source, message,
                      json.dumps(details, ensure_ascii=False) if details is not None else None))

    def backup_to(self, dest: Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = sqlite3.connect(str(dest))
        try:
            with self.write_lock:
                self.conn().backup(tmp)
        finally:
            tmp.close()


class _Tx:
    def __init__(self, db: Database) -> None:
        self.db = db

    def __enter__(self) -> sqlite3.Connection:
        self.db.write_lock.acquire()
        c = self.db.conn()
        c.execute("BEGIN")
        return c

    def __exit__(self, exc_type, exc, tb) -> None:
        c = self.db.conn()
        try:
            if exc_type is None:
                c.execute("COMMIT")
            else:
                c.execute("ROLLBACK")
        finally:
            self.db.write_lock.release()
