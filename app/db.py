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
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

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
    # ---- v3: тишина оповещений (плановые работы) ----------------------------
    """
    CREATE TABLE IF NOT EXISTS silences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at REAL NOT NULL,
        starts_at REAL NOT NULL,
        ends_at REAL NOT NULL,
        rule_ids TEXT NOT NULL DEFAULT '[]',
        reason TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        suppressed INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_silences_end ON silences(ends_at)
    """,
    # ---- v4: учётные записи DNS-провайдеров (DNS-проверка ACME, wildcard) ------
    """
    CREATE TABLE IF NOT EXISTS dns_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        provider TEXT NOT NULL,
        data TEXT NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
    # ---- v5: роль API-токена (не выше роли пользователя; '' — как у пользователя) и срок -----
    """
    ALTER TABLE api_tokens ADD COLUMN role TEXT NOT NULL DEFAULT ''
    """,
    # ---- v6: защита от атак — журнал атак и поминутные счётчики ---------------------------------
    """
    CREATE TABLE IF NOT EXISTS attack_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL, site TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
        country TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, rule TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL, method TEXT NOT NULL DEFAULT '', uri TEXT NOT NULL DEFAULT '',
        ua TEXT NOT NULL DEFAULT '', status INTEGER NOT NULL DEFAULT 0, rid TEXT NOT NULL DEFAULT '',
        host TEXT NOT NULL DEFAULT '', test INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS attack_log_ts ON attack_log(ts);
    CREATE INDEX IF NOT EXISTS attack_log_ip ON attack_log(ip, ts);
    CREATE INDEX IF NOT EXISTS attack_log_rid ON attack_log(rid);
    CREATE TABLE IF NOT EXISTS attack_minute (
        ts INTEGER NOT NULL, site TEXT NOT NULL, kind TEXT NOT NULL, rule TEXT NOT NULL, action TEXT NOT NULL,
        n INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (ts, site, kind, rule, action)
    );
    CREATE INDEX IF NOT EXISTS attack_minute_ts ON attack_minute(ts);
    """,
    # ---- v7: защита — счётчики проверки браузера и роботов, история режима «Под атакой» -------
    """
    CREATE TABLE IF NOT EXISTS prot_minute (
        ts INTEGER NOT NULL, site TEXT NOT NULL, metric TEXT NOT NULL, key TEXT NOT NULL,
        n INTEGER NOT NULL DEFAULT 0, ms INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (ts, site, metric, key)
    );
    CREATE INDEX IF NOT EXISTS prot_minute_ts ON prot_minute(ts);
    CREATE TABLE IF NOT EXISTS attack_periods (
        id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, start REAL NOT NULL, end REAL,
        auto INTEGER NOT NULL DEFAULT 0, who TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS attack_periods_start ON attack_periods(start);
    """,
    # ---- v8: база уязвимостей (CISA KEV, nuclei-templates, FIRST EPSS) ---------------------------
    """
    CREATE TABLE IF NOT EXISTS vulns (
        cve TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', vendor TEXT NOT NULL DEFAULT '',
        product TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT '',
        cvss REAL NOT NULL DEFAULT 0, epss REAL NOT NULL DEFAULT 0, epss_pct REAL NOT NULL DEFAULT 0,
        kev INTEGER NOT NULL DEFAULT 0, kev_added TEXT NOT NULL DEFAULT '', kev_due TEXT NOT NULL DEFAULT '',
        ransomware INTEGER NOT NULL DEFAULT 0, kev_action TEXT NOT NULL DEFAULT '', cwe TEXT NOT NULL DEFAULT '',
        template TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '', paths TEXT NOT NULL DEFAULT '',
        covered TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 0, seen INTEGER NOT NULL DEFAULT 0,
        last_seen REAL, updated REAL, cvss_vector TEXT NOT NULL DEFAULT '', published TEXT NOT NULL DEFAULT '',
        affected TEXT NOT NULL DEFAULT '', exploits TEXT NOT NULL DEFAULT '', enriched REAL
    );
    CREATE INDEX IF NOT EXISTS vulns_kev ON vulns(kev, kev_added);
    """,
    # ---- v9: затронутые версии в машиночитаемом виде (сверка с версиями продуктов на сайтах) -------------
    """
    ALTER TABLE vulns ADD COLUMN ranges TEXT NOT NULL DEFAULT '';
    """,
    # ---- v10: данные дистрибутивов (перенесённые исправления) и уязвимости плагинов и тем WordPress -------
    """
    CREATE TABLE IF NOT EXISTS distro_cve (
        cve TEXT NOT NULL, distro TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', fetched REAL NOT NULL DEFAULT 0,
        ok INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (cve, distro)
    );
    CREATE TABLE IF NOT EXISTS wp_vulns (
        id TEXT PRIMARY KEY, slug TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'plugin', name TEXT NOT NULL DEFAULT '',
        title TEXT NOT NULL DEFAULT '', cve TEXT NOT NULL DEFAULT '', cvss REAL NOT NULL DEFAULT 0,
        ranges TEXT NOT NULL DEFAULT '[]', patched TEXT NOT NULL DEFAULT '', published TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'wordfence'
    );
    CREATE INDEX IF NOT EXISTS wp_vulns_slug ON wp_vulns(type, slug);
    ALTER TABLE vulns ADD COLUMN wp TEXT NOT NULL DEFAULT '';
    """,
    # ---- v11: отказы «Доступа по IP» (поминутно по сайту и адресу) --------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS ipdeny_minute (
        ts INTEGER NOT NULL, site TEXT NOT NULL, ip TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
        uri TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', PRIMARY KEY (ts, site, ip)
    );
    CREATE INDEX IF NOT EXISTS ipdeny_site_ts ON ipdeny_minute(site, ts);
    """,
    # ---- v12: доступ к сайту по ссылке (ссылки и выданный по ним доступ) ---------------------------------------
    """
    CREATE TABLE IF NOT EXISTS ipaccess_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT, site INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE,
        comment TEXT NOT NULL DEFAULT '', hours REAL NOT NULL, uses_left INTEGER NOT NULL, uses_total INTEGER NOT NULL,
        expires_at REAL NOT NULL, created_by TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ipaccess_grants (
        id INTEGER PRIMARY KEY AUTOINCREMENT, site INTEGER NOT NULL, ip TEXT NOT NULL, link_id INTEGER,
        comment TEXT NOT NULL DEFAULT '', ua TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, expires_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ipaccess_grants_site ON ipaccess_grants(site, expires_at);
    """,
]


class Database:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self.write_lock = threading.RLock()
        self.on_event: Optional[Callable[..., None]] = None
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

    def close(self) -> None:
        """Закрыть соединение текущего потока (тесты, консольные команды)."""
        c = getattr(self._local, "conn", None)
        if c is not None:
            c.close()
            self._local.conn = None

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
        d = json.dumps(details, ensure_ascii=False, default=str) if details is not None else None
        if d and len(d) > 4000:  # журнал аудита — для людей: огромные детали обрезаются
            d = d[:4000] + "…"
        self.execute("INSERT INTO audit_log(ts,username,ip,action,target,details) VALUES(?,?,?,?,?,?)",
                     (time.time(), username, ip, action, target, d))

    def event(self, level: str, source: str, message: str, details: Any = None) -> None:
        self.execute("INSERT INTO events(ts,level,source,message,details) VALUES(?,?,?,?,?)",
                     (time.time(), level, source, message,
                      json.dumps(details, ensure_ascii=False, default=str) if details is not None else None))
        if self.on_event is not None:  # рассылка уведомлений о событиях (services/events.py)
            try:
                self.on_event(level, source, message, details)
            except Exception:
                pass

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
