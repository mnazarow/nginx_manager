"""Активные проверки доступности бэкендов (HTTP/HTTPS/TCP) и автоматическое переключение."""
from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional

from ..db import Database
from ..models import HealthCheck, Site, Stream
from ..nginx.generator import HEALTH_UA

log = logging.getLogger("nm.health")


@dataclass
class Target:
    key: str              # "site:3|10.0.0.5:8080"
    owner: str            # "site:3" / "stream:2" / "loc:3:1"
    owner_name: str
    address: str
    port: int
    scheme: str           # http / https / tcp
    check: HealthCheck
    host: str
    backup: bool = False
    down_cfg: bool = False
    state: str = "unknown"   # up / down / unknown / disabled
    ok_streak: int = 0
    fail_streak: int = 0
    last_check: float = 0.0
    last_latency: float = 0.0
    last_error: str = ""
    last_status: int = 0
    since: float = field(default_factory=time.time)
    history: Deque = field(default_factory=lambda: deque(maxlen=120))
    checks: int = 0
    fails: int = 0

    @property
    def backend_key(self) -> str:
        return f"{self.address}:{self.port}" if not self.address.startswith("unix:") else self.address

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "owner": self.owner, "owner_name": self.owner_name, "address": self.address,
                "port": self.port, "scheme": self.scheme, "state": self.state, "last_check": self.last_check,
                "latency_ms": round(self.last_latency * 1000, 1), "error": self.last_error,
                "status": self.last_status, "since": self.since, "backup": self.backup, "down_cfg": self.down_cfg,
                "uptime_pct": round((self.checks - self.fails) / self.checks * 100, 2) if self.checks else None,
                "history": list(self.history)[-60:], "type": self.check.type if self.scheme != "tcp" else "tcp",
                "path": self.check.path, "interval": self.check.interval}


def status_ok(code: int, spec: str) -> bool:
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            if int(a) <= code <= int(b):
                return True
        elif part and int(part) == code:
            return True
    return False


async def probe_http(t: Target) -> None:
    hc = t.check
    t0 = time.perf_counter()
    writer = None
    try:
        ctx = None
        if t.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if t.address.startswith("unix:"):
            reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(t.address[5:]), hc.timeout)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(t.address.strip("[]"), t.port, ssl=ctx,
                                        server_hostname=t.host if ctx else None), hc.timeout)
        req = (f"{hc.method} {hc.path} HTTP/1.1\r\nHost: {hc.host_header or t.host}\r\n"
               f"User-Agent: {HEALTH_UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), hc.timeout)
        parts = line.decode("latin-1", "replace").split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise ValueError(f"некорректный ответ: {line[:60]!r}")
        code = int(parts[1])
        t.last_status = code
        body_ok = True
        if hc.expected_body and hc.method == "GET":
            data = await asyncio.wait_for(reader.read(65536), hc.timeout)
            body_ok = hc.expected_body.encode() in data
        t.last_latency = time.perf_counter() - t0
        if not status_ok(code, hc.expected_status):
            raise ValueError(f"HTTP {code} (ожидалось {hc.expected_status})")
        if not body_ok:
            raise ValueError("в ответе нет ожидаемого текста")
        t.last_error = ""
    finally:
        if writer:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except Exception:
                pass


async def probe_tcp(t: Target) -> None:
    t0 = time.perf_counter()
    if t.address.startswith("unix:"):
        _r, w = await asyncio.wait_for(asyncio.open_unix_connection(t.address[5:]), t.check.timeout)
    else:
        _r, w = await asyncio.wait_for(asyncio.open_connection(t.address.strip("[]"), t.port), t.check.timeout)
    t.last_latency = time.perf_counter() - t0
    t.last_status = 0
    t.last_error = ""
    w.close()


class HealthChecker:
    def __init__(self, db: Database, on_change: Callable[[Target, str, str], Any]) -> None:
        self.db = db
        self.on_change = on_change
        self.targets: Dict[str, Target] = {}
        self.sem = asyncio.Semaphore(64)
        self.task: Optional[asyncio.Task] = None
        self.minute: Dict[str, List[float]] = {}
        self.minute_ts = int(time.time()) // 60 * 60

    def rebuild(self, sites: List, streams: List) -> None:
        new: Dict[str, Target] = {}
        for sid, s in sites:
            s: Site
            if not s.enabled or s.type != "proxy":
                continue
            groups = [(f"site:{sid}", s.name, s.backends, s.backend_scheme)]
            for i, loc in enumerate(s.locations):
                if loc.enabled and loc.action == "proxy" and not loc.use_site_backends:
                    groups.append((f"loc:{sid}:{i}", f"{s.name} {loc.path}", loc.backends, loc.backend_scheme))
            for owner, name, backends, scheme in groups:
                for b in backends:
                    key = f"{owner}|{b.key()}"
                    t = self.targets.get(key) or Target(key, owner, name, b.address, b.port or 80, scheme, s.health,
                                                        s.main_domain)
                    t.check, t.scheme, t.host, t.owner_name = s.health, scheme, s.main_domain, name
                    t.backup, t.down_cfg = b.backup, b.down
                    if not s.health.enabled:
                        t.state = "disabled"
                    elif t.state == "disabled":
                        t.state = "unknown"
                    new[key] = t
        for sid, st in streams:
            st: Stream
            if not st.enabled:
                continue
            for b in st.backends:
                key = f"stream:{sid}|{b.key()}"
                hc = HealthCheck(type="tcp", interval=15, timeout=5)
                t = self.targets.get(key) or Target(key, f"stream:{sid}", st.name, b.address, b.port or 0, "tcp", hc,
                                                    "")
                t.owner_name, t.backup, t.down_cfg = st.name, b.backup, b.down
                if not st.health_check or st.protocol == "udp":
                    t.state = "disabled"
                elif t.state == "disabled":
                    t.state = "unknown"
                new[key] = t
        self.targets = new

    async def check(self, t: Target) -> None:
        async with self.sem:
            t.last_check = time.time()
            ok = True
            try:
                if t.scheme == "tcp" or t.check.type == "tcp":
                    await probe_tcp(t)
                else:
                    await probe_http(t)
            except asyncio.TimeoutError:
                ok, t.last_error = False, f"таймаут {t.check.timeout} с"
            except ConnectionRefusedError:
                ok, t.last_error = False, "соединение отклонено (порт закрыт)"
            except OSError as e:
                ok, t.last_error = False, (e.strerror or str(e))
            except Exception as e:
                ok, t.last_error = False, str(e)
            if not ok:
                t.last_latency = 0.0
            t.checks += 1
            t.fails += 0 if ok else 1
            t.history.append([int(t.last_check), 1 if ok else 0, round(t.last_latency * 1000, 1)])
            m = self.minute.setdefault(t.key, [0, 0, 0.0])
            m[0] += 1
            m[1] += 0 if ok else 1
            m[2] += t.last_latency
            prev = t.state
            if ok:
                t.ok_streak += 1
                t.fail_streak = 0
                if t.state != "up" and (t.ok_streak >= t.check.rise or t.state == "unknown"):
                    t.state = "up"
            else:
                t.fail_streak += 1
                t.ok_streak = 0
                if t.state != "down" and t.fail_streak >= t.check.fall:
                    t.state = "down"
            if prev != t.state and prev in ("up", "down", "unknown") and t.state in ("up", "down"):
                t.since = time.time()
                if not (prev == "unknown" and t.state == "up"):
                    try:
                        res = self.on_change(t, prev, t.state)
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception:
                        log.exception("обработчик смены состояния")

    async def run(self) -> None:
        while True:
            now = time.time()
            due = [t for t in self.targets.values()
                   if t.state != "disabled" and now - t.last_check >= t.check.interval]
            for t in due:
                t.last_check = now
                asyncio.create_task(self.check(t))
            cur = int(now) // 60 * 60
            if cur > self.minute_ts:
                rows, self.minute = self.minute, {}
                mts, self.minute_ts = self.minute_ts, cur
                if rows:
                    await asyncio.to_thread(self.db.executemany,
                                            "INSERT OR REPLACE INTO health_minute(ts,target,checks,fails,lat_sum) "
                                            "VALUES(?,?,?,?,?)",
                                            [(mts, k, v[0], v[1], v[2]) for k, v in rows.items()])
            await asyncio.sleep(1)

    def start(self) -> None:
        self.task = asyncio.get_running_loop().create_task(self.run(), name="health")

    async def check_now(self, key: Optional[str] = None) -> List[Dict[str, Any]]:
        ts = [t for t in self.targets.values() if (key is None or t.key == key or t.owner == key)
              and t.state != "disabled"]
        await asyncio.gather(*(self.check(t) for t in ts))
        return [t.to_dict() for t in ts]

    def list(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(self.targets.values(), key=lambda x: (x.owner, x.address, x.port))]

    def disabled_by_failover(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for t in self.targets.values():
            if t.state == "down" and t.check.auto_failover and t.owner.startswith("site:"):
                out.setdefault(t.owner, []).append(t.backend_key)
        return out

    def history(self, key: str, start: float, end: float) -> List[Dict[str, Any]]:
        return self.db.query("SELECT ts, checks, fails, lat_sum FROM health_minute WHERE target=? AND ts>=? AND ts<? "
                             "ORDER BY ts", (key, int(start), int(end)))
