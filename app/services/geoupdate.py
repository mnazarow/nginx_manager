"""Автоматическое обновление баз GeoIP: страны и сети провайдеров (ASN).

Бесплатные базы DB-IP Lite (лицензия CC BY 4.0, обновляются ежемесячно) — с сайта DB-IP, а если он недоступен —
из зеркала sapics/ip-location-db на GitHub. Файлы кладутся в /var/lib/nginx-manager/geoip/ под именами
dbip-country-lite.mmdb и dbip-asn-lite.mmdb; база, указанная в настройках, и GeoLite2 (MaxMind) в каталоге
остаются в приоритете. Новая база проверяется (открывается и отвечает на запрос), затем заменяет старую атомарно.
"""
from __future__ import annotations

import gzip
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List

from ..config import settings

log = logging.getLogger("nm.geoupdate")

MIRROR = "https://github.com/sapics/ip-location-db/releases/download/latest/{name}"
KINDS = {
    "country": {"title": "DB-IP Country Lite (страны)", "file": "dbip-country-lite.mmdb",
                "dbip": "https://download.db-ip.com/free/dbip-country-lite-{ym}.mmdb.gz", "mirror": "dbip-country.mmdb",
                "probe": ("8.8.8.8", "country")},
    "asn": {"title": "DB-IP ASN Lite (сети провайдеров)", "file": "dbip-asn-lite.mmdb",
            "dbip": "https://download.db-ip.com/free/dbip-asn-lite-{ym}.mmdb.gz", "mirror": "dbip-asn.mmdb",
            "probe": ("8.8.8.8", "autonomous_system_number")},
}
REFRESH_DAYS = 30
RETRY_HOURS = 6


def months(now: float) -> List[str]:
    t = time.gmtime(now)
    cur = f"{t.tm_year}-{t.tm_mon:02d}"
    prev = f"{t.tm_year - 1}-12" if t.tm_mon == 1 else f"{t.tm_year}-{t.tm_mon - 1:02d}"
    return [cur, prev]


def urls(kind: str, now: float) -> List[str]:
    k = KINDS[kind]
    return [k["dbip"].format(ym=ym) for ym in months(now)] + [MIRROR.format(name=k["mirror"])]


def validate(data: bytes, kind: str) -> Dict[str, Any]:
    """Открыть базу из байтов и проверить, что это база нужного вида."""
    import maxminddb  # type: ignore
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    tmp = settings.geoip_dir / f".{kind}.check"
    tmp.write_bytes(data)
    try:
        r = maxminddb.open_database(str(tmp))
        meta = r.metadata()
        if meta.node_count < 1:
            raise ValueError("пустая база")
        ip, key = KINDS[kind]["probe"]
        rec = r.get(ip)
        r.close()
        if kind == "asn" and meta.node_count > 1000 and not (isinstance(rec, dict) and key in rec):
            raise ValueError("это не база ASN (нет autonomous_system_number)")
        return {"type": meta.database_type, "built": meta.build_epoch, "nodes": meta.node_count, "data": data}
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


class GeoUpdater:
    def __init__(self, app) -> None:
        self.app = app
        self.db = app.db
        self.running = False

    def status(self) -> Dict[str, Any]:
        return self.db.kv_get("geoip_update", {}) or {}

    def due(self, kind: str, now: float) -> bool:
        st = self.status().get(kind) or {}
        f = settings.geoip_dir / KINDS[kind]["file"]
        fresh = f.exists() and now - f.stat().st_mtime < REFRESH_DAYS * 86400
        return not fresh and now - (st.get("tried") or 0) >= RETRY_HOURS * 3600

    def update_sync(self, force: bool = False, only: str = "") -> Dict[str, Any]:
        from ..protection.vulndb import fetch_first
        now = time.time()
        st = self.status()
        res: Dict[str, Any] = {}
        for kind, k in KINDS.items():
            if only and kind != only:
                continue
            if not force and not self.due(kind, now):
                continue
            try:
                data, url = fetch_first(urls(kind, now), timeout=180, limit=300 * 1048576)
                info = validate(data, kind)
                dest = settings.geoip_dir / k["file"]
                tmp = dest.with_suffix(".tmp")
                tmp.write_bytes(info.pop("data"))
                os.chmod(tmp, 0o644)
                tmp.replace(dest)
                st[kind] = {"ok": True, "updated": now, "tried": now, "url": url, "error": "", **info,
                            "size": dest.stat().st_size}
                self.db.event("info", "geoip", f"База {k['title']} обновлена ({dest.stat().st_size // 1048576} МБ)",
                              {"url": url})
            except Exception as e:  # noqa: BLE001
                st[kind] = {**(st.get(kind) or {}), "ok": False, "tried": now, "error": str(e)[:400]}
                log.info("база %s не обновлена: %s", kind, e)
            res[kind] = st[kind]
        self.db.kv_set("geoip_update", st)
        return res

    async def tick(self, force: bool = False, only: str = "") -> Dict[str, Any]:
        import asyncio
        if self.running:
            return {}
        self.running = True
        try:
            res = await asyncio.to_thread(self.update_sync, force, only)
        finally:
            self.running = False
        if any(v.get("ok") for v in res.values()):
            await self.app.refresh_geo()  # перечитать базы и пересобрать сети стран и провайдеров
        return res

    def files(self) -> List[Dict[str, Any]]:
        out = []
        for kind, k in KINDS.items():
            f: Path = settings.geoip_dir / k["file"]
            out.append({"kind": kind, "title": k["title"], "file": str(f), "exists": f.exists(),
                        "mtime": f.stat().st_mtime if f.exists() else None,
                        "size": f.stat().st_size if f.exists() else None, **(self.status().get(kind) or {})})
        return out
