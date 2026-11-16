"""Сети провайдеров (ASN): определение автономной системы по IP и файл geo для своих правил «Сеть (ASN)».

База — mmdb в формате GeoLite2-ASN (поля autonomous_system_number и autonomous_system_organization): MaxMind
GeoLite2-ASN, DB-IP ASN Lite, IPtoASN или origin-asn из sapics/ip-location-db. Как и с сетями стран, nginx не читает
mmdb сам: панель выбирает из базы сети автономных систем, упомянутых в правилах, и пишет файл `asn-nets.conf`:

    # nm-asn db=/var/lib/nginx-manager/geoip/dbip-asn-lite.mmdb mtime=1731400000 asns=14061,16509 nets=4312
    5.101.96.0/21 14061;
    ...

В конфигурации это `geo $nm_asn { default 0; include asn-nets.conf; }`.
"""
from __future__ import annotations

import ipaddress
import os
import re
import time
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

HEADER = "# nm-asn"
DB_NAMES = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb", "dbip-asn.mmdb", "origin-asn.mmdb", "iptoasn-asn.mmdb")
_V4_COMPAT = ipaddress.ip_network("::/96")
_ALIASES = (ipaddress.ip_network("::ffff:0:0/96"), ipaddress.ip_network("2002::/16"))


def parse_asns(value: str) -> List[int]:
    """«AS14061, 16509 as13335» → [14061, 16509, 13335]; ValueError при ошибке."""
    out: List[int] = []
    for x in re.split(r"[\s,;]+", value.strip()):
        if not x:
            continue
        m = re.match(r"^(?:AS)?(\d{1,10})$", x, re.I)
        if not m or not 0 < int(m.group(1)) < 4294967296:
            raise ValueError(f"«{x}» — не номер автономной системы (AS14061 или 14061)")
        n = int(m.group(1))
        if n not in out:
            out.append(n)
    return out


def candidates(path: str, data_dir: str) -> List[str]:
    out = [path] if path else []
    out += [os.path.join(data_dir, f) for f in DB_NAMES]
    out += ["/usr/share/GeoIP/GeoLite2-ASN.mmdb", "/var/lib/GeoIP/GeoLite2-ASN.mmdb"]
    return out


def find_db(path: str, data_dir: str) -> Optional[str]:
    try:
        import maxminddb  # type: ignore  # noqa: F401
    except ImportError:
        return None
    for c in candidates(path, data_dir):
        if c and os.path.isfile(c):
            return c
    return None


def record(rec: Any) -> Tuple[int, str]:
    if not isinstance(rec, dict):
        return 0, ""
    n = rec.get("autonomous_system_number") or rec.get("asn") or 0
    org = rec.get("autonomous_system_organization") or rec.get("as_name") or rec.get("organization") or ""
    try:
        return int(n), str(org)
    except (TypeError, ValueError):
        return 0, ""


class ASNLookup:
    """Номер и организация автономной системы по IP (кэш на 50 000 адресов)."""

    def __init__(self) -> None:
        self.reader = None
        self.path = ""
        self.mtime = 0.0
        self.error = ""

    def load(self, path: str, data_dir: str) -> None:
        db = find_db(path, data_dir)
        if not db:
            self.reader, self.path = None, ""
            self.error = "база ASN не найдена"
            return
        try:
            mtime = os.path.getmtime(db)
            if self.reader and self.path == db and self.mtime == mtime:
                return
            import maxminddb  # type: ignore
            self.reader = maxminddb.open_database(db)
            self.path, self.mtime, self.error = db, mtime, ""
            self._lookup.cache_clear()
        except Exception as e:  # noqa: BLE001
            self.reader, self.error = None, str(e)

    @lru_cache(maxsize=50000)
    def _lookup(self, ip: str) -> Tuple[int, str]:
        if not self.reader:
            return 0, ""
        try:
            return record(self.reader.get(ip))
        except Exception:  # noqa: BLE001 — некорректный адрес
            return 0, ""

    def lookup(self, ip: str) -> Tuple[int, str]:
        return self._lookup(ip) if ip else (0, "")


def referenced_rules(prot: Any) -> Set[int]:
    out: Set[int] = set()
    for r in getattr(prot, "custom_rules", None) or []:
        if r.enabled and r.field == "asn":
            out.update(parse_asns(r.value))
    return out


def read_header(path: str) -> Dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            first = f.readline().strip()
    except OSError:
        return {}
    if not first.startswith(HEADER):
        return {}
    return dict(p.partition("=")[::2] for p in first[len(HEADER):].split())


def header_asns(h: Dict[str, str]) -> Set[int]:
    return {int(x) for x in h.get("asns", "").split(",") if x.isdigit()}


def empty_file() -> str:
    return f"{HEADER} db=- mtime=0 asns= nets=0 built=0\n"


def build(mmdb_path: str, asns: Iterable[int]) -> Tuple[str, Dict[str, Any]]:
    want = sorted(set(asns))
    t0 = time.time()
    nets: Dict[int, List[Any]] = {a: [] for a in want}
    orgs: Dict[int, str] = {}
    if want:
        from .geoblock import iterable_reader
        r = iterable_reader(mmdb_path)
        try:
            for net, rec in r:
                n, org = record(rec)
                if n not in nets:
                    continue
                orgs.setdefault(n, org)
                if net.version == 6:
                    if any(net.subnet_of(a) for a in _ALIASES):
                        continue
                    if net.subnet_of(_V4_COMPAT):
                        net = ipaddress.ip_network((int(net.network_address), max(0, net.prefixlen - 96)))
                nets[n].append(net)
        finally:
            r.close()
    body: List[str] = []
    per: Dict[int, int] = {}
    for a in want:
        v4 = list(ipaddress.collapse_addresses(x for x in nets[a] if x.version == 4))
        v6 = list(ipaddress.collapse_addresses(x for x in nets[a] if x.version == 6))
        per[a] = len(v4) + len(v6)
        body.extend(f"{x} {a};" for x in v4 + v6)
    try:
        mtime = int(os.path.getmtime(mmdb_path)) if mmdb_path else 0
    except OSError:
        mtime = 0
    total = sum(per.values())
    head = f"{HEADER} db={mmdb_path or '-'} mtime={mtime} asns={','.join(map(str, want))} nets={total} " \
           f"built={int(time.time())}"
    return head + "\n" + "\n".join(body) + ("\n" if body else ""), {
        "asns": per, "orgs": orgs, "nets": total, "seconds": round(time.time() - t0, 2), "db": mmdb_path}


def needs_rebuild(path: str, mmdb_path: Optional[str], asns: Set[int]) -> bool:
    h = read_header(path)
    if not h:
        return True
    if not asns:
        return bool(header_asns(h))
    if not mmdb_path:
        return False
    try:
        mtime = int(os.path.getmtime(mmdb_path))
    except OSError:
        return False
    return h.get("db") != mmdb_path or h.get("mtime") != str(mtime) or not asns <= header_asns(h)


def networks(mmdb_path: str, asn: int, limit: int = 20000) -> Tuple[List[str], str]:
    """Все сети автономной системы (для показа и блокировки) и название организации."""
    text, st = build(mmdb_path, [asn])
    nets = [line.split()[0] for line in text.splitlines()[1:] if line.strip()]
    return nets[:limit], st["orgs"].get(asn, "")
