"""Блокировка по странам: файл geo для nginx из базы GeoIP (MaxMind GeoLite2 / DB-IP, формат mmdb).

nginx не умеет читать mmdb без стороннего модуля, поэтому панель сама выбирает из базы сети
нужных стран, объединяет соседние и пишет файл `geo-countries.conf`:

    # nm-geo db=/var/lib/nginx-manager/geoip/GeoLite2-Country.mmdb mtime=1731400000 countries=CN,RU nets=8123
    10.0.0.0/8 LAN;
    1.0.1.0/24 CN;
    ...

В конфигурации это `geo $nm_cc { default --; include geo-countries.conf; }`. В файл попадают только
страны, упомянутые в правилах сайтов (и частные сети с меткой LAN), поэтому он небольшой. Файл
пересобирается при применении конфигурации, если набор стран изменился, и при обновлении базы.
"""
from __future__ import annotations

import ipaddress
import os
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# ISO 3166-1 alpha-2 (+ XK — Косово, используется в базах GeoIP)
COUNTRY_CODES: Tuple[str, ...] = (
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE",
    "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD",
    "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
    "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU",
    "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
    "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME",
    "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
    "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI",
    "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK",
    "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW",
)
COUNTRY_SET = frozenset(COUNTRY_CODES)

# Страны Евросоюза (быстрый выбор в интерфейсе)
EU = ("AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU",
      "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK")

# Частные, локальные и служебные сети: метка LAN (режим «только выбранные страны» может их пропускать)
PRIVATE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
                "::1/128", "fc00::/7", "fe80::/10")

HEADER = "# nm-geo"
_V4_COMPAT = ipaddress.ip_network("::/96")
_ALIASES = (ipaddress.ip_network("::ffff:0:0/96"), ipaddress.ip_network("2002::/16"))


def referenced(sites: Iterable[Any]) -> Set[str]:
    """Страны из правил включённых сайтов."""
    out: Set[str] = set()
    for s in sites:
        sec = s.security
        if getattr(s, "enabled", True) and sec.geo_mode != "off":
            out.update(sec.geo_countries)
    return out


def read_header(path: str) -> Dict[str, str]:
    """Параметры первой строки файла (db, mtime, countries, nets, built)."""
    try:
        with open(path, encoding="utf-8") as f:
            first = f.readline().strip()
    except OSError:
        return {}
    if not first.startswith(HEADER):
        return {}
    out = {}
    for part in first[len(HEADER):].split():
        k, _, v = part.partition("=")
        out[k] = v
    return out


def header_countries(h: Dict[str, str]) -> Set[str]:
    return {c for c in h.get("countries", "").split(",") if c}


DB_NAMES = ("GeoLite2-Country.mmdb", "dbip-country-lite.mmdb", "dbip-country.mmdb", "GeoLite2-City.mmdb")
_usable: Dict[Tuple[str, float], bool] = {}


def candidates(path: str, fallback_dir: str) -> List[str]:
    """Где искать базу: путь из настроек панели, каталог панели, стандартные каталоги geoipupdate."""
    out = [path] if path else []
    out += [os.path.join(fallback_dir, f) for f in DB_NAMES]
    out += ["/usr/share/GeoIP/GeoLite2-Country.mmdb", "/var/lib/GeoIP/GeoLite2-Country.mmdb"]
    return out


def find_db(path: str, fallback_dir: str) -> Optional[str]:
    """Первая найденная база, пригодная для блокировки по странам (открывается и перебирается)."""
    try:
        import maxminddb  # type: ignore  # noqa: F401
    except ImportError:
        return None
    for c in candidates(path, fallback_dir):
        try:
            key = (c, os.path.getmtime(c))
        except OSError:
            continue
        ok = _usable.get(key)
        if ok is None:
            try:
                iterable_reader(c).close()
                ok = True
            except Exception:
                ok = False
            _usable[key] = ok
        if ok:
            return c
    return None


def iterable_reader(mmdb_path: str):
    """Открыть базу и убедиться, что её можно перебрать (maxminddb ≥ 2.4)."""
    import maxminddb  # type: ignore
    r = maxminddb.open_database(mmdb_path)
    if not hasattr(r, "__iter__"):
        r.close()
        raise RuntimeError("для блокировки по странам нужен пакет maxminddb версии 2.4 или новее")
    return r


def _country(rec: Any) -> str:
    if not isinstance(rec, dict):
        return ""
    c = rec.get("country") or rec.get("registered_country") or {}
    return (c.get("iso_code") or "") if isinstance(c, dict) else ""


def build(mmdb_path: str, countries: Iterable[str]) -> Tuple[str, Dict[str, Any]]:
    """Текст файла geo для выбранных стран и статистика (сети по странам, время сборки)."""
    want = sorted({c for c in countries if c in COUNTRY_SET})
    t0 = time.time()
    v4: Dict[str, List[Any]] = {c: [] for c in want}
    v6: Dict[str, List[Any]] = {c: [] for c in want}
    if want:
        r = iterable_reader(mmdb_path)
        try:
            for net, rec in r:
                cc = _country(rec)
                if cc not in v4:
                    continue
                if net.version == 6:
                    if any(net.subnet_of(a) for a in _ALIASES):
                        continue
                    if net.subnet_of(_V4_COMPAT):
                        net = ipaddress.ip_network((int(net.network_address), max(0, net.prefixlen - 96)))
                (v4 if net.version == 4 else v6)[cc].append(net)
        finally:
            r.close()
    per: Dict[str, int] = {}
    body: List[str] = [f"{n} LAN;" for n in PRIVATE_NETS]
    for cc in want:
        nets = list(ipaddress.collapse_addresses(v4[cc])) + list(ipaddress.collapse_addresses(v6[cc]))
        per[cc] = len(nets)
        body.extend(f"{n} {cc};" for n in nets)
    try:
        mtime = int(os.path.getmtime(mmdb_path)) if mmdb_path else 0
    except OSError:
        mtime = 0
    total = sum(per.values())
    head = (f"{HEADER} db={mmdb_path or '-'} mtime={mtime} countries={','.join(want)} nets={total} "
            f"built={int(time.time())}")
    stats = {"countries": per, "nets": total, "seconds": round(time.time() - t0, 2), "db": mmdb_path, "mtime": mtime}
    return head + "\n" + "\n".join(body) + "\n", stats


def empty_file() -> str:
    """Начальный файл: только частные сети (nginx должен найти include ещё до выбора стран)."""
    return f"{HEADER} db=- mtime=0 countries= nets=0 built=0\n" + "".join(f"{n} LAN;\n" for n in PRIVATE_NETS)


def needs_rebuild(path: str, mmdb_path: Optional[str], countries: Set[str]) -> bool:
    h = read_header(path)
    if not h:
        return True
    if not countries:
        return bool(header_countries(h))
    if not mmdb_path:
        return False
    try:
        mtime = int(os.path.getmtime(mmdb_path))
    except OSError:
        return False
    return h.get("db") != mmdb_path or h.get("mtime") != str(mtime) or header_countries(h) != countries
