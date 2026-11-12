#!/usr/bin/env python3
"""Демонстрационная база GeoIP (mmdb) для стенда и скриншотов: страны для адресов tools/loadgen.py.

Не является настоящей базой — диапазоны /8 назначены странам условно. Для работы нужен пакет
mmdb-writer (pip install mmdb-writer). Настоящие базы: GeoLite2-Country (MaxMind, бесплатная
регистрация) или dbip-country-lite (DB-IP, без регистрации) — см. главу 09 документации.

    python3 tools/demo_geoip.py /var/lib/nginx-manager/geoip/dbip-country-lite.mmdb
"""
import sys

from mmdb_writer import MMDBWriter
from netaddr import IPSet

DEMO = {"RU": ["46.0.0.0/8", "77.0.0.0/8", "95.0.0.0/8", "178.0.0.0/8"], "DE": ["5.0.0.0/8", "217.0.0.0/8"],
        "NL": ["31.0.0.0/8", "185.0.0.0/8"], "KZ": ["188.0.0.0/8"], "FR": ["91.0.0.0/8"], "PL": ["109.0.0.0/8"],
        "GB": ["212.0.0.0/8"], "US": ["198.51.100.0/24", "8.0.0.0/8"], "CN": ["203.0.113.0/24", "1.0.0.0/8"]}


def main(out: str) -> None:
    w = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="DBIP-Country-Lite", languages=["en"],
                   description="Nginx Manager DEMO geo database (not real data)")
    for cc, nets in DEMO.items():
        w.insert_network(IPSet(nets), {"country": {"iso_code": cc}})
    w.to_db_file(out)
    print("записано:", out)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo-geo.mmdb")
