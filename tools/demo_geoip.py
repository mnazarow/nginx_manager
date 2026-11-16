#!/usr/bin/env python3
"""Демонстрационная база GeoIP (mmdb) для стенда и скриншотов: страны для адресов tools/loadgen.py.

Не является настоящей базой — диапазоны /8 назначены странам условно. Для работы нужен пакет
mmdb-writer (pip install mmdb-writer). Настоящие базы: GeoLite2-Country (MaxMind, бесплатная
регистрация) или dbip-country-lite (DB-IP, без регистрации) — см. главу 09 документации.

    python3 tools/demo_geoip.py /var/lib/nginx-manager/geoip/dbip-country-lite.mmdb
    python3 tools/demo_geoip.py --asn /var/lib/nginx-manager/geoip/dbip-asn-lite.mmdb   # сети провайдеров
"""
import sys

from mmdb_writer import MMDBWriter
from netaddr import IPSet

DEMO = {"RU": ["46.0.0.0/8", "77.0.0.0/8", "95.0.0.0/8", "178.0.0.0/8"], "DE": ["5.0.0.0/8", "217.0.0.0/8"],
        "NL": ["31.0.0.0/8", "185.0.0.0/8"], "KZ": ["188.0.0.0/8"], "FR": ["91.0.0.0/8"], "PL": ["109.0.0.0/8"],
        "GB": ["212.0.0.0/8"], "US": ["198.51.100.0/24", "8.0.0.0/8"], "CN": ["203.0.113.0/24", "1.0.0.0/8"]}


# Демонстрационные сети провайдеров (номера AS из диапазона для документации RFC 5398, названия вымышленные)
DEMO_ASN = {64500: ("Demo Hosting LLC", ["127.0.1.0/26", "46.0.0.0/9"]),
            64501: ("Example Cloud Inc.", ["127.0.1.64/26", "31.0.0.0/8", "203.0.113.0/24"]),
            64502: ("Sample Telecom", ["127.0.1.128/25", "95.0.0.0/8", "198.51.100.0/24"]),
            64503: ("Test Broadband", ["77.0.0.0/8", "188.0.0.0/8", "5.0.0.0/8"])}


def main_asn(out: str) -> None:
    w = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="DBIP-ASN-Lite (compat=GeoLite2-ASN)",
                   languages=["en"], description="Nginx Manager DEMO ASN database (not real data)")
    for asn, (org, nets) in DEMO_ASN.items():
        w.insert_network(IPSet(nets), {"autonomous_system_number": asn, "autonomous_system_organization": org})
    w.to_db_file(out)
    print("записано:", out)


def main(out: str) -> None:
    w = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="DBIP-Country-Lite", languages=["en"],
                   description="Nginx Manager DEMO geo database (not real data)")
    for cc, nets in DEMO.items():
        w.insert_network(IPSet(nets), {"country": {"iso_code": cc}})
    w.to_db_file(out)
    print("записано:", out)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--asn":
        main_asn(sys.argv[2] if len(sys.argv) > 2 else "demo-asn.mmdb")
    else:
        main(sys.argv[1] if len(sys.argv) > 1 else "demo-geo.mmdb")
