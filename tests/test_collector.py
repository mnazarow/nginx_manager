"""Сбор статистики целиком: строки журнала nginx (формат nm_json) → агрегация → БД → сводка, топы, поиск."""
import json
import os
import time

from app.db import Database
from app.models import PanelSettings
from app.stats.collector import Aggregator
from app.stats.parsing import GeoIP
from app.stats.service import StatsService

TMP = os.environ["NM_TEST_TMP"]


def line(ts, site="1", status=200, uri="/", ip="203.0.113.5", rt=0.05, bytes_=1000, ua="Mozilla/5.0 Chrome/120",
         upstream="10.0.0.1:80", ustatus="200", bn="0", gb="0", host="shop.test", method="GET", cache=""):
    return json.dumps({"t": f"{ts:.3f}", "site": site, "host": host, "ip": ip, "m": method, "u": uri, "p": "HTTP/1.1",
                       "s": str(status), "b": str(bytes_), "bs": str(bytes_ + 200), "rl": "300", "rt": f"{rt:.3f}",
                       "ua": upstream, "us": ustatus, "urt": f"{rt:.3f}" if upstream else "", "uct": "0.001",
                       "uht": "0.002", "ref": "https://google.com/", "agent": ua, "cache": cache, "sch": "https",
                       "tls": "TLSv1.3", "rid": "abc", "cr": "1", "bn": bn, "gb": gb})


def test_ingest_to_summary_and_tops():
    db = Database(f"{TMP}/collector.db")
    ps = PanelSettings(store_requests=True)
    stats = StatsService.__new__(StatsService)  # без фоновых задач и опроса nginx
    stats.db, stats.get_panel = db, lambda: ps
    stats.agg = Aggregator(db, lambda: ps, GeoIP())
    stats.started = time.time() - 7200
    base = (int(time.time()) // 60 - 5) * 60
    lines = []
    for i in range(300):
        ts = base + (i % 120)
        if i % 10 == 0:
            lines.append(line(ts, status=502, uri="/api/x", rt=1.5, ustatus="502"))
        elif i % 7 == 0:
            lines.append(line(ts, status=404, uri="/missing", ip="198.51.100.9"))
        elif i % 11 == 0:
            lines.append(line(ts, status=403, uri="/blocked", gb="1", ip="192.0.2.77"))
        else:
            lines.append(line(ts, uri=f"/p/{i % 5}", cache="HIT" if i % 2 else "MISS"))
    lines += ["", "not a json line", '{"t": "x"}']
    stats.agg.ingest_access(lines)
    assert stats.agg.parsed == 300 and stats.agg.parse_errors >= 1
    stats.agg.flush(force=True)
    s = stats.summary(base, base + 600, "1", exact_uniq=False)
    assert s["requests"] == 300
    assert s["status"]["5xx"] == 30 and s["codes"]["502"] == 30
    assert s["blocked"]["geo"] > 0 and s["blocked"]["codes"]["403"] == s["blocked"]["geo"]
    assert s["err4_pct_clean"] < s["err4_pct"]
    assert s["p95"] >= 1000 and 0 < s["hit_ratio"] < 100
    total = stats.summary(base, base + 600, "*", exact_uniq=False)
    assert total["requests"] == 300
    top = {t["key"]: t["count"] for t in stats.agg.recent_tops(60, "1", "uri", 10)}
    assert top["/api/x"] == 30
    e5 = stats.agg.recent_tops(60, "1", "e5xx", 5)
    assert e5 and e5[0]["key"].startswith("502 ")
    found = stats.search_requests({"site": "1", "status": "5xx", "start": base, "end": base + 600}, 50)
    assert found["total"] == 30 and all(r["status"] == 502 for r in found["items"])
    ip = stats.search_requests({"ip": "198.51.100.9", "start": base, "end": base + 600}, 5)
    assert ip["items"] and ip["items"][0]["uri"] == "/missing"
    db.close()


def test_parsers_survive_garbage():
    import random

    from app.stats.parsing import parse_access, parse_error, parse_stream
    random.seed(7)
    values = [None, 5, -1, 1.5, "", "-", "x" * 3000, [1], {"a": 1}, True, "0.1, 0.2 : 0.3", "1e309", "\x00"]
    keys = ["t", "site", "host", "ip", "m", "u", "p", "s", "b", "bs", "rl", "rt", "ua", "us", "urt", "agent", "cache",
            "tls", "bn", "gb", "proto", "port", "dur", "br"]
    for _ in range(2000):
        d = {k: random.choice(values) for k in random.sample(keys, random.randint(0, len(keys)))}
        if random.random() < 0.5:
            d.update(t=str(time.time()), s=str(random.choice([200, 404, 502])))
        line_ = json.dumps(d)
        r = parse_access(line_)
        if r is not None:
            assert isinstance(r["uri"], str) and 100 <= r["status"] <= 999 and r["ts"] > 0
        parse_stream(line_)
    for junk in ["", "[]", "{", "null", '{"t": null, "s": "abc"}', "2026/11/12 01:00:00 [error] 1#1: *5 x",
                 "2026/11/12 01:00:00 [crit] garbage", "\x00\x01"]:
        parse_access(junk)
        parse_error(junk)
        parse_stream(junk)
