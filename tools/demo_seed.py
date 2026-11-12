#!/usr/bin/env python3
"""Демонстрационное наполнение панели (для знакомства, тестов и скриншотов документации).

  python3 tools/demo_seed.py --password 'Admin12345!'                 сайты, поток, сертификат, правила
  python3 tools/demo_seed.py --password '...' --history-days 7       + синтетическая история статистики

Требует запущенную панель. История пишется прямо в БД (/var/lib/nginx-manager/nginx-manager.db)
и помечается как демонстрационная только на уровне данных — не используйте на рабочем сервере.
Бэкенды для демо: python3 tools/demo_backend.py 9001 9002 9003 9004
Нагрузка:          python3 tools/loadgen.py --hosts shop.example.com,api.example.com,blog.example.com
"""
import argparse
import http.cookiejar
import json
import math
import random
import sqlite3
import sys
import time
import urllib.request

API = "http://127.0.0.1:8088/api"


class Client:
    def __init__(self, base, user, password):
        self.base = base
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj),
                                              urllib.request.ProxyHandler({}))
        self.call("POST", "/auth/login", {"username": user, "password": password})

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "X-NM-CSRF": "1"})
        try:
            with self.op.open(req, timeout=60) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            print(f"! {method} {path}: {e.code} {e.read()[:300].decode('utf-8', 'replace')}")
            return None


def backend(addr, port, **kw):
    return {"address": addr, "port": port, **kw}


def seed(c: Client):
    if c.call("GET", "/sites"):
        print("Сайты уже есть — пропуск создания")
        return
    cert = c.call("POST", "/certs", {"type": "selfsigned", "name": "shop.example.com",
                                     "domains": ["shop.example.com", "www.shop.example.com"]})
    cert2 = c.call("POST", "/certs", {"type": "selfsigned", "name": "panel.example.com", "domains": ["panel.example.com"]})
    g = c.call("GET", "/settings/global")
    g.update(real_ip_enabled=True, real_ip_from=["127.0.0.1"])
    c.call("PUT", "/settings/global", g)
    c.call("POST", "/sites", {
        "name": "Интернет-магазин", "domains": ["shop.example.com", "www.shop.example.com"], "canonical_redirect": True,
        "backends": [backend("127.0.0.1", 9001, weight=2, comment="app-1"), backend("127.0.0.1", 9002, comment="app-2")],
        "balancing": "least_conn", "tags": ["prod", "магазин"], "health": {"path": "/health"},
        "ssl": {"enabled": True, "certificate_id": cert["id"], "hsts": True, "hsts_max_age": 300},
        "cache": {"enabled": True, "bypass_cookie_pattern": "session|cart"},
        "security": {"block_bad_bots": True, "conn_limit": 50},
        "performance": {"client_max_body_size": "20m", "static_expires": "7d"},
        "locations": [
            {"path": "/api/", "use_site_backends": False, "backends": [backend("127.0.0.1", 9003)], "proxy_path": "/api/",
             "rate_limit": "custom", "rate": "50r/s", "burst": 100, "cache": "off"},
            {"path": "/admin", "action": "proxy", "allow": ["127.0.0.1", "10.0.0.0/8"]},
            {"path": "/robots.txt", "match": "exact", "action": "return", "return_body": "User-agent: *\nDisallow: /admin",
             "return_type": "text/plain"},
        ]})
    c.call("POST", "/sites", {
        "name": "API сервис", "domains": ["api.example.com"], "tags": ["prod", "api"],
        "backends": [backend("127.0.0.1", 9003), backend("127.0.0.1", 9005, comment="новый узел (ещё не запущен)")],
        "health": {"path": "/health", "interval": 5}, "balancing": "least_conn",
        "security": {"rate_limit": True, "rate": "30r/s", "burst": 60, "x_frame_options": "DENY"},
        "proxy": {"next_upstream": ["error", "timeout", "http_502", "http_503", "http_504"], "read_timeout": "120s"}})
    c.call("POST", "/sites", {
        "name": "Блог", "domains": ["blog.example.com"], "backends": [backend("127.0.0.1", 9004)], "tags": ["content"],
        "health": {"path": "/health"}, "performance": {"static_expires": "7d"},
        "cache": {"enabled": True}})
    c.call("POST", "/sites", {"name": "Старый домен", "type": "redirect", "domains": ["old-shop.example.com"],
                              "redirect": {"url": "https://shop.example.com", "code": 301}})
    c.call("POST", "/sites", {"name": "Документация (статика)", "type": "static", "domains": ["docs.example.com"],
                              "enabled": False, "static": {"root": "/var/www/docs", "spa": True}})
    c.call("POST", "/streams", {"name": "PostgreSQL", "protocol": "tcp", "listen_port": 15432,
                                "backends": [backend("127.0.0.1", 9004)], "timeout": "1h", "allow": ["127.0.0.0/8", "10.0.0.0/8"]})
    c.call("POST", "/streams", {"name": "DNS", "protocol": "udp", "listen_port": 15353,
                                "backends": [backend("127.0.0.1", 53)], "timeout": "10s", "udp_responses": 1,
                                "health_check": False})
    c.call("POST", "/alerts/channels", {"name": "Дежурный webhook", "type": "webhook", "url": "http://127.0.0.1:9004/hook"})
    c.call("POST", "/config/apply", {"comment": "Демонстрационные сайты"})
    print("Созданы демонстрационные сайты, потоки и сертификаты, конфигурация применена")


def history(db_path: str, days: int):
    db = sqlite3.connect(db_path)
    now = int(time.time()) // 60 * 60
    start = now - days * 86400
    sites = {"1": 1.0, "2": 0.6, "3": 0.35, "4": 0.12, "-": 0.05}
    rnd = random.Random(42)
    uris = ["/", "/catalog", "/catalog/shoes", "/product/123", "/product/456", "/cart", "/api/items", "/api/user",
            "/search", "/static/app.js", "/static/style.css", "/img/logo.png", "/api/slow/report", "/download/file.zip"]
    ips = [f"{rnd.choice([5, 31, 46, 77, 91, 95, 109, 178, 185, 188, 212, 217])}.{rnd.randint(0, 255)}."
           f"{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(60)]
    browsers = {"Chrome": 46, "Safari": 18, "Яндекс.Браузер": 12, "Firefox": 7, "Edge": 5, "Googlebot": 4, "YandexBot": 3, "curl": 2}
    oses = {"Windows": 38, "Android": 26, "iOS": 17, "macOS": 9, "Linux": 6, "Другая": 4}
    devices = {"Компьютер": 52, "Мобильный": 38, "Планшет": 4, "Бот": 6}
    rows_m, rows_h = [], {}
    tops = {}
    sysrows = []
    t = start
    incident = start + (days - 2) * 86400 + 14 * 3600  # «инцидент» с 5xx позавчера в 14:00
    while t < now - 120:
        lt = time.localtime(t)
        hour = lt.tm_hour + lt.tm_min / 60
        diurnal = 0.25 + 0.75 * max(0.0, math.sin((hour - 6) / 24 * 2 * math.pi)) ** 1.3
        weekly = 0.8 if lt.tm_wday >= 5 else 1.0
        base = 900 * diurnal * weekly * (1 + 0.08 * rnd.uniform(-1, 1))
        inc = incident <= t < incident + 25 * 60
        tot = None
        for site, share in list(sites.items()) + [("*", None)]:
            if site == "*":
                m = tot
            else:
                req = int(base * share)
                if req <= 0:
                    continue
                e5 = int(req * (0.18 if inc and site == "2" else 0.004 * rnd.random()))
                e4 = int(req * (0.06 + 0.03 * rnd.random()))
                s3 = int(req * (0.08 if site != "4" else 0.97))
                s2 = max(0, req - e5 - e4 - s3)
                rt_avg = (0.045 if site != "4" else 0.001) * (1 + (2.5 if inc and site == "2" else 0) + 0.2 * rnd.random())
                hist = [0] * 12
                for _ in range(min(req, 200)):
                    v = rnd.expovariate(1 / rt_avg)
                    hist[next((i for i, b in enumerate((0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)) if v <= b), 11)] += 1
                k = req / max(1, sum(hist))
                hist = [int(x * k) for x in hist]
                hit = int(req * 0.55) if site in ("1", "3") else 0
                m = {"req": req, "bout": req * rnd.randint(9000, 16000), "bin": req * 420, "s1": 0, "s2": s2, "s3": s3,
                     "s4": e4, "s5": e5, "rt_sum": req * rt_avg, "rt_max": rt_avg * 25, "urt_sum": req * rt_avg * 0.9,
                     "urt_n": req, "uniq": int(req * 0.22),
                     "data": {"codes": {"200": s2, "301": s3, "404": e4, "502": e5}, "hist": hist,
                              "methods": {"GET": int(req * 0.86), "POST": int(req * 0.11), "HEAD": int(req * 0.03)},
                              "proto": {"HTTP/2.0": int(req * 0.6), "HTTP/1.1": int(req * 0.4)},
                              "tls": {"TLSv1.3": int(req * 0.55), "TLSv1.2": int(req * 0.05)} if site == "1" else {},
                              "cache": {"HIT": hit, "MISS": int(hit * 0.6), "EXPIRED": int(hit * 0.05)} if hit else {},
                              "err": {"upstream_timeout": int(e5 * 0.7), "upstream_refused": int(e5 * 0.3)} if e5 else
                              ({"client_closed": 1} if rnd.random() < 0.3 else {}),
                              "bots": int(req * 0.09), "slow": int(req * 0.01), "static": int(req * 0.3), "ustatus": {}}}
                if tot is None:
                    tot = {k: (dict(v) if isinstance(v, dict) else v) for k, v in m.items()}
                    tot["data"] = json.loads(json.dumps(m["data"]))
                else:
                    for k in ("req", "bout", "bin", "s1", "s2", "s3", "s4", "s5", "rt_sum", "urt_sum", "urt_n", "uniq"):
                        tot[k] += m[k]
                    tot["rt_max"] = max(tot["rt_max"], m["rt_max"])
                    for k, v in m["data"].items():
                        if isinstance(v, dict):
                            for kk, vv in v.items():
                                tot["data"][k][kk] = tot["data"][k].get(kk, 0) + vv
                        elif isinstance(v, list):
                            tot["data"][k] = [a + b for a, b in zip(tot["data"][k], v)]
                        else:
                            tot["data"][k] += v
            rows_m.append((t, site, m["req"], m["bout"], m["bin"], m["s1"], m["s2"], m["s3"], m["s4"], m["s5"], m["rt_sum"],
                           m["rt_max"], m["urt_sum"], m["urt_n"], m["uniq"], json.dumps(m["data"])))
            hk = (t // 3600 * 3600, site)
            h = rows_h.get(hk)
            if h is None:
                rows_h[hk] = {**{k: m[k] for k in m if k != "data"}, "data": json.loads(json.dumps(m["data"])),
                              "uniq": int(m["uniq"] * 6)}
            else:
                for k in ("req", "bout", "bin", "s1", "s2", "s3", "s4", "s5", "rt_sum", "urt_sum", "urt_n"):
                    h[k] += m[k]
                h["rt_max"] = max(h["rt_max"], m["rt_max"])
                h["uniq"] = max(h["uniq"], int(m["uniq"] * 6))
                for k, v in m["data"].items():
                    if isinstance(v, dict):
                        for kk, vv in v.items():
                            h["data"][k][kk] = h["data"][k].get(kk, 0) + vv
                    elif isinstance(v, list):
                        h["data"][k] = [a + b for a, b in zip(h["data"][k], v)]
                    else:
                        h["data"][k] += v
            if t % 3600 == 0 and site in ("*", "1", "2", "3"):
                hr = t
                req = m["req"] * 60
                for kind, dist in (("browser", browsers), ("os", oses), ("device", devices)):
                    for key, w in dist.items():
                        tops[(hr, site, kind, key)] = (int(req * w / 100), 0, 0.0)
                for i, u in enumerate(uris):
                    n = int(req * 0.35 / (i + 1))
                    tops[(hr, site, "uri", u)] = (n, n * 12000, 0.0)
                for i, ip in enumerate(ips[:30]):
                    tops[(hr, site, "ip", ip)] = (int(req * 0.05 / (i + 1) ** 0.7), int(req * 900 / (i + 1)), 0.0)
                for ref, w in (("www.google.com", 0.12), ("yandex.ru", 0.1), ("t.me", 0.03), ("vk.com", 0.02)):
                    tops[(hr, site, "referer", ref)] = (int(req * w), 0, 0.0)
                tops[(hr, site, "e4xx", "404 /missing-page")] = (int(req * 0.02), 0, 0.0)
                tops[(hr, site, "e4xx", "404 /wp-login.php")] = (int(req * 0.012), 0, 0.0)
                tops[(hr, site, "e4xx", "404 /.env")] = (int(req * 0.008), 0, 0.0)
                tops[(hr, site, "e5xx", "502 /api/items")] = (max(1, int(req * 0.002)), 0, 0.0)
                tops[(hr, site, "slow", "/api/slow/report")] = (int(req * 0.008), 0, int(req * 0.008) * 1.7)
                tops[(hr, site, "upstream", "127.0.0.1:9001")] = (int(req * 0.4), 0, 0.0)
                tops[(hr, site, "upstream", "127.0.0.1:9002")] = (int(req * 0.2), 0, 0.0)
                tops[(hr, site, "upstream", "127.0.0.1:9003")] = (int(req * 0.25), 0, 0.0)
        sysrows.append((t, 12 + 40 * diurnal * rnd.uniform(0.8, 1.2), 38 + 6 * diurnal, 0.0, 0.3 + 1.6 * diurnal,
                        0.3 + 1.4 * diurnal, 0.3 + 1.2 * diurnal, 41 + (t - start) / (days * 86400) * 3,
                        base / 60 * 420 * 8, base / 60 * 12000 * 8, 2e5 * diurnal, 1.2e6 * diurnal,
                        base / 4, 1 + diurnal * 4, base / 8, base / 5, 4.2e7, 3 + 18 * diurnal, 2, 120))
        t += 60
    with db:
        db.executemany("INSERT OR REPLACE INTO stats_minute VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows_m)
        db.executemany("INSERT OR REPLACE INTO stats_hour VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       [(k[0], k[1], v["req"], v["bout"], v["bin"], v["s1"], v["s2"], v["s3"], v["s4"], v["s5"], v["rt_sum"],
                         v["rt_max"], v["urt_sum"], v["urt_n"], v["uniq"], json.dumps(v["data"])) for k, v in rows_h.items()])
        db.executemany("INSERT OR REPLACE INTO top_hour VALUES(?,?,?,?,?,?,?)",
                       [(k[0], k[1], k[2], k[3], v[0], v[1], v[2]) for k, v in tops.items()])
        db.executemany("INSERT OR REPLACE INTO system_minute VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", sysrows)
        for i in range(40):
            ts = incident + rnd.randint(0, 25 * 60)
            db.execute("INSERT INTO errors(ts,level,category,message,client,server,site,request,upstream,host) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (ts, "error", "upstream_timeout", "upstream timed out (110: Connection timed out) while reading "
                        "response header from upstream", rnd.choice(ips), "api.example.com", "2",
                        "GET /api/items HTTP/1.1", "http://127.0.0.1:9003/api/items", "api.example.com"))
    print(f"История за {days} дн.: {len(rows_m)} поминутных строк, {len(rows_h)} почасовых, {len(tops)} позиций топов")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=API)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--history-days", type=int, default=0)
    ap.add_argument("--db", default="/var/lib/nginx-manager/nginx-manager.db")
    a = ap.parse_args()
    seed(Client(a.url, a.user, a.password))
    if a.history_days:
        history(a.db, a.history_days)
    sys.exit(0)
