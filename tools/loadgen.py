#!/usr/bin/env python3
"""Генератор тестовой нагрузки на nginx (для демонстрации статистики).

python3 tools/loadgen.py --rps 40 --duration 600 --hosts shop.example.com,api.example.com
Запросы идут на 127.0.0.1 с нужным заголовком Host и разными User-Agent/IP (X-Forwarded-For).
"""
import argparse
import asyncio
import random
import ssl

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 YaBrowser/24.10 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "curl/8.5.0", "python-requests/2.32.3",
]
PATHS = ["/", "/", "/", "/catalog", "/catalog/shoes", "/product/123", "/product/456", "/cart", "/api/items",
         "/api/items?page=2", "/api/user", "/api/slow/report", "/static/app.js", "/static/style.css", "/img/logo.png",
         "/download/file.zip", "/missing-page", "/search?q=nginx", "/.env", "/wp-login.php", "/health"]
REFS = ["https://www.google.com/", "https://yandex.ru/", "https://t.me/", "https://vk.com/", "-", "-", "-"]


async def one(host, port, use_ssl, ip):
    try:
        ctx = None
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port, ssl=ctx,
                                                              server_hostname=host if ctx else None), 5)
        method = random.choice(["GET"] * 12 + ["POST", "HEAD"])
        path = random.choice(PATHS)
        ref = random.choice(REFS)
        body = b'{"a":1}' if method == "POST" else b""
        req = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(UAS)}\r\n"
               f"X-Forwarded-For: {ip}\r\nConnection: close\r\n" + (f"Referer: {ref}\r\n" if ref != "-" else "") +
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        w.write(req)
        await w.drain()
        await asyncio.wait_for(r.read(), 15)
        w.close()
    except Exception:
        pass


async def main(a):
    hosts = a.hosts.split(",")
    ips = [f"{random.choice([5, 31, 46, 77, 91, 95, 109, 178, 185, 188, 212, 217])}.{random.randint(0, 255)}."
           f"{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(300)]
    hot = ips[:15]
    loop = asyncio.get_running_loop()
    end = loop.time() + a.duration
    while loop.time() < end:
        t = loop.time()
        wave = 1 + 0.6 * __import__("math").sin(t / 40)
        n = max(1, int(a.rps * wave / 10))
        for _ in range(n):
            host = random.choice(hosts)
            ip = random.choice(hot if random.random() < 0.4 else ips)
            use_ssl = a.ssl_hosts and host in a.ssl_hosts.split(",")
            asyncio.ensure_future(one(host, 443 if use_ssl else 80, use_ssl, ip))
        await asyncio.sleep(0.1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rps", type=float, default=30)
    ap.add_argument("--duration", type=int, default=300)
    ap.add_argument("--hosts", default="localhost")
    ap.add_argument("--ssl-hosts", default="")
    asyncio.run(main(ap.parse_args()))
