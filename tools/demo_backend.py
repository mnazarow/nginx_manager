#!/usr/bin/env python3
"""Демонстрационный бэкенд для тестирования Nginx Manager.

Запуск: python3 tools/demo_backend.py 9001 9002 9003
Эмулирует приложение: разное время ответа, ошибки 5xx, большие ответы, /health.
"""
import asyncio
import random
import sys


# «Лица» приложений для определения технологий сайтов (раздел «Защита → Уязвимости → Технологии ваших сайтов»)
PROFILES = {
    # интернет-магазин: 1С-Битрикс на PHP
    9001: ("Server: Apache/2.4.58 (Ubuntu)\r\nX-Powered-By: PHP/8.1.27\r\nX-Powered-CMS: Bitrix Site Manager\r\n"
           "Set-Cookie: PHPSESSID=demo; path=/\r\nSet-Cookie: BITRIX_SM_GUEST_ID=1; path=/\r\n",
           b'<html><head><title>Shop</title><script src="/bitrix/js/main/core/core.js"></script></head><body>'),
    9002: ("Server: Apache/2.4.58 (Ubuntu)\r\nX-Powered-By: PHP/8.1.27\r\nSet-Cookie: PHPSESSID=demo; path=/\r\n",
           b'<html><head><title>Shop</title><script src="/bitrix/js/main/core/core.js"></script></head><body>'),
    # API: Next.js на Node.js
    9003: ("X-Powered-By: Next.js\r\n", b'<html><head><title>API</title><script id="__NEXT_DATA__"></script></head><body>'),
    9005: ("X-Powered-By: Next.js\r\n", b'<html><head><title>API</title><script id="__NEXT_DATA__"></script></head><body>'),
    # блог: WordPress на PHP за Apache
    9004: ("Server: Apache/2.4.58 (Ubuntu)\r\nX-Powered-By: PHP/8.2.12\r\n",
           b'<html><head><title>Blog</title><meta name="generator" content="WordPress 6.4.2" />'
           b'<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css"></head><body>'),
}
# служебные адреса приложений — для углублённого определения технологий
PROBED = {
    (9004, "/wp-json/"): (200, "", b'{"name":"Blog","namespaces":["oembed/1.0","wp/v2","wp-site-health/v1"]}'),
    (9004, "/wp-login.php"): (200, "", b'<form id="loginform"><input type="submit" name="wp-submit"></form>'
                                       b'<link rel="stylesheet" href="/wp-admin/css/login.min.css?ver=6.4.2">'),
    (9003, "/jenkins/login"): (403, "X-Jenkins: 2.426.1\r\nX-Hudson: 1.395\r\n", b"<html>Authentication required</html>"),
}


async def handle(reader, writer, port):
    try:
        while True:
            line = await asyncio.wait_for(reader.readline(), 30)
            if not line:
                break
            parts = line.decode("latin-1").split()
            path = parts[1] if len(parts) > 1 else "/"
            length = 0
            while True:
                h = await reader.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                if h.lower().startswith(b"content-length:"):
                    length = int(h.split(b":")[1])
            if length:
                await reader.readexactly(length)
            status, delay, size = 200, random.expovariate(1 / 0.03), random.randint(500, 20000)
            if path.startswith("/health"):
                delay, size = 0, 2
            elif path.startswith("/api/slow"):
                delay = random.uniform(0.8, 2.5)
            elif path.startswith("/api/"):
                delay = random.expovariate(1 / 0.06)
                if random.random() < 0.03:
                    status = random.choice([500, 502, 503])
            elif path.startswith("/download"):
                size = random.randint(200000, 900000)
            elif path.startswith("/missing") or random.random() < 0.02:
                status = 404
            await asyncio.sleep(min(delay, 5))
            body = (b"x" * size) if size > 2 else b"OK"
            extra = ""
            if path in ("/", "/index.html") and port in PROFILES:
                extra, head = PROFILES[port]
                body = head + body + b"</body></html>"
            if (port, path) in PROBED:
                status, extra, body = PROBED[(port, path)]
            elif path.startswith(("/wp-json", "/wp-login", "/jenkins", "/status.php", "/rest/applinks",
                                  "/phpmyadmin", "/manager/html", "/actuator", "/owa/", "/zabbix", "/roundcube",
                                  "/administrator", "/bitrix/admin", "/user/login", "/users/sign_in", "/login")):
                status, body = 404, b"Not Found"
            reason = {200: "OK", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error",
                      502: "Bad Gateway", 503: "Service Unavailable"}[status]
            ctype = "application/json" if path.startswith("/api/") else "text/html; charset=utf-8"
            hdr = (f"HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                   + (extra or f"X-Powered-By: demo/{port}\r\n")
                   + "Cache-Control: public, max-age=60\r\nConnection: keep-alive\r\n\r\n")
            writer.write(hdr.encode() + body)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def main(ports):
    servers = [await asyncio.start_server(lambda r, w, p=p: handle(r, w, p), "127.0.0.1", p) for p in ports]
    print("demo backends on", ports, flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main([int(x) for x in sys.argv[1:]] or [9001]))
