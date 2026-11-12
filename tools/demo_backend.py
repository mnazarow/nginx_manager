#!/usr/bin/env python3
"""Демонстрационный бэкенд для тестирования Nginx Manager.

Запуск: python3 tools/demo_backend.py 9001 9002 9003
Эмулирует приложение: разное время ответа, ошибки 5xx, большие ответы, /health.
"""
import asyncio
import random
import sys


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
            reason = {200: "OK", 404: "Not Found", 500: "Internal Server Error", 502: "Bad Gateway",
                      503: "Service Unavailable"}[status]
            ctype = "application/json" if path.startswith("/api/") else "text/html; charset=utf-8"
            hdr = (f"HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                   f"X-Powered-By: demo/{port}\r\nCache-Control: public, max-age=60\r\nConnection: keep-alive\r\n\r\n")
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
