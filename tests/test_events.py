"""Уведомления о событиях: фильтры источников и уровня, защита от повторов, лимит в час, тишина, путь через API."""
import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from app.models import AlertChannel, PanelSettings
from app.services import events as ev

PW = "Event-Passw0rd!"
H = {"X-NM-CSRF": "1"}


@pytest.fixture(scope="module")
def hook():
    got = []

    class Hd(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), Hd)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/hook", got
    srv.shutdown()


class FakeAlerts:
    def __init__(self, url, silence=None):
        self.url, self.silence = url, silence

    def silence_for(self, rid):
        return self.silence

    def channels(self, ids):
        return [(i, AlertChannel(name=f"hook{i}", type="webhook", url=self.url)) for i in ids]


class FakeDB:
    def __init__(self):
        self.events = []

    def execute(self, *a):
        pass

    def event(self, *a, **k):
        self.events.append(a)


class FakeApp:
    def __init__(self, url, **panel):
        self.p = PanelSettings(event_channels=[1], **panel)
        self.alerts = FakeAlerts(url)
        self.db = FakeDB()

    def panel(self):
        return self.p


def run_events(app, items):
    """Прогнать события через on_event в работающем цикле и дождаться доставки."""
    async def go():
        n = ev.EventNotifier(app)
        n.attach(asyncio.get_running_loop())
        for it in items:
            await asyncio.to_thread(n.on_event, *it)   # как из Database.event в другом потоке
        for _ in range(100):
            await asyncio.sleep(0.02)
        return n
    return asyncio.run(go())


def test_filters_and_dedup(hook):
    url, got = hook
    got.clear()
    app = FakeApp(url, event_min_level="warning", event_repeat_minutes=30)
    run_events(app, [
        ("error", "certs", "Ошибка выпуска сертификата «a»: No TXT record"),
        ("info", "certs", "Сертификат «a» продлён"),                                  # ниже уровня
        ("error", "health", "Бэкенд 10.0.0.1:80 — НЕДОСТУПЕН"),                      # источник не выбран
        ("error", "alerts", "Не удалось отправить"),                                 # никогда (петля)
        ("error", "config", "Конфигурация не применена (применял admin): ошибка в строке 12"),
        ("error", "config", "Конфигурация не применена (применял admin): ошибка в строке 14"),  # повтор
    ])
    by = {g["event"]["source"]: g for g in got}   # доставка асинхронная — порядок не важен
    assert len(got) == 2 and set(by) == {"certs", "config"}, [g["title"] for g in got]
    assert by["certs"]["title"] == "Ошибка: сертификаты" and by["certs"]["severity"] == "critical"
    assert "No TXT" in by["certs"]["text"] and by["config"]["title"] == "Ошибка: применение конфигурации"


def test_repeat_counter_and_hourly_limit(hook, monkeypatch):
    url, got = hook
    got.clear()
    app = FakeApp(url, event_min_level="info", event_repeat_minutes=0, event_sources=["panel"])

    async def go():
        n = ev.EventNotifier(app)
        n.attach(asyncio.get_running_loop())
        # повтор: окно 1 мин, второе событие копится и приходит счётчиком с третьим
        app.p = PanelSettings(event_channels=[1], event_min_level="info", event_repeat_minutes=1, event_sources=["panel"])
        n.on_event("error", "panel", "Фоновая задача «x» завершилась ошибкой: 1")
        n.on_event("error", "panel", "Фоновая задача «x» завершилась ошибкой: 2")
        k = ev._key("panel", "Фоновая задача «x» завершилась ошибкой: 3")
        n.last[k][0] -= 120  # окно прошло
        n.on_event("error", "panel", "Фоновая задача «x» завершилась ошибкой: 3")
        await asyncio.sleep(0.5)
        # лимит в час: после HOURLY_LIMIT — одно предупреждение о паузе, дальше тишина
        monkeypatch.setattr(ev, "HOURLY_LIMIT", 4)
        app.p = PanelSettings(event_channels=[1], event_min_level="info", event_repeat_minutes=0, event_sources=["panel"])
        for i in range(6):
            n.on_event("warning", "panel", f"событие {chr(97 + i)}")
        await asyncio.sleep(0.8)
    asyncio.run(go())
    texts = [g["text"] for g in got]
    assert any("повторялось ещё 1 раз" in t for t in texts)
    assert any("следующие не отправляются" in t for t in texts)
    assert len(got) == 2 + 2 + 1   # 2 первых + до лимита (4 всего) + предупреждение


def test_global_silence_suppresses(hook):
    url, got = hook
    got.clear()
    app = FakeApp(url)
    app.alerts.silence = {"id": 1, "ends_at": time.time() + 600, "reason": "работы"}
    run_events(app, [("error", "watchdog", "Nginx был остановлен — запустить не удалось")])
    assert got == []


@pytest.fixture(scope="module")
def admin(hook):
    from app.main import create_app
    from app.utils import hash_password
    app = create_app()
    with TestClient(app) as c:
        app.state.nm.db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username='admin'",
                                (hash_password(PW),))
        assert c.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
        yield c


def test_api_end_to_end(admin, hook):
    """Настройка через API → настоящая запись в журнал событий → уведомление в webhook."""
    url, got = hook
    got.clear()
    admin.app.state.nm.db.execute("DELETE FROM silences")   # тишина из других тестов заглушила бы события
    cid = admin.post("/api/alerts/channels", json={"name": "Хук", "type": "webhook", "url": url}, headers=H).json()["id"]
    assert admin.post("/api/events/notify-test", headers=H).status_code == 400   # каналы не выбраны
    p = admin.get("/api/settings/panel").json()
    p.update(event_channels=[cid], event_sources=["certs", "auth"], event_min_level="warning")
    assert admin.put("/api/settings/panel", json=p, headers=H).status_code == 200
    r = admin.post("/api/events/notify-test", headers=H)
    assert r.status_code == 200 and r.json()["results"][0]["ok"], r.text
    nm = admin.app.state.nm
    nm.db.event("error", "certs", "Ошибка выпуска сертификата «shop»: unauthorized")
    # блокировка входа после неудачных попыток — событие auth
    c2 = TestClient(admin.app)
    for _ in range(nm.panel().login_max_attempts):
        c2.post("/api/auth/login", json={"username": "nobody", "password": "wrong"})
    for _ in range(100):
        if len(got) >= 3:
            break
        time.sleep(0.05)
    titles = [g["title"] for g in got]
    assert any("Проверка уведомлений" in g["text"] for g in got)       # проверочное
    assert any(g["event"]["source"] == "certs" for g in got), titles
    assert any(g["event"]["source"] == "auth" and "заблокирован" in g["text"] for g in got), titles
    nm.auth.failures.clear()
    p.update(event_channels=[])
    admin.put("/api/settings/panel", json=p, headers=H)
    admin.delete(f"/api/alerts/channels/{cid}", headers=H)
