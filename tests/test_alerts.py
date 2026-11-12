"""Оповещения: срабатывание, повтор, восстановление, тишина, каналы (на локальный HTTP-сервер)."""
import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.db import Database
from app.models import AlertChannel, AlertRule
from app.services.alerts import AlertEngine, send

TMP = os.environ["NM_TEST_TMP"]


@pytest.fixture(scope="module")
def hook():
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append((self.path, dict(self.headers), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", got
    srv.shutdown()


def test_send_formats(hook):
    url, got = hook
    got.clear()
    send(AlertChannel(name="w", type="webhook", url=url + "/w",
                      webhook_headers=[{"name": "X-Token", "value": "s3cr3t"}]), "Заголовок", "Текст <b>", "critical",
         {"metric": "m"})
    send(AlertChannel(name="s", type="slack", url=url + "/s"), "T", "x", "warning")
    send(AlertChannel(name="d", type="discord", url=url + "/d"), "T", "y" * 3000, "info")
    send(AlertChannel(name="t", type="telegram", telegram_api=url, telegram_token="123:abc", telegram_chat_id="-1"),
         "T <i>", "a & b", "resolved")
    paths = {p: (h, b) for p, h, b in got}
    assert paths["/w"][1]["severity"] == "critical" and paths["/w"][1]["metric"] == "m"
    assert paths["/w"][0]["X-Token"] == "s3cr3t"
    assert "*T*" in paths["/s"][1]["text"] and len(paths["/d"][1]["content"]) <= 1990
    tg = paths["/bot123:abc/sendMessage"][1]
    assert tg["chat_id"] == "-1" and "&lt;i&gt;" in tg["text"] and "a &amp; b" in tg["text"]


def make_engine(tmp_name, value_box):
    db = Database(f"{TMP}/{tmp_name}.db")
    eng = AlertEngine(db, lambda rule: (value_box[0], "подробности"), lambda msg: None)
    return db, eng


def test_rule_lifecycle(hook):
    url, got = hook
    got.clear()
    value = [10.0]
    db, eng = make_engine("alerts-life", value)
    cid = db.execute("INSERT INTO alert_channels(name,type,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                     ("hook", "webhook", 1, AlertChannel(name="hook", type="webhook", url=url + "/r").model_dump_json(), 0, 0))
    rule = AlertRule(name="Много 5xx", metric="error_5xx_rate", threshold=5, duration=0, repeat_minutes=0,
                     channels=[cid], site="3")
    rid = db.execute("INSERT INTO alert_rules(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                     (rule.name, 1, rule.model_dump_json(), 0, 0))
    eng.site_name = lambda sid: {"3": "Блог"}.get(sid, sid)
    # канал без правила: правило без каналов уведомляет только панель
    quiet = AlertRule(name="Тихое", metric="error_5xx_rate", threshold=5, duration=0, channels=[])
    db.execute("INSERT INTO alert_rules(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
               (quiet.name, 1, quiet.model_dump_json(), 0, 0))
    asyncio.run(eng.evaluate())   # ok → pending
    asyncio.run(eng.evaluate())   # pending → firing (duration 0)
    assert eng.state[rid]["state"] == "firing"
    fired = [b for p, h, b in got if p == "/r"]
    assert len(fired) == 1 and fired[0]["state"] == "firing" and "Сайт: Блог" in fired[0]["text"]
    value[0] = None               # нет данных — инцидент не закрывается
    asyncio.run(eng.evaluate())
    assert eng.state[rid]["state"] == "firing" and len([1 for p, _, _ in got if p == "/r"]) == 1
    value[0] = 1.0                # восстановление
    asyncio.run(eng.evaluate())
    resolved = [b for p, h, b in got if p == "/r"][-1]
    assert resolved["state"] == "resolved" and eng.state[rid]["state"] == "ok"
    events = db.query("SELECT state, rule_name, notified FROM alert_events ORDER BY id")
    assert [e["state"] for e in events if e["rule_name"] == "Много 5xx"] == ["firing", "resolved"]
    assert all(e["notified"] == "" for e in events if e["rule_name"] == "Тихое")
    # тишина: срабатывание записывается, но не отправляется
    import time
    db.execute("INSERT INTO silences(created_at,starts_at,ends_at,rule_ids,reason) VALUES(?,?,?,?,?)",
               (time.time(), time.time() - 1, time.time() + 600, "[]", "работы"))
    before = len(got)
    value[0] = 50.0
    asyncio.run(eng.evaluate())
    asyncio.run(eng.evaluate())
    assert len(got) == before
    last = db.query("SELECT notified FROM alert_events ORDER BY id DESC LIMIT 1")[0]["notified"]
    assert "тишина" in last
    db.close()
