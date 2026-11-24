"""Ядро панели в нетиповых ситуациях: фоновые циклы (сторож nginx, периодические задачи, рассылка по WebSocket)
при сбоях, метрики оповещений на пустых и странных данных, истечение временного доступа, переприменение версии без
применённой конфигурации, смена состояния бэкенда, отчёты, история анализа."""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from app import core as C
from app.models import AlertRule, ALERT_METRICS, IpAccessSettings, IpEntry
from app.nginx.manager import ApplyError
from tests.test_settings_backup import _insert, _site


@pytest.fixture()
def nm(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    api = create_app()
    with TestClient(api):
        yield api.state.nm


class Stop(Exception):
    pass


def _sleeps(monkeypatch, n):
    """asyncio.sleep в core: n первых вызовов — мгновенно, затем остановка цикла."""
    calls = []
    real = asyncio.sleep

    async def fake(sec, *a):
        calls.append(sec)
        if len(calls) > n:
            raise Stop()
        await real(0)
    monkeypatch.setattr(C.asyncio, "sleep", fake)
    return calls


# =============================================================================
#  Метрики оповещений
# =============================================================================
def test_every_metric_on_empty_data(nm):
    """Каждая метрика на чистой установке — число или «нет данных», без исключений; с фильтром сайта тоже."""
    for m in ALERT_METRICS:
        for site in ("*", "1", "999"):
            rule = AlertRule(name=m, metric=m, op=">", threshold=1, site=site if site != "*" else "")
            v, detail = nm.metric(rule)
            assert v is None or isinstance(v, (int, float)), (m, v)
            assert isinstance(detail, str)


def test_metrics_with_data(nm, monkeypatch):
    now = time.time()
    nm.db.execute("INSERT INTO ipdeny_minute(ts, site, ip, n) VALUES(?,?,?,?)", (int(now // 60) * 60, "3",
                                                                                 "203.0.113.9", 12))
    v, d = nm.metric(AlertRule(name="x", metric="ipaccess_denied", op=">", threshold=1, site="3", window=300))
    assert v > 0 and "203.0.113.9: 12" in d
    v, d = nm.metric(AlertRule(name="x", metric="ipaccess_denied", op=">", threshold=1, site="4", window=300))
    assert v == 0
    nm.db.event("warning", "bans", "Автоблокировка 203.0.113.5 на 60 мин")
    assert nm.metric(AlertRule(name="x", metric="autobans", op=">", threshold=0))[0] == 1
    for cat, lvl in (("limit_req", "error"), ("upstream", "crit")):
        nm.db.execute("INSERT INTO errors(ts, level, category, message) VALUES(?,?,?,?)", (now, lvl, cat, "m"))
    assert nm.metric(AlertRule(name="x", metric="error_log_rate", op=">", threshold=0, window=60))[0] == 2
    assert nm.metric(AlertRule(name="x", metric="rate_limited", op=">", threshold=0, window=60))[0] == 1
    # nginx остановлен / конфигурация не проходит проверку
    monkeypatch.setattr(nm.nginx, "is_running", lambda: False)
    assert nm.metric(AlertRule(name="x", metric="nginx_down", op=">", threshold=0))[0] == 1
    nm.nginx._last_test = (now, False, "nginx: [emerg] boom")
    assert nm.metric(AlertRule(name="x", metric="config_error", op=">", threshold=0)) == (1.0, "nginx: [emerg] boom")
    # сертификаты: короткоживущий с запасом не считается срочным
    monkeypatch.setattr(nm.certs, "list", lambda: [
        {"id": 1, "name": "short", "domains": ["a.test"], "days_left": 4.0, "used_by": [1], "lifetime": 6,
         "not_before": now - 2 * 86400, "not_after": now + 4 * 86400},
        {"id": 2, "name": "long", "domains": ["b.test"], "days_left": 25.0, "used_by": [2],
         "not_before": now - 65 * 86400, "not_after": now + 25 * 86400}])
    v, d = nm.metric(AlertRule(name="x", metric="cert_expiry", op="<", threshold=14))
    assert v == 25.0 and "long" in d


def test_live_filter_match():
    item = {"site": "3", "s": 503, "ip": "203.0.113.9", "u": "/API/v1", "host": "shop.test", "ua": "curl/8",
            "rt": 0.25, "bot": True}
    m = C.App._match
    assert m(item, {})
    assert m(item, {"site": "*", "status": "5xx", "ip": "203.0.113", "q": "api", "min_rt": "200"})
    assert not m(item, {"site": "4"}) and not m(item, {"status": "4xx"}) and not m(item, {"status": "502"})
    assert m(item, {"status": "503"}) and not m(item, {"ip": "198.51"}) and not m(item, {"q": "nothing"})
    assert not m(item, {"min_rt": "300"}) and not m(item, {"hide_bots": True})
    assert m(item, {"q": "CURL"}) and m(item, {"q": "shop"})


# =============================================================================
#  Фоновые циклы
# =============================================================================
def test_watchdog_restart_budget(nm, monkeypatch):
    monkeypatch.setattr(nm.nginx, "is_running", lambda: False)
    monkeypatch.setattr(nm.nginx, "last_applied", lambda: {"id": 1})
    starts = []
    results = iter([(True, ""), (False, "Job for nginx.service failed"), (True, ""), (True, ""), (True, ""),
                    (True, "")])
    monkeypatch.setattr(nm.nginx, "start", lambda: starts.append(1) or next(results))
    monkeypatch.setattr(nm.nginx, "test_config", lambda conf=None: (True, ""))
    _sleeps(monkeypatch, 8)
    with pytest.raises(Stop):
        asyncio.run(nm.watchdog())
    ev = [(r["level"], r["message"]) for r in nm.db.query("SELECT level, message FROM events WHERE "
                                                          "source='watchdog' ORDER BY id")]
    assert len(starts) == 5 and ev[0] == ("warning", "Nginx был остановлен — запущен автоматически")
    assert ev[1][0] == "error" and "Job for nginx.service failed" in ev[1][1]
    assert ev[-1][0] == "error" and "приостановлен на 10 минут" in ev[-1][1] and len(ev) == 6


def test_watchdog_survives_errors(nm, monkeypatch):
    def boom():
        raise OSError("psutil сломался")
    monkeypatch.setattr(nm.nginx, "is_running", boom)
    calls = _sleeps(monkeypatch, 3)
    with pytest.raises(Stop):
        asyncio.run(nm.watchdog())
    assert calls[:3] == [5, 10, 10]  # ошибка не останавливает цикл


def test_ticker_drops_dead_clients(nm, monkeypatch):
    class WS:
        def __init__(self, fail=False):
            self.sent, self.fail = [], fail

        async def send_text(self, t):
            if self.fail:
                raise ConnectionError("клиент ушёл")
            self.sent.append(json.loads(t))

    class Client:
        def __init__(self, ws, live=False, errors=False):
            self.ws, self.live, self.errors = ws, live, errors
            self.live_seq = self.err_seq = 0
            self.live_filter = {"status": "5xx"}
    good, bad = Client(WS(), live=True, errors=True), Client(WS(fail=True))
    nm.clients = {good, bad}
    monkeypatch.setattr(nm.stats.agg, "live_since", lambda seq, n: [
        {"seq": 5, "site": "1", "s": 502, "ip": "x", "u": "/", "host": "h", "ua": "", "rt": 0.1},
        {"seq": 6, "site": "1", "s": 200, "ip": "x", "u": "/", "host": "h", "ua": "", "rt": 0.1}])
    monkeypatch.setattr(nm.stats.agg, "errors_since", lambda seq, n: [{"seq": 9, "message": "boom"}])
    _sleeps(monkeypatch, 1)
    with pytest.raises(Stop):
        asyncio.run(nm.ticker())
    types = [m["type"] for m in good.ws.sent]
    assert types == ["tick", "requests", "errors"] and good.live_seq == 6 and good.err_seq == 9
    assert len(good.ws.sent[1]["items"]) == 1 and bad not in nm.clients
    # broadcast тоже выкидывает отвалившихся
    nm.clients = {good, Client(WS(fail=True))}
    asyncio.run(nm.broadcast({"type": "x", "ts": object()}))
    assert nm.clients == {good}


def test_periodic_one_pass_with_failures(nm, monkeypatch):
    """Один проход периодических задач: сбой диагностики и анализа не мешает остальным (отчёт, копия, доступ)."""
    order = []

    async def boom():
        order.append("diag")
        raise RuntimeError("диагностика упала")

    def insights_fail(*a):
        raise ValueError("анализ упал")
    monkeypatch.setattr(nm.diag, "run_all", boom)
    monkeypatch.setattr(nm.insights, "evaluate", insights_fail)

    async def mark(name):
        order.append(name)
    monkeypatch.setattr(nm, "expire_access", lambda: mark("access"))
    monkeypatch.setattr(nm, "maybe_send_report", lambda: mark("report"))
    monkeypatch.setattr(nm, "reconcile_failover", lambda: mark("failover"))
    monkeypatch.setattr(nm, "refresh_geo", lambda: mark("geo"))
    monkeypatch.setattr(nm.certs, "auto_renew", lambda after=None: mark("renew"))
    monkeypatch.setattr(nm.certs, "refresh_all", lambda: order.append("refresh"))
    monkeypatch.setattr(nm.diag, "auto_takeover", lambda: mark("takeover"))
    monkeypatch.setattr(nm.geoupdate, "tick", lambda: mark("geoupdate"))
    p = nm.panel()
    nm.save_panel(p.model_copy(update={"backup_hour": time.localtime().tm_hour}))
    import app.services.backup as B
    monkeypatch.setattr(B, "auto_backup", lambda app: order.append("backup"))
    _sleeps(monkeypatch, 1)
    with pytest.raises(Stop):
        asyncio.run(nm.periodic())
    assert order[0] == "diag" and {"access", "report", "failover", "renew", "takeover", "backup"} <= set(order)
    ev = nm.db.one("SELECT message FROM events WHERE source='panel' AND message LIKE 'Фоновая%' ORDER BY id")
    assert "«диагностика» завершилась ошибкой: диагностика упала" in ev["message"]
    # в тот же день повторной копии нет
    assert nm.db.kv_get("last_auto_backup") == time.strftime("%Y-%m-%d")


def test_periodic_broken_panel_settings(nm, monkeypatch):
    def bad():
        raise ValueError("испорчены настройки")
    monkeypatch.setattr(nm, "panel", bad)
    calls = _sleeps(monkeypatch, 2)
    with pytest.raises(Stop):
        asyncio.run(nm.periodic())
    assert calls == [20, 60, 60]


def test_guard_never_raises(nm, monkeypatch):
    async def boom():
        raise KeyError("x")
    asyncio.run(nm._guard("задача", boom()))
    assert "задача" in nm.db.one("SELECT message FROM events ORDER BY id DESC")["message"]

    def db_broken(*a, **k):
        raise RuntimeError("база недоступна")
    monkeypatch.setattr(nm.db, "event", db_broken)
    asyncio.run(nm._guard("задача", boom()))  # и запись события не валит цикл


# =============================================================================
#  Истечение временного доступа и переприменение
# =============================================================================
def test_expire_access(nm, monkeypatch):
    past, future = time.time() - 60, time.time() + 3600
    sid = _insert(nm.db, _site("A", "a.test", ip_access=IpAccessSettings(enabled=True, entries=[
        IpEntry(address="198.51.100.1"), IpEntry(address="203.0.113.5", expires=past),
        IpEntry(address="203.0.113.6", expires=future)])))
    nm.save_panel(nm.panel().model_copy(update={"trusted_ips": [IpEntry(address="192.0.2.1", expires=past),
                                                                IpEntry(address="192.0.2.2")]}))
    # применённая версия содержит истёкшие записи (применена до истечения)
    nm.db.execute("INSERT INTO config_versions(ts, username, comment, source, status, files, state, output, checksum) "
                  "VALUES(?,?,?,?,?,?,?,?,?)", (past - 10, "a", "", "user", "applied", "{}",
                                                json.dumps({"sites": [{"id": sid, "data": {"ip_access": {"entries": [
                                                    {"address": "203.0.113.5", "expires": past}]}}}],
                                                    "panel": {"trusted_ips": []}}), "", ""))
    snaps = []

    async def fake_snapshot(reason, source):
        snaps.append((reason, source))
        return {"version": 2}
    monkeypatch.setattr(nm, "apply_snapshot", fake_snapshot)

    async def grants_ok(force=False):
        return True, ""
    monkeypatch.setattr(nm.grants, "sync", grants_ok)
    assert asyncio.run(nm.expire_access()) == {"version": 2}
    ents = json.loads(nm.db.one("SELECT data FROM sites WHERE id=?", (sid,))["data"])["ip_access"]["entries"]
    assert [e["address"] for e in ents] == ["198.51.100.1", "203.0.113.6"]
    assert [e.address for e in nm.panel().trusted_ips] == ["192.0.2.2"]
    ev = nm.db.one("SELECT message FROM events WHERE source='access' ORDER BY id DESC")["message"]
    assert "203.0.113.5 — сайт «A»" in ev and "192.0.2.1 — доверенные адреса" in ev
    assert snaps == [("Истёк временный доступ", "expire")]
    # второй раз в те же 10 минут — без переприменения
    assert asyncio.run(nm.expire_access()) is None and len(snaps) == 1


def test_expire_access_many_and_broken_version(nm, monkeypatch):
    past = time.time() - 5
    _insert(nm.db, _site("A", "a.test", ip_access=IpAccessSettings(enabled=True, entries=[
        IpEntry(address=f"203.0.113.{i}", expires=past) for i in range(1, 15)])))

    async def grants_ok(force=False):
        return True, ""
    monkeypatch.setattr(nm.grants, "sync", grants_ok)
    nm.db.execute("INSERT INTO config_versions(ts, username, comment, source, status, files, state, output, checksum) "
                  "VALUES(?,?,?,?,?,?,?,?,?)", (past, "a", "", "user", "applied", "{}", "не json", "", ""))
    assert asyncio.run(nm.expire_access()) is None
    assert "и ещё 4" in nm.db.one("SELECT message FROM events WHERE source='access'")["message"]


def test_apply_snapshot_edge_cases(nm, monkeypatch):
    assert asyncio.run(nm.apply_snapshot("x", "user")) is None  # ничего не применялось

    from app.nginx.generator import State
    st = nm.nginx.load_state()
    monkeypatch.setattr(nm, "last_applied_state", lambda: State.from_json(st.to_json()))

    async def failing(*a, **k):
        raise ApplyError("nginx -t")
    monkeypatch.setattr(nm, "apply", failing)
    assert asyncio.run(nm.apply_snapshot("x", "user")) is None


def test_after_cert_issued_and_health_change(nm, monkeypatch):
    from app.nginx.generator import State
    from app.services.health import Target
    sid = _insert(nm.db, _site("A", "a.test", ssl={"enabled": True, "certificate_id": 7}))
    st = nm.nginx.load_state()
    monkeypatch.setattr(nm, "last_applied_state", lambda: State.from_json(st.to_json()))
    snaps = []

    async def fake_snapshot(reason, source):
        snaps.append(source)
    monkeypatch.setattr(nm, "apply_snapshot", fake_snapshot)
    monkeypatch.setattr(nm.peers, "push_cert", lambda cid: {})
    asyncio.run(nm.after_cert_issued(7))
    asyncio.run(nm.after_cert_issued(8))  # сертификат не используется — без переприменения
    assert snaps == ["certs"]
    site = nm.nginx.load_state().sites[0][1]
    t = Target(key=f"site:{sid}|127.0.0.1:8080", owner=f"site:{sid}", owner_name="A", address="127.0.0.1",
               port=8080, scheme="http", check=site.health.model_copy(update={"auto_failover": True}), host="a.test")
    t.last_error = "connection refused"
    sent = []

    async def bc(msg):
        sent.append(msg)
    monkeypatch.setattr(nm, "broadcast", bc)
    asyncio.run(nm.on_health_change(t, "up", "down"))
    asyncio.run(nm.on_health_change(t, "down", "up"))
    ev = [(r["level"], r["message"]) for r in nm.db.query("SELECT level, message FROM events WHERE source='health'")]
    assert ev[0][0] == "error" and "НЕДОСТУПЕН: connection refused" in ev[0][1] and ev[1][0] == "info"
    assert [m["state"] for m in sent] == ["down", "up"] and snaps.count("failover") == 2
    nm.save_panel(nm.panel().model_copy(update={"auto_apply_failover": False}))
    asyncio.run(nm.on_health_change(t, "up", "down"))
    assert snaps.count("failover") == 2


def test_insights_history_and_reports(nm, monkeypatch):
    f1 = {"fid": "a", "id": "s1", "level": "crit", "site": "1", "site_name": "A", "title": "5xx", "summary": "много"}
    f2 = {"fid": "b", "id": "s2", "level": "warn", "site": "*", "site_name": "", "title": "диск", "summary": "90%",
          "since": time.time() - 600}
    nm._insights_history([f1])  # первый проход — только запоминаем
    nm._insights_history([f1, f2, {**f2, "fid": "c", "level": "info"}])
    nm._insights_history([f1])
    ev = [r["message"] for r in nm.db.query("SELECT message FROM events WHERE source='insights' ORDER BY id")]
    assert ev == ["Обнаружено: диск — 90%", "Устранено: диск (длилось ~10 мин)"]
    # отчёт: срок не подошёл / подошёл, часть каналов с ошибкой
    import app.services.reports as R
    monkeypatch.setattr(R, "due", lambda p: None)
    asyncio.run(nm.maybe_send_report())
    monkeypatch.setattr(R, "due", lambda p: "day-2026-11-24")
    monkeypatch.setattr(R, "build", lambda app, period: {"title": "Отчёт за сутки"})

    async def send(app, rep, channels):
        return [{"id": 1, "ok": True}, {"id": 2, "name": "почта", "ok": False, "error": "SMTP 535"}]
    monkeypatch.setattr(R, "send", send)
    asyncio.run(nm.maybe_send_report())
    asyncio.run(nm.maybe_send_report())  # тот же период — второй раз не отправляется
    ev = nm.db.query("SELECT level, message FROM events WHERE source='reports'")
    assert len(ev) == 1 and "1 из 2" in ev[0]["message"] and "почта: SMTP 535" in ev[0]["message"]


def test_refresh_geo_events(nm, monkeypatch):
    monkeypatch.setattr(nm.nginx, "refresh_asn", lambda: (False, "nginx: [emerg] asn"))
    monkeypatch.setattr(nm.nginx, "refresh_geo", lambda force=False: (False, "nginx: [emerg] geo"))
    asyncio.run(nm.refresh_geo())
    lv = [(r["level"], r["message"]) for r in nm.db.query("SELECT level, message FROM events WHERE source='geoip'")]
    assert ("error", "Не удалось обновить сети провайдеров в nginx") in lv
    assert ("error", "Не удалось обновить сети стран в nginx") in lv
    nm.nginx.geo_stats = {"nets": 3, "countries": {"RU": 2, "DE": 1}}
    monkeypatch.setattr(nm.nginx, "refresh_geo", lambda force=False: (True, ""))
    monkeypatch.setattr(nm.nginx, "refresh_asn", lambda: None)
    asyncio.run(nm.refresh_geo(force=True))
    assert "Сети стран обновлены: 3 сетей (DE, RU)" in nm.db.one(
        "SELECT message FROM events WHERE source='geoip' ORDER BY id DESC")["message"]


def test_state_summary_and_silence(nm):
    user = nm.db.one("SELECT * FROM users WHERE username='admin'")
    s = nm.state_summary(dict(user))
    assert s["user"]["username"] == "admin" and s["silence"] is None and "nginx" in s
    now = time.time()
    nm.db.execute("INSERT INTO silences(rule_ids, reason, starts_at, ends_at, username, created_at) "
                  "VALUES(?,?,?,?,?,?)", ("[]", "работы", now - 10, now + 600, "admin", now))
    s = nm.state_summary(dict(user))
    assert s["silence"]["reason"] == "работы" and s["silence"]["all"]
