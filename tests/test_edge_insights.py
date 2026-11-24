"""Встроенный анализ на смоделированных происшествиях: всплеск 5xx и 4xx разных видов, медленный бэкенд, один
адрес с массой запросов, падение и всплеск трафика относительно вчерашнего дня, боты, старый TLS, кэш, журнал
ошибок nginx всех категорий. И на крайних данных: пустая база, один запрос, повреждённые записи статистики."""
from __future__ import annotations

import json
import time

import pytest

from app.config import settings
from app.models import Backend, CacheSettings, Site
from app.stats.parsing import ERROR_CATEGORIES
from tests.test_collector import line
from tests.test_settings_backup import _insert


@pytest.fixture()
def nm(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    api = create_app()
    with TestClient(api):
        n = api.state.nm
        n.stats.agg.get_settings = lambda: n.panel().model_copy(update={"store_requests": True})
        monkeypatch.setattr(n.nginx, "is_running", lambda: True)  # nginx «работает» — не мешает другим находкам
        yield n


def _ids(res, site=None):
    return {f["id"] for f in res["findings"] if site is None or f["site"] == site}


def _feed(nm, lines):
    nm.stats.agg.ingest_access(lines)
    nm.stats.agg.flush(force=True)


def test_empty_and_tiny_data(nm):
    now = time.time()
    res = nm.insights.evaluate(now - 900, now, "*")
    assert res["counts"]["crit"] == 0 and res["checked"] == 97
    for f in res["findings"]:
        assert f["title"] and f["level"] in ("crit", "warn", "info")
    _feed(nm, [line(now - 30, status=503)])  # один запрос с ошибкой — не повод для тревоги
    nm.insights._cache.clear()
    assert "e5xx_rate" not in _ids(nm.insights.evaluate(now - 900, now + 1, "*"))
    # повреждённая запись статистики (data не JSON) не ломает анализ
    nm.db.execute("UPDATE stats_minute SET data='не json'")
    nm.insights._cache.clear()
    nm.insights.evaluate(now - 900, now + 1, "*")


def test_incident_storm(nm):
    sid = _insert(nm.db, Site(name="Магазин", domains=["shop.test"], backends=[Backend(port=9001)],
                              cache=CacheSettings(enabled=True)))
    s = str(sid)
    now = time.time()
    t0 = now - 600
    nm.stats.started = t0 - 3600  # панель работала весь период: топы адресов — из памяти, без гонки со сбросом
    lines = []
    for i in range(2000):
        ts = t0 + (i % 590)
        k = i % 20
        if k < 6:
            lines.append(line(ts, site=s, status=[502, 504, 503, 500][k % 4], rt=3.5, uri="/api/x",
                              ustatus=str([502, 504, 503, 500][k % 4]), ua="Go-http-client/1.1"))
        elif k < 9:
            lines.append(line(ts, site=s, status=[404, 401, 429][k - 6], uri=f"/missing/{i % 7}"))
        elif k == 9:
            lines.append(line(ts, site=s, status=499, rt=9.0))
        elif k == 10:
            lines.append(line(ts, site=s, status=413, method="POST"))
        elif k < 16:
            lines.append(line(ts, site=s, rt=2.5, ua="curl/8.5", cache="MISS"))
        else:
            lines.append(line(ts, site=s, rt=2.5, ip="203.0.113.66", ua="python-requests/2.31",
                              cache="MISS" if i % 3 else "HIT"))
    _feed(nm, lines)
    # журнал ошибок nginx: по записи каждой категории много раз
    errs = []
    for cid, pat, *_ in ERROR_CATEGORIES:
        sample = {"upstream_timeout": "upstream timed out (110: Connection timed out) while reading response header "
                                      "from upstream", "upstream_refused": "connect() failed (111: Connection "
                                                                           "refused) while connecting to upstream"}
        msg = sample.get(cid, pat.replace("\\", "").replace("(", "").replace(")", "").replace("|", " ")[:80])
        for j in range(30):
            ts = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(t0 + j * 10))
            errs.append(f"{ts} [error] 1#1: *1 {msg}, client: 203.0.113.{j}, server: shop.test, "
                        f"request: \"GET / HTTP/1.1\", upstream: \"http://10.0.0.1:9001/\", host: \"shop.test\"")
    nm.stats.agg.domain_map = {"shop.test": s}
    nm.stats.agg.ingest_errors(errs)
    nm.stats.agg.flush(force=True)
    res = nm.insights.evaluate(t0, now + 1, "*")
    ids = _ids(res)
    expected = {"e5xx_rate", "e502", "e504", "latency_p95", "slow_backend", "single_ip", "bots_share",
                "log_upstream_timeout", "log_upstream_refused"}
    assert expected <= ids, expected - ids
    assert res["counts"]["crit"] >= 1
    for f in res["findings"]:  # у каждой находки — текст, уровень и сайт
        assert f["summary"] and f["level"] in ("crit", "warn", "info") and f["site_name"]
    # отключённые сценарии уходят в «скрытые»
    nm.save_panel(nm.panel().model_copy(update={"insights_muted": ["e502"]}))
    nm.insights._cache.clear()
    res2 = nm.insights.evaluate(t0, now + 1, "*")
    assert "e502" not in _ids(res2) and "e502" in {f["id"] for f in res2["muted"]}
    # анализ одного сайта и несуществующего сайта
    nm.insights._cache.clear()
    assert "e5xx_rate" in _ids(nm.insights.evaluate(t0, now + 1, s))
    nm.insights._cache.clear()
    assert "e5xx_rate" not in _ids(nm.insights.evaluate(t0, now + 1, "999"))


def test_traffic_vs_yesterday(nm):
    sid = _insert(nm.db, Site(name="Блог", domains=["blog.test"], backends=[Backend(port=9002)]))
    s = str(sid)
    now = time.time()
    hour0 = int(now - 3600) // 3600 * 3600
    # вчера и сегодня до периода: ~10 запросов/с
    rows = [(hour0 - 3600 * h, s, 36000, json.dumps({"hist": [36000] + [0] * 20})) for h in range(1, 20)]
    nm.db.executemany("INSERT INTO stats_hour(ts, site, req, data) VALUES(?,?,?,?)", rows)
    # сейчас — 0 запросов: сайт «замолчал»
    res = nm.insights.evaluate(now - 900, now, "*")
    assert {"no_traffic_site", "traffic_drop"} & _ids(res, s)
    # всплеск: в 20 раз больше обычного
    _feed(nm, [line(now - 300 + i * 0.01, site=s) for i in range(30000)])
    nm.insights._cache.clear()
    assert "traffic_spike" in _ids(nm.insights.evaluate(now - 300, now + 1, "*"), s)


def test_custom_thresholds(nm):
    p = nm.panel()
    nm.save_panel(p.model_copy(update={"insight_thresholds": {"err5": {"warn": 50, "crit": 90}}}))
    t = nm.insights.thresholds()
    assert t["err5"] == {"warn": 50.0, "crit": 90.0, "custom": True}
    assert "Свои пороги" in nm.insights.custom_note("e5xx_rate")
    assert nm.insights.level("err5", 60) == "warn" and nm.insights.level("err5", None) == "ok"
    cat = nm.insights.catalog()
    assert cat["metrics"]["err5"]["custom"] and cat["metrics"]["connections"]["capacity"] >= 1
    g = nm.global_settings().model_copy(update={"worker_processes": "auto"})
    nm.db.kv_set("global_settings", g.model_dump())
    assert nm.insights.capacity() >= 1
