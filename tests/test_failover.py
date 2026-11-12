"""Автопереключение бэкендов: выключение упавших серверов переживает любое применение конфигурации, «неприменённые
изменения» не появляются из-за переключения, работающая конфигурация сверяется с результатами проверок."""
import asyncio
import json
import os
import time
from pathlib import Path

import pytest

from app.core import effective_failover, failover_in_files
from app.models import Backend, GlobalSettings, HealthCheck, PanelSettings, Site
from app.nginx.generator import Generator, NginxCaps, Paths, State

TMP = Path(os.environ["NM_TEST_TMP"])


def site(**kw):
    d = dict(name="Магазин", domains=["shop.example.com"], type="proxy",
             backends=[Backend(address="10.0.0.1", port=80), Backend(address="10.0.0.2", port=80),
                       Backend(address="10.0.0.3", port=80, backup=True)],
             health=HealthCheck(enabled=True, auto_failover=True))
    d.update(kw)
    return Site(**d)


def render(state):
    p = Paths(str(TMP / "managed" / "stage"), str(TMP / "managed" / "live"), "/var/acme", str(TMP / "logs"),
              str(TMP / "cache"), 8089, 8088, str(TMP / "data"), bans_file=str(TMP / "bans.conf"))
    (TMP / "bans.conf").write_text("")
    return Generator(state, NginxCaps(version=(1, 24, 0), ipv6=False), p).render()


def test_markers_roundtrip():
    st = State([(7, site())], [], GlobalSettings(), PanelSettings(), {}, overrides={"site:7": ["10.0.0.2:80"]})
    files = render(st)
    assert failover_in_files(files) == {"site:7": ["10.0.0.2:80"]}
    assert effective_failover(st, st.overrides) == {"site:7": ["10.0.0.2:80"]}
    # все основные упали — генератор никого не выключает, и сверка считает так же (иначе применяла бы каждую минуту)
    st.overrides = {"site:7": ["10.0.0.1:80", "10.0.0.2:80"]}
    assert failover_in_files(render(st)) == {} == effective_failover(st, st.overrides)
    # упал резервный — выключается он
    st.overrides = {"site:7": ["10.0.0.3:80"]}
    assert failover_in_files(render(st)) == {"site:7": ["10.0.0.3:80"]} == effective_failover(st, st.overrides)
    # выключенный вручную сервер и чужие адреса не считаются; выключенный сайт — тоже
    st = State([(7, site(backends=[Backend(address="10.0.0.1", port=80), Backend(address="10.0.0.2", port=80, down=True),
                                   Backend(address="10.0.0.4", port=80)])), (8, site(enabled=False))], [],
               GlobalSettings(), PanelSettings(), {},
               overrides={"site:7": ["10.0.0.2:80", "10.9.9.9:80", "10.0.0.4:80"], "site:8": ["10.0.0.1:80"]})
    assert effective_failover(st, st.overrides) == {"site:7": ["10.0.0.4:80"]} == failover_in_files(render(st))


@pytest.fixture()
def nm(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    app = App()
    app.save_panel(PanelSettings(auto_apply_failover=True))
    sid = app.db.execute("INSERT INTO sites(name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?)",
                         ("Магазин", 1, json.dumps(site().model_dump(), ensure_ascii=False), 0, 0))
    app.refresh_runtime_maps()
    return app, sid


def _targets(app, sid, states):
    for t in app.health.targets.values():
        if t.owner == f"site:{sid}":
            t.state = states.get(t.backend_key, "up")


def _applied(app, overrides):
    """Записать «применённую» версию (nginx в тестах не перезагружается) с заданным выключением."""
    st = app.nginx.load_state()
    st.overrides = overrides
    files, _ = app.nginx.render(st)
    app.db.execute("INSERT INTO config_versions(ts,username,comment,source,status,files,state,output,checksum) "
                   "VALUES(?,?,?,?,?,?,?,?,?)", (time.time(), "t", "", "user", "applied", json.dumps(files),
                                                 json.dumps(st.to_json()), "", "x"))


def test_load_state_and_apply_keep_failover(nm, monkeypatch):
    app, sid = nm
    assert app.health.targets, "проверки бэкендов сайта должны быть зарегистрированы"
    _targets(app, sid, {"10.0.0.2:80": "down"})
    assert app.nginx.load_state().overrides == {f"site:{sid}": ["10.0.0.2:80"]}
    # применение пользователем передаёт генератору выключение упавшего сервера
    seen = {}

    def fake_apply_sync(state, username="", comment="", source=""):
        seen["overrides"] = dict(state.overrides)
        return {"version": 1, "warnings": [], "duration": 0, "output": ""}
    monkeypatch.setattr(app.nginx, "apply_sync", fake_apply_sync)
    asyncio.run(app.nginx.apply(None, "admin", "", "user"))
    assert seen["overrides"] == {f"site:{sid}": ["10.0.0.2:80"]}
    # откат (состояние из версии) — тоже
    st = app.nginx.load_state()
    st.overrides = {}
    asyncio.run(app.nginx.apply(st, "admin", "", "rollback"))
    assert seen["overrides"] == {f"site:{sid}": ["10.0.0.2:80"]}
    # автопереключение выключено в настройках панели — бэкенды не выключаются
    app.save_panel(PanelSettings(auto_apply_failover=False))
    assert app.nginx.load_state().overrides == {}


def test_no_false_pending_from_failover(nm):
    app, sid = nm
    _targets(app, sid, {"10.0.0.2:80": "down"})
    _applied(app, {f"site:{sid}": ["10.0.0.2:80"]})
    # конфигурацию не меняли — неприменённых изменений нет, хотя в работающей версии сервер выключен
    assert app.nginx.pending()["pending"] is False
    _targets(app, sid, {})
    assert app.nginx.pending()["pending"] is True  # сервер поднялся — переключение ещё не применено


def test_reconcile(nm, monkeypatch):
    app, sid = nm
    calls = []

    async def fake_snapshot(reason, source):
        calls.append((reason, source))
        return {"version": 99}
    monkeypatch.setattr(app, "apply_snapshot", fake_snapshot)
    # после применения из nmctl сервер включён, а проверки говорят «упал»
    _applied(app, {})
    _targets(app, sid, {"10.0.0.2:80": "unknown"})
    assert asyncio.run(app.reconcile_failover()) is None and not calls  # до первых проверок — не трогаем
    _targets(app, sid, {"10.0.0.2:80": "down"})
    assert asyncio.run(app.reconcile_failover()) == {"version": 99}
    assert calls[-1][1] == "failover" and "сверка" in calls[-1][0]
    # то же расхождение повторно не применяется чаще раза в 10 минут
    assert asyncio.run(app.reconcile_failover()) is None and len(calls) == 1
    # совпадает — ничего не делаем
    _applied(app, {f"site:{sid}": ["10.0.0.2:80"]})
    assert asyncio.run(app.reconcile_failover()) is None and len(calls) == 1
    # панель перезапускалась, сервер за это время поднялся (unknown → up не вызывает переключения)
    _targets(app, sid, {})
    assert asyncio.run(app.reconcile_failover()) == {"version": 99} and len(calls) == 2
    # все основные упали — генератор никого не выключает; это не расхождение
    _applied(app, {})
    _targets(app, sid, {"10.0.0.1:80": "down", "10.0.0.2:80": "down"})
    assert asyncio.run(app.reconcile_failover()) is None and len(calls) == 2
