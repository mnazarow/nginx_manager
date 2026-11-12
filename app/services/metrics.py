"""Экспорт метрик в формате Prometheus (text exposition format 0.0.4) — адрес /metrics.

Счётчики (…_total) накапливаются с момента запуска панели; Prometheus сам корректно обрабатывает их
сброс при перезапуске (функции rate()/increase()). Гистограмма времени ответа использует те же корзины,
что и графики панели, поэтому перцентили в Grafana совпадают с перцентилями в панели.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Tuple

from ..config import VERSION
from ..stats.parsing import LAT_BOUNDS

CLASSES = ("other", "1xx", "2xx", "3xx", "4xx", "5xx")


def esc(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def labels(d: Dict[str, Any]) -> str:
    if not d:
        return ""
    return "{" + ",".join(f'{k}="{esc(v)}"' for k, v in d.items()) + "}"


def num(v: float) -> str:
    if v is None or v != v:
        return "NaN"
    if v in (float("inf"), float("-inf")):
        return "+Inf" if v > 0 else "-Inf"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int) or float(v).is_integer():
        return str(int(v))
    return repr(round(float(v), 6))


class Out:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def metric(self, name: str, kind: str, help_: str, samples: Iterable[Tuple[Dict[str, Any], float]],
               suffix_samples: Iterable[Tuple[str, Dict[str, Any], float]] = ()) -> None:
        self.lines.append(f"# HELP {name} {help_}")
        self.lines.append(f"# TYPE {name} {kind}")
        for lb, v in samples:
            self.lines.append(f"{name}{labels(lb)} {num(v)}")
        for sfx, lb, v in suffix_samples:
            self.lines.append(f"{name}{sfx}{labels(lb)} {num(v)}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def site_names(app) -> Dict[str, str]:
    names = {"-": "(сервер по умолчанию)", "panel": "(панель)"}
    try:
        state = app.last_applied_state() or app.nginx.load_state()
        for sid, s in state.sites:
            names[str(sid)] = s.name
    except Exception:
        pass
    return names


def render(app) -> str:
    o = Out()
    now = time.time()
    names = site_names(app)
    agg = app.stats.agg

    o.metric("nginx_manager_info", "gauge", "Версия Nginx Manager", [({"version": VERSION}, 1)])
    o.metric("nginx_manager_uptime_seconds", "gauge", "Время работы панели", [({}, now - app.started)])
    o.metric("nginx_up", "gauge", "Мастер-процесс nginx запущен (1/0)", [({}, 1 if app.nginx.is_running() else 0)])

    st = app.stats.stub.latest()
    if st.get("ok"):
        o.metric("nginx_connections", "gauge", "Соединения nginx по состояниям (stub_status)",
                 [({"state": k}, st[k]) for k in ("active", "reading", "writing", "waiting")])
        o.metric("nginx_connections_accepted_total", "counter", "Принято соединений (stub_status)",
                 [({}, st["accepts"])])
        o.metric("nginx_connections_handled_total", "counter", "Обработано соединений (stub_status)",
                 [({}, st["handled"])])
        o.metric("nginx_http_requests_total", "counter", "Всего HTTP-запросов по данным nginx (stub_status)",
                 [({}, st["requests"])])

    # ---- по сайтам (журнал доступа)
    req, by_cls, bin_, bout, banned, geo, cache = [], [], [], [], [], [], []
    hist_samples: List[Tuple[str, Dict[str, Any], float]] = []
    for sid, t in sorted(agg.totals.items()):
        lb = {"site_id": sid, "site": names.get(sid, f"#{sid}")}
        req.append((lb, t.req))
        for i, n in enumerate(t.s):
            if n:
                by_cls.append(({**lb, "code": CLASSES[i]}, n))
        bin_.append((lb, t.bin))
        bout.append((lb, t.bout))
        banned.append((lb, t.banned))
        geo.append((lb, t.geo))
        for k, n in t.cache.items():
            cache.append(({**lb, "cache_status": k}, n))
        acc = 0
        for i, b in enumerate(LAT_BOUNDS):
            acc += t.hist[i]
            hist_samples.append(("_bucket", {**lb, "le": str(b)}, acc))
        hist_samples.append(("_bucket", {**lb, "le": "+Inf"}, t.req))
        hist_samples.append(("_sum", lb, t.rt_sum))
        hist_samples.append(("_count", lb, t.req))
    o.metric("nm_http_requests_total", "counter", "Запросов по сайтам (с запуска панели)", req)
    o.metric("nm_http_responses_total", "counter", "Ответов по классам кодов", by_cls)
    o.metric("nm_http_received_bytes_total", "counter", "Принято байт (длина запросов)", bin_)
    o.metric("nm_http_sent_bytes_total", "counter", "Отправлено байт (ответы целиком)", bout)
    o.metric("nm_http_cache_responses_total", "counter", "Ответов по статусу кэша ($upstream_cache_status)", cache)
    o.metric("nm_http_banned_requests_total", "counter", "Отклонено запросов с заблокированных IP", banned)
    o.metric("nm_http_geo_blocked_requests_total", "counter", "Отклонено запросов правилами доступа по странам", geo)
    o.metric("nm_http_request_duration_seconds", "histogram", "Время обработки запроса ($request_time)", [],
             hist_samples)

    # ---- бэкенды (активные проверки)
    up, lat = [], []
    for t in app.health.targets.values():
        if t.state == "disabled":
            continue
        lb = {"owner": t.owner, "name": t.owner_name, "backend": t.backend_key, "backup": "1" if t.backup else "0"}
        up.append((lb, 1 if t.state == "up" else 0 if t.state == "down" else float("nan")))
        if t.state == "up":
            lat.append((lb, t.last_latency))
    o.metric("nm_backend_up", "gauge", "Бэкенд доступен по активной проверке (1/0, NaN — ещё не проверен)",
             [(lb, v) for lb, v in up])
    o.metric("nm_backend_check_latency_seconds", "gauge", "Время ответа на последнюю проверку", lat)

    # ---- сертификаты
    certs = []
    try:
        for c in app.certs.list():
            if c["days_left"] is not None:
                certs.append(({"id": c["id"], "name": c["name"], "domain": (c["domains"] or [""])[0],
                               "used": "1" if c["used_by"] else "0"}, round(c["days_left"], 3)))
    except Exception:
        pass
    o.metric("nm_certificate_expiry_days", "gauge", "Дней до истечения сертификата", certs)

    # ---- блокировки
    bs = app.bans.stats()
    o.metric("nm_bans_active", "gauge", "Активных блокировок IP", [({"source": "auto"}, bs["auto"]),
                                                                    ({"source": "manual"}, bs["manual"])])
    o.metric("nm_bans_suspicious", "gauge", "Подозрительных IP (превысили пороги)", [({}, bs["suspicious"])])

    # ---- оповещения, журналы, система
    firing = sum(1 for s in app.alerts.status().values() if s.get("state") == "firing")
    o.metric("nm_alerts_firing", "gauge", "Активных оповещений", [({}, firing)])
    o.metric("nm_log_lines_parsed_total", "counter", "Разобрано строк журнала доступа", [({}, agg.parsed)])
    o.metric("nm_log_parse_errors_total", "counter", "Строк журнала, которые не удалось разобрать",
             [({}, agg.parse_errors)])
    sysm = app.stats.system.latest() or {}
    gauges = [("nm_system_cpu_percent", "cpu", "Загрузка CPU, %"), ("nm_system_memory_percent", "mem", "Память, %"),
              ("nm_system_disk_percent", "disk", "Заполнение корневого раздела, %"),
              ("nm_system_load1", "load1", "Load average за 1 минуту")]
    for name, key, h in gauges:
        if sysm.get(key) is not None:
            o.metric(name, "gauge", h, [({}, sysm[key])])
    return o.text()
