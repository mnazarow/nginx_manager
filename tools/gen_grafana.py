#!/usr/bin/env python3
"""Сборка дашборда Grafana для метрик Prometheus панели: packaging/grafana/nginx-manager.json.

python3 tools/gen_grafana.py          # перезаписать файл; tests/test_grafana.py проверяет, что он актуален и
                                      # что каждая метрика в запросах действительно отдаётся панелью
Дашборд импортируется в Grafana 9+ («Dashboards → New → Import»), источник данных — Prometheus.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "packaging" / "grafana" / "nginx-manager.json"
DS = {"type": "prometheus", "uid": "${datasource}"}
SEL = 'instance=~"$instance"'
SITE = SEL + ',site=~"$site"'
RI = "[$__rate_interval]"
# цвета: классы кодов — статусные (успех, перенаправление, ошибка клиента, ошибка сервера), остальное — по порядку
CODE_COLORS = {"2xx": "#0ca30c", "3xx": "#2a78d6", "4xx": "#eda100", "5xx": "#d03b3b", "1xx": "#898781"}

_id = [0]


def nid():
    _id[0] += 1
    return _id[0]


def target(expr, legend="", ref="A", instant=False, fmt="time_series"):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend or "__auto", "refId": ref, "range": not instant,
         "instant": instant, "format": fmt}
    return t


def stat(title, expr, x, y, w=4, h=4, unit="none", desc="", thresholds=None, mappings=None, decimals=None,
         legend="", color_mode="value"):
    fd = {"unit": unit, "color": {"mode": "thresholds"},
          "thresholds": {"mode": "absolute", "steps": thresholds or [{"color": "text", "value": None}]}}
    if mappings:
        fd["mappings"] = mappings
    if decimals is not None:
        fd["decimals"] = decimals
    return {"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": DS,
            "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "fieldConfig": {"defaults": fd, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                        "colorMode": color_mode, "graphMode": "area", "justifyMode": "auto", "textMode": "auto",
                        "orientation": "auto"},
            "targets": [target(expr, legend)]}


def series(title, targets, x, y, w=12, h=8, unit="short", desc="", stack=False, overrides=None, minv=None, maxv=None,
           legend_calcs=("mean", "max", "lastNotNull")):
    fd = {"unit": unit, "color": {"mode": "palette-classic"},
          "custom": {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 10 if not stack else 35, "showPoints": "never",
                     "spanNulls": False, "axisSoftMin": 0, "stacking": {"mode": "normal" if stack else "none"}}}
    if minv is not None:
        fd["min"] = minv
    if maxv is not None:
        fd["max"] = maxv
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": DS,
            "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "fieldConfig": {"defaults": fd, "overrides": overrides or []},
            "options": {"legend": {"displayMode": "table", "placement": "bottom", "calcs": list(legend_calcs),
                                   "showLegend": True},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
            "targets": targets}


def row(title, y, collapsed=False):
    return {"id": nid(), "type": "row", "title": title, "collapsed": collapsed, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
            "panels": []}


def color_override(name, color):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]}


def build():
    _id[0] = 0
    p = []
    y = 0
    p.append(row("Обзор", y))
    y += 1
    p += [
        stat("nginx", f"max(nginx_up{{{SEL}}})", 0, y, 3, desc="Мастер-процесс nginx запущен",
             mappings=[{"type": "value", "options": {"1": {"text": "работает", "color": "green"},
                                                     "0": {"text": "остановлен", "color": "red"}}}],
             thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}], color_mode="background"),
        stat("Запросов в секунду", f"sum(rate(nm_http_requests_total{{{SITE}}}{RI}))", 3, y, 4, unit="reqps",
             desc="По журналу доступа выбранных сайтов", decimals=1),
        stat("Доля ответов 5xx", f'sum(rate(nm_http_responses_total{{{SITE},code="5xx"}}{RI})) / '
             f"sum(rate(nm_http_requests_total{{{SITE}}}{RI}))", 7, y, 4, unit="percentunit", decimals=2,
             desc="Ошибки сервера и бэкендов среди всех ответов",
             thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 0.01},
                         {"color": "red", "value": 0.05}]),
        stat("Время ответа p95", "histogram_quantile(0.95, sum by (le) "
             f"(rate(nm_http_request_duration_seconds_bucket{{{SITE}}}{RI})))", 11, y, 4, unit="s", decimals=3,
             thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 0.5},
                         {"color": "red", "value": 2}]),
        stat("Бэкенды недоступны", f'count(nm_backend_up{{{SEL},backup="0"}} == 0) or vector(0)', 15, y, 3,
             desc="Основные серверы, не прошедшие активную проверку",
             thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}], color_mode="background"),
        stat("Ближайший сертификат", f'min(nm_certificate_expiry_days{{{SEL},used="1"}})', 18, y, 3, unit="d",
             decimals=0, desc="Дней до истечения самого «старого» используемого сертификата",
             thresholds=[{"color": "red", "value": None}, {"color": "orange", "value": 7},
                         {"color": "green", "value": 14}]),
        stat("Оповещения", f"max(nm_alerts_firing{{{SEL}}})", 21, y, 3, desc="Сработавшие правила оповещений",
             thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}], color_mode="background"),
    ]
    y += 4
    p.append(row("Трафик", y))
    y += 1
    p += [
        series("Запросы по сайтам", [target(f"sum by (site) (rate(nm_http_requests_total{{{SITE}}}{RI}))", "{{site}}")],
               0, y, unit="reqps"),
        series("Ответы по классам кодов", [target(f"sum by (code) (rate(nm_http_responses_total{{{SITE}}}{RI}))",
                                                  "{{code}}")], 12, y, unit="reqps", stack=True,
               overrides=[color_override(k, v) for k, v in CODE_COLORS.items()]),
    ]
    y += 8
    lat = "sum by (le) (rate(nm_http_request_duration_seconds_bucket{" + SITE + "}" + RI + "))"
    p += [
        series("Время ответа", [target(f"histogram_quantile(0.50, {lat})", "медиана", "A"),
                                target(f"histogram_quantile(0.95, {lat})", "p95", "B"),
                                target(f"histogram_quantile(0.99, {lat})", "p99", "C")], 0, y, unit="s",
               desc="Перцентили $request_time по корзинам гистограммы (как на графиках панели)"),
        series("Исходящий трафик по сайтам", [target(f"sum by (site) (rate(nm_http_sent_bytes_total{{{SITE}}}{RI}))",
                                                     "{{site}}")], 12, y, unit="Bps"),
    ]
    y += 8
    p += [
        series("Кэш: ответы по статусу", [target("sum by (cache_status) (rate(nm_http_cache_responses_total{"
                                                 + SITE + "}" + RI + "))", "{{cache_status}}")], 0, y, unit="reqps",
               stack=True),
        series("Входящий трафик по сайтам", [target(f"sum by (site) (rate(nm_http_received_bytes_total{{{SITE}}}{RI}))",
                                                    "{{site}}")], 12, y, unit="Bps"),
    ]
    y += 8
    p.append(row("Бэкенды", y))
    y += 1
    tl = {"id": nid(), "type": "state-timeline", "title": "Доступность бэкендов", "datasource": DS,
          "description": "Активные проверки: 1 — доступен, 0 — недоступен",
          "gridPos": {"x": 0, "y": y, "w": 12, "h": 8},
          "fieldConfig": {"defaults": {"color": {"mode": "thresholds"},
                                       "thresholds": {"mode": "absolute", "steps": [{"color": "red", "value": None},
                                                                                    {"color": "green", "value": 1}]},
                                       "mappings": [{"type": "value", "options": {
                                           "1": {"text": "доступен", "color": "green"},
                                           "0": {"text": "недоступен", "color": "red"}}}]}, "overrides": []},
          "options": {"showValue": "never", "mergeValues": True, "rowHeight": 0.8, "legend": {"showLegend": False}},
          "targets": [target(f"max by (name, backend) (nm_backend_up{{{SEL}}})", "{{name}} → {{backend}}")]}
    p += [tl, series("Время ответа на проверку", [target(f"max by (name, backend) "
                                                         f"(nm_backend_check_latency_seconds{{{SEL}}})",
                                                         "{{name}} → {{backend}}")], 12, y, unit="s")]
    y += 8
    p.append(row("Безопасность", y))
    y += 1
    p += [
        series("Отклонённые запросы", [
            target(f"sum(rate(nm_http_banned_requests_total{{{SITE}}}{RI}))", "заблокированные IP", "A"),
            target(f"sum(rate(nm_http_geo_blocked_requests_total{{{SITE}}}{RI}))", "доступ по странам", "B")],
            0, y, w=12, unit="reqps"),
        series("Блокировки IP", [target(f"sum by (source) (nm_bans_active{{{SEL}}})", "активные: {{source}}", "A"),
                                 target(f"max(nm_bans_suspicious{{{SEL}}})", "подозрительные", "B")],
               12, y, w=12, unit="short"),
    ]
    y += 8
    p.append(row("Сервер и nginx", y))
    y += 1
    p += [
        series("Соединения nginx", [target(f"max by (state) (nginx_connections{{{SEL}}})", "{{state}}")],
               0, y, w=8, unit="short"),
        series("Ресурсы сервера", [target(f"max(nm_system_cpu_percent{{{SEL}}})", "CPU", "A"),
                                   target(f"max(nm_system_memory_percent{{{SEL}}})", "память", "B"),
                                   target(f"max(nm_system_disk_percent{{{SEL}}})", "диск", "C")],
               8, y, w=8, unit="percent", minv=0, maxv=100),
        series("Load average (1 мин)", [target(f"max(nm_system_load1{{{SEL}}})", "load1")], 16, y, w=8, unit="short"),
    ]
    y += 8
    certs = {"id": nid(), "type": "table", "title": "Сертификаты", "datasource": DS,
             "description": "Дней до истечения; «используется» — подключён к сайту или к панели",
             "gridPos": {"x": 0, "y": y, "w": 12, "h": 8},
             "fieldConfig": {"defaults": {"unit": "d", "decimals": 1, "custom": {"cellOptions": {"type": "color-text"}},
                                          "thresholds": {"mode": "absolute", "steps": [
                                              {"color": "red", "value": None}, {"color": "orange", "value": 7},
                                              {"color": "green", "value": 14}]}}, "overrides": []},
             "options": {"showHeader": True, "sortBy": [{"displayName": "Value", "desc": False}]},
             "transformations": [{"id": "organize", "options": {
                 "excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True, "id": True},
                 "renameByName": {"name": "Сертификат", "domain": "Домен", "used": "Используется",
                                  "Value": "Дней осталось"}}}],
             "targets": [target(f"nm_certificate_expiry_days{{{SEL}}}", "", instant=True, fmt="table")]}
    p += [certs,
          series("Сборщик статистики", [target(f"sum(rate(nm_log_lines_parsed_total{{{SEL}}}{RI}))", "строк/с", "A"),
                                        target(f"sum(rate(nm_log_parse_errors_total{{{SEL}}}{RI}))",
                                               "нераспознанных строк/с", "B")], 12, y, w=12, unit="short",
                 desc="Нераспознанные строки — журнал nginx не в формате панели (см. «Диагностика»)")]
    y += 8
    p += [stat("Версия панели", f"max by (version) (nginx_manager_info{{{SEL}}})", 0, y, 6, 3, legend="{{version}}",
               desc="Метка version метрики nginx_manager_info"),
          stat("Панель работает", f"max(nginx_manager_uptime_seconds{{{SEL}}})", 6, y, 6, 3, unit="s"),
          stat("Запросов по данным nginx", f"sum(rate(nginx_http_requests_total{{{SEL}}}{RI}))", 12, y, 6, 3,
               unit="reqps", desc="stub_status: все запросы nginx, включая не попавшие в журналы сайтов"),
          stat("Принято соединений в секунду", f"sum(rate(nginx_connections_accepted_total{{{SEL}}}{RI}))",
               18, y, 6, 3, unit="cps")]
    for x in p:  # подписи версий в «Версии панели» — из легенды
        if x["title"] == "Версия панели":
            x["options"]["textMode"] = "name"
    return {
        "__requires": [{"type": "grafana", "id": "grafana", "name": "Grafana", "version": "9.0.0"},
                       {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"}],
        "uid": "nginx-manager", "title": "Nginx Manager", "description":
            "Метрики Prometheus панели Nginx Manager: трафик и ошибки по сайтам, время ответа, бэкенды, "
            "блокировки, сертификаты, сервер. Документация: глава 09 «Мониторинг».",
        "tags": ["nginx", "nginx-manager"], "editable": True, "graphTooltip": 1, "schemaVersion": 39, "version": 1,
        "time": {"from": "now-6h", "to": "now"}, "refresh": "30s", "timezone": "",
        "links": [], "annotations": {"list": []},
        "templating": {"list": [
            {"name": "datasource", "label": "Источник данных", "type": "datasource", "query": "prometheus",
             "current": {}, "hide": 0, "refresh": 1},
            {"name": "instance", "label": "Сервер", "type": "query", "datasource": DS,
             "query": {"query": "label_values(nginx_manager_info, instance)", "refId": "instance"},
             "definition": "label_values(nginx_manager_info, instance)", "refresh": 2, "multi": True,
             "includeAll": True, "current": {}, "sort": 1},
            {"name": "site", "label": "Сайт", "type": "query", "datasource": DS,
             "query": {"query": 'label_values(nm_http_requests_total{instance=~"$instance"}, site)', "refId": "site"},
             "definition": 'label_values(nm_http_requests_total{instance=~"$instance"}, site)', "refresh": 2,
             "multi": True, "includeAll": True, "allValue": ".*", "current": {}, "sort": 1},
        ]},
        "panels": p,
    }


def main() -> int:
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        return 0 if OUT.exists() and OUT.read_text(encoding="utf-8") == text else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"записан {OUT.relative_to(ROOT)}: панелей {len(build()['panels'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
