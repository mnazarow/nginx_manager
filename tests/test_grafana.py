"""Дашборд Grafana (packaging/grafana/nginx-manager.json): собран из tools/gen_grafana.py, каждая метрика в запросах
действительно отдаётся панелью на /metrics, панели не перекрываются, все запросы идут через выбранный источник."""
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DASH = ROOT / "packaging" / "grafana" / "nginx-manager.json"


def _gen():
    spec = importlib.util.spec_from_file_location("gen_grafana", ROOT / "tools" / "gen_grafana.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def exported_metrics() -> set:
    """Имена метрик из services/metrics.py (для гистограмм — с суффиксами _bucket/_sum/_count)."""
    src = (ROOT / "app" / "services" / "metrics.py").read_text(encoding="utf-8")
    names = set()
    for name, kind in re.findall(r'o\.metric\("([a-z0-9_]+)", "(gauge|counter|histogram)"', src):
        names |= {name + s for s in ("_bucket", "_sum", "_count")} if kind == "histogram" else {name}
    names |= set(re.findall(r'\("(nm_system_[a-z0-9_]+)", "', src))
    return names


def exprs(d):
    out = [t["expr"] for p in d["panels"] for t in p.get("targets", [])]
    out += [v["query"]["query"] for v in d["templating"]["list"] if isinstance(v.get("query"), dict)]
    return out


PROMQL_WORDS = {"sum", "by", "rate", "max", "min", "count", "or", "vector", "histogram_quantile", "label_values",
                "instance", "site", "code", "le", "backup", "used", "name", "backend", "source", "state",
                "cache_status", "version", "without", "on", "and", "unless", "avg", "increase"}


def test_dashboard_up_to_date():
    built = json.dumps(_gen().build(), ensure_ascii=False, indent=2) + "\n"
    assert DASH.read_text(encoding="utf-8") == built, "устарел дашборд: python3 tools/gen_grafana.py"


def test_metrics_exist():
    d = json.loads(DASH.read_text(encoding="utf-8"))
    have = exported_metrics()
    assert {"nm_http_requests_total", "nm_http_request_duration_seconds_bucket", "nginx_up",
            "nm_system_load1"} <= have
    used = set()
    for e in exprs(d):
        e = re.sub(r'"[^"]*"', '""', e)            # значения меток
        e = re.sub(r"\[[^\]]*\]", "", e)           # окна [$__rate_interval]
        for w in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", e):
            if w not in PROMQL_WORDS:
                used.add(w)
    missing = used - have
    assert not missing, f"в дашборде метрики, которых панель не отдаёт: {sorted(missing)}"
    # и наоборот — значимые метрики панели на дашборде есть
    assert {"nm_backend_up", "nm_certificate_expiry_days", "nm_http_responses_total", "nm_bans_active"} <= used


def test_layout_and_datasource():
    d = json.loads(DASH.read_text(encoding="utf-8"))
    ids = [p["id"] for p in d["panels"]]
    assert len(ids) == len(set(ids))
    cells = set()
    for p in d["panels"]:
        g = p["gridPos"]
        assert 0 <= g["x"] and g["x"] + g["w"] <= 24, p["title"]
        for x in range(g["x"], g["x"] + g["w"]):
            for y in range(g["y"], g["y"] + g["h"]):
                assert (x, y) not in cells, f"панель «{p['title']}» перекрывает другую"
                cells.add((x, y))
        if p["type"] != "row":
            assert p["datasource"] == {"type": "prometheus", "uid": "${datasource}"}, p["title"]
            assert p["targets"] and all(t["datasource"]["uid"] == "${datasource}" for t in p["targets"])
            assert p["title"]
    names = [v["name"] for v in d["templating"]["list"]]
    assert names == ["datasource", "instance", "site"]
    assert d["uid"] == "nginx-manager" and d["schemaVersion"] >= 36
