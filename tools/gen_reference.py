#!/usr/bin/env python3
"""Генерация справочника параметров в документации из моделей (app/models.py).

Заполняет блоки между маркерами <!-- GEN:имя --> и <!-- /GEN:имя --> в docs/*.md.
Запуск из корня проекта: python3 tools/gen_reference.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.schema import describe  # noqa: E402
from app import models as M  # noqa: E402
from app.stats.parsing import ERROR_CATEGORIES  # noqa: E402

TYPE_RU = {"bool": "переключатель (да/нет)", "int": "целое число", "float": "число", "str": "строка",
           "select": "выбор из списка", "multiselect": "несколько значений из списка", "list": "список строк",
           "intlist": "список", "array": "список элементов", "object": "группа параметров"}
UI_RU = {"lines": "список, по одному значению на строку", "code": "фрагмент конфигурации nginx",
         "password": "пароль (скрытый ввод)", "certificate": "выбор сертификата", "tags": "метки через запятую",
         "textarea": "многострочный текст", "pemfile": "PEM-текст или файл", "cachezone": "выбор зоны кэша",
         "site": "выбор сайта", "channels": "выбор каналов", "listenip": "IP-адрес", "tristate": "наследовать / да / нет"}


def fmt_default(f):
    d = f.get("default")
    if d is None:
        return "—"
    if isinstance(d, bool):
        return "включено" if d else "выключено"
    if isinstance(d, list):
        if not d:
            return "пусто"
        if all(isinstance(x, dict) for x in d):
            return f"{len(d)} элемент(ов)"
        return ", ".join(f"`{x}`" for x in d[:12]) + (" …" if len(d) > 12 else "")
    if isinstance(d, dict):
        return "—"
    if d == "":
        return "пусто"
    lbl = (f.get("labels") or {}).get(str(d))
    return f"`{d}`" + (f" ({lbl})" if lbl and f["type"] == "select" else "")


def example(f):
    if f.get("example"):
        return f["example"]
    ph = f.get("ph")
    if ph:
        return ph.replace("\n", ", ")
    return ""


def show_text(f):
    s = f.get("show")
    if not s:
        return ""
    parts = []
    for k, vals in s.items():
        k = k.lstrip("^")
        vs = ", ".join("вкл" if v is True else "выкл" if v is False else f"`{v}`" for v in vals)
        parts.append(f"`{k}` = {vs}")
    return "Показывается, когда " + " и ".join(parts) + "."


def render_fields(fields, prefix="", level=4, skip_tabs=None, only_tab=None, kind=""):
    out = []
    for f in fields:
        if f.get("ui") == "hidden":
            continue
        if only_tab and f.get("tab") and f["tab"] != only_tab:
            continue
        key = f"{prefix}{f['key']}"
        # явный якорь: на него ведёт ссылка «Подробнее» из подсказки поля в панели (app/schema.py: anchor())
        anchor = f'<a id="{doc_anchor(kind, key)}"></a>\n' if kind else ""
        if f["type"] == "object":
            out.append(f"\n{anchor}\n{'#' * level} {f['label']} — `{key}`\n")
            if f.get("doc"):
                out.append(f"{f['doc']}\n")
            out.extend(render_fields(f["fields"], key + ".", level + 1, kind=kind))
            continue
        out.append(f"\n{anchor}\n{'#' * level} {f['label']} — `{key}`\n")
        typ = UI_RU.get(f.get("ui"), TYPE_RU.get(f["type"], f["type"]))
        if f["type"] == "array":
            typ = "таблица элементов"
        row = [typ, fmt_default(f)]
        rng = ""
        if "min" in f or "max" in f:
            rng = f"{f.get('min', '')}…{f.get('max', '')}"
        if f.get("unit"):
            rng = (rng + " " if rng else "") + f["unit"]
        out.append("| Тип | По умолчанию | Диапазон / ед. | Директива nginx | Расширенный |")
        out.append("|---|---|---|---|---|")
        out.append(f"| {row[0]} | {row[1]} | {rng or '—'} | {('`' + f['directive'] + '`') if f.get('directive') else '—'} "
                   f"| {'да' if f.get('adv') else 'нет'} |\n")
        if f.get("help"):
            out.append(f"{f['help']}.\n" if not f["help"].endswith((".", "!", "?", ")")) else f"{f['help']}\n")
        if f.get("doc"):
            out.append(f"{f['doc']}\n")
        if f["type"] in ("select", "multiselect") and f.get("options"):
            labels = f.get("labels") or {}
            out.append("Варианты:\n")
            for o in f["options"]:
                lbl = labels.get(str(o), "")
                out.append(f"- `{o}`" + (f" — {lbl}" if lbl else ""))
            out.append("")
        if f.get("rec"):
            out.append(f"> **Рекомендация.** {f['rec']}\n")
        ex = example(f)
        if ex:
            out.append(f"**Пример:** `{ex}`\n")
        st = show_text(f)
        if st:
            out.append(f"*{st}*\n")
        if f["type"] == "array" and f.get("fields"):
            out.append("Поля элемента:\n")
            out.append("| Поле | Тип | По умолчанию | Описание |")
            out.append("|---|---|---|---|")
            for sf in f["fields"]:
                if sf.get("ui") == "hidden" or sf["type"] in ("array", "object"):
                    continue
                parts = [x.strip() for x in (sf.get("help", ""), sf.get("rec", "") and ("Рекомендация: " + sf["rec"])) if x]
                desc = " ".join(x if x.endswith((".", "!", "?", ":", ")")) or i == len(parts) - 1 else x + "."
                                for i, x in enumerate(parts))
                out.append(f"| {sf['label']} (`{sf['key']}`) | {TYPE_RU.get(sf['type'], sf['type'])} | "
                           f"{fmt_default(sf)} | {desc.replace('|', '/')} |")
            out.append("")
    return out


# Скриншоты, которые вставляются в начало раздела вкладки (имя файла в docs/images)
TAB_IMAGES = {
    ("site", "main"): "site-editor.png", ("site", "backends"): "site-editor-dark.png",
    ("site", "ssl"): "site-editor-ssl.png", ("site", "locations"): "site-editor-locations.png",
    ("site", "cache"): "site-editor-cache.png", ("site", "security"): "site-editor-security.png",
    ("global", "ssl"): "global-ssl.png", ("panel", "bans"): "settings-bans.png",
}


def tab_image(kind, tab_id, tab_label):
    img = TAB_IMAGES.get((kind, tab_id))
    return [f"![Вкладка «{tab_label}»](images/{img})\n"] if img else []


def doc_anchor(kind, key):
    from app.schema import anchor
    return anchor(kind, key)


def site_reference():
    fields = describe(M.Site)
    out = []
    for tab_id, tab_label in M.SITE_TABS:
        tab_fields = [f for f in fields if f.get("tab") == tab_id]
        if not tab_fields:
            continue
        out.append(f"\n### Вкладка «{tab_label}»\n")
        out.extend(tab_image("site", tab_id, tab_label))
        out.extend(render_fields(tab_fields, level=4, kind="site"))
    return "\n".join(out)


def tabbed(model, tabs, kind=""):
    fields = describe(model)
    out = []
    for tab_id, tab_label in tabs:
        tab_fields = [f for f in fields if f.get("tab") == tab_id]
        if not tab_fields:
            continue
        out.append(f"\n### {tab_label}\n")
        out.extend(tab_image(kind, tab_id, tab_label))
        out.extend(render_fields(tab_fields, level=4, kind=kind))
    return "\n".join(out)


def plain(model, level=3, kind=""):
    return "\n".join(render_fields(describe(model), level=level, kind=kind))


def error_categories():
    out = ["| Категория | Признак в журнале nginx | Уровень | Что означает и что делать |", "|---|---|---|---|"]
    for cid, pat, title, lvl, hint in ERROR_CATEGORIES:
        p = pat.replace("|", " / ").replace("\\", "")
        if len(p) > 80:
            p = p[:77] + "…"
        out.append(f"| **{title}** (`{cid}`) | `{p}` | {lvl} | {hint.replace('|', '/')} |")
    return "\n".join(out)


def alert_metrics():
    out = ["| Метрика (`metric`) | Описание | Единица | Как вычисляется |", "|---|---|---|---|"]
    how = {
        "nginx_down": "1, если мастер-процесс nginx не найден, иначе 0",
        "config_error": "1, если последняя проверка `nginx -t` (выполняется каждые 5 минут) неуспешна",
        "backend_down": "число основных (не backup) серверов в состоянии DOWN по активной проверке",
        "error_5xx_rate": "доля ответов 5xx среди всех запросов за окно, %",
        "error_4xx_rate": "доля ответов 4xx за окно, %",
        "latency_p95": "95-й перцентиль `$request_time` по гистограмме за окно",
        "latency_avg": "среднее `$request_time` за окно",
        "rps_high": "запросов в секунду за окно (условие «>»)",
        "rps_low": "запросов в секунду за окно (условие «<», для обнаружения пропажи трафика)",
        "bandwidth_out": "исходящий трафик (байты ответов × 8 / окно), Мбит/с",
        "active_connections": "Active connections из stub_status",
        "cert_expiry": "минимальное число дней до истечения среди используемых сертификатов",
        "cpu": "загрузка CPU сервера (psutil), %", "memory": "используемая память, %",
        "disk": "максимум заполнения корневого раздела и раздела журналов, %",
        "error_log_rate": "записей уровня error/crit/alert/emerg в журнале nginx за окно, пересчитано в минуту",
        "rate_limited": "срабатываний limit_req/limit_conn в журнале ошибок за окно, в минуту",
        "autobans": "число автоматических блокировок IP за окно (раздел «Блокировки»)",
        "insights_crit": "число находок уровня «проблема» во встроенном анализе за последние 15 минут "
                         "(обновляется раз в минуту)",
    }
    for k, (label, unit) in M.ALERT_METRICS.items():
        out.append(f"| `{k}` | {label} | {unit or '—'} | {how.get(k, '')} |")
    return "\n".join(out)


def insight_metrics():
    from app.services.insights import METRICS
    out = ["| Показатель | Что показывает | Норма / внимание / проблема | Что делать |", "|---|---|---|---|"]
    for k, m in METRICS.items():
        unit = f" {m['unit']}" if m.get("unit") else ""
        if m.get("warn_ratio"):
            thr = (f"< {int(m['warn_ratio'] * 100)}% ёмкости / ≥ {int(m['warn_ratio'] * 100)}% / "
                   f"≥ {int(m['crit_ratio'] * 100)}%")
        elif m.get("dir") == "above":
            thr = f"< {m['warn']:g}{unit} / ≥ {m['warn']:g}{unit} / ≥ {m['crit']:g}{unit}"
        elif m.get("dir") == "below":
            thr = f"> {m['warn']:g}{unit} / ≤ {m['warn']:g}{unit} / ≤ {m['crit']:g}{unit}"
        else:
            thr = "без порогов — важна динамика"
        if m.get("min_req"):
            thr += f" (оценивается от {m['min_req']} запросов)"
        out.append(f"| **{m['label']}** (`{k}`) | {m['desc']} {m['how']} | {thr}. {m['norm']} | {m['advice']} |"
                   .replace("\n", " "))
    return "\n".join(out)


def insight_scenarios():
    from app.services.insights import GROUPS, S
    out = []
    for gid, title in GROUPS:
        items = [s for s in S if s.group == gid]
        if not items:
            continue
        out.append(f"\n## {title}\n")
        if gid == "errorlog":
            out.append("Каждая категория журнала ошибок nginx — отдельный сценарий. Уровень находки: «критическая» "
                       "категория — проблема (с 1 записи), «ошибка» и «предупреждение» — внимание (с 5 и 10 записей), "
                       "«информация» — к сведению (с 50 записей).\n")
            out.append("| Сценарий | Условие | Что означает и что делать |")
            out.append("|---|---|---|")
            for s in items:
                out.append(f"| **{s.title}** (`{s.id}`) | {s.when} | {s.what} |")
            continue
        for s in items:
            out.append(f'\n<a id="sc-{s.id}"></a>\n\n### {s.title}\n')
            out.append(f"*Идентификатор:* `{s.id}`. *Когда срабатывает:* {s.when}.\n")
            out.append(f"{s.what}\n")
            if s.causes:
                out.append("**Вероятные причины:**\n")
                out.extend(f"- {c}" for c in s.causes)
                out.append("")
            if s.actions:
                out.append("**Что сделать:**\n")
                out.extend(f"{i}. {a}" for i, a in enumerate(s.actions, 1))
                out.append("")
    return "\n".join(out)


API_GROUPS = [
    ("/api/auth", "Вход, профиль, 2FA, токены"),
    ("/api/state", "Общее"), ("/api/schema", "Общее"), ("/api/overview", "Общее"), ("/api/version", "Общее"),
    ("/api/docs", "Общее"),
    ("/api/sites", "Сайты"), ("/api/streams", "Потоки TCP/UDP"),
    ("/api/config", "Конфигурация и версии"), ("/api/settings", "Настройки"), ("/api/nginx", "Управление nginx"),
    ("/api/certs", "Сертификаты"),
    ("/api/stats", "Статистика"), ("/api/requests", "Журналы"), ("/api/errors", "Журналы"),
    ("/api/health", "Бэкенды"), ("/api/diagnostics", "Диагностика"), ("/api/collector", "Диагностика"),
    ("/api/insights", "Анализ и отчёты"), ("/api/reports", "Анализ и отчёты"),
    ("/api/bans", "Блокировки и доступ по странам"), ("/api/geo", "Блокировки и доступ по странам"),
    ("/api/alerts", "Оповещения"),
    ("/api/users", "Пользователи и аудит"), ("/api/audit", "Пользователи и аудит"), ("/api/events", "Пользователи и аудит"),
    ("/api/backup", "Резервные копии и импорт"), ("/api/import", "Резервные копии и импорт"),
]
ROLE_NAMES = {"viewer": "наблюдатель", "operator": "оператор", "admin": "администратор"}


def api_routes():
    """Все маршруты REST API: (группа, метод, путь, роль, описание). Используется и тестом полноты документации."""
    from fastapi.routing import APIRoute
    from app.api.routes import router
    out = []
    for r in router.routes:
        if not isinstance(r, APIRoute):
            continue
        roles = [ROLE_NAMES[d.call.__name__] for d in r.dependant.dependencies
                 if getattr(d.call, "__name__", "") in ROLE_NAMES]
        role = roles[0] if roles else "без входа"
        group = next((g for pre, g in API_GROUPS if r.path == pre or r.path.startswith(pre + "/")), "Прочее")
        doc = " ".join((r.endpoint.__doc__ or "").split())
        for m in sorted(r.methods):
            out.append((group, m, r.path, role, doc))
    return out


def api_reference():
    rows = api_routes()
    order = []
    for _, g in API_GROUPS:
        if g not in order:
            order.append(g)
    order.append("Прочее")
    out = [f"Всего методов: **{len(rows)}**. Роль — минимальная роль пользователя или токена; «администратор» "
           "включает права оператора, «оператор» — права наблюдателя.", ""]
    for g in order:
        items = [r for r in rows if r[0] == g]
        if not items:
            continue
        out += [f"#### {g}", "", "| Метод | Путь | Роль | Описание |", "|---|---|---|---|"]
        for _, m, path, role, doc in items:
            cell = doc.replace("|", "\\|")
            out.append(f"| `{m}` | `{path}` | {role} | {cell} |")
        out.append("")
    return "\n".join(out).rstrip()


BLOCKS = {
    "site": site_reference,
    "location": lambda: plain(M.Location, 4, "location"),
    "backend": lambda: plain(M.Backend, 4, "backend"),
    "stream": lambda: plain(M.Stream, 3, "stream"),
    "global": lambda: tabbed(M.GlobalSettings, M.GLOBAL_TABS, "global"),
    "panel": lambda: tabbed(M.PanelSettings, M.PANEL_TABS, "panel"),
    "certificate": lambda: plain(M.CertificateRequest, 3, "certificate"),
    "alert_rule": lambda: plain(M.AlertRule, 3, "alert_rule"),
    "alert_channel": lambda: plain(M.AlertChannel, 3, "alert_channel"),
    "errors": error_categories,
    "alert_metrics": alert_metrics,
    "insight_metrics": insight_metrics,
    "insight_scenarios": insight_scenarios,
    "api": api_reference,
}


def refresh(text):
    """Текст главы с перегенерированными блоками GEN."""
    for name, fn in BLOCKS.items():
        pat = re.compile(rf"(<!-- GEN:{name} -->)(.*?)(<!-- /GEN:{name} -->)", re.S)
        if pat.search(text):
            body = fn()
            text = pat.sub(lambda m, body=body: m.group(1) + "\n<!-- Сгенерировано tools/gen_reference.py — не редактируйте вручную -->\n"
                           + body + "\n" + m.group(3), text)
    return text


def main():
    changed = 0
    for md in sorted((ROOT / "docs").glob("*.md")):
        text = md.read_text(encoding="utf-8")
        new = refresh(text)
        if new != text:
            md.write_text(new, encoding="utf-8")
            changed += 1
            print("обновлён", md.name)
    print(f"Готово, файлов изменено: {changed}")

if __name__ == "__main__":
    main()
