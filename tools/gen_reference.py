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


def render_fields(fields, prefix="", level=4, skip_tabs=None, only_tab=None):
    out = []
    for f in fields:
        if f.get("ui") == "hidden":
            continue
        if only_tab and f.get("tab") and f["tab"] != only_tab:
            continue
        key = f"{prefix}{f['key']}"
        if f["type"] == "object":
            out.append(f"\n{'#' * level} {f['label']} — `{key}`\n")
            if f.get("doc"):
                out.append(f"{f['doc']}\n")
            out.extend(render_fields(f["fields"], key + ".", level + 1))
            continue
        out.append(f"\n{'#' * level} {f['label']} — `{key}`\n")
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
    ("global", "ssl"): "global-ssl.png",
}


def tab_image(kind, tab_id, tab_label):
    img = TAB_IMAGES.get((kind, tab_id))
    return [f"![Вкладка «{tab_label}»](images/{img})\n"] if img else []


def site_reference():
    fields = describe(M.Site)
    out = []
    for tab_id, tab_label in M.SITE_TABS:
        tab_fields = [f for f in fields if f.get("tab") == tab_id]
        if not tab_fields:
            continue
        out.append(f"\n### Вкладка «{tab_label}»\n")
        out.extend(tab_image("site", tab_id, tab_label))
        out.extend(render_fields(tab_fields, level=4))
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
        out.extend(render_fields(tab_fields, level=4))
    return "\n".join(out)


def plain(model, level=3):
    return "\n".join(render_fields(describe(model), level=level))


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
    }
    for k, (label, unit) in M.ALERT_METRICS.items():
        out.append(f"| `{k}` | {label} | {unit or '—'} | {how.get(k, '')} |")
    return "\n".join(out)


BLOCKS = {
    "site": site_reference,
    "location": lambda: plain(M.Location, 4),
    "backend": lambda: plain(M.Backend, 4),
    "stream": lambda: plain(M.Stream, 3),
    "global": lambda: tabbed(M.GlobalSettings, M.GLOBAL_TABS, "global"),
    "panel": lambda: tabbed(M.PanelSettings, M.PANEL_TABS),
    "certificate": lambda: plain(M.CertificateRequest, 3),
    "alert_rule": lambda: plain(M.AlertRule, 3),
    "alert_channel": lambda: plain(M.AlertChannel, 3),
    "errors": error_categories,
    "alert_metrics": alert_metrics,
}


def main():
    changed = 0
    for md in sorted((ROOT / "docs").glob("*.md")):
        text = md.read_text(encoding="utf-8")
        new = text
        for name, fn in BLOCKS.items():
            pat = re.compile(rf"(<!-- GEN:{name} -->)(.*?)(<!-- /GEN:{name} -->)", re.S)
            if pat.search(new):
                body = fn()
                new = pat.sub(lambda m: m.group(1) + "\n<!-- Сгенерировано tools/gen_reference.py из app/models.py -->\n"
                              + body + "\n" + m.group(3), new)
        if new != text:
            md.write_text(new, encoding="utf-8")
            changed += 1
            print("обновлён", md.name)
    print(f"Готово, файлов изменено: {changed}")


if __name__ == "__main__":
    main()
