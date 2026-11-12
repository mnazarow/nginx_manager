"""Регулярные отчёты: сводка за сутки или неделю в каналы уведомлений (Telegram, e-mail, Slack, Discord, webhook).

Отчёт сравнивает период с предыдущим таким же периодом и включает: нагрузку и ошибки, время ответа, трафик,
сайты, проблемы по встроенному анализу, бэкенды, сертификаты, блокировки и журнал ошибок nginx.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from ..models import AlertChannel

WEEKDAYS = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"]
LEVEL_MARK = {"crit": "🔴", "warn": "🟡", "info": "🔵"}


def _num(n: float) -> str:
    n = float(n or 0)
    for lim, suf in ((1e9, " млрд"), (1e6, " млн"), (1e3, " тыс.")):
        if abs(n) >= lim:
            return f"{n / lim:.1f}".replace(".", ",").replace(",0", "") + suf
    return f"{int(round(n)):,}".replace(",", " ")


def _bytes(b: float) -> str:
    b = float(b or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024 or unit == "ТБ":
            return f"{b:.1f} {unit}".replace(".", ",").replace(",0 ", " ")
        b /= 1024
    return f"{b:.1f} ТБ"


def _pct(v: float, d: int = 1) -> str:
    return f"{v:.{d}f}%".replace(".", ",")


def _delta(cur: float, prev: float) -> str:
    if not prev:
        return ""
    ch = (cur - prev) / prev * 100
    if abs(ch) < 1:
        return " (без изменений)"
    return f" ({'+' if ch > 0 else '−'}{abs(ch):.0f}% к прошлому периоду)"


def period_bounds(period: str, now: Optional[float] = None) -> Tuple[float, float]:
    """Последний завершённый период: сутки — вчера 00:00–00:00, неделя — 7 суток до сегодняшней полуночи."""
    now_dt = datetime.fromtimestamp(now or time.time())
    end = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=7 if period == "week" else 1)
    return start.timestamp(), end.timestamp()


def build(app, period: str = "day", start: Optional[float] = None, end: Optional[float] = None) -> Dict[str, Any]:
    if start is None or end is None:
        start, end = period_bounds(period)
    span = end - start
    st = app.stats
    cur = st.summary(start, end, "*", exact_uniq=False)
    prev = st.summary(start - span, start, "*", exact_uniq=False)
    d0, d1 = datetime.fromtimestamp(start), datetime.fromtimestamp(end - 1)
    title = (f"Отчёт за {d0:%d.%m.%Y}" if period == "day" else f"Отчёт за неделю {d0:%d.%m}–{d1:%d.%m.%Y}")
    lines: List[str] = []
    n = cur["requests"]
    rps = f"{cur['rps']:.1f}".replace(".", ",")
    lines.append(f"Запросов: {_num(n)}{_delta(n, prev['requests'])}, в среднем {rps} в секунду")
    if n:
        lines.append(f"Ошибки 5xx: {_pct(cur['err5_pct'], 2)} (было {_pct(prev['err5_pct'], 2)}) · 4xx: {_pct(cur['err4_pct'])}")
        lines.append(f"Время ответа p95: {cur['p95']:.0f} мс (было {prev['p95']:.0f} мс) · среднее бэкенда "
                     f"{cur['urt_avg']:.0f} мс")
        lines.append(f"Трафик: {_bytes(cur['bytes_out'])}{_delta(cur['bytes_out'], prev['bytes_out'])}"
                     + (f" · кэш HIT {_pct(cur['hit_ratio'], 0)}" if cur.get("cache") else ""))
    # сайты
    state = app.last_applied_state() or app.nginx.load_state()
    names = {str(sid): s.name for sid, s in state.sites}
    names.update({"-": "Сервер по умолчанию (неизвестные домены)", "panel": "Панель"})
    sites = st.compare_sites(start, end)
    if sites:
        lines.append("")
        lines.append("Сайты:")
        for r in sites[:8]:
            sn = r["req"] or 0
            e5 = r["s5"] / sn * 100 if sn else 0
            lines.append(f" • {names.get(str(r['site']), r['site'])} — {_num(sn)} запросов, 5xx {_pct(e5, 2)}, "
                         f"среднее {r['rt_avg']:.0f} мс")
    # анализ
    res = app.insights.evaluate(start, end, "*")
    found = [f for f in res["findings"] if f["level"] in ("crit", "warn")]
    lines.append("")
    if found:
        lines.append(f"Проблемы по анализу ({res['counts']['crit']} серьёзных, {res['counts']['warn']} требуют внимания):")
        for f in found[:10]:
            where = f"{f['site_name']}: " if f["site"] != "*" else ""
            lines.append(f" {LEVEL_MARK[f['level']]} {where}{f['title']} — {f['summary']}"[:300])
        if len(found) > 10:
            lines.append(f" … и ещё {len(found) - 10}")
    else:
        lines.append("Анализ: серьёзных проблем за период не найдено.")
    # текущее состояние
    down = [t for t in app.health.targets.values() if t.state == "down"]
    lines.append("")
    lines.append("Сейчас:")
    lines.append(f" • nginx {'работает' if app.nginx.is_running() else 'НЕ ЗАПУЩЕН'}; бэкендов недоступно: {len(down)}"
                 + (" (" + ", ".join(f"{t.owner_name} {t.address}:{t.port}" for t in down[:3]) + ")" if down else ""))
    try:
        exp = [c for c in app.certs.list() if c["used_by"] and c["days_left"] is not None and c["days_left"] < 21]
        if exp:
            lines.append(" • сертификаты истекают: " + ", ".join(f"{c['name']} ({max(0, c['days_left']):.0f} дн.)"
                                                              for c in exp[:5]))
    except Exception:
        pass
    bs = app.bans.stats()
    autob = app.db.scalar("SELECT COUNT(*) FROM events WHERE source='bans' AND ts>=? AND ts<? AND message LIKE "
                          "'Автоблокировка%'", (start, end)) or 0
    lines.append(f" • блокировок IP активно: {bs['active']}; автоматических за период: {autob}")
    errs = sorted((cur.get("errors") or {}).items(), key=lambda x: -x[1]["count"])
    if errs:
        lines.append(f" • записей в журнале ошибок nginx: {_num(sum(v['count'] for _, v in errs))} (чаще всего: "
                     + "; ".join(f"{v['title']} — {_num(v['count'])}" for _, v in errs[:3]) + ")")
    return {"title": title, "text": "\n".join(lines), "period": period, "from": start, "to": end,
            "counts": res["counts"]}


async def send(app, report: Dict[str, Any], channel_ids: List[int]) -> List[Dict[str, Any]]:
    from .alerts import send as send_one
    results = []
    for cid in channel_ids:
        row = app.db.one("SELECT id, data FROM alert_channels WHERE id=?", (cid,))
        if not row:
            results.append({"id": cid, "ok": False, "error": "канал не найден"})
            continue
        import json
        ch = AlertChannel.model_validate(json.loads(row["data"]))
        if not ch.enabled:
            results.append({"id": cid, "name": ch.name, "ok": False, "error": "канал выключен"})
            continue
        sev = "critical" if report["counts"].get("crit") else "warning" if report["counts"].get("warn") else "info"
        try:
            await asyncio.to_thread(send_one, ch, report["title"], report["text"], sev,
                                    {"report": True, "period": report["period"], "from": report["from"],
                                     "to": report["to"], "counts": report["counts"]})
            results.append({"id": cid, "name": ch.name, "ok": True})
        except Exception as e:
            results.append({"id": cid, "name": ch.name, "ok": False, "error": f"{type(e).__name__}: {e}"[:300]})
    return results


def due(panel, now: Optional[float] = None) -> Optional[str]:
    """Ключ отчёта, который пора отправить (или None): день/неделя по расписанию из настроек панели."""
    if not panel.report_enabled or not panel.report_channels:
        return None
    t = datetime.fromtimestamp(now or time.time())
    if t.hour != panel.report_hour:
        return None
    if panel.report_period == "week" and t.weekday() != int(panel.report_weekday):
        return None
    return f"{panel.report_period}:{t:%Y-%m-%d}"
