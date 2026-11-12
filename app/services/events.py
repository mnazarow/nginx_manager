"""Уведомления о событиях: записи журнала «События» (сбой продления сертификата, ошибка применения конфигурации,
перезапуск nginx сторожем, блокировка входа…) рассылаются в каналы оповещений.

В отличие от правил оповещений (метрика > порог в течение N секунд) здесь нет состояния: каждое событие — отдельное
уведомление. Защита от шума: подписка на источники и минимальный уровень, одинаковые события не повторяются чаще
заданного интервала (счётчик повторов приходит со следующим), общий лимит в час, глобальная «тишина» на время работ.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..utils import spawn

log = logging.getLogger("nm.events")

SOURCES = {
    "certs": "Сертификаты", "config": "Применение конфигурации", "watchdog": "Сторож nginx",
    "health": "Бэкенды (недоступен / восстановлен)", "auth": "Вход в панель", "panel": "Сервис панели",
    "backup": "Резервные копии", "geoip": "GeoIP и доступ по странам", "bans": "Блокировки IP",
    "insights": "Встроенный анализ", "reports": "Регулярные отчёты",
}
LEVELS = {"info": 0, "warning": 1, "error": 2}
LEVEL_TITLE = {"info": "Событие", "warning": "Внимание", "error": "Ошибка"}
SEVERITY = {"info": "info", "warning": "warning", "error": "critical"}
HOURLY_LIMIT = 30


def _key(source: str, message: str) -> Tuple[str, str]:
    """Ключ «одинаковых» событий: числа (версии, номера, длительности) не делают событие новым."""
    return source, re.sub(r"\d+([.,:]\d+)*", "#", message)[:200]


class EventNotifier:
    def __init__(self, app) -> None:
        self.app = app
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.last: Dict[Tuple[str, str], List[float]] = {}   # ключ → [время отправки, повторов с тех пор]
        self.sent: Deque[float] = deque()
        self.paused_until = 0.0

    def attach(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    # вызывается из Database.event — в любом потоке
    def on_event(self, level: str, source: str, message: str, details: Any = None) -> None:
        try:
            p = self.app.panel()
            if not p.event_channels or source not in p.event_sources or source == "alerts":
                return
            if LEVELS.get(level, 0) < LEVELS.get(p.event_min_level, 1):
                return
            now = time.time()
            k = _key(source, message)
            prev = self.last.get(k)
            if prev and now - prev[0] < p.event_repeat_minutes * 60:
                prev[1] += 1
                return
            repeats = prev[1] if prev else 0
            self.last[k] = [now, 0]
            if len(self.last) > 2000:  # старые ключи не копятся бесконечно
                for kk, v in sorted(self.last.items(), key=lambda x: x[1][0])[:1000]:
                    self.last.pop(kk, None)
            if self.loop is None or self.loop.is_closed():
                return
            self.loop.call_soon_threadsafe(
                lambda: spawn(self.deliver(level, source, message, details, repeats), name="event-notify"))
        except Exception:
            log.exception("уведомление о событии")

    def _over_limit(self, now: float) -> Optional[str]:
        """None — можно отправлять; иначе текст единственного предупреждения о паузе (или '' — молчать)."""
        while self.sent and now - self.sent[0] > 3600:
            self.sent.popleft()
        if now < self.paused_until:
            return ""
        if len(self.sent) >= HOURLY_LIMIT:
            self.paused_until = self.sent[0] + 3600
            until = time.strftime("%H:%M", time.localtime(self.paused_until))
            return (f"За последний час отправлено {HOURLY_LIMIT} уведомлений о событиях — следующие не отправляются "
                    f"до {until}. Все события есть в журнале «События» панели.")
        return None

    async def deliver(self, level: str, source: str, message: str, details: Any = None, repeats: int = 0,
                      force_channels: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """Отправить событие в каналы подписки (или в указанные — для проверки). Возвращает результат по каналам."""
        from .alerts import send
        p = self.app.panel()
        now = time.time()
        if force_channels is None:
            sil = self.app.alerts.silence_for(None)
            if sil:  # глобальная тишина на время работ глушит и события
                self.app.db.execute("UPDATE silences SET suppressed=suppressed+1 WHERE id=?", (sil["id"],))
                return []
            limit = self._over_limit(now)
            if limit == "":
                return []
            if limit:
                level, source, message, details, repeats = "warning", "panel", limit, None, 0
        self.sent.append(now)
        title = f"{LEVEL_TITLE.get(level, 'Событие')}: {SOURCES.get(source, source).lower()}"
        text = message + (f"\n\nТакое же событие повторялось ещё {repeats} раз за последние "
                          f"{p.event_repeat_minutes} мин." if repeats else "")
        extra = {"event": {"level": level, "source": source, "message": message, "details": details,
                           "repeats": repeats}}
        results = []
        for cid, ch in self.app.alerts.channels(force_channels if force_channels is not None else p.event_channels):
            try:
                await asyncio.to_thread(send, ch, title, text, SEVERITY.get(level, "info"), extra)
                results.append({"id": cid, "name": ch.name, "ok": True})
            except Exception as e:
                results.append({"id": cid, "name": ch.name, "ok": False, "error": f"{type(e).__name__}: {e}"[:300]})
                log.warning("уведомление о событии в «%s» не доставлено: %s", ch.name, e)
                # источник alerts в рассылку не попадает — петли не будет
                self.app.db.event("error", "alerts", f"Не удалось отправить уведомление о событии в «{ch.name}»: {e}"[:500])
        return results
