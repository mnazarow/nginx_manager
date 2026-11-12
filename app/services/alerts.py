"""Правила оповещений и отправка уведомлений (Telegram, Slack, Discord, webhook, e-mail)."""
from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import ssl
import socket
import time
import urllib.request
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..db import Database
from ..models import ALERT_METRICS, AlertChannel, AlertRule

log = logging.getLogger("nm.alerts")

SEV_ICON = {"info": "ℹ️", "warning": "⚠️", "critical": "🔴", "resolved": "✅"}


def _post_json(url: str, payload: dict, headers: Optional[Dict[str, str]] = None, timeout: float = 10) -> Tuple[int, str]:
    data = json.dumps(payload, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "NginxManager",
                                          **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read(2000).decode("utf-8", "replace")


def send(channel: AlertChannel, title: str, text: str, severity: str = "warning",
         extra: Optional[Dict[str, Any]] = None) -> None:
    host = socket.gethostname()
    icon = SEV_ICON.get(severity, "")
    if channel.type == "telegram":
        msg = f"{icon} <b>{_html(title)}</b>\n{_html(text)}\n<i>{_html(host)} · Nginx Manager</i>"
        _post_json(f"{channel.telegram_api.rstrip('/')}/bot{channel.telegram_token}/sendMessage",
                   {"chat_id": channel.telegram_chat_id, "text": msg, "parse_mode": "HTML",
                    "disable_web_page_preview": True})
    elif channel.type == "slack":
        _post_json(channel.url, {"text": f"{icon} *{title}*\n{text}\n_{host}_"})
    elif channel.type == "discord":
        _post_json(channel.url, {"content": f"{icon} **{title}**\n{text}\n*{host}*"[:1990]})
    elif channel.type == "webhook":
        _post_json(channel.url, {"title": title, "text": text, "severity": severity, "host": host,
                                 "ts": time.time(), **(extra or {})},
                   headers={h.name: h.value for h in channel.webhook_headers})
    elif channel.type == "email":
        msg = EmailMessage()
        msg["Subject"] = f"[{host}] {title}"
        msg["From"] = channel.email_from
        msg["To"] = ", ".join(channel.email_to)
        msg.set_content(f"{title}\n\n{text}\n\n--\n{host} · Nginx Manager")
        if channel.smtp_security == "ssl":
            s = smtplib.SMTP_SSL(channel.smtp_host, channel.smtp_port, timeout=15,
                                 context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=15)
            if channel.smtp_security == "starttls":
                s.starttls(context=ssl.create_default_context())
        try:
            if channel.smtp_user:
                s.login(channel.smtp_user, channel.smtp_password)
            s.send_message(msg)
        finally:
            s.quit()


def _html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class AlertEngine:
    """Вычисляет правила каждые 10 секунд. Состояния: ok → pending → firing → ok (resolved)."""

    def __init__(self, db: Database, metric_fn: Callable[[AlertRule], Tuple[Optional[float], str]],
                 broadcast: Callable[[Dict[str, Any]], Any]) -> None:
        self.db = db
        self.metric_fn = metric_fn
        self.broadcast = broadcast
        self.state: Dict[int, Dict[str, Any]] = {}
        self.task: Optional[asyncio.Task] = None

    def rules(self) -> List[Tuple[int, AlertRule]]:
        out = []
        for r in self.db.query("SELECT id, data FROM alert_rules ORDER BY id"):
            try:
                out.append((r["id"], AlertRule.model_validate(json.loads(r["data"]))))
            except Exception:
                continue
        return out

    def channels(self, ids: List[int]) -> List[Tuple[int, AlertChannel]]:
        out = []
        for r in self.db.query("SELECT id, data FROM alert_channels"):
            if not ids or r["id"] in ids:
                try:
                    ch = AlertChannel.model_validate(json.loads(r["data"]))
                    if ch.enabled:
                        out.append((r["id"], ch))
                except Exception:
                    continue
        return out

    async def notify(self, rule: AlertRule, title: str, text: str, severity: str,
                     extra: Optional[Dict[str, Any]] = None) -> List[str]:
        results = []
        for cid, ch in self.channels(rule.channels):
            for attempt in range(3):
                try:
                    await asyncio.to_thread(send, ch, title, text, severity, extra)
                    results.append(f"{ch.name}: ok")
                    break
                except Exception as e:
                    if attempt == 2:
                        results.append(f"{ch.name}: ошибка {e}")
                        self.db.event("error", "alerts", f"Не удалось отправить уведомление в «{ch.name}»: {e}")
                    else:
                        await asyncio.sleep(2 * (attempt + 1))
        return results

    async def evaluate(self) -> None:
        now = time.time()
        active_ids = set()
        for rid, rule in self.rules():
            active_ids.add(rid)
            st = self.state.setdefault(rid, {"state": "ok", "since": now, "last_notify": 0.0, "value": None})
            if not rule.enabled:
                st.update(state="ok", value=None)
                continue
            try:
                value, detail = self.metric_fn(rule)
            except Exception as e:
                log.debug("метрика %s: %s", rule.metric, e)
                continue
            st["value"] = value
            st["detail"] = detail
            if value is None:
                breach = False
            else:
                breach = value > rule.threshold if rule.operator == ">" else value < rule.threshold
            label, unit = ALERT_METRICS.get(rule.metric, (rule.metric, ""))
            vtxt = f"{value:.2f}".rstrip("0").rstrip(".") if isinstance(value, float) else str(value)
            if breach:
                if st["state"] == "ok":
                    st.update(state="pending", since=now)
                if st["state"] == "pending" and now - st["since"] >= rule.duration:
                    st["state"] = "firing"
                    st["fired_at"] = now
                    msg = f"{label}: {vtxt} {unit} (порог {rule.operator} {rule.threshold:g} {unit})"
                    if detail:
                        msg += f"\n{detail}"
                    if rule.site != "*":
                        msg += f"\nСайт: {rule.site}"
                    res = await self.notify(rule, rule.name, msg, rule.severity,
                                            {"metric": rule.metric, "value": value, "state": "firing"})
                    st["last_notify"] = now
                    self._event(rid, rule, "firing", msg, value, res)
                elif st["state"] == "firing" and rule.repeat_minutes and \
                        now - st["last_notify"] >= rule.repeat_minutes * 60:
                    msg = f"Всё ещё: {label}: {vtxt} {unit}" + (f"\n{detail}" if detail else "")
                    res = await self.notify(rule, rule.name, msg, rule.severity,
                                            {"metric": rule.metric, "value": value, "state": "repeat"})
                    st["last_notify"] = now
                    self._event(rid, rule, "repeat", msg, value, res)
            else:
                if st["state"] == "firing":
                    dur = int(now - st.get("fired_at", now))
                    msg = f"{label}: {vtxt} {unit} — норма (длительность инцидента {dur // 60} мин {dur % 60} с)"
                    res = []
                    if rule.notify_resolved:
                        res = await self.notify(rule, f"Восстановлено: {rule.name}", msg, "resolved",
                                                {"metric": rule.metric, "value": value, "state": "resolved"})
                    self._event(rid, rule, "resolved", msg, value, res)
                if st["state"] != "ok":
                    st.update(state="ok", since=now)
        for rid in list(self.state):
            if rid not in active_ids:
                del self.state[rid]

    def _event(self, rid: int, rule: AlertRule, state: str, msg: str, value, res: List[str]) -> None:
        self.db.execute("INSERT INTO alert_events(ts,rule_id,rule_name,severity,state,message,value,notified) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (time.time(), rid, rule.name, rule.severity, state, msg,
                         value if isinstance(value, (int, float)) else None, "; ".join(res)))
        try:
            r = self.broadcast({"type": "alert", "rule": rule.name, "state": state, "severity": rule.severity,
                                "message": msg})
            if asyncio.iscoroutine(r):
                asyncio.get_running_loop().create_task(r)
        except Exception:
            pass

    async def run(self) -> None:
        await asyncio.sleep(15)  # дать статистике накопиться
        while True:
            try:
                await self.evaluate()
            except Exception:
                log.exception("оценка правил оповещений")
            await asyncio.sleep(10)

    def start(self) -> None:
        self.task = asyncio.get_running_loop().create_task(self.run(), name="alerts")

    def status(self) -> Dict[int, Dict[str, Any]]:
        return self.state


DEFAULT_RULES = [
    AlertRule(name="Nginx не работает", metric="nginx_down", operator=">", threshold=0, duration=20,
              severity="critical", window=10, min_requests=0, repeat_minutes=30),
    AlertRule(name="Много ошибок 5xx", metric="error_5xx_rate", operator=">", threshold=5, duration=120,
              window=120, min_requests=30, severity="critical"),
    AlertRule(name="Бэкенд недоступен", metric="backend_down", operator=">", threshold=0, duration=30,
              severity="warning", window=10, min_requests=0),
    AlertRule(name="Сертификат скоро истечёт", metric="cert_expiry", operator="<", threshold=14, duration=0,
              severity="warning", window=60, min_requests=0, repeat_minutes=1440),
    AlertRule(name="Медленные ответы (p95 > 2 с)", metric="latency_p95", operator=">", threshold=2000, duration=300,
              window=300, min_requests=50, severity="warning"),
    AlertRule(name="Диск заполнен более чем на 90%", metric="disk", operator=">", threshold=90, duration=300,
              severity="warning", window=60, min_requests=0, repeat_minutes=720),
    AlertRule(name="Ошибка конфигурации nginx", metric="config_error", operator=">", threshold=0, duration=0,
              severity="critical", window=60, min_requests=0),
]
