"""Действия из Telegram: кнопки под уведомлениями об атакующих адресах.

Под уведомлением об автоблокировке, активном атакующем и т. п. бот показывает кнопки: «Заблокировать на сутки»,
«Разблокировать», «Пожаловаться в AbuseIPDB» и ссылку на профиль адреса в панели. Нажатие приходит панели через
getUpdates (длинный опрос, без входящих подключений к серверу). Панель выполняет действие, только если:
  * данные кнопки подписаны секретом этой панели (подделать нельзя — HMAC);
  * нажали в том же чате, куда ушло уведомление;
  * нажавший — в списке разрешённых пользователей Telegram канала (если список задан).
Каждое действие пишется в журнал событий и аудит с именем пользователя Telegram.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("nm.tgbot")

ACTIONS = {"b": "Заблокировать на сутки", "u": "Разблокировать", "r": "Пожаловаться в AbuseIPDB"}


def secret(db) -> bytes:
    s = db.kv_get("tg_actions_secret")
    if not s:
        s = secrets.token_hex(24)
        db.kv_set("tg_actions_secret", s)
    return s.encode()


def sign(key: bytes, act: str, ip: str) -> str:
    return hmac.new(key, f"{act}:{ip}".encode(), hashlib.sha256).hexdigest()[:12]


def callback_data(key: bytes, act: str, ip: str) -> str:
    """«nm1:действие:адрес:подпись» — до 64 байт (ограничение Telegram)."""
    return f"nm1:{act}:{ip}:{sign(key, act, ip)}"


def parse_callback(key: bytes, data: str) -> Optional[Tuple[str, str]]:
    parts = (data or "").split(":")
    if len(parts) < 4 or parts[0] != "nm1" or parts[1] not in ACTIONS:
        return None
    act, sig = parts[1], parts[-1]
    ip = ":".join(parts[2:-1])  # в IPv6 есть двоеточия
    if not hmac.compare_digest(sig, sign(key, act, ip)):
        return None
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return None
    return act, ip


def keyboard(key: bytes, ip: str, acts: List[str], profile_url: str = "") -> Dict[str, Any]:
    row = [{"text": ACTIONS[a], "callback_data": callback_data(key, a, ip)} for a in acts if a in ACTIONS]
    rows = [row[:2], row[2:]] if len(row) > 2 else [row]
    if profile_url:
        rows.append([{"text": "Профиль адреса в панели", "url": profile_url}])
    return {"inline_keyboard": [r for r in rows if r]}


def actions_for(source: str, message: str, details: Any) -> Tuple[str, List[str]]:
    """Адрес и кнопки для уведомления о событии (адрес берётся из подробностей события)."""
    if not isinstance(details, dict):
        return "", []
    ip = str(details.get("ip") or details.get("net") or "")
    if not ip:
        return "", []
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return "", []
    if source == "bans" and message.startswith("Автоблокировка"):
        return ip, ["u", "r"]
    if details.get("attacker"):
        return ip, ["b", "r"]
    return "", []


def api(base: str, token: str, method: str, payload: Dict[str, Any], timeout: float = 35) -> Dict[str, Any]:
    req = urllib.request.Request(f"{base.rstrip('/')}/bot{token}/{method}",
                                 data=json.dumps(payload, ensure_ascii=False).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "NginxManager"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — адрес API задаёт администратор
            return json.loads(r.read(4 * 1048576))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read(65536))
        except ValueError:
            return {"ok": False, "description": f"HTTP {e.code}"}


class TelegramActions:
    def __init__(self, app) -> None:
        self.app = app
        self.db = app.db
        self.offsets: Dict[str, int] = {}
        self.status: Dict[str, Dict[str, Any]] = {}
        self.task: Optional[asyncio.Task] = None

    def channels(self) -> List[Tuple[int, Any]]:
        from ..models import AlertChannel
        out = []
        for r in self.db.query("SELECT id, data FROM alert_channels ORDER BY id"):
            try:
                ch = AlertChannel.model_validate(json.loads(r["data"]))
            except Exception:  # noqa: BLE001
                continue
            if ch.enabled and ch.type == "telegram" and ch.telegram_actions:
                out.append((r["id"], ch))
        return out

    def profile_url(self, ip: str) -> str:
        p = self.app.panel()
        if not p.panel_domain:
            return ""
        return f"https://{p.panel_domain}/#/protection?tab=attackers&hours=168&q={ip}"

    # ---------------------------------------------------------------- обработка нажатия
    def handle(self, ch, cq: Dict[str, Any]) -> str:
        """Нажатие кнопки → текст ответа (показывается во всплывающем окне Telegram)."""
        parsed = parse_callback(secret(self.db), cq.get("data") or "")
        if not parsed:
            return "Кнопка устарела или подделана"
        chat = str(((cq.get("message") or {}).get("chat") or {}).get("id", ""))
        if chat != str(ch.telegram_chat_id):
            return "Действие доступно только в чате уведомлений"
        user = cq.get("from") or {}
        uid = str(user.get("id", ""))
        if ch.telegram_admins and uid not in ch.telegram_admins and f"@{user.get('username', '')}" not in \
                ch.telegram_admins:
            return "Нет прав: вас нет в списке разрешённых пользователей канала"
        who = f"telegram:@{user['username']}" if user.get("username") else f"telegram:{uid}"
        act, ip = parsed
        try:
            if act == "b":
                self.app.bans.add(ip, 1440, "Из Telegram", "manual", who, "manual")
                spawn_sync(self.app)
                self.db.event("info", "bans", f"{ip} заблокирован на сутки из Telegram ({who})")
                msg = f"{ip} заблокирован на сутки"
            elif act == "u":
                row = self.db.one("SELECT id FROM bans WHERE net=?", (ip,))
                if not row:
                    return f"{ip} уже не заблокирован"
                self.app.bans.remove(row["id"])
                spawn_sync(self.app)
                self.db.event("info", "bans", f"Разблокирован {ip} из Telegram ({who})")
                msg = f"{ip} разблокирован"
            else:
                r = self.app.protection.intel.report(ip, who)
                msg = f"Жалоба на {ip} отправлена (категории {', '.join(map(str, r['categories']))})"
        except Exception as e:  # noqa: BLE001
            return f"Не выполнено: {e}"[:190]
        self.db.execute("INSERT INTO audit_log(ts, username, ip, action, target, details) VALUES(?,?,?,?,?,?)",
                        (time.time(), who, "", {"b": "ip_banned", "u": "ip_unbanned", "r": "abuseipdb_report"}[act],
                         ip, json.dumps({"via": "telegram", "chat": chat}, ensure_ascii=False)))
        return msg

    def poll_once(self, token_key: str, ch, timeout: int = 25) -> int:
        """Один длинный опрос getUpdates для бота канала; возвращает число обработанных нажатий."""
        off = self.offsets.get(token_key)
        payload: Dict[str, Any] = {"timeout": timeout, "allowed_updates": ["callback_query"]}
        if off is not None:
            payload["offset"] = off
        d = api(ch.telegram_api, ch.telegram_token, "getUpdates", payload, timeout=timeout + 10)
        if not d.get("ok"):
            raise ValueError(d.get("description") or "ошибка getUpdates")
        n = 0
        for u in d.get("result") or []:
            self.offsets[token_key] = u["update_id"] + 1
            cq = u.get("callback_query")
            if not cq:
                continue
            text = self.handle(ch, cq)
            api(ch.telegram_api, ch.telegram_token, "answerCallbackQuery",
                {"callback_query_id": cq["id"], "text": text, "show_alert": False}, timeout=15)
            msg = cq.get("message") or {}
            if msg.get("message_id"):
                who = (cq.get("from") or {}).get("username") or (cq.get("from") or {}).get("first_name") or ""
                api(ch.telegram_api, ch.telegram_token, "sendMessage",
                    {"chat_id": ch.telegram_chat_id, "text": f"{text}" + (f" — @{who}" if who else ""),
                     "reply_to_message_id": msg["message_id"]}, timeout=15)
            n += 1
        return n

    async def run(self) -> None:
        await asyncio.sleep(10)
        while True:
            chans = self.channels()
            if not chans:
                await asyncio.sleep(30)
                continue
            seen = set()
            for cid, ch in chans:
                key = hashlib.sha256(ch.telegram_token.encode()).hexdigest()[:16]
                if key in seen:
                    continue
                seen.add(key)
                try:
                    n = await asyncio.to_thread(self.poll_once, key, ch, 20 if len(chans) == 1 else 2)
                    self.status[str(cid)] = {"ok": True, "at": time.time(), "handled": n, "error": ""}
                except Exception as e:  # noqa: BLE001
                    prev = (self.status.get(str(cid)) or {}).get("error")
                    self.status[str(cid)] = {"ok": False, "at": time.time(), "error": str(e)[:300]}
                    if not prev:
                        self.db.event("warning", "alerts", f"Telegram «{ch.name}»: кнопки действий не работают — {e}"
                                      [:400])
                    await asyncio.sleep(30)
            await asyncio.sleep(1)

    def start(self) -> None:
        self.task = asyncio.get_running_loop().create_task(self.run(), name="tg-actions")


def spawn_sync(app) -> None:
    """Применить список блокировок в nginx из потока опроса Telegram."""
    loop = getattr(app.events, "loop", None)
    if loop and not loop.is_closed():
        loop.call_soon_threadsafe(lambda: loop.create_task(app.bans.sync(force=True)))
