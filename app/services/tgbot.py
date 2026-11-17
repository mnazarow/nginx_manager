"""Действия из Telegram: кнопки под уведомлениями об атакующих адресах и команды боту.

Под уведомлением об автоблокировке, активном атакующем и т. п. бот показывает кнопки: «Заблокировать на сутки»,
«Разблокировать», «Пожаловаться в AbuseIPDB» и ссылку на профиль адреса в панели. Нажатие приходит панели через
getUpdates (длинный опрос, без входящих подключений к серверу). Панель выполняет действие, только если:
  * данные кнопки подписаны секретом этой панели (подделать нельзя — HMAC);
  * нажали в том же чате, куда ушло уведомление;
  * нажавший — в списке разрешённых пользователей Telegram канала (если список задан).
Каждое действие пишется в журнал событий и аудит с именем пользователя Telegram.

Команды в том же чате (те же права): /status, /top, /ip, /ban, /unban, /help.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ..config import VERSION

log = logging.getLogger("nm.tgbot")

ACTIONS = {"b": "Заблокировать на сутки", "u": "Разблокировать", "r": "Пожаловаться в AbuseIPDB",
           "g": "Закрыть доступ"}  # g — доступ к сайту, открытый по ссылке (параметр — номер выдачи)
COMMANDS = ("help", "start", "status", "top", "ip", "ban", "unban")
HELP = ("Команды Nginx Manager:\n"
        "/status — состояние: nginx, атаки за час, блокировки, «Под атакой», проблемы\n"
        "/top — самые активные атакующие за час (с кнопками блокировки)\n"
        "/ip 203.0.113.5 — адрес: атаки за неделю, сеть, блокировка\n"
        "/ban 203.0.113.5 [часов] — заблокировать (по умолчанию на сутки)\n"
        "/unban 203.0.113.5 — разблокировать")


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
    if act == "g":
        return (act, ip) if ip.isdigit() else None
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
    if source == "access" and str(details.get("grant") or "").isdigit():
        return str(details["grant"]), ["g"]  # доступ по ссылке: кнопка «Закрыть доступ»
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

    # ---------------------------------------------------------------- права
    @staticmethod
    def check(ch, chat: str, user: Dict[str, Any]) -> Tuple[str, str]:
        """(кто, ошибка): действие — только из чата канала и, если задан список, только разрешённым."""
        if chat != str(ch.telegram_chat_id):
            return "", "Действие доступно только в чате уведомлений"
        uid = str(user.get("id", ""))
        if ch.telegram_admins and uid not in ch.telegram_admins and f"@{user.get('username', '')}" not in \
                ch.telegram_admins:
            return "", "Нет прав: вас нет в списке разрешённых пользователей канала"
        return (f"telegram:@{user['username']}" if user.get("username") else f"telegram:{uid}"), ""

    # ---------------------------------------------------------------- обработка нажатия
    def handle(self, ch, cq: Dict[str, Any]) -> str:
        """Нажатие кнопки → текст ответа (показывается во всплывающем окне Telegram)."""
        parsed = parse_callback(secret(self.db), cq.get("data") or "")
        if not parsed:
            return "Кнопка устарела или подделана"
        chat = str(((cq.get("message") or {}).get("chat") or {}).get("id", ""))
        who, err = self.check(ch, chat, cq.get("from") or {})
        if err:
            return err
        act, ip = parsed
        return self.act(act, ip, who, chat)

    def act(self, act: str, ip: str, who: str, chat: str, minutes: int = 1440) -> str:
        try:
            if act == "b":
                self.app.bans.add(ip, minutes, "Из Telegram", "manual", who, "manual")
                spawn_sync(self.app)
                span = "на сутки" if minutes == 1440 else f"на {minutes // 60} ч" if minutes % 60 == 0 else \
                    f"на {minutes} мин"
                self.db.event("info", "bans", f"{ip} заблокирован {span} из Telegram ({who})")
                msg = f"{ip} заблокирован {span}"
            elif act == "u":
                row = self.db.one("SELECT id FROM bans WHERE net=?", (ip,))
                if not row:
                    return f"{ip} уже не заблокирован"
                self.app.bans.remove(row["id"])
                spawn_sync(self.app)
                self.db.event("info", "bans", f"Разблокирован {ip} из Telegram ({who})")
                msg = f"{ip} разблокирован"
            elif act == "g":
                g = self.db.one("SELECT * FROM ipaccess_grants WHERE id=?", (int(ip),))
                if not g or g["expires_at"] <= time.time():
                    return "Этот доступ уже закрыт"
                self.db.execute("UPDATE ipaccess_grants SET expires_at=? WHERE id=?", (time.time() - 1, g["id"]))
                loop = getattr(self.app.events, "loop", None)
                if loop and not loop.is_closed():
                    loop.call_soon_threadsafe(lambda: loop.create_task(self.app.grants.sync()))
                self.db.event("info", "access", f"Доступ для {g['ip']} (сайт #{g['site']}) закрыт из Telegram ({who})")
                msg = f"Доступ для {g['ip']} закрыт"
            else:
                r = self.app.protection.intel.report(ip, who)
                msg = f"Жалоба на {ip} отправлена (категории {', '.join(map(str, r['categories']))})"
        except Exception as e:  # noqa: BLE001
            return f"Не выполнено: {e}"[:190]
        self.db.execute("INSERT INTO audit_log(ts, username, ip, action, target, details) VALUES(?,?,?,?,?,?)",
                        (time.time(), who, "", {"b": "ip_banned", "u": "ip_unbanned", "r": "abuseipdb_report",
                                                "g": "access_grant_revoked"}[act],
                         ip, json.dumps({"via": "telegram", "chat": chat}, ensure_ascii=False)))
        return msg

    # ---------------------------------------------------------------- команды
    def command(self, ch, msg: Dict[str, Any]) -> Optional[Tuple[str, Optional[Dict[str, Any]]]]:
        """Команда в чате канала → (текст ответа, клавиатура) или None, если это не команда панели."""
        text = (msg.get("text") or "").strip()
        if not text.startswith("/"):
            return None
        parts = text.split()
        cmd = parts[0][1:].split("@", 1)[0].lower()
        args = parts[1:]
        if cmd not in COMMANDS:
            return None
        chat = str((msg.get("chat") or {}).get("id", ""))
        if chat != str(ch.telegram_chat_id):
            return None  # чужой чат — молчим
        who, err = self.check(ch, chat, msg.get("from") or {})
        if err:
            return err, None
        if cmd in ("help", "start"):
            return HELP, None
        if cmd == "status":
            return self.status_text(), None
        if cmd == "top":
            return self.top_text()
        ip = args[0] if args else ""
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            return f"Укажите адрес: /{cmd} 203.0.113.5" + (" [часов]" if cmd == "ban" else ""), None
        if cmd == "ip":
            return self.ip_text(ip)
        if cmd == "ban":
            hours = 24
            if len(args) > 1:
                try:
                    hours = max(1, min(int(args[1]), 24 * 365))
                except ValueError:
                    return "Срок — число часов: /ban 203.0.113.5 6", None
            return self.act("b", ip, who, chat, hours * 60), None
        if cmd == "unban":
            return self.act("u", ip, who, chat), None
        return None

    def status_text(self) -> str:
        app = self.app
        now = time.time()
        ov = self.db.one("SELECT SUM(CASE WHEN action='blocked' THEN n ELSE 0 END) AS blocked, "
                         "SUM(CASE WHEN action='challenged' THEN n ELSE 0 END) AS challenged, SUM(n) AS n "
                         "FROM attack_minute WHERE ts>=?", (now - 3600,)) or {}
        bans = (self.db.one("SELECT COUNT(*) AS n FROM bans WHERE expires_at IS NULL OR expires_at>?", (now,))
                or {}).get("n", 0)
        st = app.protection.attack_state()
        under = ["все сайты"] if st.get("global") else []
        under += [f"сайт {k}" for k, v in (st.get("sites") or {}).items() if v]
        counts = (getattr(app.insights, "last", None) or {}).get("counts") or {}
        try:
            running = app.nginx.is_running()
        except Exception:  # noqa: BLE001
            running = False
        lines = [f"{socket.gethostname()} · Nginx Manager {VERSION}",
                 f"nginx: {'работает' if running else 'НЕ РАБОТАЕТ'}",
                 f"Атак за час: {int(ov.get('n') or 0)} (заблокировано {int(ov.get('blocked') or 0)}, "
                 f"проверка браузера {int(ov.get('challenged') or 0)})",
                 f"Заблокированных адресов: {bans}",
                 f"«Под атакой»: {', '.join(under) if under else 'выключен'}",
                 f"Проблемы по анализу: критичных {counts.get('crit', 0)}, внимание {counts.get('warn', 0)}"]
        return "\n".join(lines)

    def top_text(self) -> Tuple[str, Optional[Dict[str, Any]]]:
        rows = self.app.protection.analytics.attackers(1, limit=5)
        if not rows:
            return "За последний час атак не было", None
        key = secret(self.db)
        lines, kb = ["Атакующие за час:"], []
        for r in rows:
            lines.append(f"{r['ip']}{' (' + r['country'] + ')' if r.get('country') else ''}: оценка {r['score']}, "
                         f"атак {r['n']}, {r['tool_title']}" + (" — заблокирован" if r["banned"] else ""))
            if not r["banned"]:
                kb.append([{"text": f"Заблокировать {r['ip']}", "callback_data": callback_data(key, "b", r["ip"])}])
        return "\n".join(lines), ({"inline_keyboard": kb[:5]} if kb else None)

    def ip_text(self, ip: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        rows = [r for r in self.app.protection.analytics.attackers(168, limit=2000) if r["ip"] == ip]
        ban = self.db.one("SELECT expires_at, reason FROM bans WHERE net=?", (ip,))
        if rows:
            r = rows[0]
            text = (f"{ip}{' (' + r['country'] + ')' if r.get('country') else ''}"
                    f"{', AS' + str(r['asn']) + ' ' + r.get('org', '') if r.get('asn') else ''}\n"
                    f"За неделю: атак {r['n']}, правил {r['rules']}, сайтов {r['sites']}, оценка угрозы {r['score']}, "
                    f"инструмент — {r['tool_title']}")
        else:
            text = f"{ip}: атак за неделю нет"
        text += "\n" + (f"Заблокирован: {ban['reason']}" if ban else "Не заблокирован")
        acts = ["u"] if ban else ["b"]
        if self.app.protection.settings().abuseipdb_key:
            acts.append("r")
        return text, keyboard(secret(self.db), ip, acts, self.profile_url(ip))

    def poll_once(self, token_key: str, ch, timeout: int = 25) -> int:
        """Один длинный опрос getUpdates для бота канала; возвращает число обработанных нажатий и команд."""
        off = self.offsets.get(token_key)
        payload: Dict[str, Any] = {"timeout": timeout, "allowed_updates": ["callback_query", "message"]}
        if off is not None:
            payload["offset"] = off
        d = api(ch.telegram_api, ch.telegram_token, "getUpdates", payload, timeout=timeout + 10)
        if not d.get("ok"):
            raise ValueError(d.get("description") or "ошибка getUpdates")
        n = 0
        for u in d.get("result") or []:
            self.offsets[token_key] = u["update_id"] + 1
            msg_in = u.get("message")
            if msg_in:
                res = self.command(ch, msg_in)
                if res:
                    text, markup = res
                    body: Dict[str, Any] = {"chat_id": ch.telegram_chat_id, "text": text[:4000],
                                            "reply_to_message_id": msg_in.get("message_id"),
                                            "disable_web_page_preview": True}
                    if markup:
                        body["reply_markup"] = markup
                    api(ch.telegram_api, ch.telegram_token, "sendMessage", body, timeout=15)
                    n += 1
                continue
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
