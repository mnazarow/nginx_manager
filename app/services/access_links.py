"""Временный доступ к сайту по ссылке (раздел сайта «Доступ по IP»).

Администратор создаёт ссылку: на сколько часов открывается доступ, сколько раз ссылкой можно воспользоваться и до
какого времени она действует. Посетитель открывает https://сайт/.nm-access/<код>; nginx отправляет запрос в панель
(как страницу проверки браузера: только с этого сервера и с ключом X-NM-Key). Панель показывает страницу с кнопкой
«Открыть доступ» — по самой ссылке (GET) доступ не выдаётся, иначе его «съели» бы программы предпросмотра ссылок в
мессенджерах. После нажатия адрес посетителя попадает в файл ip-grants.conf (geo $nm_ipgrant: адрес → «,номера
сайтов,»), и nginx перечитывает его без новой версии конфигурации. Истёкший доступ убирается из файла раз в минуту.
В базе хранится только хеш кода ссылки.
"""
from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import logging
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("nm.access")

MAX_LINKS_PER_SITE = 200


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(db, site: int, hours: float, valid_hours: float, uses: int, comment: str, user: str) -> Tuple[int, str]:
    if not (0.25 <= hours <= 24 * 90):
        raise ValueError("Срок доступа: от 15 минут до 90 дней")
    if not (0.25 <= valid_hours <= 24 * 90):
        raise ValueError("Срок действия ссылки: от 15 минут до 90 дней")
    if not (1 <= uses <= 100):
        raise ValueError("Число использований: от 1 до 100")
    n = (db.one("SELECT COUNT(*) AS n FROM ipaccess_links WHERE site=? AND expires_at>? AND uses_left>0",
                (site, time.time())) or {}).get("n", 0)
    if n >= MAX_LINKS_PER_SITE:
        raise ValueError(f"У сайта уже {n} действующих ссылок — удалите ненужные")
    token = secrets.token_urlsafe(24)
    now = time.time()
    lid = db.execute("INSERT INTO ipaccess_links(site, token_hash, comment, hours, uses_left, uses_total, expires_at, "
                     "created_by, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                     (site, _hash(token), comment.strip()[:120], float(hours), int(uses), int(uses),
                      now + valid_hours * 3600, user, now))
    return lid, token


def find(db, token: str) -> Optional[Dict[str, Any]]:
    if not token or len(token) > 100:
        return None
    return db.one("SELECT * FROM ipaccess_links WHERE token_hash=?", (_hash(token),))


def state(row: Optional[Dict[str, Any]], site: int) -> str:
    """ok | missing | other_site | expired | used."""
    if not row:
        return "missing"
    if row["site"] != site:
        return "other_site"
    if row["expires_at"] <= time.time():
        return "expired"
    if row["uses_left"] <= 0:
        return "used"
    return "ok"


def grant(db, link: Dict[str, Any], ip: str, ua: str) -> Dict[str, Any]:
    """Выдать доступ адресу по ссылке (использование списывается). Повтор с того же адреса продлевает доступ."""
    ip = str(ipaddress.ip_address(ip))
    now = time.time()
    exp = now + link["hours"] * 3600
    cur = db.one("SELECT * FROM ipaccess_grants WHERE site=? AND ip=? AND expires_at>?", (link["site"], ip, now))
    db.execute("UPDATE ipaccess_links SET uses_left=uses_left-1 WHERE id=? AND uses_left>0", (link["id"],))
    if cur:
        db.execute("UPDATE ipaccess_grants SET expires_at=MAX(expires_at, ?), link_id=? WHERE id=?",
                   (exp, link["id"], cur["id"]))
        gid = cur["id"]
    else:
        gid = db.execute("INSERT INTO ipaccess_grants(site, ip, link_id, comment, ua, created_at, expires_at) "
                         "VALUES(?,?,?,?,?,?,?)", (link["site"], ip, link["id"], link["comment"], ua[:200], now, exp))
    return db.one("SELECT * FROM ipaccess_grants WHERE id=?", (gid,))


def active_grants(db, site: Optional[int] = None) -> List[Dict[str, Any]]:
    q = "SELECT * FROM ipaccess_grants WHERE expires_at>?"
    args: list = [time.time()]
    if site is not None:
        q += " AND site=?"
        args.append(site)
    return db.query(q + " ORDER BY expires_at DESC", tuple(args))


def render(db) -> str:
    """Содержимое ip-grants.conf: «адрес ,5,7,;» — по строке на адрес, номера сайтов через запятую."""
    by: Dict[str, List[int]] = {}
    for g in active_grants(db):
        by.setdefault(g["ip"], [])
        if g["site"] not in by[g["ip"]]:
            by[g["ip"]].append(g["site"])
    lines = ["# Nginx Manager: доступ к сайтам по ссылке (раздел сайта «Доступ по IP»); файл обновляет панель"]
    for ip in sorted(by):
        lines.append(f'{ip} ",{",".join(str(x) for x in sorted(by[ip]))},";')
    return "\n".join(lines) + "\n"


def cleanup(db, days: int = 30) -> None:
    cut = time.time() - days * 86400
    db.execute("DELETE FROM ipaccess_grants WHERE expires_at<?", (cut,))
    db.execute("DELETE FROM ipaccess_links WHERE expires_at<? OR (uses_left<=0 AND created_at<?)", (cut, cut))


class GrantSync:
    """Запись ip-grants.conf и перечитывание nginx (при выдаче, отзыве и истечении доступа)."""

    def __init__(self, app) -> None:
        self.app = app
        self.last = None
        self.lock: Optional[asyncio.Lock] = None

    async def sync(self, force: bool = False) -> Tuple[bool, str]:
        from ..config import settings
        content = render(self.app.db)
        if content == self.last and not force:
            return True, ""
        if self.lock is None:
            self.lock = asyncio.Lock()
        async with self.lock:
            mgr = self.app.nginx
            async with mgr.lock:
                ok, out = await asyncio.to_thread(mgr.write_side_file, settings.grants_file, content)
            if ok:
                self.last = content
            else:
                self.app.db.event("error", "access", "Не удалось обновить доступ по ссылкам в nginx",
                                  {"output": out[-2000:]})
            return ok, out


# =============================================================================
#  Страница для посетителя
# =============================================================================
PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport"
content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>{title}</title><style>
body{{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f5f6f8;color:#1d2330;margin:0;
display:flex;min-height:100vh;align-items:center;justify-content:center}}main{{background:#fff;border-radius:14px;
box-shadow:0 2px 14px rgba(0,0,0,.08);padding:32px 36px;max-width:440px;width:calc(100% - 40px)}}
h1{{font-size:21px;margin:0 0 10px}}p{{margin:8px 0;color:#3a4252}}code{{background:#eef0f4;padding:1px 6px;
border-radius:5px}}button,a.btn{{display:inline-block;margin-top:14px;background:#1f6feb;color:#fff;border:0;
border-radius:8px;padding:11px 20px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none}}
.muted{{color:#5f6878;font-size:14px}}@media (prefers-color-scheme:dark){{body{{background:#14171c;color:#e6e8ec}}
main{{background:#1d2128}}p{{color:#c4c9d2}}code{{background:#2a2f38}}.muted{{color:#9aa3b2}}}}</style></head>
<body><main>{body}</main></body></html>"""

REASONS = {"missing": "Ссылка не найдена — проверьте, что она скопирована целиком.",
           "other_site": "Ссылка выдана для другого сайта.",
           "expired": "Срок действия ссылки истёк. Попросите администратора прислать новую.",
           "used": "Ссылкой уже воспользовались. Попросите администратора прислать новую."}


def page(title: str, body: str) -> str:
    return PAGE.format(title=html.escape(title), body=body)


def when(ts: float) -> str:
    lt = time.localtime(ts)
    today = time.localtime()
    day = "" if (lt.tm_year, lt.tm_yday) == (today.tm_year, today.tm_yday) else time.strftime("%d.%m.%Y ", lt)
    return day + time.strftime("%H:%M", lt) + " " + (time.strftime("%Z", lt) or "")


def hours_text(h: float) -> str:
    if h < 1:
        return f"{int(round(h * 60))} мин"
    if h < 48 and abs(h - round(h)) < 1e-6:
        n = int(round(h))
        return f"{n} ч"
    if abs(h / 24 - round(h / 24)) < 1e-6:
        return f"{int(round(h / 24))} дн."
    return f"{h:g} ч"
