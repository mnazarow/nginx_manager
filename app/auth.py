"""Аутентификация и авторизация: пользователи, сессии, API-токены, 2FA, защита от перебора."""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
import time
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, Request

from .config import settings
from .db import Database
from .utils import hash_password, totp_step, verify_password

# хеш для сравнения, когда пользователя нет: время ответа не выдаёт, существует ли логин
_DUMMY_HASH = hash_password("nm-dummy-password-for-timing")

ROLES = {"admin": 3, "operator": 2, "viewer": 1}
ROLE_LABELS = {"admin": "Администратор", "operator": "Оператор", "viewer": "Наблюдатель"}
COOKIE = "nm_session"


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class AuthService:
    def __init__(self, db: Database, get_panel) -> None:
        self.db = db
        self.get_panel = get_panel
        self.failures: Dict[str, List[float]] = {}
        self.totp_used: Dict[int, int] = {}  # последний принятый шаг TOTP по пользователю (код не принимается дважды)

    # ------------------------------------------------------------------
    def client_ip(self, request: Request) -> str:
        ip = request.client.host if request.client else ""
        if ip in settings.trust_proxy:
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                ip = xff.split(",")[-1].strip() or ip
            elif request.headers.get("x-real-ip"):
                ip = request.headers["x-real-ip"]
        return ip

    def ip_allowed(self, ip: str) -> bool:
        allow = self.get_panel().panel_allow
        if not allow:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if a.is_loopback:
            return True
        for net in allow:
            try:
                if a in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
        return False

    # ---- защита от перебора --------------------------------------------
    def locked(self, ip: str) -> Optional[int]:
        p = self.get_panel()
        now = time.time()
        fails = [t for t in self.failures.get(ip, []) if now - t < p.login_lock_minutes * 60]
        self.failures[ip] = fails
        if len(fails) >= p.login_max_attempts:
            return int(p.login_lock_minutes * 60 - (now - fails[-p.login_max_attempts]))
        return None

    def fail(self, ip: str) -> None:
        self.failures.setdefault(ip, []).append(time.time())

    # ---- пользователи ---------------------------------------------------
    def users(self) -> List[Dict[str, Any]]:
        rows = self.db.query("SELECT id, username, role, totp_enabled, disabled, must_change_password, created_at, "
                             "last_login FROM users ORDER BY id")
        return rows

    def create_user(self, username: str, password: str, role: str, must_change: bool = False) -> int:
        username = username.strip()
        if not username or len(username) > 64 or any(c.isspace() for c in username):
            raise ValueError("Некорректное имя пользователя")
        if role not in ROLES:
            raise ValueError("Неизвестная роль")
        check_password_strength(password)
        if self.db.one("SELECT 1 FROM users WHERE username=?", (username,)):
            raise ValueError("Пользователь уже существует")
        return self.db.execute("INSERT INTO users(username,password_hash,role,created_at,must_change_password) "
                               "VALUES(?,?,?,?,?)", (username, hash_password(password), role, time.time(),
                                                     int(must_change)))

    def set_password(self, uid: int, password: str) -> None:
        check_password_strength(password)
        self.db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                        (hash_password(password), uid))
        self.db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))

    def authenticate(self, username: str, password: str, otp: str = "") -> Dict[str, Any]:
        u = self.db.one("SELECT * FROM users WHERE username=?", (username,))
        ok = verify_password(password, u["password_hash"] if u else _DUMMY_HASH)
        if not u or u["disabled"] or not ok:
            raise PermissionError("Неверное имя пользователя или пароль")
        if u["totp_enabled"]:
            if not otp:
                raise LookupError("totp_required")
            step = totp_step(u["totp_secret"], otp)
            if step is None:
                raise PermissionError("Неверный код двухфакторной аутентификации")
            if step <= self.totp_used.get(u["id"], -1):
                raise PermissionError("Этот код уже использован — дождитесь следующего кода в приложении")
            self.totp_used[u["id"]] = step
        return u

    def create_session(self, uid: int, ip: str, ua: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        ttl = self.get_panel().session_hours * 3600
        self.db.execute("INSERT INTO sessions(id,user_id,created_at,expires_at,last_seen,ip,user_agent) "
                        "VALUES(?,?,?,?,?,?,?)", (_h(token), uid, now, now + ttl, now, ip, ua[:300]))
        self.db.execute("UPDATE users SET last_login=? WHERE id=?", (now, uid))
        return token

    def destroy_session(self, token: str) -> None:
        self.db.execute("DELETE FROM sessions WHERE id=?", (_h(token),))

    def user_by_session(self, token: str) -> Optional[Dict[str, Any]]:
        r = self.db.one("SELECT s.id sid, s.expires_at, s.last_seen, u.* FROM sessions s JOIN users u "
                        "ON u.id=s.user_id WHERE s.id=?", (_h(token),))
        if not r or r["disabled"] or r["expires_at"] < time.time():
            return None
        if time.time() - r["last_seen"] > 60:
            ttl = self.get_panel().session_hours * 3600
            self.db.execute("UPDATE sessions SET last_seen=?, expires_at=? WHERE id=?",
                            (time.time(), time.time() + ttl, r["sid"]))
        return r

    def user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        r = self.db.one("SELECT t.id tid, t.expires_at texp, u.* FROM api_tokens t JOIN users u ON u.id=t.user_id "
                        "WHERE t.token_hash=?", (_h(token),))
        if not r or r["disabled"] or (r["texp"] and r["texp"] < time.time()):
            return None
        self.db.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (time.time(), r["tid"]))
        return r

    def create_token(self, uid: int, name: str, days: int = 0) -> str:
        token = "nm_" + secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO api_tokens(user_id,name,token_hash,prefix,created_at,expires_at) "
                        "VALUES(?,?,?,?,?,?)", (uid, name[:100], _h(token), token[:10], time.time(),
                                                time.time() + days * 86400 if days else None))
        return token

    # ---- текущий пользователь из запроса ------------------------------
    def resolve(self, request: Request) -> Optional[Dict[str, Any]]:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            u = self.user_by_token(auth[7:].strip())
            if u:
                u["via"] = "token"
            return u
        tok = request.cookies.get(COOKIE)
        if tok:
            u = self.user_by_session(tok)
            if u:
                u["via"] = "session"
            return u
        return None


def check_password_strength(pw: str) -> None:
    if len(pw) < 8:
        raise ValueError("Пароль должен быть не короче 8 символов")
    if pw.isdigit() or pw.isalpha() and pw.lower() == pw:
        raise ValueError("Пароль слишком простой: используйте буквы разного регистра, цифры или символы")


def require(request: Request, role: str = "viewer") -> Dict[str, Any]:
    app = request.app.state.nm
    ip = app.auth.client_ip(request)
    if not app.auth.ip_allowed(ip):
        raise HTTPException(403, "Доступ к панели с вашего IP запрещён")
    user = app.auth.resolve(request)
    if not user:
        raise HTTPException(401, "Требуется вход")
    if request.method not in ("GET", "HEAD", "OPTIONS") and user.get("via") == "session":
        # защита от CSRF: браузер не отправит этот заголовок с чужого сайта без CORS
        if request.headers.get("x-nm-csrf") != "1":
            raise HTTPException(403, "CSRF-проверка не пройдена")
    if ROLES.get(user["role"], 0) < ROLES[role]:
        raise HTTPException(403, f"Недостаточно прав (нужна роль «{ROLE_LABELS[role]}»)")
    # политика входа проверяется на сервере, а не только в интерфейсе: пока не выполнена, можно смотреть,
    # но не изменять (кроме своего профиля). API-токены — отдельные учётные данные, к ним это не относится.
    if user.get("via") == "session" and request.method not in ("GET", "HEAD", "OPTIONS") \
            and not request.url.path.startswith("/api/auth/"):
        if user.get("must_change_password"):
            raise HTTPException(403, "Сначала смените временный пароль (раздел «Мой профиль»)")
        if user["role"] == "admin" and not user.get("totp_enabled") and app.panel().require_2fa_admin:
            raise HTTPException(403, "Политика панели требует двухфакторную аутентификацию для администраторов — "
                                     "включите её в разделе «Мой профиль»")
    user["ip"] = ip
    return user


def viewer(request: Request) -> Dict[str, Any]:
    return require(request, "viewer")


def operator(request: Request) -> Dict[str, Any]:
    return require(request, "operator")


def admin(request: Request) -> Dict[str, Any]:
    return require(request, "admin")
