"""Вспомогательные функции: запуск команд, хеши паролей, TOTP, разное."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import secrets
import shutil
import struct
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
#  Запуск внешних команд
# ---------------------------------------------------------------------------
def run(cmd: Sequence[str], timeout: float = 60, input: Optional[str] = None,
        env: Optional[dict] = None) -> Tuple[int, str]:
    """Выполнить команду, вернуть (код, stdout+stderr). Никогда не бросает исключение."""
    try:
        p = subprocess.run(list(cmd), input=input, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, **(env or {})})
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"команда не найдена: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"превышено время выполнения ({timeout} с): {' '.join(cmd)}"
    except Exception as e:  # pragma: no cover
        return 1, f"{type(e).__name__}: {e}"


async def arun(cmd: Sequence[str], timeout: float = 60, input: Optional[str] = None) -> Tuple[int, str]:
    return await asyncio.to_thread(run, cmd, timeout, input)


def which(name: str) -> Optional[str]:
    p = shutil.which(name)
    if p:
        return p
    for d in ("/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin", "/usr/bin", "/snap/bin"):
        cand = Path(d) / name
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def has_systemd() -> bool:
    return Path("/run/systemd/system").is_dir() and which("systemctl") is not None


def atomic_write(path: Union[str, Path], data: Union[str, bytes], mode: int = 0o644) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp{os.getpid()}")
    if isinstance(data, str):
        data = data.encode("utf-8")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
#  Пароли панели: scrypt (stdlib)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2 ** 14, 8, 1
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(base64.b64decode(dk)))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


# ---------------------------------------------------------------------------
#  APR1-MD5 для htpasswd (поддерживается nginx на любых платформах)
# ---------------------------------------------------------------------------
_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def apr1(password: str, salt: Optional[str] = None) -> str:
    salt = (salt or "".join(secrets.choice(_ITOA64) for _ in range(8)))[:8]
    pw, sl, magic = password.encode(), salt.encode(), b"$apr1$"
    ctx = pw + magic + sl
    final = hashlib.md5(pw + sl + pw).digest()
    for i in range(len(pw), 0, -16):
        ctx += final[:min(16, i)]
    i = len(pw)
    while i:
        ctx += b"\x00" if i & 1 else pw[:1]
        i >>= 1
    final = hashlib.md5(ctx).digest()
    for i in range(1000):
        c = (pw if i & 1 else final)
        if i % 3:
            c += sl
        if i % 7:
            c += pw
        c += (final if i & 1 else pw)
        final = hashlib.md5(c).digest()

    def to64(v: int, n: int) -> str:
        out = ""
        for _ in range(n):
            out += _ITOA64[v & 0x3F]
            v >>= 6
        return out

    f = final
    res = (to64((f[0] << 16) | (f[6] << 8) | f[12], 4) + to64((f[1] << 16) | (f[7] << 8) | f[13], 4) +
           to64((f[2] << 16) | (f[8] << 8) | f[14], 4) + to64((f[3] << 16) | (f[9] << 8) | f[15], 4) +
           to64((f[4] << 16) | (f[10] << 8) | f[5], 4) + to64(f[11], 2))
    return f"$apr1${salt}${res}"


# ---------------------------------------------------------------------------
#  TOTP (RFC 6238) для двухфакторной аутентификации
# ---------------------------------------------------------------------------
def totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret: str, t: Optional[float] = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int((t or time.time()) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret: str, code: str, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    now = time.time()
    return any(hmac.compare_digest(totp_code(secret, now + i * 30), code) for i in range(-window, window + 1))


# ---------------------------------------------------------------------------
def human_bytes(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ПБ"


def sha256(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def tail_lines(path: Path, n: int = 200, max_bytes: int = 2_000_000) -> List[str]:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read().decode("utf-8", "replace")
        return data.splitlines()[-n:]
    except OSError:
        return []
