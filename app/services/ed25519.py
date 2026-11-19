"""Подписи Ed25519 (RFC 8032) без сторонних библиотек — для списков адресов по ссылке.

Код — эталонная реализация из RFC 8032, раздел 6 (расширенные координаты). Скорость (десятки миллисекунд на
проверку) не важна: подпись проверяется один раз на загрузку списка.

Форматы, которые понимает панель:
- открытый ключ — base64 32 байт («сырой» ключ) или base64 DER SubjectPublicKeyInfo (тело PEM из
  `openssl pkey -pubout`, начинается с MCowBQYDK2VwAyEA), с префиксом «ed25519:» или без;
- подпись — 64 байта как есть (`openssl pkeyutl -sign -rawin`) или base64 этих 64 байт (`nmctl lists sign`).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
from typing import Optional, Tuple

p = 2 ** 255 - 19
q = 2 ** 252 + 27742317777372353535851937790883648493
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


d = -121665 * _inv(121666) % p
_SQRT_M1 = pow(2, (p - 1) // 4, p)


def _sha512_modq(s: bytes) -> int:
    return int.from_bytes(hashlib.sha512(s).digest(), "little") % q


def _add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % p, (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p
    E, F, G_, H = B - A, D - C, D + C, B + A
    return (E * F, G_ * H, F * G_, E * H)


def _mul(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_gy = 4 * _inv(5) % p
_gx = _recover_x(_gy, 0)
G = (_gx, _gy, 1, _gx * _gy % p)


def _compress(P) -> bytes:
    zi = _inv(P[2])
    x, y = P[0] * zi % p, P[1] * zi % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


def _expand(secret: bytes) -> Tuple[int, bytes]:
    if len(secret) != 32:
        raise ValueError("закрытый ключ Ed25519 — 32 байта")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    return _compress(_mul(_expand(secret)[0], G))


def sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(secret)
    A = _compress(_mul(a, G))
    r = _sha512_modq(prefix + msg)
    Rs = _compress(_mul(r, G))
    s = (r + _sha512_modq(Rs + A + msg) * a) % q
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    h = _sha512_modq(signature[:32] + public + msg)
    return _equal(_mul(s, G), _add(R, _mul(h, A)))


def keygen() -> Tuple[bytes, bytes]:
    secret = os.urandom(32)
    return secret, public_key(secret)


# ---------------------------------------------------------------- форматы
def parse_public(text: str) -> bytes:
    t = "".join((text or "").split())
    if t.lower().startswith("ed25519:"):
        t = t[8:]
    t = t.replace("-----BEGINPUBLICKEY-----", "").replace("-----ENDPUBLICKEY-----", "")
    try:
        raw = base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("открытый ключ — base64 (ed25519:… или тело PEM из openssl pkey -pubout)")
    if len(raw) == 44 and raw.startswith(SPKI_PREFIX):
        raw = raw[12:]
    if len(raw) != 32 or _decompress(raw) is None:
        raise ValueError("это не открытый ключ Ed25519")
    return raw


def parse_publics(text: str) -> list:
    """Несколько открытых ключей (смена ключа: старый и новый на переходный период) — через пробел, запятую или
    перевод строки; PEM-блоки — целиком. До трёх ключей."""
    import re
    t = text or ""
    keys = [parse_public(m) for m in re.findall(r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", t, re.S)]
    t = re.sub(r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", " ", t, flags=re.S)
    keys += [parse_public(x) for x in re.split(r"[\s,;]+", t) if x]
    out = []
    for k in keys:
        if k not in out:
            out.append(k)
    if len(out) > 3:
        raise ValueError("не больше трёх открытых ключей")
    return out


def verify_any(publics: list, msg: bytes, signature: bytes) -> bool:
    return any(verify(k, msg, signature) for k in publics)


def parse_signature(blob: bytes) -> bytes:
    if len(blob) == 64:
        return blob
    try:
        raw = base64.b64decode(b"".join(blob.split()), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("файл подписи — 64 байта или base64 этих 64 байт")
    if len(raw) != 64:
        raise ValueError("файл подписи — 64 байта или base64 этих 64 байт")
    return raw


def format_public(raw: bytes) -> str:
    return "ed25519:" + base64.b64encode(raw).decode()


def parse_secret(text: str) -> bytes:
    """Закрытый ключ из `nmctl lists keygen` (ed25519-secret:base64 32 байт) или PEM PKCS#8 из openssl genpkey."""
    t = "".join((text or "").split())
    if t.startswith("ed25519-secret:"):
        raw = base64.b64decode(t[15:])
    else:
        t = t.replace("-----BEGINPRIVATEKEY-----", "").replace("-----ENDPRIVATEKEY-----", "")
        der = base64.b64decode(t)
        raw = der[-32:] if len(der) == 48 else b""  # PKCS#8 Ed25519: 16 байт заголовка + 32 байта
    if len(raw) != 32:
        raise ValueError("закрытый ключ Ed25519 не распознан")
    return raw
