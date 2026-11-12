"""Проверка значений, попадающих в конфигурацию nginx.

Главная задача — не допустить «инъекции» директив через поля формы
(символы ; { } перевод строки и т.п.), а также поймать опечатки до `nginx -t`.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

DURATION_RE = re.compile(r"^\d+(ms|s|m|h|d|w|M|y)?$")
SIZE_RE = re.compile(r"^\d+[kKmMgG]?$")
RATE_RE = re.compile(r"^\d+r/[sm]$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
COOKIE_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
NAME_RE = re.compile(r"^[\w .:@()+\-]{1,100}$", re.UNICODE)
ZONE_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
NGX_VAR_EXPR_RE = re.compile(r"^[\w$:/.\-]+$")
FORBIDDEN_CHARS = set(";{}\n\r\0`\\")


class ValidationError(ValueError):
    pass


def no_ctrl(v: str, field: str = "значение") -> str:
    if any(c in v for c in "\n\r\0"):
        raise ValidationError(f"{field}: недопустим перевод строки")
    return v


def safe_token(v: str, field: str = "значение") -> str:
    """Строка без пробелов и спецсимволов конфигурации nginx."""
    if not v or v.startswith("#") or any(c in FORBIDDEN_CHARS or c.isspace() or c in "\"'" for c in v):
        raise ValidationError(f"{field}: недопустимые символы (пробелы, ; {{ }} кавычки, \\)")
    return v


def duration(v: str, allow_empty: bool = True) -> str:
    v = (v or "").strip()
    if not v and allow_empty:
        return ""
    if not DURATION_RE.match(v):
        raise ValidationError(f"«{v}» — неверный формат времени. Примеры: 500ms, 30s, 5m, 1h, 7d")
    return v


def size(v: str, allow_empty: bool = True) -> str:
    v = (v or "").strip()
    if not v and allow_empty:
        return ""
    if not SIZE_RE.match(v):
        raise ValidationError(f"«{v}» — неверный формат размера. Примеры: 512, 16k, 10m, 1g")
    return v


def rate(v: str) -> str:
    v = (v or "").strip()
    if not RATE_RE.match(v):
        raise ValidationError(f"«{v}» — неверный формат скорости. Примеры: 10r/s, 300r/m")
    return v


def domain(v: str) -> str:
    v = (v or "").strip().lower().rstrip(".")
    if not v:
        raise ValidationError("пустое доменное имя")
    if v == "_":
        return v
    if v.startswith("~"):
        # регулярное выражение server_name
        if any(c in v for c in ";{}\n\r\"' \t"):
            raise ValidationError(f"«{v}»: недопустимые символы в регулярном выражении server_name")
        return v
    try:
        ipaddress.ip_address(v.strip("[]"))
        return v
    except ValueError:
        pass
    raw = v
    prefix = ""
    if v.startswith("*."):
        prefix, v = "*.", v[2:]
    elif v.startswith("."):
        prefix, v = ".", v[1:]
    suffix = ""
    if v.endswith(".*"):
        suffix, v = ".*", v[:-2]
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValidationError(f"«{raw}» — некорректное доменное имя")
    labels = v.split(".")
    if len(v) > 253 or not all(HOST_LABEL_RE.match(lbl) for lbl in labels):
        raise ValidationError(f"«{raw}» — некорректное доменное имя")
    return prefix + v + suffix


def host_or_ip(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("unix:"):
        path = v[5:]
        if not path.startswith("/") or any(c in path for c in ";{}\"' \n"):
            raise ValidationError(f"«{v}» — некорректный путь unix-сокета")
        return v
    try:
        ip = ipaddress.ip_address(v.strip("[]"))
        return f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        pass
    d = domain(v)
    if d.startswith(("*", "~", ".")) or d.endswith(".*") or d == "_":
        raise ValidationError(f"«{v}» — адрес бэкенда должен быть IP или именем хоста")
    return d


def listen_ip(v: str) -> str:
    v = (v or "").strip()
    if not v or v in ("*", "0.0.0.0"):
        return ""
    try:
        ip = ipaddress.ip_address(v.strip("[]"))
        return f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        raise ValidationError(f"«{v}» — некорректный IP-адрес для listen")


def cidr(v: str) -> str:
    v = (v or "").strip()
    if v == "all":
        return v
    try:
        if "/" in v:
            return str(ipaddress.ip_network(v, strict=False))
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ValidationError(f"«{v}» — некорректный IP-адрес или подсеть (пример: 10.0.0.0/8)")


def header_name(v: str) -> str:
    v = (v or "").strip()
    if not HEADER_NAME_RE.match(v):
        raise ValidationError(f"«{v}» — некорректное имя заголовка")
    return v


def location_path(v: str, match: str) -> str:
    v = (v or "").strip()
    if not v:
        raise ValidationError("путь location не может быть пустым")
    no_ctrl(v, "путь location")
    if match in ("prefix", "exact", "prefix_priority"):
        if not v.startswith("/") and not v.startswith("@"):
            raise ValidationError(f"«{v}»: префиксный путь должен начинаться с /")
        if any(c in v for c in ";{}\"' \t"):
            raise ValidationError(f"«{v}»: недопустимые символы в пути")
    else:
        if any(c in v for c in ";\"\t"):
            raise ValidationError(f"«{v}»: недопустимые символы в регулярном выражении")
        try:
            re.compile(v.replace("(?<", "(?P<") if "(?<" in v and "(?<=" not in v and "(?<!" not in v else v)
        except re.error as e:
            raise ValidationError(f"«{v}»: ошибка в регулярном выражении: {e}")
    return v


def url(v: str) -> str:
    v = (v or "").strip()
    if not re.match(r"^(https?://[^\s\"';{}]+|\$scheme://[^\s\"';{}]+|/[^\s\"';{}]*)$", v):
        raise ValidationError(f"«{v}» — некорректный URL (пример: https://example.com)")
    return v


def http_url(v: str, allow_empty: bool = True) -> str:
    """Адрес внешнего сервиса, к которому обращается сама панель: только http(s), без пробелов и управляющих символов."""
    v = (v or "").strip()
    if not v and allow_empty:
        return v
    if not re.match(r"^https?://[^\s/?#]+[^\s]*$", v):
        raise ValidationError(f"«{v}» — нужен адрес вида https://host/путь")
    return v


def quote(v: str) -> str:
    """Экранирование строки для конфигурации nginx (в двойных кавычках)."""
    no_ctrl(v)
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def quote_multiline(v: str) -> str:
    """Строка с переводами строк (тело ответа return): \n → escape-последовательность nginx."""
    if "\r" in v or "\0" in v:
        raise ValidationError("недопустимые управляющие символы")
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def quote_if_needed(v: str) -> str:
    if v and not any(c.isspace() or c in ";{}\"'#\\" for c in v):
        return v
    return quote(v)


HTPASSWD_HASH_RE = re.compile(r"^[A-Za-z0-9./$={}+_-]{1,255}$")


def htpasswd_hash(v: str) -> str:
    """Хеш пароля для файла htpasswd: одна строка без пробелов и двоеточий ($apr1$, $2y$, {SHA}, crypt)."""
    v = (v or "").strip()
    if v and not HTPASSWD_HASH_RE.match(v):
        raise ValidationError("некорректный хеш пароля (ожидается $apr1$…, $2y$…, {SHA}… или crypt)")
    return v


def port(v: Optional[int]) -> Optional[int]:
    if v is None:
        return v
    if not 1 <= int(v) <= 65535:
        raise ValidationError(f"порт {v} вне диапазона 1–65535")
    return int(v)


def parse_duration_seconds(v: str) -> float:
    """'1h' -> 3600.0 (для внутренних расчётов)."""
    m = re.match(r"^(\d+)(ms|s|m|h|d|w|M|y)?$", (v or "").strip())
    if not m:
        return 0.0
    n = int(m.group(1))
    unit = m.group(2) or "s"
    mult = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800,
            "M": 2592000, "y": 31536000}[unit]
    return n * mult


def parse_size_bytes(v: str) -> int:
    m = re.match(r"^(\d+)([kKmMgG]?)$", (v or "").strip())
    if not m:
        return 0
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2).lower()]


# -----------------------------------------------------------------------------
#  «Свои директивы»: что может добавить только администратор
# -----------------------------------------------------------------------------
# nginx читает конфигурацию и открывает журналы от root (мастер-процесс), поэтому некоторые директивы в
# произвольном тексте дают больше, чем «настроить сайт»: include показывает строки любого файла в ошибке nginx -t,
# журнал или временный каталог вне стандартных мест создаёт файл от root (например, в /etc/cron.d), модули
# Lua/Perl/njs выполняют код. Администратор может всё (он и так управляет сервером), оператор и наблюдатель — нет.
RISKY_DIRECTIVES = {
    "include", "load_module", "env", "ssl_engine", "xslt_stylesheet",
    "client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path", "uwsgi_temp_path", "scgi_temp_path",
    "proxy_cache_path", "fastcgi_cache_path", "uwsgi_cache_path", "scgi_cache_path",
}
RISKY_PREFIXES = ("lua_", "perl", "js_", "access_by_", "content_by_", "rewrite_by_", "init_by_", "init_worker_by_",
                  "set_by_", "header_filter_by_", "body_filter_by_", "log_by_", "balancer_by_", "ssl_certificate_by_")
SAFE_INCLUDES = {"mime.types", "fastcgi_params", "fastcgi.conf", "scgi_params", "uwsgi_params", "proxy_params"}
SAFE_LOG_DIR = "/var/log/nginx/"


def _raw_statements(text: str):
    """Директивы произвольного текста конфигурации: (имя, аргументы) — без учёта вложенности, так что лишняя
    закрывающая скобка или блок не спрячут директиву. Кавычки и комментарии — как у nginx."""
    args, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#" and not args or c == "#" and text[i - 1].isspace():
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            if args:
                yield args[0], args[1:]
            args = []
            i += 1
        elif c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            args.append("".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};\"'":
                j += 2 if text[j] == "\\" else 1
            args.append(text[i:j].replace("\\", ""))
            i = j
    if args:
        yield args[0], args[1:]


def _safe_path(p: str, base: str) -> bool:
    import posixpath
    return p.startswith(base) and ".." not in p.split("/") and posixpath.normpath(p).startswith(base.rstrip("/"))


def risky_raw_directives(text: str) -> list:
    """Директивы из текста «Своих директив», которые может добавить только администратор (см. RISKY_DIRECTIVES)."""
    out = []
    for name, args in _raw_statements(text or ""):
        low = name.lower()
        bad = low in RISKY_DIRECTIVES or low.startswith(RISKY_PREFIXES) or "_by_lua" in low
        if low == "include" and len(args) == 1:
            a = args[0]
            bad = not (a in SAFE_INCLUDES or a.split("/")[-1] in SAFE_INCLUDES and _safe_path(a, "/etc/nginx/")
                       or _safe_path(a, "/etc/nginx/snippets/") or (a.startswith("snippets/") and ".." not in a))
        if low in ("access_log", "error_log") and args:
            a = args[0]
            bad = not (a == "off" or a.startswith(("syslog:", "memory:", "stderr")) or _safe_path(a, SAFE_LOG_DIR))
        if bad:
            out.append(" ".join([name] + args[:1]))
    return out
