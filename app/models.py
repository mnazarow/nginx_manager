"""Модели данных (pydantic) — единый источник правды для:
  * проверки входных данных API;
  * генерации конфигурации nginx;
  * построения форм веб-панели (метаданные полей: label/help/doc/tab/...);
  * справочника параметров в документации (tools/gen_reference.py).
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import validators as V


def F(default: Any = None, *, label: str, help: str = "", doc: str = "", rec: str = "",
      example: str = "", tab: str = "", ui: str = "", adv: bool = False,
      show: Optional[Dict[str, Any]] = None, labels: Optional[Dict[str, str]] = None,
      unit: str = "", ph: str = "", factory=None, directive: str = "", **kw):
    extra = {k: v for k, v in dict(label=label, help=help, doc=doc, rec=rec, example=example,
                                   tab=tab, ui=ui, adv=adv, show=show, labels=labels, unit=unit,
                                   ph=ph, directive=directive).items() if v}
    if factory is not None:
        return Field(default_factory=factory, json_schema_extra=extra, **kw)
    return Field(default, json_schema_extra=extra, **kw)


def _tls_protocols(v: str) -> str:
    v = " ".join((v or "").split())
    for p in v.split():
        if p not in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
            raise V.ValidationError(f"Неизвестный протокол {p}")
    return v


def _domains(v: List[str]) -> List[str]:
    out: List[str] = []
    for d in v:
        for part in d.replace(",", " ").split():
            nd = V.domain(part)
            if nd not in out:
                out.append(nd)
    return out


class Model(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=False)


# =============================================================================
#  Общие элементы
# =============================================================================
class Header(Model):
    name: str = F("", label="Заголовок", ph="X-Frame-Options")
    value: str = F("", label="Значение", ph="SAMEORIGIN",
                   help="Можно использовать переменные nginx, например $host")
    always: bool = F(True, label="always",
                     help="Добавлять и к ответам с ошибками (4xx/5xx)")

    @field_validator("name")
    @classmethod
    def _n(cls, v): return V.header_name(v)

    @field_validator("value")
    @classmethod
    def _v(cls, v): return V.no_ctrl(v, "значение заголовка")


class Backend(Model):
    address: str = F("127.0.0.1", label="Адрес", ph="10.0.0.5 или app.local или unix:/run/app.sock",
                     help="IP-адрес, имя хоста или unix-сокет бэкенда")
    port: Optional[int] = F(80, label="Порт", help="Игнорируется для unix-сокета", ge=1, le=65535)
    weight: int = F(1, label="Вес", ge=1, le=1000, directive="server ... weight=",
                    help="Доля запросов относительно других серверов группы",
                    doc="Сервер с весом 3 получает в 3 раза больше запросов, чем сервер с весом 1 "
                        "(для round_robin и least_conn).",
                    rec="Задавайте вес пропорционально производительности серверов.")
    max_fails: int = F(3, label="max_fails", ge=0, le=100, directive="server ... max_fails=",
                       help="Число неудачных попыток за fail_timeout, после которых сервер считается недоступным",
                       doc="0 — отключить учёт ошибок. Неудачными считаются попытки, подпадающие под "
                           "proxy_next_upstream (error, timeout и т.д.).",
                       rec="3 для большинства случаев; 1 — для быстрого переключения при наличии резерва.")
    fail_timeout: str = F("30s", label="fail_timeout", directive="server ... fail_timeout=",
                          help="Окно подсчёта ошибок и время «выключения» сервера",
                          rec="10s–30s")
    backup: bool = F(False, label="Резервный", directive="server ... backup",
                     help="Получает запросы, только когда все основные серверы недоступны",
                     doc="Не совместим с методами балансировки hash, ip_hash и random.")
    down: bool = F(False, label="Выключен", directive="server ... down",
                   help="Временно исключить сервер из балансировки (без удаления)")
    max_conns: int = F(0, label="max_conns", ge=0, le=100000, adv=True, directive="server ... max_conns=",
                       help="Лимит одновременных соединений к серверу (0 — без лимита)")
    comment: str = F("", label="Комментарий", adv=True)

    @field_validator("address")
    @classmethod
    def _a(cls, v): return V.host_or_ip(v)

    @field_validator("fail_timeout")
    @classmethod
    def _ft(cls, v): return V.duration(v, allow_empty=False)

    @field_validator("comment")
    @classmethod
    def _c(cls, v): return V.no_ctrl(v)

    def key(self) -> str:
        return self.address if self.address.startswith("unix:") else f"{self.address}:{self.port or 80}"


BALANCING_LABELS = {
    "round_robin": "Round Robin — по очереди с учётом весов",
    "least_conn": "Least Connections — на сервер с наименьшим числом соединений",
    "ip_hash": "IP Hash — клиент «прилипает» к серверу по IP",
    "hash": "Hash — по произвольному ключу (URI, cookie...)",
    "random": "Random — случайный выбор",
    "random_two": "Random two least_conn — из двух случайных выбирается менее загруженный",
}


class HealthCheck(Model):
    enabled: bool = F(True, label="Активные проверки",
                      help="Панель периодически опрашивает каждый бэкенд и показывает его состояние",
                      doc="Open-source nginx не умеет активные проверки, поэтому их выполняет сервис "
                          "Nginx Manager. Результат виден на странице «Бэкенды», используется в оповещениях "
                          "и (при включённом автопереключении) в конфигурации.")
    type: Literal["http", "tcp"] = F("http", label="Тип проверки",
                                     labels={"http": "HTTP-запрос", "tcp": "TCP-подключение"})
    path: str = F("/", label="Путь", show={"type": ["http"]}, ph="/health",
                  rec="Используйте лёгкий служебный эндпоинт (/health, /ping), не главную страницу.")
    method: Literal["GET", "HEAD"] = F("GET", label="Метод", show={"type": ["http"]})
    expected_status: str = F("200-399", label="Ожидаемые коды", show={"type": ["http"]},
                             help="Диапазоны и коды через запятую: 200-299,301,401")
    expected_body: str = F("", label="Ожидаемый текст в ответе", show={"type": ["http"]}, adv=True,
                           help="Если задан — ответ должен содержать эту строку")
    host_header: str = F("", label="Заголовок Host", show={"type": ["http"]}, adv=True,
                         help="По умолчанию — первый домен сайта")
    interval: int = F(15, label="Интервал", unit="с", ge=2, le=3600, rec="10–30 с")
    timeout: int = F(5, label="Таймаут", unit="с", ge=1, le=120)
    fall: int = F(3, label="Неудач до статуса DOWN", ge=1, le=20)
    rise: int = F(2, label="Успехов до статуса UP", ge=1, le=20)
    auto_failover: bool = F(False, label="Автоматическое переключение",
                            help="Помечать недоступный бэкенд как down в конфигурации nginx и возвращать при восстановлении",
                            doc="При смене состояния сервис перегенерирует конфигурацию на основе последней "
                                "применённой версии (неприменённые правки не затрагиваются), проверяет её "
                                "и делает reload. Если недоступны все серверы группы, ни один не выключается.",
                            rec="Включайте, если бэкенды «зависают» (принимают TCP, но не отвечают) — "
                                "пассивная проверка nginx (max_fails) такие случаи распознаёт плохо.")

    @field_validator("expected_status")
    @classmethod
    def _es(cls, v):
        import re
        v = v.replace(" ", "")
        if not re.match(r"^\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*$", v):
            raise V.ValidationError("Формат: 200-399 или 200,301,302")
        return v

    @field_validator("path")
    @classmethod
    def _p(cls, v):
        if not v.startswith("/"):
            raise V.ValidationError("Путь должен начинаться с /")
        return V.safe_token(v, "путь")


class BasicAuthUser(Model):
    username: str = F("", label="Пользователь")
    password: str = F("", label="Пароль", ui="password",
                      help="Хранится только хеш (APR1-MD5). Оставьте пустым, чтобы не менять")
    password_hash: str = F("", label="Хеш", ui="hidden")

    @field_validator("username")
    @classmethod
    def _u(cls, v):
        if not v or ":" in v or any(c.isspace() or ord(c) < 32 for c in v) or len(v) > 64:
            raise V.ValidationError("Имя пользователя не должно содержать пробелы и двоеточия (до 64 символов)")
        return v

    @field_validator("password_hash")
    @classmethod
    def _h(cls, v):
        return V.htpasswd_hash(v)


# =============================================================================
#  Сайт (виртуальный хост)
# =============================================================================
class SSLSettings(Model):
    enabled: bool = F(False, label="Включить HTTPS", tab="ssl",
                      help="Слушать HTTPS-порт с выбранным сертификатом")
    certificate_id: Optional[int] = F(None, label="Сертификат", ui="certificate", show={"enabled": [True]},
                                      help="Выберите сертификат или выпустите новый на странице «Сертификаты»")
    force_https: bool = F(True, label="Перенаправлять HTTP → HTTPS", show={"enabled": [True]},
                          directive="return 301 https://...",
                          doc="Все запросы по HTTP (кроме проверок Let's Encrypt) перенаправляются на HTTPS.",
                          rec="Включено. Отключайте только если клиенты не умеют HTTPS.")
    redirect_code: Literal[301, 302, 307, 308] = F(301, label="Код перенаправления", show={"enabled": [True]},
                                                    adv=True,
                                                    labels={"301": "301 Moved Permanently",
                                                            "302": "302 Found",
                                                            "307": "307 Temporary Redirect",
                                                            "308": "308 Permanent Redirect (сохраняет метод)"},
                                                    rec="301 для сайтов; 308 для API (POST не превратится в GET).")
    http2: bool = F(True, label="HTTP/2", show={"enabled": [True]}, directive="http2 on",
                    doc="Мультиплексирование запросов в одном TCP-соединении, сжатие заголовков.",
                    rec="Включено.")
    http3: bool = F(False, label="HTTP/3 (QUIC)", show={"enabled": [True]}, adv=True,
                    directive="listen ... quic",
                    help="Требуется nginx ≥ 1.25 с модулем http_v3 и открытый UDP-порт 443",
                    doc="Доступно, только если ваш nginx собран с --with-http_v3_module. "
                        "Сервис проверит это при применении.")
    hsts: bool = F(False, label="HSTS", show={"enabled": [True]}, directive="Strict-Transport-Security",
                   help="Браузер запомнит, что сайт доступен только по HTTPS",
                   doc="ВНИМАНИЕ: после включения браузеры не позволят зайти по HTTP в течение max-age. "
                       "Включайте, когда HTTPS стабильно работает.",
                   rec="Начните с max-age=300, затем увеличьте до 31536000.")
    hsts_max_age: int = F(31536000, label="HSTS max-age", unit="с", show={"enabled": [True], "hsts": [True]},
                          ge=0, le=63072000)
    hsts_subdomains: bool = F(False, label="HSTS includeSubDomains", show={"enabled": [True], "hsts": [True]})
    hsts_preload: bool = F(False, label="HSTS preload", show={"enabled": [True], "hsts": [True]}, adv=True)
    ocsp_stapling: bool = F(False, label="OCSP stapling", show={"enabled": [True]}, adv=True,
                            directive="ssl_stapling",
                            help="Ускоряет проверку отзыва сертификата. Требует resolver в глобальных настройках",
                            doc="Let's Encrypt прекратил поддержку OCSP в 2025 году — для его сертификатов "
                                "оставьте выключенным.")
    protocols: str = F("", label="Протоколы TLS (переопределить)", show={"enabled": [True]}, adv=True,
                       ph="TLSv1.2 TLSv1.3", directive="ssl_protocols",
                       help="Пусто — использовать глобальную настройку")

    @field_validator("protocols")
    @classmethod
    def _pr(cls, v): return _tls_protocols(v)


class ProxySettings(Model):
    host_header: Literal["client", "backend", "custom"] = F(
        "client", label="Заголовок Host к бэкенду", directive="proxy_set_header Host",
        labels={"client": "Как у клиента ($host)", "backend": "Адрес бэкенда", "custom": "Задать вручную"},
        doc="«Как у клиента» нужно большинству приложений с виртуальными хостами. «Адрес бэкенда» — "
            "когда бэкенд — внешний сервис (например, S3 или другой сайт).",
        rec="Как у клиента.")
    custom_host: str = F("", label="Свой Host", show={"host_header": ["custom"]}, ph="internal.example.com")
    websocket: bool = F(True, label="Поддержка WebSocket", directive="proxy_set_header Upgrade/Connection",
                        help="Пробрасывать заголовки Upgrade/Connection",
                        doc="Безопасно оставлять включённым: для обычных запросов Connection остаётся пустым, "
                            "что сохраняет keepalive до бэкенда.")
    connect_timeout: str = F("5s", label="Таймаут подключения", directive="proxy_connect_timeout",
                             help="Сколько ждать установки TCP-соединения с бэкендом",
                             rec="2s–10s. Большие значения замедляют переключение на живой сервер.")
    read_timeout: str = F("60s", label="Таймаут чтения", directive="proxy_read_timeout",
                          help="Максимальная пауза между двумя чтениями ответа бэкенда",
                          doc="Если бэкенд долго генерирует ответ (отчёты, выгрузки) — увеличьте. "
                              "Для WebSocket/SSE это время простоя соединения.",
                          rec="60s для сайтов, 300s–3600s для долгих API/WebSocket.")
    send_timeout: str = F("60s", label="Таймаут отправки", directive="proxy_send_timeout",
                          help="Максимальная пауза при передаче запроса бэкенду")
    buffering: bool = F(True, label="Буферизация ответа", directive="proxy_buffering",
                        doc="Включено: nginx быстро забирает ответ у бэкенда и сам отдаёт медленным клиентам. "
                            "Выключите для SSE/стриминга (или отправляйте X-Accel-Buffering: no).",
                        rec="Включено.")
    request_buffering: bool = F(True, label="Буферизация запроса", directive="proxy_request_buffering",
                                help="Принимать тело запроса целиком перед отправкой бэкенду",
                                rec="Выключите для потоковой загрузки больших файлов.")
    buffer_size: str = F("", label="proxy_buffer_size", adv=True, ph="16k", directive="proxy_buffer_size",
                         help="Буфер для заголовков ответа. Увеличьте при ошибке «upstream sent too big header»",
                         rec="Пусто (глобальное) или 16k–32k для приложений с большими cookie.")
    buffers: str = F("", label="proxy_buffers", adv=True, ph="16 16k", directive="proxy_buffers",
                     help="Количество и размер буферов тела ответа")
    busy_buffers_size: str = F("", label="proxy_busy_buffers_size", adv=True, ph="32k",
                               directive="proxy_busy_buffers_size")
    next_upstream: List[Literal["error", "timeout", "invalid_header", "http_500", "http_502",
                                "http_503", "http_504", "http_403", "http_404", "http_429",
                                "non_idempotent", "off"]] = F(
        factory=lambda: ["error", "timeout"], label="Повтор на другом сервере при",
        directive="proxy_next_upstream", ui="multiselect",
        doc="При каких ошибках nginx попробует следующий сервер группы. non_idempotent разрешает "
            "повторять POST/PATCH (опасно — возможны дубли).",
        rec="error timeout http_502 http_503 http_504")
    next_upstream_tries: int = F(0, label="Макс. попыток", ge=0, le=20, adv=True,
                                 directive="proxy_next_upstream_tries", help="0 — без ограничения")
    next_upstream_timeout: str = F("", label="Общее время попыток", adv=True, ph="10s",
                                   directive="proxy_next_upstream_timeout")
    pass_real_ip: bool = F(True, label="Передавать IP клиента",
                           directive="X-Real-IP, X-Forwarded-For, X-Forwarded-Proto/Host/Port",
                           help="Заголовки X-Real-IP, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host")
    pass_request_id: bool = F(True, label="X-Request-ID", directive="proxy_set_header X-Request-ID",
                              help="Уникальный ID запроса для сквозной трассировки (виден в журнале запросов)")
    hide_headers: List[str] = F(factory=lambda: ["X-Powered-By"], label="Скрыть заголовки бэкенда",
                                directive="proxy_hide_header", ui="lines",
                                help="По одному на строку. Например X-Powered-By, Server")
    ssl_verify: bool = F(False, label="Проверять сертификат бэкенда", adv=True, directive="proxy_ssl_verify",
                         show={"^backend_scheme": ["https"]},
                         help="Для https-бэкендов. Требует доверенный сертификат на бэкенде")
    ssl_server_name: bool = F(True, label="Передавать SNI бэкенду", adv=True, directive="proxy_ssl_server_name",
                              show={"^backend_scheme": ["https"]})
    intercept_errors: bool = F(False, label="Перехватывать ошибки бэкенда", directive="proxy_intercept_errors",
                               help="Показывать страницы ошибок панели вместо ошибок приложения (код ≥ 300)")
    redirect: Literal["default", "off"] = F("default", label="proxy_redirect", adv=True,
                                            directive="proxy_redirect",
                                            help="Переписывать Location/Refresh от бэкенда")
    http_version: Literal["1.0", "1.1"] = F("1.1", label="Версия HTTP к бэкенду", adv=True,
                                            directive="proxy_http_version",
                                            rec="1.1 (нужно для keepalive и WebSocket)")

    @field_validator("connect_timeout", "read_timeout", "send_timeout", "next_upstream_timeout")
    @classmethod
    def _d(cls, v): return V.duration(v)

    @field_validator("buffer_size", "busy_buffers_size")
    @classmethod
    def _s(cls, v): return V.size(v)

    @field_validator("buffers")
    @classmethod
    def _b(cls, v):
        v = " ".join((v or "").split())
        if v:
            parts = v.split()
            if len(parts) != 2 or not parts[0].isdigit():
                raise V.ValidationError("Формат: <число> <размер>, например 16 16k")
            V.size(parts[1], allow_empty=False)
        return v

    @field_validator("hide_headers")
    @classmethod
    def _hh(cls, v): return [V.header_name(x) for x in v if x.strip()]

    @field_validator("custom_host")
    @classmethod
    def _ch(cls, v): return V.safe_token(v, "Host") if v else v


class CacheSettings(Model):
    enabled: bool = F(False, label="Включить кэширование", directive="proxy_cache",
                      doc="Ответы бэкенда сохраняются на диск (зона кэша из глобальных настроек) и отдаются "
                          "без обращения к бэкенду до истечения срока. Учитывает Cache-Control/Expires "
                          "бэкенда, если не включено «Игнорировать заголовки».",
                      rec="Включайте для публичного контента; для личных кабинетов настройте обход по cookie.")
    zone: str = F("default", label="Зона кэша", ui="cachezone", show={"enabled": [True]})
    valid: List[str] = F(factory=lambda: ["200 301 302 10m", "404 1m"], label="Время жизни",
                         ui="lines", show={"enabled": [True]}, directive="proxy_cache_valid",
                         help="По строке: коды ответа и время. «any 1m» — для всех кодов")
    key: str = F("$scheme$request_method$host$request_uri", label="Ключ кэша", show={"enabled": [True]}, adv=True,
                 directive="proxy_cache_key")
    bypass_cookies: List[str] = F(factory=lambda: ["session", "sessionid", "PHPSESSID", "wordpress_logged_in"],
                                  label="Не кэшировать при наличии cookie", ui="lines", show={"enabled": [True]},
                                  directive="proxy_cache_bypass / proxy_no_cache",
                                  help="Запросы авторизованных пользователей идут мимо кэша")
    bypass_cookie_pattern: str = F("", label="Не кэшировать, если cookie совпадает с шаблоном", show={"enabled": [True]},
                                   ph="wordpress_logged_in|wp-postpass|comment_author",
                                   help="Регулярное выражение по заголовку Cookie (для cookie с изменяемым суффиксом)",
                                   doc="Поле выше сравнивает точные имена cookie. WordPress и многие CMS добавляют к имени "
                                       "хеш (wordpress_logged_in_a1b2…) — для них используйте шаблон.")
    bypass_authorization: bool = F(True, label="Не кэшировать запросы с Authorization", show={"enabled": [True]})
    bypass_arg: str = F("nocache", label="Параметр обхода кэша", show={"enabled": [True]}, adv=True,
                        help="?nocache=1 — запрос мимо кэша")
    methods: List[Literal["GET", "HEAD", "POST"]] = F(factory=lambda: ["GET", "HEAD"], label="Кэшируемые методы",
                                                      ui="multiselect", show={"enabled": [True]}, adv=True,
                                                      directive="proxy_cache_methods")
    min_uses: int = F(1, label="Кэшировать после N запросов", ge=1, le=100, show={"enabled": [True]}, adv=True,
                      directive="proxy_cache_min_uses")
    use_stale: List[Literal["error", "timeout", "updating", "http_500", "http_502", "http_503",
                            "http_504", "http_403", "http_404", "http_429"]] = F(
        factory=lambda: ["error", "timeout", "updating", "http_500", "http_502", "http_503", "http_504"],
        label="Отдавать устаревший кэш при", ui="multiselect", show={"enabled": [True]},
        directive="proxy_cache_use_stale",
        doc="Если бэкенд упал, посетители получат последнюю сохранённую версию страницы.")
    background_update: bool = F(True, label="Фоновое обновление", show={"enabled": [True]}, adv=True,
                                directive="proxy_cache_background_update")
    lock: bool = F(True, label="Блокировка (cache lock)", show={"enabled": [True]}, adv=True,
                   directive="proxy_cache_lock",
                   help="Только один запрос идёт к бэкенду за новым элементом, остальные ждут")
    ignore_headers: List[Literal["Cache-Control", "Expires", "Set-Cookie", "Vary", "X-Accel-Expires"]] = F(
        factory=list, label="Игнорировать заголовки бэкенда", ui="multiselect", show={"enabled": [True]}, adv=True,
        directive="proxy_ignore_headers",
        doc="Игнорирование Set-Cookie может привести к кэшированию персональных данных — будьте осторожны.")
    status_header: bool = F(True, label="Заголовок X-Cache-Status", show={"enabled": [True]},
                            help="HIT / MISS / EXPIRED / BYPASS — удобно для отладки")

    @field_validator("valid")
    @classmethod
    def _valid(cls, v):
        import re
        out = []
        for line in v:
            line = " ".join(line.split())
            if not line:
                continue
            if not re.match(r"^((\d{3} )+|any )\d+(ms|s|m|h|d|w|M|y)?$", line + ("" if line[-1].isalnum() else "")):
                raise V.ValidationError(f"«{line}»: формат «200 302 10m» или «any 1m»")
            out.append(line)
        return out

    @field_validator("bypass_cookies")
    @classmethod
    def _bc(cls, v):
        out = []
        for c in v:
            c = c.strip()
            if not c:
                continue
            if not V.COOKIE_RE.match(c):
                raise V.ValidationError(f"«{c}»: имя cookie — только латиница, цифры и _")
            out.append(c)
        return out

    @field_validator("key")
    @classmethod
    def _k(cls, v): return V.safe_token(v, "ключ кэша")

    @field_validator("bypass_cookie_pattern")
    @classmethod
    def _bcp(cls, v):
        v = (v or "").strip()
        if v:
            import re
            if any(c in v for c in ";{}\"\n"):
                raise V.ValidationError("Недопустимые символы в шаблоне")
            try:
                re.compile(v)
            except re.error as e:
                raise V.ValidationError(f"Ошибка в регулярном выражении: {e}")
        return v

    @field_validator("bypass_arg")
    @classmethod
    def _ba(cls, v):
        if v and not V.COOKIE_RE.match(v):
            raise V.ValidationError("Имя параметра — только латиница, цифры и _")
        return v


DEFAULT_BAD_BOTS = ["AhrefsBot", "SemrushBot", "MJ12bot", "DotBot", "PetalBot", "BLEXBot", "Bytespider",
                    "masscan", "zgrab", "nikto", "sqlmap", "nmap", "Nuclei"]


class SecuritySettings(Model):
    access_mode: Literal["all", "allowlist"] = F("all", label="Режим доступа",
                                                 labels={"all": "Разрешить всем, кроме чёрного списка",
                                                         "allowlist": "Только белый список IP"},
                                                 directive="allow / deny")
    allow: List[str] = F(factory=list, label="Белый список IP/подсетей", ui="lines",
                         show={"access_mode": ["allowlist"]}, ph="203.0.113.0/24", directive="allow")
    deny: List[str] = F(factory=list, label="Чёрный список IP/подсетей", ui="lines", directive="deny",
                        ph="198.51.100.7")
    geo_mode: Literal["off", "deny", "allow"] = F(
        "off", label="Доступ по странам", directive="geo $nm_cc + map",
        labels={"off": "Без ограничений", "deny": "Запретить выбранные страны",
                "allow": "Разрешить только выбранные страны"},
        help="Страна определяется по базе GeoIP (Настройки панели → Статистика)")
    geo_countries: List[str] = F(factory=list, label="Страны", ui="countries", show={"geo_mode": ["deny", "allow"]},
                                 help="Начните вводить название или код страны")
    geo_allow_private: bool = F(True, label="Пускать локальные сети", show={"geo_mode": ["allow"]},
                                help="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 и т.п. — у них нет страны")
    geo_exceptions: List[str] = F(factory=list, label="Исключения (IP и подсети)", ui="lines",
                                  show={"geo_mode": ["deny", "allow"]}, ph="203.0.113.10",
                                  help="Эти адреса пропускаются независимо от страны")
    geo_status: Literal[403, 444, 451] = F(403, label="Ответ заблокированным", show={"geo_mode": ["deny", "allow"]},
                                           labels={"403": "403 Forbidden", "444": "444 — закрыть соединение",
                                                   "451": "451 Unavailable For Legal Reasons"})
    basic_auth: bool = F(False, label="Защита паролем (Basic Auth)", directive="auth_basic",
                         doc="Браузер запросит логин и пароль. Пароли хранятся в виде APR1-MD5-хеша. "
                             "Используйте только вместе с HTTPS — иначе пароль передаётся открыто.")
    basic_auth_realm: str = F("Restricted", label="Текст приглашения", show={"basic_auth": [True]})
    basic_auth_users: List[BasicAuthUser] = F(factory=list, label="Пользователи", show={"basic_auth": [True]},
                                              ui="table")
    satisfy_any: bool = F(False, label="IP из белого списка входят без пароля", show={"basic_auth": [True]},
                          directive="satisfy any")
    rate_limit: bool = F(False, label="Ограничение частоты запросов", directive="limit_req",
                         doc="Алгоритм «дырявое ведро»: с одного IP допускается rate запросов, кратковременные "
                             "всплески до burst. Превышение — ответ с кодом limit_status.",
                         rec="Сайт: 10–30r/s, burst 50. API: по SLA. Логин-формы: 5r/m отдельной локацией.")
    rate: str = F("20r/s", label="Скорость", show={"rate_limit": [True]}, ph="20r/s", directive="limit_req_zone rate=")
    burst: int = F(50, label="Всплеск (burst)", ge=0, le=100000, show={"rate_limit": [True]})
    nodelay: bool = F(True, label="nodelay", show={"rate_limit": [True]},
                      help="Не задерживать запросы в пределах burst, а обслуживать сразу")
    rate_key: Literal["$binary_remote_addr", "$server_name", "$http_x_api_key", "$cookie_session"] = F(
        "$binary_remote_addr", label="Ключ ограничения", show={"rate_limit": [True]}, adv=True,
        labels={"$binary_remote_addr": "IP клиента", "$server_name": "Весь сайт целиком",
                "$http_x_api_key": "Заголовок X-API-Key", "$cookie_session": "Cookie session"})
    limit_status: int = F(429, label="Код ответа при превышении", ge=400, le=599,
                          show={"rate_limit": [True]}, adv=True, directive="limit_req_status")
    conn_limit: int = F(0, label="Макс. соединений с одного IP", ge=0, le=100000, directive="limit_conn",
                        help="0 — без ограничения", rec="20–100 для сайтов")
    block_hidden_files: bool = F(True, label="Блокировать скрытые файлы (.git, .env, .htaccess)",
                                 directive="location ~ /\\.(?!well-known)",
                                 rec="Включено — частая причина утечек исходников и паролей.")
    block_bad_bots: bool = F(False, label="Блокировать нежелательных ботов и сканеры",
                             directive="if ($http_user_agent ~* ...)")
    bad_bots: List[str] = F(factory=lambda: list(DEFAULT_BAD_BOTS), label="Список User-Agent", ui="lines",
                            show={"block_bad_bots": [True]}, help="Подстроки User-Agent, без учёта регистра")
    block_exploits: bool = F(False, label="Базовая защита от эксплойтов",
                             help="Блокирует типовые SQL-инъекции, обход каталогов, вставку тега script в строку запроса",
                             doc="Простой фильтр по регулярным выражениям, не заменяет полноценный WAF. "
                                 "Может давать ложные срабатывания на нестандартных приложениях — проверьте "
                                 "журнал запросов (ответы 403) после включения.")
    allowed_methods: List[Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]] = F(
        factory=list, label="Разрешённые HTTP-методы", ui="multiselect",
        help="Пусто — разрешены все. Прочие получат 405")
    security_headers: bool = F(True, label="Заголовки безопасности",
                               help="X-Content-Type-Options, X-Frame-Options, Referrer-Policy и др.")
    x_frame_options: Literal["SAMEORIGIN", "DENY", "off"] = F("SAMEORIGIN", label="X-Frame-Options",
                                                              show={"security_headers": [True]})
    referrer_policy: Literal["strict-origin-when-cross-origin", "no-referrer", "same-origin",
                             "origin", "no-referrer-when-downgrade", "off"] = F(
        "strict-origin-when-cross-origin", label="Referrer-Policy", show={"security_headers": [True]})
    permissions_policy: str = F("", label="Permissions-Policy", show={"security_headers": [True]}, adv=True,
                                ph="camera=(), microphone=(), geolocation=()")
    csp: str = F("", label="Content-Security-Policy", show={"security_headers": [True]}, adv=True,
                 ph="default-src 'self'", help="Пусто — не добавлять. Сначала тестируйте в Report-Only")
    csp_report_only: bool = F(False, label="CSP только отчёт (Report-Only)", show={"security_headers": [True]},
                              adv=True)

    @field_validator("allow", "deny", "geo_exceptions")
    @classmethod
    def _ips(cls, v): return [V.cidr(x) for x in v if x.strip()]

    @field_validator("geo_countries")
    @classmethod
    def _cc(cls, v):
        from .services.geoblock import COUNTRY_SET
        out = []
        for x in v:
            x = x.strip().upper()
            if not x:
                continue
            if x not in COUNTRY_SET:
                raise V.ValidationError(f"«{x}» — неизвестный код страны (ISO 3166-1, например RU, DE, US)")
            if x not in out:
                out.append(x)
        return out

    @model_validator(mode="after")
    def _geo(self):
        if self.geo_mode != "off" and not self.geo_countries:
            raise V.ValidationError("Доступ по странам: выберите хотя бы одну страну или отключите ограничение")
        if any(x == "all" for x in self.geo_exceptions):
            raise V.ValidationError("Исключения по странам: укажите конкретные адреса или подсети, а не all")
        return self

    @field_validator("rate")
    @classmethod
    def _rate(cls, v): return V.rate(v)

    @field_validator("bad_bots")
    @classmethod
    def _bb(cls, v):
        out = []
        for x in v:
            x = x.strip()
            if not x:
                continue
            if any(c in x for c in ";{}\"'\n"):
                raise V.ValidationError(f"«{x}»: недопустимые символы")
            out.append(x)
        return out

    @field_validator("permissions_policy", "csp", "basic_auth_realm")
    @classmethod
    def _nc(cls, v): return V.no_ctrl(v)


class PerformanceSettings(Model):
    gzip: Literal["inherit", "on", "off"] = F("inherit", label="Сжатие gzip", directive="gzip",
                                              labels={"inherit": "Как в глобальных настройках", "on": "Включено",
                                                      "off": "Выключено"})
    client_max_body_size: str = F("", label="Макс. размер тела запроса", ph="100m",
                                  directive="client_max_body_size",
                                  help="Пусто — глобальное значение. 0 — без ограничения",
                                  rec="Под размер загружаемых файлов; ошибка 413 — признак слишком малого значения.")
    limit_rate: str = F("", label="Ограничение скорости отдачи на соединение", ph="1m", adv=True,
                        directive="limit_rate", help="Байт/с, например 500k или 1m. Пусто — без ограничения")
    limit_rate_after: str = F("", label="Ограничивать после", ph="10m", adv=True, directive="limit_rate_after")
    keepalive_timeout: str = F("", label="keepalive_timeout клиентов", ph="65s", adv=True,
                               directive="keepalive_timeout")
    access_log: bool = F(True, label="Журнал запросов и статистика",
                         help="Выключение отключит статистику этого сайта", directive="access_log")
    log_static: bool = F(True, label="Учитывать статику (css/js/картинки)", adv=True,
                         help="Выключите, чтобы статика не засоряла журнал и топы")
    static_expires: str = F("", label="Кэш статики в браузере (expires)", ph="7d", adv=True,
                            directive="expires", help="Для css/js/картинок/шрифтов. Пусто — не задавать")

    @field_validator("client_max_body_size", "limit_rate", "limit_rate_after")
    @classmethod
    def _s(cls, v): return V.size(v)

    @field_validator("keepalive_timeout", "static_expires")
    @classmethod
    def _d(cls, v): return V.duration(v)


class MaintenanceSettings(Model):
    enabled: bool = F(False, label="Режим обслуживания",
                      help="Все посетители (кроме белого списка) увидят страницу «Ведутся работы» с кодом 503",
                      doc="Удобно на время обновления приложения: включили → применили → обновили бэкенд → "
                          "выключили. Код 503 и заголовок Retry-After сообщают поисковикам, что это временно.")
    allow: List[str] = F(factory=list, label="IP, которым сайт доступен", ui="lines", show={"enabled": [True]},
                         ph="203.0.113.10")
    title: str = F("Ведутся технические работы", label="Заголовок страницы", show={"enabled": [True]})
    message: str = F("Сайт временно недоступен. Пожалуйста, зайдите позже.", label="Текст", ui="textarea",
                     show={"enabled": [True]})
    retry_after: int = F(3600, label="Retry-After", unit="с", ge=0, le=604800, show={"enabled": [True]})

    @field_validator("allow")
    @classmethod
    def _ips(cls, v): return [V.cidr(x) for x in v if x.strip()]


class ErrorPagesSettings(Model):
    enabled: bool = F(True, label="Собственные страницы ошибок",
                      help="Аккуратные страницы для 502/503/504 вместо стандартных страниц nginx",
                      directive="error_page")
    codes: List[Literal[400, 401, 403, 404, 405, 429, 500, 502, 503, 504]] = F(
        factory=lambda: [502, 503, 504], label="Коды", ui="multiselect", show={"enabled": [True]},
        doc="Для кодов, которые отдаёт само приложение (404, 500), страницы панели будут показаны только "
            "при включённом «Перехватывать ошибки бэкенда».")


class RedirectSettings(Model):
    url: str = F("https://example.com", label="Куда перенаправлять", ph="https://new.example.com",
                 help="Целевой адрес. Можно $scheme://$host для смены только пути")
    code: Literal[301, 302, 307, 308] = F(301, label="Код", labels={"301": "301 — постоянный",
                                                                    "302": "302 — временный",
                                                                    "307": "307 — временный, метод сохраняется",
                                                                    "308": "308 — постоянный, метод сохраняется"})
    preserve_path: bool = F(True, label="Сохранять путь и параметры",
                            help="/page?x=1 → https://target/page?x=1")

    @field_validator("url")
    @classmethod
    def _u(cls, v): return V.url(v)


class StaticSettings(Model):
    root: str = F("/var/www/html", label="Корневой каталог", directive="root", ph="/var/www/site")
    index: str = F("index.html index.htm", label="Индексные файлы", directive="index")
    spa: bool = F(False, label="Режим SPA (try_files → /index.html)", directive="try_files",
                  help="Для React/Vue/Angular-приложений с клиентской маршрутизацией")
    autoindex: bool = F(False, label="Листинг каталогов", directive="autoindex")
    expires: str = F("", label="Кэш в браузере", ph="1h", directive="expires")

    @field_validator("root")
    @classmethod
    def _r(cls, v):
        if not v.startswith("/"):
            raise V.ValidationError("Путь должен быть абсолютным")
        return V.safe_token(v, "путь")

    @field_validator("index")
    @classmethod
    def _i(cls, v):
        parts = v.split()
        for p in parts:
            V.safe_token(p, "индексный файл")
        return " ".join(parts)

    @field_validator("expires")
    @classmethod
    def _e(cls, v): return V.duration(v)


class Location(Model):
    id: str = F(factory=lambda: secrets.token_hex(4), label="ID", ui="hidden")
    enabled: bool = F(True, label="Включена")
    path: str = F("/api/", label="Путь", ph="/api/ или \\.php$",
                  help="Префикс URL или регулярное выражение (в зависимости от типа сопоставления)")
    match: Literal["prefix", "exact", "prefix_priority", "regex", "regex_ci"] = F(
        "prefix", label="Тип сопоставления", directive="location [=|^~|~|~*]",
        labels={"prefix": "Префикс (/path)", "exact": "Точное совпадение (= /path)",
                "prefix_priority": "Приоритетный префикс (^~ /path)", "regex": "Регулярное выражение (~)",
                "regex_ci": "Регулярное без учёта регистра (~*)"},
        doc="Порядок выбора nginx: точное совпадение → самый длинный префикс; если это ^~ — он; иначе "
            "регулярные выражения по порядку; если ни одно не подошло — самый длинный префикс.")
    action: Literal["proxy", "redirect", "return", "static", "deny"] = F(
        "proxy", label="Действие",
        labels={"proxy": "Проксировать", "redirect": "Перенаправить", "return": "Вернуть ответ",
                "static": "Отдать файлы с диска", "deny": "Запретить (403)"})
    use_site_backends: bool = F(True, label="Использовать бэкенды сайта", show={"action": ["proxy"]},
                                help="Выключите, чтобы направить эту локацию на другие серверы")
    backends: List[Backend] = F(factory=list, label="Бэкенды локации", ui="table",
                                show={"action": ["proxy"], "use_site_backends": [False]})
    backend_scheme: Literal["http", "https"] = F("http", label="Протокол бэкенда",
                                                 show={"action": ["proxy"], "use_site_backends": [False]})
    balancing: Literal["round_robin", "least_conn", "ip_hash", "random"] = F(
        "round_robin", label="Балансировка", show={"action": ["proxy"], "use_site_backends": [False]},
        labels=BALANCING_LABELS)
    proxy_path: str = F("", label="Заменить путь на", show={"action": ["proxy"]}, ph="/",
                        help="Например: локация /api/ + замена «/» → /api/users уходит на бэкенд как /users",
                        directive="proxy_pass http://upstream/<путь>")
    websocket: Optional[bool] = F(None, label="WebSocket", show={"action": ["proxy"]}, ui="tristate",
                                  help="Пусто — как у сайта")
    read_timeout: str = F("", label="Таймаут чтения", show={"action": ["proxy"]}, ph="как у сайта",
                          directive="proxy_read_timeout")
    buffering: Optional[bool] = F(None, label="Буферизация ответа", show={"action": ["proxy"]}, ui="tristate",
                                  help="Пусто — как у сайта. Выключите для SSE/стриминга")
    cache: Literal["inherit", "on", "off"] = F("inherit", label="Кэш", show={"action": ["proxy"]},
                                               labels={"inherit": "Как у сайта", "on": "Включить",
                                                       "off": "Выключить"})
    cache_valid: str = F("", label="Время жизни кэша", show={"action": ["proxy"], "cache": ["on"]}, ph="200 5m")
    redirect_url: str = F("", label="URL перенаправления", show={"action": ["redirect"]}, ph="https://example.com/new")
    redirect_code: Literal[301, 302, 307, 308] = F(301, label="Код", show={"action": ["redirect"]})
    return_code: int = F(200, label="Код ответа", show={"action": ["return"]}, ge=100, le=599)
    return_body: str = F("", label="Тело ответа", show={"action": ["return"]}, ph="OK")
    return_type: str = F("text/plain", label="Content-Type", show={"action": ["return"]})
    static_root: str = F("", label="Каталог", show={"action": ["static"]}, ph="/var/www/static",
                         help="Файлы ищутся как <каталог><путь запроса без префикса>")
    static_expires: str = F("", label="Кэш в браузере", show={"action": ["static"]}, ph="30d")
    rate_limit: Literal["inherit", "off", "custom"] = F("inherit", label="Ограничение частоты",
                                                        labels={"inherit": "Как у сайта", "off": "Выключить",
                                                                "custom": "Своё"})
    rate: str = F("5r/m", label="Скорость", show={"rate_limit": ["custom"]})
    burst: int = F(5, label="Burst", show={"rate_limit": ["custom"]}, ge=0, le=100000)
    allow: List[str] = F(factory=list, label="Доступ только с IP", ui="lines", adv=True,
                         help="Если задано — остальным 403 (например, /admin только из офиса)")
    basic_auth: Literal["inherit", "off", "on"] = F("inherit", label="Basic Auth", adv=True,
                                                    labels={"inherit": "Как у сайта", "off": "Выключить",
                                                            "on": "Включить (пользователи сайта)"})
    client_max_body_size: str = F("", label="Макс. тело запроса", adv=True, ph="1g")
    headers: List[Header] = F(factory=list, label="Доп. заголовки ответа", ui="table", adv=True)
    proxy_headers: List[Header] = F(factory=list, label="Доп. заголовки к бэкенду", ui="table", adv=True,
                                    show={"action": ["proxy"]})
    custom: str = F("", label="Свои директивы", ui="code", adv=True,
                    help="Вставляются внутрь location как есть. Проверяются через nginx -t")

    @model_validator(mode="after")
    def _check(self):
        self.path = V.location_path(self.path, self.match)
        if self.action == "proxy" and not self.use_site_backends and not self.backends:
            raise V.ValidationError(f"Локация {self.path}: добавьте хотя бы один бэкенд")
        if self.proxy_path:
            if self.match in ("regex", "regex_ci"):
                raise V.ValidationError(f"Локация {self.path}: замена пути невозможна для регулярных выражений")
            V.safe_token(self.proxy_path, "замена пути")
            if not self.proxy_path.startswith("/"):
                raise V.ValidationError("Замена пути должна начинаться с /")
        if self.action == "redirect":
            self.redirect_url = V.url(self.redirect_url)
        if self.action == "static":
            if not self.static_root.startswith("/"):
                raise V.ValidationError(f"Локация {self.path}: укажите абсолютный путь каталога")
            V.safe_token(self.static_root, "каталог")
        if self.rate_limit == "custom":
            V.rate(self.rate)
        self.allow = [V.cidr(x) for x in self.allow if x.strip()]
        self.read_timeout = V.duration(self.read_timeout)
        self.static_expires = V.duration(self.static_expires)
        self.client_max_body_size = V.size(self.client_max_body_size)
        if "\r" in self.return_body or "\0" in self.return_body:
            raise V.ValidationError("Недопустимые символы в теле ответа")
        V.safe_token(self.return_type, "Content-Type") if self.return_type else None
        if self.cache_valid:
            CacheSettings(valid=[self.cache_valid])
        return self


SITE_TABS = [
    ("main", "Основное"), ("backends", "Бэкенды"), ("ssl", "SSL / HTTPS"), ("locations", "Локации"),
    ("proxy", "Проксирование"), ("cache", "Кэш"), ("security", "Безопасность"),
    ("performance", "Производительность"), ("errors", "Ошибки и обслуживание"), ("advanced", "Дополнительно"),
]


class Site(Model):
    name: str = F("", label="Название", tab="main", ph="Интернет-магазин",
                  help="Отображается в панели и статистике")
    enabled: bool = F(True, label="Включён", tab="main", help="Выключенный сайт не попадает в конфигурацию nginx")
    type: Literal["proxy", "redirect", "static"] = F(
        "proxy", label="Тип", tab="main",
        labels={"proxy": "Обратный прокси (reverse proxy)", "redirect": "Перенаправление на другой адрес",
                "static": "Статический сайт (файлы с диска)"})
    domains: List[str] = F(factory=list, label="Домены", tab="main", ui="lines", directive="server_name",
                           ph="example.com\nwww.example.com",
                           help="По одному на строку. Поддерживаются *.example.com и регулярные ~^(.+)\\.example\\.com$",
                           doc="Первый домен считается основным (используется для Host в проверках и "
                               "канонического перенаправления). Кириллические домены (IDN) автоматически "
                               "переводятся в punycode.")
    canonical_redirect: bool = F(False, label="Перенаправлять на основной домен", tab="main",
                                 help="Запросы ко всем остальным доменам → 301 на первый в списке",
                                 rec="Включите, если в списке есть и example.com, и www.example.com.")
    listen_ip: str = F("", label="IP для прослушивания", tab="main", adv=True, ui="listenip",
                       help="Пусто — все адреса сервера. Укажите внешний IP, если их несколько",
                       directive="listen <ip>:<port>")
    http_port: int = F(80, label="HTTP-порт", tab="main", ge=1, le=65535, adv=True)
    https_port: int = F(443, label="HTTPS-порт", tab="main", ge=1, le=65535, adv=True)
    default_server: bool = F(False, label="Сервер по умолчанию", tab="main", adv=True, directive="default_server",
                             help="Обрабатывать запросы с неизвестным Host этим сайтом")
    tags: List[str] = F(factory=list, label="Метки", tab="main", ui="tags", help="Для группировки и фильтрации")
    notes: str = F("", label="Заметки", tab="main", ui="textarea")

    backends: List[Backend] = F(factory=list, label="Серверы бэкенда", tab="backends", ui="table",
                                show={"type": ["proxy"]}, directive="upstream { server ... }")
    backend_scheme: Literal["http", "https"] = F("http", label="Протокол бэкенда", tab="backends",
                                                 show={"type": ["proxy"]},
                                                 help="https — если бэкенд сам принимает только TLS")
    balancing: Literal["round_robin", "least_conn", "ip_hash", "hash", "random", "random_two"] = F(
        "round_robin", label="Метод балансировки", tab="backends", show={"type": ["proxy"]}, labels=BALANCING_LABELS,
        doc="round_robin — равномерно с учётом весов; least_conn — лучше при запросах разной длительности; "
            "ip_hash/hash — «липкие сессии», когда приложение хранит сессии в памяти; random_two — хорошо при "
            "нескольких балансировщиках перед одной группой.",
        rec="least_conn для API и приложений; ip_hash, если сессии не вынесены в общее хранилище.")
    hash_key: str = F("$request_uri", label="Ключ hash", tab="backends", show={"balancing": ["hash"]},
                      ph="$request_uri или $cookie_sessionid")
    hash_consistent: bool = F(True, label="Консистентное хеширование (ketama)", tab="backends",
                              show={"balancing": ["hash"]},
                              help="При изменении состава группы перераспределяется минимум ключей")
    keepalive: int = F(32, label="Keepalive-соединений к бэкенду", tab="backends", show={"type": ["proxy"]},
                       ge=0, le=10000, directive="keepalive",
                       doc="Число простаивающих соединений, которые каждый воркер держит открытыми. "
                           "Сильно снижает задержку и нагрузку (нет TCP/TLS-рукопожатия на каждый запрос).",
                       rec="16–64; 0 — выключить (если бэкенд некорректно работает с keepalive).")
    keepalive_timeout: str = F("60s", label="Keepalive timeout", tab="backends", show={"type": ["proxy"]},
                               adv=True, directive="keepalive_timeout (upstream)")
    keepalive_requests: int = F(1000, label="Keepalive requests", tab="backends", show={"type": ["proxy"]},
                                adv=True, ge=1, le=1000000, directive="keepalive_requests (upstream)")
    health: HealthCheck = F(factory=HealthCheck, label="Проверка доступности", tab="backends",
                            show={"type": ["proxy"]})

    ssl: SSLSettings = F(factory=SSLSettings, label="HTTPS", tab="ssl")
    locations: List[Location] = F(factory=list, label="Локации", tab="locations", ui="locations",
                                  doc="Позволяют направлять разные пути на разные бэкенды, отдавать статику, "
                                      "ставить отдельные лимиты и доступ. Локация «/» переопределяет основную.")
    proxy: ProxySettings = F(factory=ProxySettings, label="Проксирование", tab="proxy", show={"type": ["proxy"]})
    headers: List[Header] = F(factory=list, label="Доп. заголовки ответа", tab="proxy", ui="table",
                              directive="add_header")
    proxy_headers: List[Header] = F(factory=list, label="Доп. заголовки к бэкенду", tab="proxy", ui="table",
                                    show={"type": ["proxy"]}, directive="proxy_set_header")
    cache: CacheSettings = F(factory=CacheSettings, label="Кэширование", tab="cache", show={"type": ["proxy"]})
    security: SecuritySettings = F(factory=SecuritySettings, label="Безопасность", tab="security")
    performance: PerformanceSettings = F(factory=PerformanceSettings, label="Производительность", tab="performance")
    error_pages: ErrorPagesSettings = F(factory=ErrorPagesSettings, label="Страницы ошибок", tab="errors")
    maintenance: MaintenanceSettings = F(factory=MaintenanceSettings, label="Обслуживание", tab="errors")
    redirect: RedirectSettings = F(factory=RedirectSettings, label="Перенаправление", tab="main",
                                   show={"type": ["redirect"]})
    static: StaticSettings = F(factory=StaticSettings, label="Статика", tab="main", show={"type": ["static"]})
    custom_server: str = F("", label="Свои директивы в server { }", tab="advanced", ui="code",
                           help="Вставляются в HTTPS-блок server (или HTTP, если HTTPS выключен)",
                           doc="Для возможностей, которых нет в форме. Конфигурация всегда проверяется "
                               "nginx -t перед применением — ошибка не сломает работающий nginx.")
    custom_location: str = F("", label="Свои директивы в location / { }", tab="advanced", ui="code")
    custom_http: str = F("", label="Свои директивы на уровне http (map, geo...)", tab="advanced", ui="code", adv=True)

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        v = v.strip()
        if not v:
            raise V.ValidationError("Укажите название")
        return V.no_ctrl(v)[:100]

    @field_validator("domains")
    @classmethod
    def _d(cls, v): return _domains(v)

    @field_validator("listen_ip")
    @classmethod
    def _l(cls, v): return V.listen_ip(v)

    @field_validator("hash_key")
    @classmethod
    def _hk(cls, v): return V.safe_token(v, "ключ hash")

    @field_validator("keepalive_timeout")
    @classmethod
    def _kt(cls, v): return V.duration(v, allow_empty=False)

    @field_validator("tags")
    @classmethod
    def _t(cls, v): return [V.no_ctrl(t.strip())[:40] for t in v if t.strip()]

    @model_validator(mode="after")
    def _check(self):
        if not self.domains:
            raise V.ValidationError("Укажите хотя бы один домен (или «_» для любого)")
        if self.http_port == self.https_port:
            raise V.ValidationError("HTTP и HTTPS порты должны различаться")
        root_override = any(loc.enabled and loc.path == "/" and loc.match in ("prefix", "prefix_priority")
                            for loc in self.locations)
        if self.type == "proxy" and not self.backends and not root_override:
            raise V.ValidationError("Добавьте хотя бы один сервер бэкенда")
        if self.balancing in ("ip_hash", "hash", "random", "random_two") and any(b.backup for b in self.backends):
            raise V.ValidationError("Резервные (backup) серверы несовместимы с методами hash/ip_hash/random")
        seen = set()
        for loc in self.locations:
            k = (loc.match if loc.match != "prefix_priority" else "prefix", loc.path)
            if k in seen:
                raise V.ValidationError(f"Дублируется локация {loc.path}")
            seen.add(k)
        if self.ssl.enabled and not self.ssl.certificate_id:
            raise V.ValidationError("Для HTTPS выберите сертификат")
        if self.type == "proxy" and self.backends and all(b.down for b in self.backends):
            raise V.ValidationError("Все серверы бэкенда выключены (down)")
        return self

    @property
    def main_domain(self) -> str:
        for d in self.domains:
            if not d.startswith(("~", "*", ".")) and d != "_":
                return d
        return self.domains[0] if self.domains else "localhost"


# =============================================================================
#  TCP/UDP-потоки
# =============================================================================
class Stream(Model):
    name: str = F("", label="Название", ph="PostgreSQL")
    enabled: bool = F(True, label="Включён")
    protocol: Literal["tcp", "udp", "both"] = F("tcp", label="Протокол",
                                                labels={"tcp": "TCP", "udp": "UDP", "both": "TCP + UDP"})
    listen_port: int = F(5432, label="Внешний порт", ge=1, le=65535, directive="listen")
    listen_ip: str = F("", label="IP для прослушивания", adv=True)
    ipv6: bool = F(True, label="Слушать IPv6", adv=True)
    backends: List[Backend] = F(factory=list, label="Серверы", ui="table")
    balancing: Literal["round_robin", "least_conn", "hash", "random"] = F(
        "round_robin", label="Балансировка", labels=BALANCING_LABELS)
    hash_key: str = F("$remote_addr", label="Ключ hash", show={"balancing": ["hash"]})
    connect_timeout: str = F("5s", label="Таймаут подключения", directive="proxy_connect_timeout")
    timeout: str = F("10m", label="Таймаут простоя", directive="proxy_timeout",
                     help="Соединение закрывается, если данных нет дольше этого времени",
                     rec="Для БД и SSH — 1h и более; для DNS (UDP) — 10s.")
    proxy_protocol: bool = F(False, label="Отправлять PROXY protocol бэкенду", adv=True,
                             directive="proxy_protocol",
                             help="Бэкенд узнает реальный IP клиента (бэкенд должен поддерживать PROXY protocol)")
    udp_responses: int = F(0, label="Ожидаемых UDP-ответов", adv=True, ge=0, le=100,
                           show={"protocol": ["udp", "both"]}, directive="proxy_responses",
                           help="0 — не ограничивать. Для DNS — 1")
    allow: List[str] = F(factory=list, label="Белый список IP", ui="lines",
                         help="Если задан — остальным доступ закрыт")
    deny: List[str] = F(factory=list, label="Чёрный список IP", ui="lines")
    conn_limit: int = F(0, label="Макс. соединений с IP", ge=0, le=100000, adv=True)
    health_check: bool = F(True, label="Проверять доступность (TCP)")
    notes: str = F("", label="Заметки", ui="textarea")

    @field_validator("listen_ip")
    @classmethod
    def _l(cls, v): return V.listen_ip(v)

    @field_validator("allow", "deny")
    @classmethod
    def _ips(cls, v): return [V.cidr(x) for x in v if x.strip()]

    @field_validator("connect_timeout", "timeout")
    @classmethod
    def _d(cls, v): return V.duration(v, allow_empty=False)

    @field_validator("hash_key")
    @classmethod
    def _hk(cls, v): return V.safe_token(v, "ключ hash")

    @model_validator(mode="after")
    def _check(self):
        if not self.name.strip():
            raise V.ValidationError("Укажите название")
        if not self.backends:
            raise V.ValidationError("Добавьте хотя бы один сервер")
        for b in self.backends:
            if b.address.startswith("unix:") and self.protocol != "tcp":
                raise V.ValidationError("Unix-сокет возможен только для TCP")
            if not b.address.startswith("unix:") and not b.port:
                raise V.ValidationError(f"Укажите порт для {b.address}")
        return self


# =============================================================================
#  Глобальные настройки nginx
# =============================================================================
class CacheZone(Model):
    name: str = F("default", label="Имя", help="Латиница, цифры, _")
    max_size: str = F("1g", label="Макс. размер на диске")
    keys_zone_size: str = F("10m", label="Память под ключи", help="1 МБ ≈ 8000 ключей")
    inactive: str = F("7d", label="Удалять неиспользуемое через")
    levels: Literal["1:2", "1", "2", "1:1:2", "2:2"] = F("1:2", label="Уровни каталогов", adv=True)

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        if not V.ZONE_RE.match(v):
            raise V.ValidationError("Имя зоны: латиница в нижнем регистре, цифры, _")
        return v

    @field_validator("max_size", "keys_zone_size")
    @classmethod
    def _s(cls, v): return V.size(v, allow_empty=False)

    @field_validator("inactive")
    @classmethod
    def _i(cls, v): return V.duration(v, allow_empty=False)


CLOUDFLARE_IPS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]

TLS_PRESETS = {
    "modern": ("TLSv1.3", ""),
    "intermediate": ("TLSv1.2 TLSv1.3",
                     "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                     "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                     "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"),
    "old": ("TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:"
            "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:"
            "AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA"),
}

GLOBAL_TABS = [
    ("workers", "Процессы"), ("http", "HTTP и соединения"), ("buffers", "Буферы и таймауты"),
    ("gzip", "Сжатие"), ("ssl", "SSL/TLS"), ("proxy", "Прокси по умолчанию"), ("realip", "Реальный IP клиента"),
    ("default", "Сервер по умолчанию"), ("cache", "Зоны кэша"), ("logs", "Журналы"), ("advanced", "Дополнительно"),
]


class GlobalSettings(Model):
    user: str = F("", label="Пользователь воркеров", tab="workers", directive="user", ph="www-data",
                  help="Пусто — определить автоматически (www-data / nginx)")
    worker_processes: str = F("auto", label="worker_processes", tab="workers", directive="worker_processes",
                              help="auto — по числу ядер CPU", rec="auto")
    worker_connections: int = F(4096, label="worker_connections", tab="workers", ge=256, le=1048576,
                                directive="worker_connections",
                                doc="Максимум соединений на воркер, включая соединения к бэкендам. При "
                                    "проксировании каждый клиент занимает ~2 соединения. Ёмкость сервера ≈ "
                                    "worker_processes × worker_connections / 2.",
                                rec="4096–16384. Ошибка «worker_connections are not enough» — повод увеличить.")
    worker_rlimit_nofile: int = F(65535, label="worker_rlimit_nofile", tab="workers", ge=1024, le=4194304,
                                  directive="worker_rlimit_nofile",
                                  help="Лимит открытых файлов воркера. Должен быть ≥ 2 × worker_connections")
    multi_accept: bool = F(True, label="multi_accept", tab="workers", directive="multi_accept",
                           help="Принимать сразу все новые соединения")
    ipv6: Literal["auto", "on", "off"] = F("auto", label="IPv6", tab="workers",
                                           labels={"auto": "Автоматически (если есть в системе)", "on": "Включить",
                                                   "off": "Выключить"},
                                           help="Добавлять listen [::]:порт")
    sendfile: bool = F(True, label="sendfile", tab="http", directive="sendfile")
    tcp_nopush: bool = F(True, label="tcp_nopush", tab="http", directive="tcp_nopush")
    tcp_nodelay: bool = F(True, label="tcp_nodelay", tab="http", directive="tcp_nodelay")
    keepalive_timeout: str = F("65s", label="keepalive_timeout", tab="http", directive="keepalive_timeout",
                               help="Сколько держать простаивающее соединение с клиентом", rec="30s–75s")
    keepalive_requests: int = F(1000, label="keepalive_requests", tab="http", ge=1, le=1000000,
                                directive="keepalive_requests")
    server_tokens: bool = F(False, label="Показывать версию nginx", tab="http", directive="server_tokens",
                            rec="Выключено — не раскрывать версию атакующим.")
    server_names_hash_bucket_size: int = F(128, label="server_names_hash_bucket_size", tab="http", adv=True,
                                           ge=32, le=1024, directive="server_names_hash_bucket_size",
                                           help="Увеличьте при ошибке «could not build server_names_hash»")
    server_names_hash_max_size: int = F(1024, label="server_names_hash_max_size", tab="http", adv=True,
                                        ge=512, le=65536, directive="server_names_hash_max_size")
    types_hash_max_size: int = F(2048, label="types_hash_max_size", tab="http", adv=True, ge=1024, le=65536,
                                 directive="types_hash_max_size")
    http2_global: bool = F(True, label="Разрешить HTTP/2", tab="http", help="Глобальный выключатель HTTP/2")
    proxy_protocol: bool = F(False, label="Принимать PROXY protocol на HTTP-портах", tab="http", adv=True,
                             directive="listen ... proxy_protocol",
                             doc="Включайте, только если перед nginx стоит балансировщик (HAProxy, AWS NLB), "
                                 "отправляющий PROXY protocol. Иначе все запросы будут отклоняться.")
    client_max_body_size: str = F("50m", label="client_max_body_size", tab="buffers",
                                  directive="client_max_body_size", rec="10m–100m; 0 — без ограничения")
    client_body_buffer_size: str = F("128k", label="client_body_buffer_size", tab="buffers",
                                     directive="client_body_buffer_size")
    client_header_buffer_size: str = F("1k", label="client_header_buffer_size", tab="buffers", adv=True,
                                       directive="client_header_buffer_size")
    large_client_header_buffers: str = F("4 16k", label="large_client_header_buffers", tab="buffers",
                                         directive="large_client_header_buffers",
                                         help="Увеличьте при ошибке 400 «Request Header Or Cookie Too Large»")
    client_body_timeout: str = F("60s", label="client_body_timeout", tab="buffers", directive="client_body_timeout")
    client_header_timeout: str = F("60s", label="client_header_timeout", tab="buffers",
                                   directive="client_header_timeout",
                                   rec="10s–20s для защиты от медленных атак (slowloris).")
    send_timeout: str = F("60s", label="send_timeout", tab="buffers", directive="send_timeout")
    reset_timedout_connection: bool = F(True, label="reset_timedout_connection", tab="buffers", adv=True,
                                        directive="reset_timedout_connection")
    open_file_cache: bool = F(True, label="open_file_cache", tab="buffers", adv=True, directive="open_file_cache",
                              help="Кэш дескрипторов файлов (для статики)")
    gzip: bool = F(True, label="Включить gzip", tab="gzip", directive="gzip",
                   doc="Сжимает текстовые ответы (HTML, CSS, JS, JSON) в 3–10 раз. Изображения и видео не "
                       "сжимаются — они уже сжаты.")
    gzip_level: int = F(5, label="Уровень сжатия", tab="gzip", ge=1, le=9, directive="gzip_comp_level",
                        rec="4–6: дальше рост CPU не окупается.", show={"gzip": [True]})
    gzip_min_length: int = F(1024, label="Мин. размер ответа", tab="gzip", ge=0, le=10485760, unit="байт",
                             directive="gzip_min_length", show={"gzip": [True]})
    gzip_proxied: bool = F(True, label="Сжимать ответы бэкенда", tab="gzip", directive="gzip_proxied any",
                           show={"gzip": [True]})
    gzip_types: List[str] = F(factory=lambda: [
        "text/plain", "text/css", "text/xml", "text/javascript", "application/javascript", "application/json",
        "application/xml", "application/rss+xml", "application/atom+xml", "application/xhtml+xml",
        "application/wasm", "image/svg+xml", "font/ttf", "font/otf", "application/vnd.ms-fontobject"],
        label="MIME-типы", tab="gzip", ui="lines", directive="gzip_types", show={"gzip": [True]})
    ssl_preset: Literal["modern", "intermediate", "old", "custom"] = F(
        "intermediate", label="Профиль TLS (Mozilla)", tab="ssl",
        labels={"modern": "Modern — только TLS 1.3", "intermediate": "Intermediate — TLS 1.2/1.3 (рекомендуется)",
                "old": "Old — совместимость со старыми клиентами (небезопасно)", "custom": "Свой"},
        directive="ssl_protocols / ssl_ciphers", rec="Intermediate")
    ssl_protocols: str = F("TLSv1.2 TLSv1.3", label="ssl_protocols", tab="ssl", show={"ssl_preset": ["custom"]})
    ssl_ciphers: str = F("", label="ssl_ciphers", tab="ssl", show={"ssl_preset": ["custom"]}, ui="textarea")
    ssl_prefer_server_ciphers: bool = F(False, label="ssl_prefer_server_ciphers", tab="ssl", adv=True,
                                        directive="ssl_prefer_server_ciphers")
    ssl_session_cache: str = F("50m", label="Размер кэша TLS-сессий", tab="ssl", directive="ssl_session_cache shared",
                               help="1 МБ ≈ 4000 сессий")
    ssl_session_timeout: str = F("1d", label="ssl_session_timeout", tab="ssl", directive="ssl_session_timeout")
    ssl_session_tickets: bool = F(False, label="ssl_session_tickets", tab="ssl", adv=True,
                                  directive="ssl_session_tickets", rec="Выключено (forward secrecy)")
    ssl_dhparam: bool = F(False, label="Использовать DH-параметры (ffdhe2048)", tab="ssl", adv=True,
                          directive="ssl_dhparam", help="Нужно только для DHE-шифров профиля intermediate/old")
    resolver: List[str] = F(factory=list, label="DNS-резолверы", tab="ssl", ui="lines", directive="resolver",
                            ph="1.1.1.1\n8.8.8.8",
                            help="Для OCSP stapling и бэкендов, заданных именами. Пусто — не задавать")
    resolver_valid: str = F("300s", label="Кэш DNS", tab="ssl", adv=True, directive="resolver ... valid=")
    proxy_connect_timeout: str = F("5s", label="proxy_connect_timeout", tab="proxy")
    proxy_read_timeout: str = F("60s", label="proxy_read_timeout", tab="proxy")
    proxy_send_timeout: str = F("60s", label="proxy_send_timeout", tab="proxy")
    proxy_buffer_size: str = F("16k", label="proxy_buffer_size", tab="proxy",
                               help="16k решает большинство ошибок «upstream sent too big header»")
    proxy_buffers: str = F("16 16k", label="proxy_buffers", tab="proxy")
    proxy_busy_buffers_size: str = F("32k", label="proxy_busy_buffers_size", tab="proxy", adv=True)
    real_ip_enabled: bool = F(False, label="Определять реальный IP за CDN/балансировщиком", tab="realip",
                              directive="set_real_ip_from / real_ip_header",
                              doc="Если перед nginx стоит Cloudflare, другой CDN или балансировщик, $remote_addr "
                                  "будет их адресом. Модуль realip подставляет IP клиента из заголовка — для "
                                  "статистики, ограничений и списков доступа.",
                              rec="Указывайте только реально доверенные адреса: иначе клиент сможет подделать IP.")
    real_ip_header: Literal["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP",
                            "proxy_protocol"] = F("X-Forwarded-For", label="Заголовок", tab="realip",
                                                  show={"real_ip_enabled": [True]})
    real_ip_from: List[str] = F(factory=list, label="Доверенные адреса", tab="realip", ui="lines",
                                show={"real_ip_enabled": [True]}, help="Есть кнопка «Добавить диапазоны Cloudflare»")
    real_ip_recursive: bool = F(True, label="real_ip_recursive", tab="realip", show={"real_ip_enabled": [True]})
    default_action: Literal["close", "404", "page", "redirect"] = F(
        "close", label="Ответ на неизвестный домен", tab="default",
        labels={"close": "Закрыть соединение (444) — рекомендуется", "404": "Ошибка 404",
                "page": "Страница-заглушка", "redirect": "Перенаправить на URL"},
        doc="Что получит запрос с Host, не совпадающим ни с одним сайтом (сканеры, обращения по IP). "
            "Для HTTPS неизвестные имена отклоняются на этапе TLS (ssl_reject_handshake), чтобы не раскрывать "
            "сертификаты.")
    default_redirect: str = F("https://example.com", label="URL", tab="default",
                              show={"default_action": ["redirect"]})
    default_page_title: str = F("Сервер работает", label="Заголовок заглушки", tab="default",
                                show={"default_action": ["page"]})
    cache_zones: List[CacheZone] = F(factory=lambda: [CacheZone()], label="Зоны кэша", tab="cache", ui="table",
                                     directive="proxy_cache_path")
    access_log_buffer: str = F("64k", label="Буфер журнала запросов", tab="logs", directive="access_log ... buffer=",
                               help="Пусто — писать сразу. Буфер снижает нагрузку на диск",
                               rec="32k–64k; статистика при этом запаздывает до flush-интервала.")
    access_log_flush: str = F("1s", label="Интервал сброса буфера", tab="logs", directive="access_log ... flush=")
    error_log_level: Literal["debug", "info", "notice", "warn", "error", "crit"] = F(
        "warn", label="Уровень журнала ошибок", tab="logs", directive="error_log", rec="warn")
    log_ignore_status: bool = F(False, label="Не писать в журнал health-check запросы", tab="logs", adv=True,
                                help="Запросы User-Agent «NginxManager-HealthCheck» не учитываются")
    include_conf_d: bool = F(True, label="Подключать /etc/nginx/conf.d/*.conf", tab="advanced",
                             help="Для совместимости с конфигурациями других пакетов")
    include_sites_enabled: bool = F(False, label="Подключать /etc/nginx/sites-enabled/*", tab="advanced",
                                    help="Осторожно: файл default конфликтует с сервером по умолчанию панели")
    custom_main: str = F("", label="Свои директивы (main)", tab="advanced", ui="code")
    custom_events: str = F("", label="Свои директивы (events)", tab="advanced", ui="code", adv=True)
    custom_http: str = F("", label="Свои директивы (http)", tab="advanced", ui="code")
    custom_stream: str = F("", label="Свои директивы (stream)", tab="advanced", ui="code", adv=True)

    @field_validator("worker_processes")
    @classmethod
    def _wp(cls, v):
        v = v.strip()
        if v != "auto" and not (v.isdigit() and 1 <= int(v) <= 1024):
            raise V.ValidationError("auto или число 1–1024")
        return v

    @field_validator("user")
    @classmethod
    def _u(cls, v): return V.safe_token(v, "пользователь") if v else v

    @field_validator("keepalive_timeout", "client_body_timeout", "client_header_timeout", "send_timeout",
                     "ssl_session_timeout", "resolver_valid", "proxy_connect_timeout", "proxy_read_timeout",
                     "proxy_send_timeout", "access_log_flush")
    @classmethod
    def _dur(cls, v): return V.duration(v)

    @field_validator("client_max_body_size", "client_body_buffer_size", "client_header_buffer_size",
                     "ssl_session_cache", "proxy_buffer_size", "proxy_busy_buffers_size", "access_log_buffer")
    @classmethod
    def _sz(cls, v): return V.size(v)

    @field_validator("large_client_header_buffers", "proxy_buffers")
    @classmethod
    def _nb(cls, v):
        v = " ".join(v.split())
        parts = v.split()
        if len(parts) != 2 or not parts[0].isdigit():
            raise V.ValidationError("Формат: <число> <размер>, например 4 16k")
        V.size(parts[1], allow_empty=False)
        return v

    @field_validator("gzip_types")
    @classmethod
    def _gt(cls, v): return [V.safe_token(x.strip(), "MIME-тип") for x in v if x.strip()]

    @field_validator("ssl_protocols")
    @classmethod
    def _sp(cls, v): return _tls_protocols(v) or "TLSv1.2 TLSv1.3"

    @field_validator("ssl_ciphers")
    @classmethod
    def _sc(cls, v):
        v = "".join(v.split())
        if v and not __import__("re").match(r"^[A-Za-z0-9_:+!@=.\-]+$", v):
            raise V.ValidationError("Недопустимые символы в списке шифров")
        return v

    @field_validator("resolver")
    @classmethod
    def _r(cls, v):
        out = []
        for x in v:
            x = x.strip()
            if not x:
                continue
            host, _, p = x.rpartition(":") if x.count(":") == 1 else (x, "", "")
            V.host_or_ip(host or x)
            out.append(x)
        return out

    @field_validator("real_ip_from")
    @classmethod
    def _rif(cls, v): return [V.cidr(x) for x in v if x.strip()]

    @field_validator("default_redirect")
    @classmethod
    def _dr(cls, v): return V.url(v)

    @field_validator("default_page_title")
    @classmethod
    def _dpt(cls, v): return V.no_ctrl(v)

    @model_validator(mode="after")
    def _check(self):
        names = [z.name for z in self.cache_zones]
        if len(names) != len(set(names)):
            raise V.ValidationError("Имена зон кэша должны быть уникальны")
        if self.worker_rlimit_nofile < self.worker_connections:
            raise V.ValidationError("worker_rlimit_nofile должен быть не меньше worker_connections")
        return self


# =============================================================================
#  Настройки самой панели
# =============================================================================
PANEL_TABS = [("stats", "Статистика и хранение"), ("network", "Сеть и внешний IP"), ("security", "Безопасность панели"),
              ("bans", "Блокировки IP"), ("acme", "Let's Encrypt"), ("monitor", "Мониторинг"),
              ("reports", "Отчёты"), ("backup", "Резервные копии")]


class PanelSettings(Model):
    store_requests: bool = F(True, label="Сохранять журнал запросов в БД", tab="stats",
                             help="Позволяет искать по истории запросов. Выключите на очень нагруженных серверах",
                             rec="Включено; при > 2000 запросов/с — выключите или уменьшите срок хранения.")
    requests_retention_hours: int = F(72, label="Хранить журнал запросов", unit="ч", tab="stats", ge=1, le=8760)
    requests_max_rows: int = F(5_000_000, label="Макс. строк журнала запросов", tab="stats", ge=10000,
                               le=500_000_000)
    requests_sample: int = F(1, label="Сохранять каждый N-й запрос", tab="stats", ge=1, le=1000, adv=True,
                             help="Сэмплирование журнала (агрегированная статистика всегда точная)")
    skip_static_in_log: bool = F(False, label="Не сохранять в журнал статику", tab="stats", adv=True)
    minute_retention_days: int = F(14, label="Хранить поминутную статистику", unit="дн", tab="stats", ge=1, le=365)
    hour_retention_days: int = F(400, label="Хранить почасовую статистику", unit="дн", tab="stats", ge=7, le=3650)
    top_retention_days: int = F(31, label="Хранить почасовые топы", unit="дн", tab="stats", ge=1, le=365)
    top_keep: int = F(100, label="Позиций в каждом топе", tab="stats", ge=10, le=1000, adv=True)
    errors_retention_days: int = F(30, label="Хранить журнал ошибок", unit="дн", tab="stats", ge=1, le=365)
    system_retention_days: int = F(30, label="Хранить системные метрики", unit="дн", tab="stats", ge=1, le=365)
    slow_request_ms: int = F(1000, label="Медленный запрос, если дольше", unit="мс", tab="stats", ge=10, le=600000)
    geoip_enabled: bool = F(True, label="Определять страну по IP", tab="stats",
                            help="Нужна база GeoLite2-Country.mmdb / dbip-country.mmdb и пакет maxminddb")
    geoip_path: str = F("", label="Путь к базе GeoIP", tab="stats", adv=True,
                        ph="/var/lib/nginx-manager/geoip/GeoLite2-Country.mmdb")
    external_ip: str = F("", label="Внешний IP сервера", tab="network", ph="авто",
                         help="Пусто — определить автоматически (интерфейсы + внешний сервис)")
    ip_detect_url: str = F("https://api.ipify.org", label="Сервис определения внешнего IP", tab="network",
                           help="Пусто — не обращаться к внешним сервисам")
    panel_domain: str = F("", label="Домен панели", tab="network", ph="panel.example.com",
                          help="Если задан — nginx будет проксировать этот домен на панель (удобно с HTTPS)")
    panel_certificate_id: Optional[int] = F(None, label="Сертификат для домена панели", tab="network",
                                            ui="certificate")
    panel_allow: List[str] = F(factory=list, label="Доступ к панели только с IP", tab="security", ui="lines",
                               help="Пусто — с любых. Сброс: nmctl allowlist clear",
                               rec="Укажите IP офиса/VPN.")
    session_hours: int = F(12, label="Время жизни сессии", unit="ч", tab="security", ge=1, le=720)
    login_max_attempts: int = F(5, label="Неудачных входов до блокировки", tab="security", ge=3, le=100)
    login_lock_minutes: int = F(15, label="Блокировка на", unit="мин", tab="security", ge=1, le=1440)
    require_2fa_admin: bool = F(False, label="Требовать 2FA для администраторов", tab="security")
    letsencrypt_email: str = F("", label="E-mail для Let's Encrypt", tab="acme",
                               help="Уведомления об истечении и восстановлении аккаунта")
    letsencrypt_staging: bool = F(False, label="Тестовый сервер (staging)", tab="acme",
                                  help="Для отладки: лимиты выше, но сертификаты недоверенные")
    letsencrypt_key_type: Literal["ecdsa", "rsa"] = F("ecdsa", label="Тип ключа", tab="acme")
    renew_days_before: int = F(30, label="Продлевать за", unit="дн", tab="acme", ge=5, le=60)
    auto_restart_nginx: bool = F(True, label="Автоматически запускать упавший nginx", tab="monitor",
                                 help="Сторож проверяет процесс каждые 10 секунд")
    auto_apply_failover: bool = F(True, label="Разрешить автопереключение бэкендов", tab="monitor",
                                  help="Глобальный выключатель для опции «Автоматическое переключение» сайтов")
    diagnostics_interval: int = F(600, label="Фоновая диагностика каждые", unit="с", tab="monitor", ge=60, le=86400)
    metrics_enabled: bool = F(True, label="Метрики Prometheus (/metrics)", tab="monitor",
                              help="Адрес http://сервер:порт-панели/metrics; доступ по API-токену или с IP из списка ниже")
    metrics_allow: List[str] = F(factory=list, label="Читать /metrics без токена с IP", tab="monitor", ui="lines",
                                 show={"metrics_enabled": [True]}, ph="10.0.0.5")
    # ---------------------------------------------------------------- блокировки
    ban_response: Literal["444", "403", "429"] = F(
        "444", label="Ответ заблокированным", tab="bans",
        labels={"444": "444 — закрыть соединение без ответа", "403": "403 Forbidden (страница ошибки)",
                "429": "429 Too Many Requests"},
        help="Изменение вступает в силу после «Применить»")
    autoban_enabled: bool = F(False, label="Автоматическая блокировка", tab="bans",
                              help="Блокировать IP, превысившие пороги ниже. Выключено — такие IP только показываются "
                                   "в разделе «Блокировки → Подозрительные»")
    autoban_window: int = F(300, label="Окно подсчёта", unit="с", tab="bans", ge=30, le=3600)
    autoban_scan: int = F(5, label="Зондирование уязвимостей", unit="запросов", tab="bans", ge=0, le=100000,
                          help="Запросы к /.env, /.git, phpMyAdmin, обход каталогов, SQL-инъекции… 0 — не учитывать")
    autoban_auth: int = F(30, label="Неудачные авторизации (401)", unit="ответов", tab="bans", ge=0, le=100000,
                          help="Подбор пароля Basic Auth или API. 0 — не учитывать")
    autoban_default_host: int = F(30, label="Обращения по IP / к чужим доменам", unit="запросов", tab="bans", ge=0,
                                  le=100000, help="Запросы, попавшие на сервер по умолчанию. 0 — не учитывать")
    autoban_4xx: int = F(300, label="Ответы 4xx", unit="ответов", tab="bans", ge=0, le=1000000,
                         help="Перебор адресов, массовые 404/403/429. 0 — не учитывать")
    autoban_requests: int = F(0, label="Всего запросов с одного IP", unit="запросов", tab="bans", ge=0, le=10000000,
                              help="Грубая защита от флуда. 0 — не учитывать (рекомендуется ограничение частоты сайта)")
    autoban_minutes: int = F(60, label="Срок блокировки", unit="мин", tab="bans", ge=1, le=525600)
    autoban_escalate: bool = F(True, label="Увеличивать срок для повторных нарушителей", tab="bans",
                               help="×4 за каждое повторное нарушение в течение 30 дней, максимум 30 суток")
    autoban_ignore_bots: bool = F(True, label="Не блокировать поисковых ботов за 4xx и частоту", tab="bans",
                                  help="По User-Agent (Googlebot, YandexBot…). За зондирование уязвимостей блокируются все")
    autoban_whitelist: List[str] = F(factory=list, label="Никогда не блокировать", tab="bans", ui="lines",
                                     ph="203.0.113.0/24",
                                     help="Ваши офисы, мониторинг, партнёры. 127.0.0.1 и «Доступ к панели только с IP» "
                                          "не блокируются всегда")
    # ---------------------------------------------------------------- регулярные отчёты
    report_enabled: bool = F(False, label="Отправлять регулярный отчёт", tab="reports",
                             help="Сводка нагрузки, ошибок, проблем по анализу и состояния в выбранные каналы")
    report_period: Literal["day", "week"] = F("day", label="Период", tab="reports",
                                              labels={"day": "Ежедневно (за прошедшие сутки)",
                                                      "week": "Еженедельно (за прошедшие 7 суток)"})
    report_hour: int = F(9, label="Час отправки", tab="reports", ge=0, le=23, help="По времени сервера")
    report_weekday: Literal["0", "1", "2", "3", "4", "5", "6"] = F(
        "0", label="День недели", tab="reports", show={"report_period": ["week"]},
        labels={"0": "Понедельник", "1": "Вторник", "2": "Среда", "3": "Четверг", "4": "Пятница", "5": "Суббота",
                "6": "Воскресенье"})
    report_channels: List[int] = F(factory=list, label="Каналы", tab="reports", ui="channels",
                                   help="Каналы настраиваются в разделе «Оповещения → Каналы уведомлений»")
    insight_thresholds: Dict[str, Dict[str, float]] = F(factory=dict, label="Пороги анализа", ui="hidden",
                                                        help="Свои пороги показателей (раздел «Анализ → Пороги»)")
    insights_muted: List[str] = F(factory=list, label="Скрытые подсказки анализа", ui="hidden",
                                  help="Сценарии, которые не показываются в «Анализе и подсказках»")
    backup_keep: int = F(14, label="Хранить автоматических копий", tab="backup", ge=1, le=365)
    backup_hour: int = F(3, label="Час ежедневного резервного копирования", tab="backup", ge=0, le=23)
    backup_keep_update: int = F(5, label="Хранить копий перед обновлениями", tab="backup", ge=1, le=100,
                                help="Копии базы, кода прежней версии и nginx.conf, которые делает update.sh и "
                                     "nmctl backup. Ручные копии из панели не удаляются")

    @field_validator("panel_allow")
    @classmethod
    def _pa(cls, v): return [V.cidr(x) for x in v if x.strip()]

    @field_validator("external_ip")
    @classmethod
    def _ei(cls, v):
        if v.strip():
            import ipaddress
            ipaddress.ip_address(v.strip())
        return v.strip()

    @field_validator("panel_domain")
    @classmethod
    def _pd(cls, v): return V.domain(v) if v.strip() else ""

    @field_validator("geoip_path")
    @classmethod
    def _gp(cls, v): return V.no_ctrl(v)

    @field_validator("ip_detect_url")
    @classmethod
    def _iu(cls, v): return V.http_url(v)

    @field_validator("metrics_allow", "autoban_whitelist")
    @classmethod
    def _nets(cls, v): return [V.cidr(x) for x in v if x.strip()]


# =============================================================================
#  Оповещения
# =============================================================================
ALERT_METRICS = {
    "nginx_down": ("Nginx не запущен", ""),
    "config_error": ("Ошибка конфигурации nginx (nginx -t)", ""),
    "backend_down": ("Бэкенд недоступен", ""),
    "error_5xx_rate": ("Доля ответов 5xx", "%"),
    "error_4xx_rate": ("Доля ответов 4xx", "%"),
    "latency_p95": ("Время ответа p95", "мс"),
    "latency_avg": ("Среднее время ответа", "мс"),
    "rps_high": ("Запросов в секунду (выше)", "rps"),
    "rps_low": ("Запросов в секунду (ниже — пропал трафик)", "rps"),
    "bandwidth_out": ("Исходящий трафик", "Мбит/с"),
    "active_connections": ("Активных соединений", ""),
    "cert_expiry": ("Сертификат истекает через", "дн"),
    "cpu": ("Загрузка CPU", "%"),
    "memory": ("Использование памяти", "%"),
    "disk": ("Заполнение диска", "%"),
    "error_log_rate": ("Ошибок nginx в минуту", "/мин"),
    "rate_limited": ("Отклонено лимитами (429/503 limit_req)", "/мин"),
    "autobans": ("Автоблокировок IP за окно", "шт."),
    "insights_crit": ("Проблем по встроенному анализу (последние 15 минут)", "шт."),
}


class AlertRule(Model):
    name: str = F("", label="Название")
    enabled: bool = F(True, label="Включено")
    metric: Literal[tuple(ALERT_METRICS.keys())] = F(  # type: ignore[valid-type]
        "error_5xx_rate", label="Метрика", labels={k: v[0] for k, v in ALERT_METRICS.items()})
    site: str = F("*", label="Сайт", ui="site", help="* — все сайты вместе")
    operator: Literal[">", "<"] = F(">", label="Условие")
    threshold: float = F(5.0, label="Порог")
    window: int = F(60, label="Окно усреднения", unit="с", ge=10, le=3600,
                    help="За какой период считается значение")
    duration: int = F(60, label="Держится не менее", unit="с", ge=0, le=86400,
                      help="Защита от ложных срабатываний на кратковременных всплесках")
    min_requests: int = F(20, label="Мин. запросов в окне", ge=0, le=1000000,
                          help="Для долей (%) — не срабатывать при малом трафике")
    severity: Literal["info", "warning", "critical"] = F("warning", label="Важность",
                                                         labels={"info": "Информация", "warning": "Предупреждение",
                                                                 "critical": "Критично"})
    channels: List[int] = F(factory=list, label="Каналы уведомлений", ui="channels")
    repeat_minutes: int = F(60, label="Повторять уведомление каждые", unit="мин", ge=0, le=10080,
                            help="0 — не повторять, пока не восстановится")
    notify_resolved: bool = F(True, label="Сообщать о восстановлении")


class AlertChannel(Model):
    name: str = F("", label="Название")
    type: Literal["telegram", "webhook", "slack", "discord", "email"] = F(
        "telegram", label="Тип", labels={"telegram": "Telegram", "webhook": "Webhook (JSON)",
                                         "slack": "Slack (Incoming Webhook)", "discord": "Discord", "email": "E-mail (SMTP)"})
    enabled: bool = F(True, label="Включён")
    telegram_token: str = F("", label="Токен бота", show={"type": ["telegram"]}, ui="password",
                            help="Получите у @BotFather")
    telegram_chat_id: str = F("", label="Chat ID", show={"type": ["telegram"]},
                              help="ID пользователя/группы. Узнать: @userinfobot или getUpdates")
    telegram_api: str = F("https://api.telegram.org", label="API URL", show={"type": ["telegram"]}, adv=True)
    url: str = F("", label="URL", show={"type": ["webhook", "slack", "discord"]})
    webhook_headers: List[Header] = F(factory=list, label="Заголовки", ui="table", show={"type": ["webhook"]}, adv=True)
    smtp_host: str = F("", label="SMTP-сервер", show={"type": ["email"]})
    smtp_port: int = F(587, label="Порт", show={"type": ["email"]}, ge=1, le=65535)
    smtp_security: Literal["starttls", "ssl", "none"] = F("starttls", label="Шифрование", show={"type": ["email"]})
    smtp_user: str = F("", label="Логин", show={"type": ["email"]})
    smtp_password: str = F("", label="Пароль", ui="password", show={"type": ["email"]})
    email_from: str = F("", label="От кого", show={"type": ["email"]})
    email_to: List[str] = F(factory=list, label="Кому", ui="lines", show={"type": ["email"]})

    @field_validator("telegram_api", "url")
    @classmethod
    def _u(cls, v): return V.http_url(v)

    @model_validator(mode="after")
    def _check(self):
        if not self.name.strip():
            raise V.ValidationError("Укажите название")
        if self.type == "telegram" and (not self.telegram_token or not self.telegram_chat_id):
            raise V.ValidationError("Укажите токен бота и chat id")
        if self.type in ("webhook", "slack", "discord") and not self.url.startswith(("http://", "https://")):
            raise V.ValidationError("Укажите URL (http/https)")
        if self.type == "email" and (not self.smtp_host or not self.email_to or not self.email_from):
            raise V.ValidationError("Укажите SMTP-сервер, отправителя и получателей")
        return self


# =============================================================================
#  Сертификаты
# =============================================================================
class CertificateRequest(Model):
    type: Literal["letsencrypt", "upload", "selfsigned", "path"] = F(
        "letsencrypt", label="Способ",
        labels={"letsencrypt": "Выпустить Let's Encrypt (бесплатно, авто-продление)",
                "upload": "Загрузить свой (PEM)", "selfsigned": "Самоподписанный (для тестов)",
                "path": "Файлы уже на сервере"})
    name: str = F("", label="Название", ph="example.com")
    domains: List[str] = F(factory=list, label="Домены", ui="lines", show={"type": ["letsencrypt", "selfsigned"]},
                           help="Все домены должны указывать на этот сервер (A/AAAA-записи), порт 80 открыт")
    email: str = F("", label="E-mail", show={"type": ["letsencrypt"]}, help="Пусто — из настроек панели")
    staging: bool = F(False, label="Тестовый сервер", show={"type": ["letsencrypt"]})
    key_type: Literal["ecdsa", "rsa"] = F("ecdsa", label="Тип ключа", show={"type": ["letsencrypt", "selfsigned"]})
    cert_pem: str = F("", label="Сертификат + цепочка (PEM)", ui="pemfile", show={"type": ["upload"]})
    key_pem: str = F("", label="Закрытый ключ (PEM)", ui="pemfile", show={"type": ["upload"]})
    cert_path: str = F("", label="Путь к fullchain.pem", show={"type": ["path"]})
    key_path: str = F("", label="Путь к privkey.pem", show={"type": ["path"]})
    days: int = F(825, label="Срок, дней", show={"type": ["selfsigned"]}, ge=1, le=3650)

    @field_validator("domains")
    @classmethod
    def _d(cls, v): return _domains(v)


MODELS = {
    "site": Site, "stream": Stream, "global": GlobalSettings, "panel": PanelSettings,
    "alert_rule": AlertRule, "alert_channel": AlertChannel, "certificate": CertificateRequest,
    "location": Location, "backend": Backend,
}
TABS = {"site": SITE_TABS, "global": GLOBAL_TABS, "panel": PANEL_TABS}


# Подробные описания, рекомендации и примеры для подсказок и документации
def _apply_field_docs() -> None:
    from . import fielddocs
    fielddocs.apply([Site, Backend, HealthCheck, SSLSettings, ProxySettings, CacheSettings, SecuritySettings,
                     PerformanceSettings, MaintenanceSettings, ErrorPagesSettings, RedirectSettings, StaticSettings,
                     Location, Stream, GlobalSettings, CacheZone, Header, BasicAuthUser, PanelSettings, AlertRule,
                     AlertChannel, CertificateRequest])


_apply_field_docs()
