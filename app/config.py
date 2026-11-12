"""Bootstrap-конфигурация сервиса Nginx Manager.

Источники (по возрастанию приоритета):
  1. значения по умолчанию ниже;
  2. файл /etc/nginx-manager/panel.conf (формат KEY=VALUE, как у systemd EnvironmentFile);
  3. переменные окружения с префиксом NM_.

Всё, что меняется из веб-панели (сайты, глобальные настройки nginx, хранение статистики и т.д.),
хранится в базе данных, а не здесь. Здесь только то, что нужно для старта процесса.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Dict

APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
WEB_DIR = ROOT_DIR / "web"
DOCS_DIR = ROOT_DIR / "docs"

try:
    VERSION = (ROOT_DIR / "VERSION").read_text().strip()
except OSError:  # pragma: no cover
    VERSION = "dev"

CONF_FILE = Path(os.environ.get("NM_CONF_FILE", "/etc/nginx-manager/panel.conf"))

DEFAULTS: Dict[str, str] = {
    "BIND_HOST": "0.0.0.0",
    "BIND_PORT": "8088",
    "DATA_DIR": "/var/lib/nginx-manager",
    "SECRET_KEY": "",
    "NGINX_BIN": "",                      # пусто = автопоиск
    "NGINX_CONF": "/etc/nginx/nginx.conf",
    "MANAGED_DIR": "/etc/nginx/nginx-manager",
    "LOG_DIR": "/var/log/nginx",
    "CACHE_DIR": "/var/cache/nginx/nginx-manager",
    "STUB_STATUS_PORT": "8089",
    "LOG_LEVEL": "info",
    "TLS_CERT": "",                       # HTTPS для самой панели (необязательно)
    "TLS_KEY": "",
    "TRUST_PROXY": "127.0.0.1,::1",       # от кого принимать X-Forwarded-For для панели
    "DEV_MODE": "0",
    "DISABLE_COLLECTOR": "0",
}


def _read_conf_file(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k.startswith("NM_"):
                k = k[3:]
            out[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


class Settings:
    """Неизменяемые во время работы параметры процесса."""

    def __init__(self) -> None:
        values = dict(DEFAULTS)
        values.update(_read_conf_file(CONF_FILE))
        for k in list(DEFAULTS):
            env = os.environ.get("NM_" + k)
            if env is not None:
                values[k] = env
        self.raw = values
        self.bind_host = values["BIND_HOST"]
        self.bind_port = int(values["BIND_PORT"])
        self.data_dir = Path(values["DATA_DIR"])
        self.nginx_bin = values["NGINX_BIN"]
        self.nginx_conf = Path(values["NGINX_CONF"])
        self.managed_dir = Path(values["MANAGED_DIR"])
        self.log_dir = Path(values["LOG_DIR"])
        self.cache_dir = Path(values["CACHE_DIR"])
        self.stub_status_port = int(values["STUB_STATUS_PORT"])
        self.log_level = values["LOG_LEVEL"]
        self.tls_cert = values["TLS_CERT"]
        self.tls_key = values["TLS_KEY"]
        self.trust_proxy = [x.strip() for x in values["TRUST_PROXY"].split(",") if x.strip()]
        self.dev_mode = values["DEV_MODE"] in ("1", "true", "yes")
        self.disable_collector = values["DISABLE_COLLECTOR"] in ("1", "true", "yes")
        self.secret_key = values["SECRET_KEY"] or self._load_or_create_secret()

    # --- производные пути -------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.data_dir / "nginx-manager.db"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def certs_dir(self) -> Path:
        return self.data_dir / "certs"

    @property
    def acme_webroot(self) -> Path:
        return self.data_dir / "acme"

    @property
    def geoip_dir(self) -> Path:
        return self.data_dir / "geoip"

    @property
    def access_log(self) -> Path:
        return self.log_dir / "nm-access.log"

    @property
    def error_log(self) -> Path:
        return self.log_dir / "nm-error.log"

    @property
    def stream_log(self) -> Path:
        return self.log_dir / "nm-stream.log"

    @property
    def versions_dir(self) -> Path:
        return self.managed_dir / "versions"

    @property
    def live_dir(self) -> Path:
        return self.managed_dir / "live"

    def _load_or_create_secret(self) -> str:
        p = self.data_dir / ".secret_key"
        try:
            s = p.read_text().strip()
            if s:
                return s
        except OSError:
            pass
        s = secrets.token_urlsafe(48)
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            p.write_text(s)
            os.chmod(p, 0o600)
        except OSError:
            pass
        return s

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.backups_dir, self.certs_dir, self.acme_webroot,
                  self.acme_webroot / ".well-known" / "acme-challenge", self.geoip_dir):
            d.mkdir(parents=True, exist_ok=True)
        os.chmod(self.data_dir, 0o711)  # nginx-воркеру нужен проход к acme/
        os.chmod(self.certs_dir, 0o700)
        for d in (self.acme_webroot, self.acme_webroot / ".well-known",
                  self.acme_webroot / ".well-known" / "acme-challenge"):
            os.chmod(d, 0o755)


settings = Settings()
