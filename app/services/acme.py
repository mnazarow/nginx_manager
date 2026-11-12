"""ACME: центры сертификации, DNS-проверка через плагины certbot и сборка команды certbot.

Команда собирается чистой функцией certbot_command() — её проверяют тесты, а сквозной выпуск на стенде
(tools/acme_e2e.py) проверяет её же против настоящего ACME-сервера (Pebble) и DNS-сервера (BIND).
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import settings
from ..models import DnsAccount, PanelSettings
from ..utils import atomic_write, run, which

CA_DIRECTORIES = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
}
CA_TITLES = {"letsencrypt": "Let's Encrypt", "zerossl": "ZeroSSL", "google": "Google Trust Services",
             "custom": "свой ACME-сервер"}

# authenticator — имя плагина certbot; pkg — пакет Debian/Ubuntu и RHEL (EPEL); ini — строки файла учётных данных
PLUGINS: Dict[str, Dict[str, Any]] = {
    "cloudflare": {"auth": "dns-cloudflare", "pkg": "python3-certbot-dns-cloudflare",
                   "ini": {"dns_cloudflare_api_token": "cf_api_token"}},
    "digitalocean": {"auth": "dns-digitalocean", "pkg": "python3-certbot-dns-digitalocean",
                     "ini": {"dns_digitalocean_token": "do_token"}},
    "linode": {"auth": "dns-linode", "pkg": "python3-certbot-dns-linode", "ini": {"dns_linode_key": "linode_key"}},
    "ovh": {"auth": "dns-ovh", "pkg": "python3-certbot-dns-ovh",
            "ini": {"dns_ovh_endpoint": "ovh_endpoint", "dns_ovh_application_key": "ovh_application_key",
                    "dns_ovh_application_secret": "ovh_application_secret", "dns_ovh_consumer_key": "ovh_consumer_key"}},
    "route53": {"auth": "dns-route53", "pkg": "python3-certbot-dns-route53"},
    "google": {"auth": "dns-google", "pkg": "python3-certbot-dns-google"},
    "rfc2136": {"auth": "dns-rfc2136", "pkg": "python3-certbot-dns-rfc2136",
                "ini": {"dns_rfc2136_server": "rfc_server", "dns_rfc2136_port": "rfc_port",
                        "dns_rfc2136_name": "rfc_key_name", "dns_rfc2136_secret": "rfc_key_secret",
                        "dns_rfc2136_algorithm": "rfc_algorithm"}},
    "hook": {"auth": "manual"},
}


def creds_dir() -> Path:
    return settings.data_dir / "dns-credentials"


def credentials_paths(account_id: int) -> List[Path]:
    d = creds_dir()
    return [d / f"{account_id}.ini", d / f"{account_id}.json", d / f"{account_id}.aws"]


def remove_credentials(account_id: int) -> None:
    for p in credentials_paths(account_id):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def write_credentials(account_id: int, acc: DnsAccount) -> Tuple[List[str], Dict[str, str]]:
    """Записать файл учётных данных (права 600, каталог 700) и вернуть аргументы certbot и переменные окружения.

    Файл остаётся на диске: на него ссылается конфигурация продления certbot (/etc/letsencrypt/renewal),
    поэтому системный таймер certbot тоже может продлить сертификат."""
    p = PLUGINS[acc.provider]
    d = creds_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    auth = p["auth"]
    env: Dict[str, str] = {}
    if acc.provider == "hook":
        args = ["--manual", "--preferred-challenges", "dns", "--manual-auth-hook", acc.hook_auth]
        if acc.hook_cleanup:
            args += ["--manual-cleanup-hook", acc.hook_cleanup]
        return args, env
    args = ["--authenticator", auth]
    if "ini" in p:
        path = d / f"{account_id}.ini"
        lines = [f"# Nginx Manager: учётная запись DNS #{account_id} «{acc.name}» ({acc.provider})"]
        lines += [f"{k} = {getattr(acc, f)}" for k, f in p["ini"].items()]
        atomic_write(path, "\n".join(lines) + "\n", 0o600)
        args += [f"--{auth}-credentials", str(path)]
    elif acc.provider == "google":
        path = d / f"{account_id}.json"
        atomic_write(path, acc.google_json.strip() + "\n", 0o600)
        args += ["--dns-google-credentials", str(path)]
    elif acc.provider == "route53":
        path = d / f"{account_id}.aws"
        atomic_write(path, f"[default]\naws_access_key_id = {acc.aws_access_key_id}\n"
                           f"aws_secret_access_key = {acc.aws_secret_access_key}\n", 0o600)
        env = {"AWS_SHARED_CREDENTIALS_FILE": str(path), "AWS_CONFIG_FILE": str(path)}
    if acc.propagation_seconds:
        args += [f"--{auth}-propagation-seconds", str(acc.propagation_seconds)]
    return args, env


def directory_for(panel: PanelSettings, staging: bool = False) -> str:
    """Адрес каталога ACME по настройкам панели (для новых сертификатов)."""
    if panel.acme_ca == "custom":
        return panel.acme_directory
    if panel.acme_ca == "letsencrypt" and (staging or panel.letsencrypt_staging):
        return CA_DIRECTORIES["letsencrypt-staging"]
    return CA_DIRECTORIES[panel.acme_ca]


def ca_title(server: str) -> str:
    """Название центра для интерфейса: известные — по имени, свой — по адресу сервера."""
    for k, url in CA_DIRECTORIES.items():
        if url == server:
            return "Let's Encrypt (тестовый)" if k == "letsencrypt-staging" else CA_TITLES[k]
    from urllib.parse import urlparse
    host = urlparse(server).netloc
    return f"свой ACME ({host})" if host else server


def certbot_command(certbot: str, *, cert_name: str, domains: List[str], server: str, email: str,
                    key_type: str, challenge: str = "http", webroot: str = "", dns_args: Optional[List[str]] = None,
                    eab: Optional[Tuple[str, str]] = None, renew: bool = False) -> List[str]:
    """Команда certbot certonly для выпуска или продления (без секретов в аргументах — они в файлах)."""
    cmd = [certbot, "certonly", "--non-interactive", "--agree-tos", "--cert-name", cert_name,
           "--keep-until-expiring", "--deploy-hook", "nginx -s reload", "--server", server, "--key-type", key_type]
    if challenge == "dns":
        cmd += list(dns_args or [])
    else:
        cmd += ["--webroot", "-w", webroot]
    if renew:
        cmd.append("--force-renewal")
    cmd += ["-m", email] if email else ["--register-unsafely-without-email"]
    if eab and eab[0] and eab[1]:
        cmd += ["--eab-kid", eab[0], "--eab-hmac-key", eab[1]]
    for d in domains:
        cmd += ["-d", d]
    return cmd


def redact(cmd: List[str]) -> str:
    """Команда для журнала выпуска: HMAC-ключ EAB не показывается."""
    out, hide = [], False
    for a in cmd:
        out.append("••••" if hide else a)
        hide = a == "--eab-hmac-key"
    return " ".join(out)


_plugins_cache: Tuple[float, Optional[set]] = (0.0, None)


def installed_plugins(refresh: bool = False) -> Optional[set]:
    """Плагины certbot (`certbot plugins`); None — certbot не установлен или не запускается. Кэш на минуту."""
    global _plugins_cache
    ts, val = _plugins_cache
    if not refresh and val is not None and time.time() - ts < 60:
        return val
    cb = which("certbot")
    if not cb:
        _plugins_cache = (time.time(), None)
        return None
    code, out = run([cb, "plugins"], timeout=60)
    val = set(re.findall(r"^\* (\S+)", out, re.M)) if code == 0 else None
    _plugins_cache = (time.time(), val)
    return val


def plugin_ready(provider: str) -> Optional[bool]:
    """Установлен ли плагин certbot для провайдера (None — не удалось узнать: certbot не работает)."""
    auth = PLUGINS[provider]["auth"]
    plugins = installed_plugins()
    if plugins is None:
        return None
    return auth in plugins


def install_command(provider: str) -> Optional[List[str]]:
    """Команда установки плагина: пакет дистрибутива (Debian/Ubuntu, RHEL с EPEL) или snap, если certbot из snap."""
    pkg = PLUGINS[provider].get("pkg")
    if not pkg:
        return None
    cb = which("certbot") or ""
    if cb.startswith("/snap/"):
        return ["sh", "-c", f"snap set certbot trust-plugin-with-root=ok && snap install {pkg.replace('python3-', '')} "
                            f"&& snap connect certbot:plugin {pkg.replace('python3-', '')}"]
    if which("apt-get"):
        return ["apt-get", "install", "-y", pkg]
    if which("dnf"):
        return ["dnf", "install", "-y", pkg]
    if which("yum"):
        return ["yum", "install", "-y", pkg]
    return None


def check_account(acc: DnsAccount) -> Dict[str, Any]:
    """Проверка учётной записи без выпуска: плагин установлен, скрипты существуют и исполняемы."""
    res: Dict[str, Any] = {"ok": True, "items": []}

    def item(ok: bool, text: str, hint: str = "") -> None:
        res["items"].append({"ok": ok, "text": text, "hint": hint})
        res["ok"] = res["ok"] and ok

    if acc.provider == "hook":
        for label, path in (("Скрипт создания записи", acc.hook_auth), ("Скрипт удаления записи", acc.hook_cleanup)):
            if not path:
                continue
            ok = os.path.isfile(path) and os.access(path, os.X_OK)
            item(ok, f"{label}: {path}", "" if ok else "Файл не найден или не исполняемый (chmod +x)")
        return res
    ready = plugin_ready(acc.provider)
    pkg = PLUGINS[acc.provider]["pkg"]
    if ready is None:
        item(False, "certbot не установлен или не запускается", "Диагностика → «Сертификаты» покажет причину")
    else:
        item(bool(ready), f"Плагин certbot {PLUGINS[acc.provider]['auth']}" + (" установлен" if ready else " не установлен"),
             "" if ready else f"Нажмите «Установить плагин» или выполните: apt install {pkg} (dnf install {pkg} — "
                              "на RHEL из EPEL)")
    if acc.provider == "google":
        d = json.loads(acc.google_json)
        item(bool(d.get("client_email")), f"Сервисный аккаунт: {d.get('client_email', '—')}")
    return res
