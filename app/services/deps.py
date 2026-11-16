"""Системные пакеты и модули nginx, которые нужны функциям панели.

Используется обновлением (update.sh доустанавливает недостающее через «nmctl deps --packages apt|dnf») и
«Диагностикой» (проверка «Пакеты и модули» с исправлением в один щелчок). Каждый пункт: что даёт, нужен ли при
текущих настройках, есть ли уже и какими пакетами ставится в Debian/Ubuntu (apt) и RHEL-совместимых (dnf).
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..utils import run, which


def _dpkg_installed(name: str) -> bool:
    if not which("dpkg-query"):
        return False
    code, out = run(["dpkg-query", "-W", "-f=${Status}", name], 10)
    return code == 0 and "install ok installed" in out


def report(db, mgr) -> List[Dict[str, Any]]:
    """Список пунктов: {id, title, why, needed, ok, apt, dnf}."""
    from ..models import ProtectionSettings
    from ..protection.nginx import challenge_ready, modsec_ready
    caps = mgr.caps(refresh=True)
    try:
        state = mgr.load_state()
        streams = any(s.enabled for _, s in state.streams)
    except Exception:  # noqa: BLE001 — база ещё не создана (первая установка)
        streams = False
    p = ProtectionSettings.model_validate(db.kv_get("protection_settings", {}) or {})
    distro_nginx = _dpkg_installed("nginx-core") or _dpkg_installed("nginx-light") or _dpkg_installed("nginx-full")
    crs_dir = ""
    try:
        crs_dir = mgr.crs()[0] or ""
    except Exception:  # noqa: BLE001
        pass
    out = [
        {"id": "certbot", "title": "certbot", "why": "выпуск и продление сертификатов Let's Encrypt",
         "needed": True, "ok": bool(which("certbot")), "apt": ["certbot"], "dnf": ["certbot"]},
        {"id": "openssl", "title": "openssl", "why": "самоподписанные сертификаты, проверка цепочек",
         "needed": True, "ok": bool(which("openssl")), "apt": ["openssl"], "dnf": ["openssl"]},
        {"id": "logrotate", "title": "logrotate", "why": "ротация журналов nginx и панели",
         "needed": True, "ok": bool(which("logrotate")), "apt": ["logrotate"], "dnf": ["logrotate"]},
        {"id": "stream", "title": "модуль nginx stream", "why": "TCP/UDP-потоки" + (" (используются)" if streams else ""),
         "needed": True, "ok": bool(caps.stream_available), "required": streams,
         "apt": ["libnginx-mod-stream"], "dnf": ["nginx-mod-stream"]},
        {"id": "secure_link", "title": "модуль nginx secure_link", "why": "проверка браузера и режим «Под атакой»",
         "needed": True, "ok": challenge_ready(caps),
         # nginx-core и nginx-light в Ubuntu 22.04 и Debian собраны без модуля — сборка nginx-extras того же
         # дистрибутива его содержит; nginx с nginx.org и пакеты RHEL — содержат
         "apt": ["nginx-extras"] if distro_nginx else [], "dnf": []},
        {"id": "modsecurity", "title": "ModSecurity и OWASP CRS", "why": "глубокая проверка тела запросов (включена)",
         "needed": bool(p.modsec_enabled), "ok": modsec_ready(caps) and bool(crs_dir),
         "apt": ["libnginx-mod-http-modsecurity", "modsecurity-crs"], "dnf": []},
    ]
    for x in out:
        x.setdefault("required", False)
    return [x for x in out if x["needed"] or x["required"]]


def missing_packages(items: List[Dict[str, Any]], pkg: str) -> List[str]:
    """Пакеты для установки недостающего (pkg: apt | dnf | yum)."""
    key = "apt" if pkg == "apt" else "dnf"
    out: List[str] = []
    for x in items:
        if not x["ok"]:
            for name in x.get(key) or []:
                if name not in out:
                    out.append(name)
    return out
