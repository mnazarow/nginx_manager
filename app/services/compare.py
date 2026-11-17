"""Сравнение конфигурации с другим сервером («Другие серверы» → «Сравнить»).

Каждый сервер отдаёт сводку применённой конфигурации (/sync/summary): по сайту — хеши его разделов (номера
сертификатов, свои у каждого сервера, не учитываются — вместо них домены и срок сертификата), по потокам, защите
и общим настройкам — хеши по полям. Сайты сопоставляются по доменам, потоки — по внешнему порту: номера записей
на серверах разные. Содержимое настроек (адреса бэкендов, пароли, ключи) не передаётся — только хеши.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from ..config import VERSION
from ..models import GlobalSettings, ProtectionSettings, Site, Stream

FORMAT = 1
# поля, которые у серверов законно различаются и в сравнении не участвуют
SKIP_GLOBAL = {"server_name_default", "resolver"}
SKIP_PROTECTION = {"crowdsec_url", "crowdsec_key", "crowdsec_action", "crowdsec_minutes"}  # у каждого сервера свой


def _h(v: Any) -> str:
    return hashlib.sha256(json.dumps(v, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:16]


def site_key(s: Site) -> str:
    plain = sorted(d.lower() for d in s.domains)
    return ",".join(plain) if plain else f"name:{s.name}"


def _sections(d: Dict[str, Any], skip=()) -> Dict[str, str]:
    return {k: _h(v) for k, v in d.items() if k not in skip}


def summary(app) -> Dict[str, Any]:
    state = app.last_applied_state() or app.nginx.load_state()
    certs = {c["id"]: c for c in app.certs.list()}
    sites: Dict[str, Any] = {}
    for sid, s in state.sites:
        d = s.model_dump(mode="json")
        ssl = dict(d.get("ssl") or {})
        cid = ssl.pop("certificate_id", None)
        d["ssl"] = ssl
        c = certs.get(cid) if ssl.get("enabled") else None
        sites[site_key(s)] = {"id": sid, "name": s.name, "enabled": s.enabled,
                              "sections": _sections(d, ("name", "notes")),
                              "cert": {"domains": sorted(c["domains"]), "not_after": c.get("not_after"),
                                       "status": c["status"]} if c else None}
    streams = {f"{s.listen_ip or '*'}:{s.listen_port}/{getattr(s, 'protocol', 'tcp')}":
               {"name": s.name, "enabled": s.enabled, "sections": _sections(s.model_dump(mode="json"), ("name", "notes"))}
               for _, s in state.streams}
    trusted = sorted(e.address for e in state.panel.trusted_ips if e.origin in ("", None))
    # правила защиты, привязанные к сайтам: номера сайтов → домены (на серверах номера разные)
    keys = {sid: site_key(s) for sid, s in state.sites}
    prot = state.protection.model_dump(mode="json")
    for k in ("custom_rules", "rate_rules"):
        prot[k] = [{**r, "sites": sorted(keys.get(i, f"#{i}") for i in r.get("sites") or [])} for r in prot.get(k) or []]
    last = app.nginx.last_applied() or {}
    return {"format": FORMAT, "me": app.peers.origin(), "version": VERSION, "config_version": last.get("id"),
            "applied_at": last.get("created_at"), "at": time.time(), "sites": sites, "streams": streams,
            "global": _sections(state.glob.model_dump(mode="json"), SKIP_GLOBAL),
            "protection": _sections(prot, SKIP_PROTECTION), "trusted": trusted}


def _label(model, key: str) -> str:
    f = model.model_fields.get(key)
    extra = (f.json_schema_extra if f else None) or {}
    return extra.get("label") or key if isinstance(extra, dict) else key


SITE_GROUPS = {"domains": "Домены", "backends": "Бэкенды", "ssl": "HTTPS", "ip_access": "Доступ по IP",
               "locations": "Пути (locations)", "headers": "Заголовки", "cache": "Кэш"}


def diff(mine: Dict[str, Any], theirs: Dict[str, Any]) -> Dict[str, Any]:
    """Расхождения: сайты/потоки только здесь, только там, различающиеся (с названиями разделов); поля общих
    настроек и защиты; доверенные адреса; сертификаты с разными доменами или сроками."""
    def objs(kind: str, model) -> Dict[str, Any]:
        a, b = mine.get(kind) or {}, theirs.get(kind) or {}
        changed: List[Dict[str, Any]] = []
        for k in sorted(set(a) & set(b)):
            sa, sb = a[k]["sections"], b[k]["sections"]
            keys = sorted(x for x in set(sa) | set(sb) if sa.get(x) != sb.get(x))
            item: Dict[str, Any] = {"key": k, "id": a[k].get("id"), "name": a[k]["name"], "their_name": b[k]["name"],
                                    "fields": [SITE_GROUPS.get(x) or _label(model, x) for x in keys]}
            if a[k].get("enabled") != b[k].get("enabled"):
                item["enabled"] = [a[k].get("enabled"), b[k].get("enabled")]
            ca, cb = a[k].get("cert"), b[k].get("cert")
            if kind == "sites" and (ca or cb) and (not ca or not cb or ca["domains"] != cb["domains"]):
                item["cert"] = "сертификаты на разные домены" if ca and cb else "HTTPS только на одном из серверов"
            elif kind == "sites" and ca and cb and ca.get("not_after") and cb.get("not_after") and \
                    abs(float(ca["not_after"]) - float(cb["not_after"])) > 3 * 86400:
                item["cert_days"] = [ca["not_after"], cb["not_after"]]
            if item["fields"] or "enabled" in item or "cert" in item or "cert_days" in item:
                changed.append(item)
        return {"only_here": [{"key": k, "id": a[k].get("id"), "name": a[k]["name"]} for k in sorted(set(a) - set(b))],
                "only_there": [{"key": k, "name": b[k]["name"]} for k in sorted(set(b) - set(a))],
                "changed": changed, "same": sum(1 for k in set(a) & set(b)) - len(changed)}

    def fields(kind: str, model) -> List[str]:
        a, b = mine.get(kind) or {}, theirs.get(kind) or {}
        return [_label(model, k) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k) and k in a and k in b]

    ta, tb = set(mine.get("trusted") or []), set(theirs.get("trusted") or [])
    out = {"sites": objs("sites", Site), "streams": objs("streams", Stream),
           "global": fields("global", GlobalSettings), "protection": fields("protection", ProtectionSettings),
           "trusted": {"only_here": sorted(ta - tb), "only_there": sorted(tb - ta)},
           "peer": {**(theirs.get("me") or {}), "version": theirs.get("version"),
                    "config_version": theirs.get("config_version"), "applied_at": theirs.get("applied_at")},
           "me": {**(mine.get("me") or {}), "version": mine.get("version"), "config_version": mine.get("config_version")}}
    s = out["sites"]
    st = out["streams"]
    out["total"] = (len(s["only_here"]) + len(s["only_there"]) + len(s["changed"]) + len(st["only_here"])
                    + len(st["only_there"]) + len(st["changed"]) + len(out["global"]) + len(out["protection"])
                    + len(out["trusted"]["only_here"]) + len(out["trusted"]["only_there"]))
    return out


def compare(app, peer) -> Dict[str, Any]:
    from .peers import _err, call
    try:
        code, d = call(peer, "GET", "/sync/summary", None, app.panel().peers_verify_tls, timeout=30)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"нет связи: {e}"[:300]}
    if code == 404:
        return {"ok": False, "error": "на сервере старая версия Nginx Manager — сравнение есть с версии 2.8"}
    if code != 200 or not isinstance(d, dict):
        return {"ok": False, "error": _err(code, d)}
    res: Optional[Dict[str, Any]] = diff(summary(app), d)
    return {"ok": True, **res}
