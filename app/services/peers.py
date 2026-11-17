"""Несколько серверов: блокировки IP и настройки защиты от атак — общие для всех серверов с Nginx Manager.

Каждый сервер раз в минуту (и сразу после изменения) отправляет другим свой полный список блокировок, кроме
полученных от других серверов, — POST /api/sync/bans с API-токеном сервера-получателя. Получатель сверяет
блокировки этого источника: добавляет новые, обновляет сроки, снимает исчезнувшие. Так блокировка или разблокировка
на любом сервере за минуту действует на всех, а потерянное сообщение исправляется следующей сверкой. Настройки
защиты (фильтр запросов, свои правила, списки угроз, база уязвимостей…) можно отправить кнопкой или автоматически
при сохранении — получатель применяет конфигурацию с проверкой nginx -t.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("nm.peers")

SYNC_SOURCE = "sync"
INTERVAL = 60


def instance_id(db) -> str:
    v = db.kv_get("instance_id")
    if not v:
        v = secrets.token_hex(8)
        db.kv_set("instance_id", v)
    return v


def call(peer, method: str, path: str, body: Optional[Dict[str, Any]] = None, verify: bool = True,
         timeout: int = 20) -> Tuple[int, Any]:
    url = peer.url.rstrip("/") + "/api" + path
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {peer.token}", "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "NginxManager-Sync/1.0"})
    ctx = None
    if url.startswith("https://") and not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:  # noqa: S310 — адрес задаёт администратор
            raw = r.read(16 * 1048576)
            return r.status, json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read(65536) or b"null")
        except ValueError:
            payload = None
        return e.code, payload


def _err(code: int, payload: Any) -> str:
    detail = payload.get("detail") if isinstance(payload, dict) else ""
    return {401: "401: неверный API-токен", 403: f"403: {detail or 'недостаточно прав у токена'}",
            404: "404: на сервере старая версия Nginx Manager (нужна 2.3 или новее)"}.get(code, f"{code}: {detail}")


class PeerSync:
    def __init__(self, app) -> None:
        self.app = app
        self.db = app.db
        self.dirty = True
        self.last_push = 0.0
        self.task: Optional[asyncio.Task] = None

    # ---------------------------------------------------------------- состояние
    def peers(self) -> List[Any]:
        return [p for p in self.app.panel().peers if p.enabled]

    def status(self) -> Dict[str, Any]:
        return self.db.kv_get("peers_status", {}) or {}

    def _set(self, pid: str, **kw) -> None:
        st = self.status()
        st[pid] = {**(st.get(pid) or {}), **kw}
        self.db.kv_set("peers_status", st)

    def own_bans(self) -> List[Dict[str, Any]]:
        now = time.time()
        return [{"net": r["net"], "expires_at": r["expires_at"], "reason": (r["reason"] or "")[:200],
                 "country": r.get("country") or "", "rule": r.get("rule") or ""}
                for r in self.db.query("SELECT * FROM bans WHERE (expires_at IS NULL OR expires_at > ?) AND "
                                       "source NOT LIKE 'sync%'", (now,))]

    def origin(self) -> Dict[str, str]:
        return {"id": instance_id(self.db), "name": self.app.panel().peer_name or socket.gethostname()}

    # ---------------------------------------------------------------- отправка
    def own_trusted(self) -> List[Dict[str, Any]]:
        """Свои действующие доверенные адреса (полученные с других серверов дальше не передаются)."""
        from .trusted import active
        return [{"address": e.address, "comment": e.comment, "expires": e.expires}
                for e in active([e for e in self.app.panel().trusted_ips if not e.origin])]

    def push_bans_to(self, peer) -> Dict[str, Any]:
        verify = self.app.panel().peers_verify_tls
        bans = self.own_bans()
        body: Dict[str, Any] = {"origin": self.origin(), "bans": bans}
        # пустой список — получатель уберёт ранее полученные адреса (отправку выключили)
        body["trusted"] = self.own_trusted() if getattr(peer, "trusted", True) else []
        code, d = call(peer, "POST", "/sync/bans", body, verify)
        if code != 200:
            raise ValueError(_err(code, d))
        return {"sent": len(bans), "trusted_sent": len(body["trusted"]), **(d or {})}

    def push_bans(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        for peer in self.peers():
            if not peer.bans:
                continue
            try:
                r = self.push_bans_to(peer)
                tr = r.get("trusted") if isinstance(r.get("trusted"), dict) else {}
                self._set(peer.id, bans_ok=True, bans_at=time.time(), bans_error="", bans_sent=r["sent"],
                          bans_added=r.get("added", 0), bans_removed=r.get("removed", 0), peer_name=r.get("name", ""),
                          trusted_sent=r.get("trusted_sent", 0), trusted_skipped=str(tr.get("skipped") or ""),
                          # старая версия на получателе не возвращает trusted — адреса там не применяются
                          trusted_old="trusted" not in r)
                res[peer.id] = {"ok": True, **r}
            except Exception as e:  # noqa: BLE001
                msg = str(e)[:300] if isinstance(e, ValueError) else f"нет связи: {e}"[:300]
                prev = (self.status().get(peer.id) or {}).get("bans_error")
                self._set(peer.id, bans_ok=False, bans_error=msg, bans_tried=time.time())
                if not prev:
                    self.db.event("warning", "bans", f"Сервер «{peer.name}»: блокировки не отправлены — {msg}")
                res[peer.id] = {"ok": False, "error": msg}
        self.last_push = time.time()
        return res

    def push_protection(self, only: Optional[str] = None) -> Dict[str, Any]:
        """Отправить настройки защиты (с применением конфигурации на сервере-получателе)."""
        data = self.app.protection.settings().model_dump()
        # домены сайтов: получатель сопоставит по ним правила, привязанные к сайтам (номера сайтов там другие)
        sites = {str(sid): list(site.domains) for sid, site in self.app.nginx.load_state().sites}
        verify = self.app.panel().peers_verify_tls
        res: Dict[str, Any] = {}
        for peer in self.peers():
            if only and peer.id != only:
                continue
            try:
                code, d = call(peer, "POST", "/sync/protection", {"origin": self.origin(), "settings": data,
                                                                  "sites": sites}, verify, timeout=90)
                if code != 200:
                    raise ValueError(_err(code, d))
                ok = bool((d or {}).get("ok"))
                self._set(peer.id, prot_ok=ok, prot_at=time.time(),
                          prot_error="" if ok else str((d or {}).get("error") or "")[:300],
                          prot_mapped=int((d or {}).get("mapped") or 0), prot_dropped=int((d or {}).get("dropped") or 0))
                res[peer.id] = {"ok": ok, **(d or {})}
            except Exception as e:  # noqa: BLE001
                msg = str(e)[:300]
                self._set(peer.id, prot_ok=False, prot_error=msg, prot_tried=time.time())
                res[peer.id] = {"ok": False, "error": msg}
        return res

    def transfer(self, peer, site_ids: List[int], with_certs: bool, overwrite: bool, apply: bool) -> Dict[str, Any]:
        """Отправить сайты (и их сертификаты) на сервер peer. Сертификаты запоминаются: после продления здесь они
        будут отправлены туда же автоматически."""
        from . import transfer as TF
        payload = TF.build(self.db, site_ids, with_certs)
        body = {"origin": self.origin(), **payload, "overwrite": overwrite, "apply": apply}
        try:
            code, d = call(peer, "POST", "/sync/sites", body, self.app.panel().peers_verify_tls, timeout=180)
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"нет связи: {e}"[:300])
        if code == 404:
            raise ValueError("на сервере старая версия Nginx Manager (перенос сайтов — с версии 2.6)")
        if code != 200:
            raise ValueError(_err(code, d))
        if payload["certs"]:
            TF.remember(self.db, peer.id, payload["certs"])
        self.db.event("info", "peers", f"Сайты отправлены на сервер «{peer.name}»: {len(payload['sites'])}, "
                      f"сертификатов {len(payload['certs'])}")
        return {"ok": True, "sent": len(payload["sites"]), "certs_sent": len(payload["certs"]), **(d or {})}

    def push_cert(self, cid: int) -> Dict[str, Any]:
        """Продлённый сертификат — на серверы, куда он раньше переносился вместе с сайтами."""
        from . import transfer as TF
        pids = TF.peers_for_cert(self.db, cid)
        if not pids:
            return {}
        c = TF.read_cert(self.db, cid)
        if not c:
            return {}
        res: Dict[str, Any] = {}
        for peer in self.peers():
            if peer.id not in pids:
                continue
            try:
                code, d = call(peer, "POST", "/sync/sites", {"origin": self.origin(), "sites": [], "certs": [c]},
                               self.app.panel().peers_verify_tls, timeout=120)
                if code != 200:
                    raise ValueError(_err(code, d))
                TF.remember(self.db, peer.id, [c])
                res[peer.id] = {"ok": True}
            except Exception as e:  # noqa: BLE001
                msg = str(e)[:300]
                self.db.event("warning", "peers", f"Сертификат «{c['name']}» не отправлен на сервер «{peer.name}»: "
                              f"{msg}")
                res[peer.id] = {"ok": False, "error": msg}
        return res

    def test(self, peer) -> Dict[str, Any]:
        try:
            code, d = call(peer, "GET", "/sync/hello", None, self.app.panel().peers_verify_tls, timeout=10)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"нет связи: {e}"[:300]}
        if code != 200:
            return {"ok": False, "error": _err(code, d)}
        if (d or {}).get("id") == instance_id(self.db):
            return {"ok": False, "error": "это этот же сервер"}
        return {"ok": True, **(d or {})}

    # ---------------------------------------------------------------- приём
    def receive_bans(self, origin: Dict[str, Any], bans: List[Dict[str, Any]], user: str) -> Dict[str, Any]:
        from .bans import in_any, normalize_net
        oid = str(origin.get("id") or "")[:32]
        oname = str(origin.get("name") or oid)[:80]
        if not oid or oid == instance_id(self.db):
            raise ValueError("неверный источник")
        src = f"{SYNC_SOURCE}:{oid}"
        now = time.time()
        trusted = self.app.bans.trusted_nets()
        want: Dict[str, Dict[str, Any]] = {}
        for b in bans[:50000]:
            try:
                net = normalize_net(str(b.get("net", "")))
            except ValueError:
                continue
            exp = b.get("expires_at")
            if exp is not None and float(exp) <= now:
                continue
            if in_any(net.split("/")[0], trusted):
                continue  # доверенные адреса этого сервера не блокируем
            want[net] = {"expires_at": None if exp is None else float(exp), "reason": str(b.get("reason") or "")[:200],
                         "country": str(b.get("country") or "")[:2], "rule": str(b.get("rule") or "")[:40]}
        have = {r["net"]: r for r in self.db.query("SELECT * FROM bans WHERE source=?", (src,))}
        own = {r["net"] for r in self.db.query("SELECT net FROM bans WHERE source NOT LIKE 'sync%'")}
        added = removed = updated = 0
        for net, b in want.items():
            if net in own:
                continue  # своя блокировка важнее (свой срок и причина)
            reason = f"с сервера «{oname}»: {b['reason']}" if b["reason"] else f"с сервера «{oname}»"
            if net not in have:
                self.db.execute("INSERT OR IGNORE INTO bans(net, reason, source, rule, username, created_at, "
                                "expires_at, country) VALUES(?,?,?,?,?,?,?,?)",
                                (net, reason[:300], src, b["rule"] or "sync", user, now, b["expires_at"], b["country"]))
                added += 1
            elif have[net]["expires_at"] != b["expires_at"]:
                self.db.execute("UPDATE bans SET expires_at=? WHERE net=? AND source=?", (b["expires_at"], net, src))
                updated += 1
        for net in set(have) - set(want):
            self.db.execute("DELETE FROM bans WHERE net=? AND source=?", (net, src))
            removed += 1
        if added or removed or updated:
            self.app.bans.dirty = True
            self.app.touch()
        st = self.db.kv_get("peers_incoming", {}) or {}
        st[oid] = {"name": oname, "at": now, "count": len(want), "added": added, "removed": removed}
        self.db.kv_set("peers_incoming", st)
        return {"added": added, "removed": removed, "updated": updated, "name": self.origin()["name"]}

    async def receive_trusted(self, origin: Dict[str, Any], entries: List[Dict[str, Any]], user: str) -> Dict[str, Any]:
        """Принять доверенные адреса другого сервера: заменить полученные от него ранее; при изменении — снять
        блокировки этих адресов и переприменить последнюю применённую конфигурацию (неприменённые правки не трогаем)."""
        from . import trusted as TR
        oid = str(origin.get("id") or "")[:32]
        oname = str(origin.get("name") or oid)[:80]
        if not oid or oid == instance_id(self.db):
            raise ValueError("неверный источник")
        res = await asyncio.to_thread(TR.store, self.db, oid, oname, entries)
        if res["changed"]:
            res["unbanned"] = await asyncio.to_thread(self.app.bans.drop_trusted)
            self.db.event("info", "peers", f"Сервер «{oname}»: доверенные адреса обновлены — {res['count']} "
                          f"(+{res['added']}, −{res['removed']})", {"user": user})
            self.app.touch()
            applied = await self.app.apply_snapshot(f"Доверенные адреса с сервера «{oname}»", "sync")
            res["applied"] = bool(applied)
        return res

    # ---------------------------------------------------------------- фон
    def mark(self) -> None:
        self.dirty = True

    async def run(self) -> None:
        await asyncio.sleep(15)
        while True:
            try:
                if self.peers() and (self.dirty and time.time() - self.last_push > 3 or
                                     time.time() - self.last_push > INTERVAL):
                    self.dirty = False
                    await asyncio.to_thread(self.push_bans)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("синхронизация блокировок")
            await asyncio.sleep(2)

    def start(self) -> None:
        self.task = asyncio.get_running_loop().create_task(self.run(), name="peers")
