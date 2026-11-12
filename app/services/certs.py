"""Сертификаты: ACME через certbot (HTTP-01 webroot или DNS-01 через плагины), загрузка своих, самоподписанные,
файлы на диске."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import shutil
import socket
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import settings
from ..db import Database
from ..models import CertificateRequest, DnsAccount
from . import acme
from ..utils import atomic_write, run, spawn, which

log = logging.getLogger("nm.certs")


def _parse_date(s: str) -> Optional[float]:
    s = s.strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def cert_info(path: str) -> Dict[str, Any]:
    code, out = run(["openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-startdate", "-enddate",
                     "-serial", "-fingerprint", "-sha256", "-ext", "subjectAltName"], timeout=15)
    if code != 0:
        # старый openssl без -ext
        code, out = run(["openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-startdate", "-enddate",
                         "-serial", "-fingerprint", "-sha256", "-text"], timeout=15)
        if code != 0:
            return {"ok": False, "error": out.strip()[:500]}
    info: Dict[str, Any] = {"ok": True}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            info["subject"] = line[8:].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line[7:].strip()
        elif line.startswith("notBefore="):
            info["not_before"] = _parse_date(line[10:])
        elif line.startswith("notAfter="):
            info["not_after"] = _parse_date(line[9:])
        elif line.startswith("serial="):
            info["serial"] = line[7:]
        elif "Fingerprint=" in line:
            info["fingerprint"] = line.split("=", 1)[1]
    info["domains"] = sorted(set(re.findall(r"DNS:([^,\s]+)", out)))
    m = re.search(r"CN\s*=\s*([^,/]+)", info.get("subject", ""))
    info["cn"] = m.group(1).strip() if m else ""
    if not info["domains"] and info["cn"]:
        info["domains"] = [info["cn"]]
    info["self_signed"] = info.get("subject") == info.get("issuer")
    info["chain_len"] = Path(path).read_text(errors="ignore").count("BEGIN CERTIFICATE") if Path(path).exists() else 0
    return info


def key_matches(cert_path: str, key_path: str) -> bool:
    c1, a = run(["openssl", "x509", "-in", cert_path, "-noout", "-pubkey"], timeout=15)
    c2, b = run(["openssl", "pkey", "-in", key_path, "-pubout"], timeout=15)
    return c1 == 0 and c2 == 0 and a.strip() == b.strip()


def domain_covered(domain: str, cert_domains: List[str]) -> bool:
    domain = domain.lower()
    for d in cert_domains:
        d = d.lower()
        if d == domain:
            return True
        if d.startswith("*.") and domain.count(".") == d.count(".") and domain.endswith(d[1:]):
            return True
    return False


class CertificateService:
    def __init__(self, db: Database, get_panel) -> None:
        self.db = db
        self.get_panel = get_panel
        self.jobs: Dict[int, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    def list(self) -> List[Dict[str, Any]]:
        rows = self.db.query("SELECT * FROM certificates ORDER BY id")
        now = time.time()
        used: Dict[int, List[str]] = {}
        for r in self.db.query("SELECT id, name, data FROM sites"):
            d = json.loads(r["data"])
            cid = (d.get("ssl") or {}).get("certificate_id")
            if cid and (d.get("ssl") or {}).get("enabled"):
                used.setdefault(cid, []).append(r["name"])
        panel = self.get_panel()
        if panel.panel_certificate_id:
            used.setdefault(panel.panel_certificate_id, []).append("Панель")
        for r in rows:
            r["domains"] = json.loads(r["domains"] or "[]")
            r["data"] = json.loads(r["data"] or "{}")
            r["days_left"] = (r["not_after"] - now) / 86400 if r["not_after"] else None
            r["used_by"] = used.get(r["id"], [])
            r["job"] = self.jobs.get(r["id"])
        return rows

    def get(self, cid: int) -> Optional[Dict[str, Any]]:
        return next((c for c in self.list() if c["id"] == cid), None)

    def _update_from_file(self, cid: int) -> Dict[str, Any]:
        r = self.db.one("SELECT * FROM certificates WHERE id=?", (cid,))
        if not r:
            return {}
        if not Path(r["cert_path"]).exists():
            self.db.execute("UPDATE certificates SET status='missing', last_error=?, updated_at=? WHERE id=?",
                            ("Файл сертификата не найден", time.time(), cid))
            return {}
        info = cert_info(r["cert_path"])
        if not info.get("ok"):
            self.db.execute("UPDATE certificates SET status='error', last_error=?, updated_at=? WHERE id=?",
                            (info.get("error", ""), time.time(), cid))
            return info
        status = "valid"
        err = ""
        if not Path(r["key_path"]).exists():
            status, err = "error", "Файл закрытого ключа не найден"
        elif not key_matches(r["cert_path"], r["key_path"]):
            status, err = "error", "Закрытый ключ не соответствует сертификату"
        elif info.get("not_after") and info["not_after"] < time.time():
            status, err = "expired", "Срок действия истёк"
        data = json.loads(r["data"] or "{}")
        data.update({k: info.get(k) for k in ("subject", "serial", "fingerprint", "self_signed", "chain_len", "cn")})
        self.db.execute("UPDATE certificates SET domains=?, not_before=?, not_after=?, issuer=?, status=?, last_error=?,"
                        " data=?, updated_at=? WHERE id=?",
                        (json.dumps(info.get("domains", [])), info.get("not_before"), info.get("not_after"),
                         info.get("issuer", ""), status, err, json.dumps(data), time.time(), cid))
        return info

    def refresh_all(self) -> None:
        for r in self.db.query("SELECT id FROM certificates WHERE status != 'pending'"):
            try:
                self._update_from_file(r["id"])
            except Exception:
                log.exception("обновление сертификата %s", r["id"])

    # ------------------------------------------------------------------
    def create(self, req: CertificateRequest, username: str) -> int:
        now = time.time()
        name = req.name.strip() or (req.domains[0] if req.domains else f"cert-{int(now)}")
        cid = self.db.execute(
            "INSERT INTO certificates(name,type,domains,status,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (name, req.type, json.dumps(req.domains), "pending",
             json.dumps({"key_type": req.key_type, "staging": req.staging, "email": req.email}), now, now))
        try:
            if req.type == "upload":
                self._store_upload(cid, req)
            elif req.type == "path":
                for p in (req.cert_path, req.key_path):
                    if not p or not Path(p).is_file():
                        raise ValueError(f"Файл не найден: {p}")
                self.db.execute("UPDATE certificates SET cert_path=?, key_path=? WHERE id=?",
                                (req.cert_path, req.key_path, cid))
                self._update_from_file(cid)
            elif req.type == "selfsigned":
                self._selfsigned(cid, req)
        except Exception as e:
            self.db.execute("DELETE FROM certificates WHERE id=?", (cid,))
            raise ValueError(str(e))
        return cid

    def _store_upload(self, cid: int, req: CertificateRequest) -> None:
        cert = req.cert_pem.strip()
        key = req.key_pem.strip()
        if "BEGIN CERTIFICATE" not in cert:
            raise ValueError("Сертификат должен быть в формате PEM (-----BEGIN CERTIFICATE-----)")
        if "PRIVATE KEY" not in key:
            raise ValueError("Ключ должен быть в формате PEM (-----BEGIN ... PRIVATE KEY-----)")
        if "ENCRYPTED" in key:
            raise ValueError("Ключ зашифрован паролем — расшифруйте его: openssl pkey -in key.pem -out key-plain.pem")
        d = settings.certs_dir / str(cid)
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        atomic_write(d / "fullchain.pem", cert + "\n", 0o644)
        atomic_write(d / "privkey.pem", key + "\n", 0o600)
        if not key_matches(str(d / "fullchain.pem"), str(d / "privkey.pem")):
            shutil.rmtree(d, ignore_errors=True)
            raise ValueError("Закрытый ключ не соответствует сертификату")
        self.db.execute("UPDATE certificates SET cert_path=?, key_path=? WHERE id=?",
                        (str(d / "fullchain.pem"), str(d / "privkey.pem"), cid))
        self._update_from_file(cid)

    def _selfsigned(self, cid: int, req: CertificateRequest) -> None:
        if not req.domains:
            raise ValueError("Укажите хотя бы один домен")
        d = settings.certs_dir / str(cid)
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        san = ",".join(f"DNS:{x}" for x in req.domains)
        key_args = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"] if req.key_type == "ecdsa" \
            else ["-newkey", "rsa:2048"]
        code, out = run(["openssl", "req", "-x509", "-nodes", *key_args, "-days", str(req.days),
                         "-keyout", str(d / "privkey.pem"), "-out", str(d / "fullchain.pem"),
                         "-subj", f"/CN={req.domains[0]}", "-addext", f"subjectAltName={san}"], timeout=60)
        if code != 0:
            raise ValueError("openssl: " + out[-500:])
        os.chmod(d / "privkey.pem", 0o600)
        self.db.execute("UPDATE certificates SET cert_path=?, key_path=? WHERE id=?",
                        (str(d / "fullchain.pem"), str(d / "privkey.pem"), cid))
        self._update_from_file(cid)

    # ------------------------------------------------------------------
    #  Let's Encrypt
    # ------------------------------------------------------------------
    def certbot(self) -> Optional[str]:
        return which("certbot")

    def http01_selftest(self, domain: str) -> Dict[str, Any]:
        """Проверка, что http://domain/.well-known/acme-challenge/<token> доходит до этого сервера."""
        token = "nm-selftest-" + secrets.token_hex(8)
        d = settings.acme_webroot / ".well-known" / "acme-challenge"
        d.mkdir(parents=True, exist_ok=True)
        f = d / token
        f.write_text(token)
        os.chmod(f, 0o644)
        res: Dict[str, Any] = {"domain": domain}
        try:
            try:
                ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, 80, proto=socket.IPPROTO_TCP)})
            except socket.gaierror as e:
                res.update(ok=False, error=f"DNS: домен не разрешается ({e})")
                return res
            res["dns"] = ips
            # 1) локально через nginx (проверяет конфигурацию)
            try:
                rq = urllib.request.Request(f"http://127.0.0.1/.well-known/acme-challenge/{token}",
                                            headers={"Host": domain})
                with urllib.request.urlopen(rq, timeout=5) as resp:
                    local_ok = resp.read().decode() == token
            except Exception as e:
                local_ok = False
                res["local_error"] = str(e)
            res["local"] = local_ok
            # 2) по DNS-имени (проверяет DNS + маршрут + firewall, если сервер видит сам себя)
            try:
                with urllib.request.urlopen(f"http://{domain}/.well-known/acme-challenge/{token}", timeout=8) as resp:
                    remote_ok = resp.read().decode() == token
            except Exception as e:
                remote_ok = False
                res["remote_error"] = str(e)
            res["remote"] = remote_ok
            res["ok"] = local_ok and remote_ok
            if not local_ok:
                res["error"] = "nginx не отдаёт файлы проверки — примените конфигурацию и проверьте, что nginx запущен"
            elif not remote_ok:
                res["error"] = ("Домен не указывает на этот сервер или порт 80 закрыт снаружи "
                                "(проверка из самого сервера может не пройти при NAT — это не всегда ошибка)")
            return res
        finally:
            try:
                f.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------
    #  Учётные записи DNS
    # ------------------------------------------------------------------
    def dns_account(self, aid: int) -> Optional[DnsAccount]:
        r = self.db.one("SELECT data FROM dns_accounts WHERE id=?", (aid,))
        return DnsAccount.model_validate(json.loads(r["data"])) if r else None

    def dns_accounts_usage(self) -> Dict[int, List[str]]:
        """Какие сертификаты используют каждую учётную запись DNS."""
        out: Dict[int, List[str]] = {}
        for r in self.db.query("SELECT name, data FROM certificates WHERE type='letsencrypt'"):
            d = json.loads(r["data"] or "{}")
            if d.get("challenge") == "dns" and d.get("dns_account_id"):
                out.setdefault(int(d["dns_account_id"]), []).append(r["name"])
        return out

    def sync_dns_credentials(self, aid: int) -> None:
        """Переписать файл учётных данных после изменения записи — на него ссылается продление certbot."""
        acc = self.dns_account(aid)
        if acc and aid in self.dns_accounts_usage():
            acme.write_credentials(aid, acc)

    # ------------------------------------------------------------------
    async def issue_letsencrypt(self, req: CertificateRequest, username: str,
                                after: Optional[Any] = None) -> int:
        if not self.certbot():
            raise ValueError("certbot не установлен. Установите: apt install certbot / dnf install certbot")
        if not req.domains:
            raise ValueError("Укажите домены")
        panel = self.get_panel()
        server = acme.directory_for(panel, req.staging)
        if not server:
            raise ValueError("Укажите адрес каталога ACME в настройках панели (вкладка «Сертификаты (ACME)»)")
        if panel.acme_ca in ("zerossl", "google") and not (panel.acme_eab_kid and panel.acme_eab_hmac):
            raise ValueError(f"{acme.CA_TITLES[panel.acme_ca]} требует ключ EAB — укажите Key ID и HMAC-ключ в "
                             "настройках панели (вкладка «Сертификаты (ACME)»)")
        if req.challenge == "dns":
            acc = self.dns_account(req.dns_account_id)
            if not acc:
                raise ValueError("Учётная запись DNS не найдена")
            if acc.provider != "hook":
                ready = await asyncio.to_thread(acme.plugin_ready, acc.provider)
                if ready is None:
                    raise ValueError("certbot не запускается — подробности в «Диагностике»")
                if not ready:
                    raise ValueError(f"Не установлен плагин certbot для {acc.provider}: установите "
                                     f"{acme.PLUGINS[acc.provider]['pkg']} (кнопка «Установить плагин» на вкладке "
                                     "«Учётные записи DNS»)")
        email = req.email or panel.letsencrypt_email
        now = time.time()
        name = req.name.strip() or req.domains[0]
        cid = self.db.execute(
            "INSERT INTO certificates(name,type,domains,status,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (name, "letsencrypt", json.dumps(req.domains), "pending",
             json.dumps({"key_type": req.key_type, "staging": server == acme.CA_DIRECTORIES["letsencrypt-staging"],
                         "email": email, "cert_name": f"nm-{secrets.token_hex(3)}", "server": server,
                         "challenge": req.challenge,
                         # корневой сертификат своего ACME-сервера — чтобы продление работало и после смены центра
                         "ca_bundle": panel.acme_ca_bundle if panel.acme_ca == "custom" else "",
                         "dns_account_id": req.dns_account_id if req.challenge == "dns" else 0}), now, now))
        spawn(self._run_certbot(cid, after), name=f"certbot-{cid}")
        return cid

    async def _run_certbot(self, cid: int, after=None, renew: bool = False) -> None:
        r = self.db.one("SELECT * FROM certificates WHERE id=?", (cid,))
        if not r:
            return
        data = json.loads(r["data"] or "{}")
        domains = json.loads(r["domains"])
        cert_name = data.get("cert_name") or f"nm-{cid}"
        job = self.jobs[cid] = {"state": "running", "started": time.time(), "log": [], "renew": renew}

        def step(msg: str) -> None:
            job["log"].append(f"{time.strftime('%H:%M:%S')} {msg}")

        try:
            panel = self.get_panel()
            # сертификат продлевается в том же центре, где выпущен (старые записи — Let's Encrypt)
            server = data.get("server") or acme.CA_DIRECTORIES[
                "letsencrypt-staging" if data.get("staging") else "letsencrypt"]
            challenge = data.get("challenge") or "http"
            env: Dict[str, str] = {}
            dns_args: List[str] = []
            if challenge == "dns":
                aid = int(data.get("dns_account_id") or 0)
                acc = self.dns_account(aid)
                if not acc:
                    raise RuntimeError("Учётная запись DNS удалена — выберите другую и выпустите сертификат заново")
                dns_args, env = await asyncio.to_thread(acme.write_credentials, aid, acc)
                step(f"DNS-проверка: TXT-записи _acme-challenge создаёт «{acc.name}» ({acc.provider})")
            else:
                step("Проверка доступности доменов по HTTP (самотест)...")
                for d in domains:
                    st = await asyncio.to_thread(self.http01_selftest, d)
                    if st.get("local") is False:
                        step(f"✗ {d}: {st.get('error')}")
                    elif st.get("remote") is False:
                        step(f"⚠ {d}: {st.get('error')}. DNS: {', '.join(st.get('dns', [])) or '—'}")
                    else:
                        step(f"✓ {d}: проверка пройдена (DNS: {', '.join(st.get('dns', []))})")
            eab = None
            if panel.acme_eab_kid and panel.acme_eab_hmac and server == acme.directory_for(panel):
                eab = (panel.acme_eab_kid, panel.acme_eab_hmac)
            bundle = data.get("ca_bundle") or (panel.acme_ca_bundle if panel.acme_ca == "custom" and
                                               server == panel.acme_directory else "")
            if bundle:
                env["REQUESTS_CA_BUNDLE"] = bundle
            cmd = acme.certbot_command(self.certbot() or "certbot", cert_name=cert_name, domains=domains,
                                       server=server, email=data.get("email", ""),
                                       key_type=data.get("key_type", "ecdsa"), challenge=challenge,
                                       webroot=str(settings.acme_webroot), dns_args=dns_args, eab=eab, renew=renew)
            step(f"Центр сертификации: {acme.ca_title(server)}")
            step("Запуск: " + acme.redact(cmd))
            code, out = await asyncio.to_thread(run, cmd, 600 if challenge == "dns" else 300, None, env)
            lost = re.search(r"Account (https?://\S+) not found|accountDoesNotExist", out)
            if code != 0 and lost:
                # аккаунт удалён на стороне центра (деактивирован, сервер пересоздан): локальная запись certbot
                # бесполезна — убираем её и повторяем один раз, certbot зарегистрирует новый аккаунт
                removed = await asyncio.to_thread(forget_acme_account, server, lost.group(1) or "")
                step(f"Аккаунт ACME не найден у центра сертификации — регистрирую новый (удалено локальных "
                     f"записей: {removed})")
                code, out = await asyncio.to_thread(run, cmd, 600 if challenge == "dns" else 300, None, env)
            for line in out.strip().splitlines()[-40:]:
                step(line)
            if code != 0:
                hint = certbot_hint(out)
                raise RuntimeError(hint or "certbot завершился с ошибкой")
            live = Path("/etc/letsencrypt/live") / cert_name
            self.db.execute("UPDATE certificates SET cert_path=?, key_path=?, status='valid', last_error='', "
                            "updated_at=? WHERE id=?",
                            (str(live / "fullchain.pem"), str(live / "privkey.pem"), time.time(), cid))
            self._update_from_file(cid)
            job["state"] = "done"
            step("✓ Сертификат выпущен")
            self.db.event("info", "certs", f"Сертификат «{r['name']}» {'продлён' if renew else 'выпущен'}")
            if after:
                res = after(cid)
                if asyncio.iscoroutine(res):
                    await res
        except Exception as e:
            job["state"] = "error"
            job["error"] = str(e)
            step(f"✗ {e}")
            self.db.execute("UPDATE certificates SET status=?, last_error=?, updated_at=? WHERE id=?",
                            ("valid" if renew else "error", str(e)[:2000], time.time(), cid))
            self.db.event("error", "certs", f"Ошибка выпуска сертификата «{r['name']}»: {e}")
        finally:
            job["finished"] = time.time()

    async def renew(self, cid: int, after=None) -> None:
        r = self.db.one("SELECT * FROM certificates WHERE id=?", (cid,))
        if not r:
            raise ValueError("Сертификат не найден")
        if r["type"] == "letsencrypt":
            spawn(self._run_certbot(cid, after, renew=True), name=f"certbot-renew-{cid}")
        elif r["type"] == "selfsigned":
            req = CertificateRequest(type="selfsigned", domains=json.loads(r["domains"]),
                                     key_type=json.loads(r["data"]).get("key_type", "ecdsa"))
            await asyncio.to_thread(self._selfsigned, cid, req)
        else:
            await asyncio.to_thread(self._update_from_file, cid)

    async def auto_renew(self, after=None) -> List[int]:
        days = self.get_panel().renew_days_before
        out = []
        for r in self.db.query("SELECT id, not_before, not_after, type, status FROM certificates "
                               "WHERE type='letsencrypt'"):
            job = self.jobs.get(r["id"]) or {}
            if job.get("state") == "running":
                continue
            # после неудачи — пауза (6 ч, для коротких сертификатов меньше), чтобы не упираться в лимиты центра
            # на неудачные проверки; кнопка «Продлить» работает всегда
            backoff = min(6 * 3600.0, lifetime_days(r) * 86400 / 12)
            if job.get("state") == "error" and time.time() - job.get("finished", 0) < backoff:
                continue
            if r["not_after"] and r["not_after"] - time.time() < renew_threshold(r["not_before"], r["not_after"], days):
                out.append(r["id"])
                await self._run_certbot(r["id"], after, renew=True)
        return out

    def delete(self, cid: int) -> None:
        r = self.db.one("SELECT * FROM certificates WHERE id=?", (cid,))
        if not r:
            return
        for s in self.db.query("SELECT name, data FROM sites"):
            d = json.loads(s["data"])
            if (d.get("ssl") or {}).get("certificate_id") == cid:
                raise ValueError(f"Сертификат используется сайтом «{s['name']}»")
        if self.get_panel().panel_certificate_id == cid:
            raise ValueError("Сертификат используется доменом панели")
        if r["type"] in ("upload", "selfsigned"):
            shutil.rmtree(settings.certs_dir / str(cid), ignore_errors=True)
        elif r["type"] == "letsencrypt" and self.certbot():
            name = json.loads(r["data"] or "{}").get("cert_name")
            if name:
                run([self.certbot() or "certbot", "delete", "--cert-name", name, "--non-interactive"], timeout=60)
        self.db.execute("DELETE FROM certificates WHERE id=?", (cid,))

    def certbot_timer_active(self) -> Optional[bool]:
        if which("systemctl"):
            code, _ = run(["systemctl", "is-active", "--quiet", "certbot.timer"])
            if code == 0:
                return True
            code2, _ = run(["systemctl", "is-active", "--quiet", "snap.certbot.renew.timer"])
            if code2 == 0:
                return True
        for p in ("/etc/cron.d/certbot",):
            if Path(p).exists():
                return True
        return False


def forget_acme_account(server: str, account_url: str = "", base: str = "/etc/letsencrypt/accounts") -> int:
    """Удалить локальную запись certbot об аккаунте ACME, которого больше нет у центра. Если адрес аккаунта
    известен — только её; иначе все аккаунты этого сервера. Возвращает число удалённых записей."""
    from urllib.parse import urlsplit
    u = urlsplit(server)
    d = Path(base) / u.netloc / u.path.strip("/")
    n = 0
    if not d.is_dir():
        return 0
    for acc in d.iterdir():
        try:
            uri = json.loads((acc / "regr.json").read_text()).get("uri", "")
        except (OSError, ValueError):
            uri = ""
        if not account_url or uri == account_url:
            shutil.rmtree(acc, ignore_errors=True)
            n += 1
    return n


def lifetime_days(c: Dict[str, Any]) -> float:
    """Срок действия сертификата в днях (90, если неизвестен)."""
    nb, na = c.get("not_before"), c.get("not_after")
    return (na - nb) / 86400 if nb and na and na > nb else 90.0


def expiry_level(c: Dict[str, Any]) -> Optional[str]:
    """«crit» / «warn» / None по оставшемуся сроку. Пороги 7 и 21 день — для обычных 90-дневных сертификатов; для
    коротких (ACME-профили на 6–45 дней, step-ca на сутки) — та же доля срока, иначе предупреждение висело бы всегда."""
    days = c.get("days_left")
    if days is None:
        return None
    life = lifetime_days(c)
    if days < min(7.0, life * 0.08):
        return "crit"
    if days < min(21.0, life * 0.23):
        return "warn"
    return None


def fmt_left(days: float) -> str:
    """Оставшийся срок для сообщений: часы для коротких сертификатов, дни — для обычных."""
    if days < 2:
        return f"{max(0.0, days) * 24:.0f} ч"
    return f"{days:.0f} дн."


def renew_threshold(not_before: Optional[float], not_after: Optional[float], days: int) -> float:
    """За сколько секунд до истечения продлевать: настройка «Продлевать за N дней», но не позже трети срока
    действия — иначе короткие сертификаты (6–45 дней) продлевались бы при каждой проверке."""
    limit = days * 86400.0
    if not_before and not_after and not_after > not_before:
        limit = min(limit, (not_after - not_before) / 3)
    return limit


def certbot_hint(out: str) -> str:
    rules = [
        # нет связи с самим ACME-сервером (а не центра — с нашим сервером): раньше правил про порт 80
        (r"Requesting \S+: (Connection refused|.*timed out|.*Name or service not known|.*Temporary failure in name "
         r"resolution|.*Network is unreachable|.*No route to host)|Max retries exceeded with url: /directory",
         "Нет связи с ACME-сервером центра сертификации: проверьте адрес каталога в настройках панели, DNS и выход "
         "сервера в интернет (прокси, firewall исходящих соединений). Действующий сертификат не изменён."),
        # DNS-проверка и подключение к центру сертификации — раньше общих правил
        (r"No TXT record found|Incorrect TXT record|NXDOMAIN looking up TXT",
         "Центр сертификации не увидел TXT-запись _acme-challenge: увеличьте «Ожидание распространения записи» в "
         "учётной записи DNS или проверьте, что зона обслуживается этим провайдером (NS-записи домена)."),
        (r"Invalid access token|Authentication error|9109|10000|403 Forbidden.*api\.cloudflare",
         "DNS-провайдер отклонил учётные данные: проверьте токен и его права на изменение DNS-записей зоны."),
        (r"Unable to determine zone|zone.*not found|Could not find zone|No zone found|"
         r"Unable to find a Route53 hosted zone",
         "Зона домена не найдена у DNS-провайдера: домен обслуживается другим провайдером, или у токена нет "
         "доступа к этой зоне."),
        (r"Encountered error when making query: The DNS operation timed out|making query.*timed out",
         "DNS-сервер для динамических обновлений (RFC 2136) не отвечает: проверьте его IP и порт в учётной записи "
         "DNS, доступ к порту 53 по UDP и TCP (firewall) и что сервер запущен."),
        (r"(?-i:\b(?:REFUSED|NOTAUTH|BADKEY|BADSIG|BADTIME)\b)",
         "DNS-сервер отклонил динамическое обновление (RFC 2136): проверьте имя и секрет ключа TSIG, алгоритм, "
         "политику update-policy зоны и синхронизацию времени (BADTIME)."),
        (r"manual-auth-hook|hook command .* returned error|Hook '--manual-auth-hook'",
         "Скрипт создания DNS-записи завершился с ошибкой — запустите его вручную с переменными CERTBOT_DOMAIN и "
         "CERTBOT_VALIDATION."),
        (r"Account \S+ not found|accountDoesNotExist",
         "Аккаунт ACME не найден у центра сертификации (удалён, деактивирован или сервер пересоздан). Панель "
         "регистрирует новый автоматически; если ошибка повторяется — проверьте e-mail и EAB в настройках панели."),
        (r"externalAccountRequired|external account|EAB",
         "Центр сертификации требует привязку аккаунта (EAB): укажите Key ID и HMAC-ключ в настройках панели."),
        (r"CERTIFICATE_VERIFY_FAILED|certificate verify failed",
         "Не удаётся проверить TLS-сертификат ACME-сервера: укажите его корневой сертификат в настройках панели "
         "(«Доверенный корневой сертификат ACME-сервера»)."),
        (r"too many certificates|rateLimited|too many failed authorizations",
         "Превышен лимит Let's Encrypt. Подождите (лимиты сбрасываются в течение недели) или используйте "
         "тестовый сервер (staging) для отладки."),
        (r"DNS problem: NXDOMAIN|DNS problem", "Ошибка DNS: домен не существует или не имеет A/AAAA-записи."),
        (r"Timeout during connect|Fetching .* Timeout|Connection refused",
         "Серверы Let's Encrypt не смогли подключиться к порту 80. Проверьте firewall/NAT/проброс порта 80."),
        (r"Invalid response from .*404", "Проверочный файл не найден (404): домен указывает на другой сервер или "
                                         "конфигурация не применена."),
        (r"unauthorized", "Проверка домена не пройдена (unauthorized): домен указывает не на этот сервер."),
        (r"CAA record", "CAA-запись домена запрещает выпуск сертификатов Let's Encrypt."),
        (r"Another instance of Certbot is already running", "Certbot уже запущен — повторите через минуту."),
    ]
    for pat, hint in rules:
        if re.search(pat, out, re.I):
            return hint
    return ""
