"""Сертификаты: Let's Encrypt (certbot, HTTP-01 webroot), загрузка своих, самоподписанные, файлы на диске."""
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
from ..models import CertificateRequest
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

    async def issue_letsencrypt(self, req: CertificateRequest, username: str,
                                after: Optional[Any] = None) -> int:
        if not self.certbot():
            raise ValueError("certbot не установлен. Установите: apt install certbot / dnf install certbot")
        if not req.domains:
            raise ValueError("Укажите домены")
        panel = self.get_panel()
        email = req.email or panel.letsencrypt_email
        now = time.time()
        name = req.name.strip() or req.domains[0]
        cid = self.db.execute(
            "INSERT INTO certificates(name,type,domains,status,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (name, "letsencrypt", json.dumps(req.domains), "pending",
             json.dumps({"key_type": req.key_type, "staging": req.staging or panel.letsencrypt_staging,
                         "email": email, "cert_name": f"nm-{secrets.token_hex(3)}"}), now, now))
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
            step("Проверка доступности доменов по HTTP (самотест)...")
            for d in domains:
                st = await asyncio.to_thread(self.http01_selftest, d)
                if st.get("local") is False:
                    step(f"✗ {d}: {st.get('error')}")
                elif st.get("remote") is False:
                    step(f"⚠ {d}: {st.get('error')}. DNS: {', '.join(st.get('dns', [])) or '—'}")
                else:
                    step(f"✓ {d}: проверка пройдена (DNS: {', '.join(st.get('dns', []))})")
            cmd = [self.certbot() or "certbot", "certonly", "--webroot", "-w", str(settings.acme_webroot),
                   "--cert-name", cert_name, "--non-interactive", "--agree-tos", "--keep-until-expiring",
                   "--deploy-hook", "nginx -s reload"]
            if renew:
                cmd.append("--force-renewal")
            if data.get("email"):
                cmd += ["-m", data["email"]]
            else:
                cmd.append("--register-unsafely-without-email")
            if data.get("staging"):
                cmd.append("--staging")
            cmd += ["--key-type", data.get("key_type", "ecdsa")]
            for d in domains:
                cmd += ["-d", d]
            step("Запуск: " + " ".join(cmd))
            code, out = await asyncio.to_thread(run, cmd, 300)
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
        for r in self.db.query("SELECT id, not_after, type, status FROM certificates WHERE type='letsencrypt'"):
            if r["id"] in self.jobs and self.jobs[r["id"]].get("state") == "running":
                continue
            if r["not_after"] and r["not_after"] - time.time() < days * 86400:
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


def certbot_hint(out: str) -> str:
    rules = [
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
