"""Обмен данными об угрозах: AbuseIPDB и CrowdSec.

AbuseIPDB (нужен бесплатный ключ API):
  * проверка адреса в профиле атакующего — уверенность в злонамеренности, число жалоб, провайдер, тип сети;
  * жалобы на атакующих — вручную из профиля или автоматически на адреса с высокой оценкой угрозы (с лимитом в сутки);
  * чёрный список AbuseIPDB как список угроз (адреса с уверенностью от заданной, раз в сутки).

CrowdSec: решения локального API (LAPI) агента CrowdSec на этом или другом сервере — как список угроз,
обновляется раз в несколько минут (ключ баунсера: `cscli bouncers add nginx-manager`).
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"

# Категории AbuseIPDB: https://www.abuseipdb.com/categories
ABUSE_CATS = {"web": 21, "hacking": 15, "sqli": 16, "brute": 18, "badbot": 19, "ddos": 4, "scan": 14}
INTEL_FEEDS = {"abuseipdb": "AbuseIPDB (чёрный список)", "crowdsec": "CrowdSec (решения агента)"}


def http_json(url: str, headers: Dict[str, str], data: Optional[bytes] = None, timeout: int = 20,
              method: Optional[str] = None) -> Tuple[int, Any]:
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": "NginxManager/1.0", "Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — адрес задаёт администратор
            body = r.read(64 * 1048576)
            return r.status, (json.loads(body) if body.strip() else None)
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read(65536) or b"null")
        except ValueError:
            payload = None
        return e.code, payload


def _api_error(code: int, payload: Any) -> str:
    if isinstance(payload, dict):
        errs = payload.get("errors") or []
        if errs and isinstance(errs, list) and isinstance(errs[0], dict):
            return f"{code}: {errs[0].get('detail') or errs[0]}"
        if payload.get("message"):
            return f"{code}: {payload['message']}"
    return {401: "401: неверный ключ API", 403: "403: доступ запрещён", 429: "429: превышен лимит запросов"}.get(
        code, f"ответ {code}")


# =============================================================================
#  AbuseIPDB
# =============================================================================
def abuse_check(key: str, ip: str, days: int = 90) -> Dict[str, Any]:
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": days})
    code, d = http_json(f"{ABUSEIPDB_API}/check?{q}", {"Key": key})
    if code != 200 or not isinstance(d, dict) or "data" not in d:
        raise ValueError(_api_error(code, d))
    x = d["data"]
    return {"score": x.get("abuseConfidenceScore", 0), "reports": x.get("totalReports", 0),
            "users": x.get("numDistinctUsers", 0), "last": x.get("lastReportedAt") or "", "isp": x.get("isp") or "",
            "domain": x.get("domain") or "", "usage": x.get("usageType") or "", "country": x.get("countryCode") or "",
            "tor": bool(x.get("isTor")), "whitelisted": bool(x.get("isWhitelisted")),
            "link": f"https://www.abuseipdb.com/check/{ip}"}


def abuse_report(key: str, ip: str, categories: Iterable[int], comment: str) -> Dict[str, Any]:
    data = urllib.parse.urlencode({"ip": ip, "categories": ",".join(str(c) for c in sorted(set(categories))),
                                   "comment": comment[:1000]}).encode()
    code, d = http_json(f"{ABUSEIPDB_API}/report", {"Key": key}, data=data, method="POST")
    if code != 200 or not isinstance(d, dict) or "data" not in d:
        raise ValueError(_api_error(code, d))
    return {"score": (d.get("data") or {}).get("abuseConfidenceScore")}


def abuse_blacklist(key: str, confidence: int = 90, limit: int = 10000) -> List[str]:
    q = urllib.parse.urlencode({"confidenceMinimum": confidence, "limit": limit})
    code, d = http_json(f"{ABUSEIPDB_API}/blacklist?{q}", {"Key": key}, timeout=120)
    if code != 200 or not isinstance(d, dict) or not isinstance(d.get("data"), list):
        raise ValueError(_api_error(code, d))
    return [x["ipAddress"] for x in d["data"] if isinstance(x, dict) and x.get("ipAddress")]


def report_categories(rules: Iterable[Tuple[str, str]], tool: str = "") -> List[int]:
    """Категории жалобы по сработавшим правилам (вид, правило) и инструменту атакующего."""
    cats = {ABUSE_CATS["web"]}
    for kind, rule in rules:
        cat = rule.split("/", 1)[0] if "/" in rule else kind
        if cat == "sqli" or "942" in rule[:12]:
            cats.add(ABUSE_CATS["sqli"])
        if kind in ("fakebot",) or cat.startswith("bots_"):
            cats.add(ABUSE_CATS["badbot"])
        if kind == "ratelimit" or rule.startswith("login"):
            cats.add(ABUSE_CATS["brute"])
        if cat in ("vuln", "cve", "rce", "webshells", "java", "files", "traversal", "php") or kind == "honeypot":
            cats.add(ABUSE_CATS["hacking"])
    if tool in ("sqlmap", "nuclei", "nikto", "wpscan", "acunetix", "burp", "zap", "dirbust", "nmap", "masscan",
                "zgrab"):
        cats.add(ABUSE_CATS["hacking"])
    return sorted(cats)


def report_comment(rules: List[Tuple[str, str, int]]) -> str:
    """Текст жалобы: без доменов и адресов ваших сайтов — только сработавшие правила."""
    total = sum(n for _, _, n in rules)
    parts = [f"{rule} x{n}" for _, rule, n in rules[:8]]
    return f"Web attack requests blocked by Nginx Manager WAF ({total}): " + ", ".join(parts)


# =============================================================================
#  CrowdSec LAPI
# =============================================================================
def crowdsec_decisions(url: str, key: str) -> List[Tuple[str, str]]:
    """Действующие решения агента CrowdSec: [(адрес или подсеть, тип: ban/captcha)]."""
    base = url.rstrip("/")
    code, d = http_json(f"{base}/v1/decisions/stream?startup=true", {"X-Api-Key": key})
    if code != 200:
        raise ValueError(_api_error(code, d) if code not in (401, 403) else
                         f"{code}: неверный ключ баунсера (cscli bouncers add nginx-manager)")
    out: List[Tuple[str, str]] = []
    for x in (d or {}).get("new") or []:
        if not isinstance(x, dict):
            continue
        scope = str(x.get("scope", "")).lower()
        val = str(x.get("value", ""))
        if scope in ("ip", "range") and val:
            out.append((val, str(x.get("type") or "ban")))
    return out


class Intel:
    """Состояние и действия обмена данными об угрозах (для ProtectionService)."""

    def __init__(self, svc) -> None:
        self.svc = svc
        self.db = svc.db
        self.cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def status(self) -> Dict[str, Any]:
        return self.db.kv_get("intel_status", {}) or {}

    def _set(self, key: str, **kw) -> None:
        st = self.status()
        st[key] = {**(st.get(key) or {}), **kw}
        self.db.kv_set("intel_status", st)

    # ---------------------------------------------------------------- AbuseIPDB
    def check(self, ip: str, force: bool = False) -> Dict[str, Any]:
        p = self.svc.settings()
        if not p.abuseipdb_key:
            return {"error": "не задан ключ AbuseIPDB («Защита → Обмен данными»)"}
        hit = self.cache.get(ip)
        if hit and not force and time.time() - hit[0] < 86400:
            return hit[1]
        try:
            r = abuse_check(p.abuseipdb_key, ip)
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)[:300]}
        rep = (self.db.kv_get("abuse_reported", {}) or {}).get(ip)
        r["reported_by_us"] = rep
        self.cache[ip] = (time.time(), r)
        if len(self.cache) > 5000:
            self.cache.clear()
        return r

    def reported(self) -> Dict[str, float]:
        return self.db.kv_get("abuse_reported", {}) or {}

    def report(self, ip: str, user: str = "") -> Dict[str, Any]:
        p = self.svc.settings()
        if not p.abuseipdb_key:
            raise ValueError("не задан ключ AbuseIPDB")
        if p.abuseipdb_report == "off":
            raise ValueError("жалобы в AbuseIPDB выключены")
        since = time.time() - 86400
        rules = [(r["kind"], r["rule"], r["n"]) for r in self.db.query(
            "SELECT kind, rule, COUNT(*) AS n FROM attack_log WHERE ip=? AND ts>=? AND test=0 AND action IN "
            "('blocked','detected','banned') GROUP BY kind, rule ORDER BY n DESC", (ip, since))]
        if not rules:
            raise ValueError("за сутки от адреса нет атак — жаловаться не на что")
        tool = ""
        try:
            tool = (self.svc.analytics.attackers(24, q=ip) or [{}])[0].get("tool", "")
        except Exception:  # noqa: BLE001
            tool = ""
        cats = report_categories([(k, r) for k, r, _ in rules], tool)
        res = abuse_report(p.abuseipdb_key, ip, cats, report_comment(rules))
        rep = self.reported()
        rep[ip] = time.time()
        self.db.kv_set("abuse_reported", {k: v for k, v in rep.items() if time.time() - v < 7 * 86400})
        day = time.strftime("%Y-%m-%d")
        st = self.status().get("abuseipdb_report") or {}
        sent = st.get("sent", 0) + 1 if st.get("day") == day else 1
        self._set("abuseipdb_report", day=day, sent=sent, last=time.time(), error="")
        self.cache.pop(ip, None)
        self.db.event("info", "protection", f"Жалоба в AbuseIPDB на {ip}" + (f" ({user})" if user else " (автоматически)"),
                      {"categories": cats, "rules": [r for _, r, _ in rules[:8]]})
        return {"ok": True, "categories": cats, **res}

    def auto_report(self) -> int:
        """Жалобы на адреса с оценкой угрозы от порога за последний час (не чаще раза в сутки на адрес)."""
        p = self.svc.settings()
        if not p.abuseipdb_key or p.abuseipdb_report != "auto":
            return 0
        day = time.strftime("%Y-%m-%d")
        st = self.status().get("abuseipdb_report") or {}
        sent_today = st.get("sent", 0) if st.get("day") == day else 0
        left = max(0, p.abuseipdb_report_daily - sent_today)
        if not left:
            return 0
        rep = self.reported()
        trusted = list(p.bypass_ips)
        from .service import _in_net
        n = 0
        for r in self.svc.analytics.attackers(1, limit=200):
            if n >= min(left, 30):
                break
            ip = r["ip"]
            if r["score"] < p.abuseipdb_report_score or time.time() - rep.get(ip, 0) < 86400:
                continue
            if any(_in_net(ip, t) for t in trusted) or ip.startswith(("127.", "10.", "192.168.", "::1")):
                continue
            try:
                self.report(ip)
                n += 1
            except Exception as e:  # noqa: BLE001
                self._set("abuseipdb_report", error=str(e)[:300], tried=time.time())
                break
        return n

    # ---------------------------------------------------------------- списки
    def fetch_feed(self, fid: str) -> List[str]:
        p = self.svc.settings()
        if fid == "abuseipdb":
            return abuse_blacklist(p.abuseipdb_key, p.abuseipdb_blacklist_score)
        if fid == "crowdsec":
            return [v for v, _t in crowdsec_decisions(p.crowdsec_url, p.crowdsec_key)]
        raise ValueError(fid)

    def feeds(self) -> List[Tuple[str, str, bool]]:
        """(id, действие, включён) встроенных списков обмена данными."""
        p = self.svc.settings()
        return [("abuseipdb", p.abuseipdb_blacklist_action, bool(p.abuseipdb_key and p.abuseipdb_blacklist)),
                ("crowdsec", p.crowdsec_action, bool(p.crowdsec_url and p.crowdsec_key))]
