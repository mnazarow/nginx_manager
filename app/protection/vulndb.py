"""База уязвимостей и автоматическое обновление баз защиты из публичных источников.

Источники (каждый необязателен; недоступный не мешает остальным):
  * CISA KEV — каталог уязвимостей, которые эксплуатируются на практике (официальный адрес и зеркало CISA
    на GitHub): производитель, продукт, дата добавления, срок устранения, использование вымогателями;
  * ProjectDiscovery nuclei-templates — открытые шаблоны проверки уязвимостей: индекс CVE (название, критичность,
    CVSS, описание) и сами шаблоны, из которых берутся HTTP-запросы эксплойтов;
  * FIRST EPSS — вероятность эксплуатации уязвимости в ближайшие 30 дней (ежедневный CSV);
  * OWASP Core Rule Set — последний выпуск правил ModSecurity с GitHub (по желанию, вместо пакета дистрибутива).

Из шаблонов строится «карта путей эксплойтов» для nginx: точный нормализованный путь ($uri) → CVE. Значение
отмечает, нужен ли в параметрах признак атаки (p) или опасен сам путь (a). Пути, общие для многих уязвимостей,
типовые (/, /login, /wp-admin/admin-ajax.php…), статика и пути, которые сайты успешно обслуживают обычным
посетителям, в карту не попадают. Файл карты меняется без версии конфигурации (как списки угроз).
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..config import settings
from . import distro as DI
from . import rules as W
from . import wordpress as WPM

log = logging.getLogger("nm.vulndb")

KEV_URLS = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"]
NUCLEI_INDEX = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
NUCLEI_TARBALL = "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/heads/main"
NUCLEI_RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/{path}"
EPSS_URLS = ["https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
             "https://epss.cyentia.com/epss_scores-current.csv.gz"]
CVELIST_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group}xxx/{cve}.json"
EXPLOITDB_URLS = ["https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"]
ENRICH_TTL = 30 * 86400
MAX_ENRICH = 2500
CRS_LATEST = "https://api.github.com/repos/coreruleset/coreruleset/releases/latest"
CRS_TARBALL = "https://github.com/coreruleset/coreruleset/archive/refs/tags/{tag}.tar.gz"
CRS_GIT = "https://github.com/coreruleset/coreruleset"  # запасной путь: git ls-remote и git clone выпуска
CRS_KEEP = 2  # сколько скачанных выпусков хранить (текущий и предыдущий — для отката)

SOURCES = {
    "kev": ("CISA KEV", "каталог уязвимостей, которые эксплуатируются на практике"),
    "nuclei": ("ProjectDiscovery nuclei-templates", "открытые шаблоны проверки уязвимостей: CVSS, описание, "
                                                     "HTTP-запросы эксплойтов"),
    "epss": ("FIRST EPSS", "вероятность эксплуатации в ближайшие 30 дней"),
    "cvelist": ("CVE Program (cvelistV5)", "CVSS производителя или CISA, тип уязвимости (CWE), затронутые версии"),
    "exploitdb": ("Exploit-DB", "опубликованные эксплойты"),
    "distro": ("Ubuntu и Debian (OSV, OpenVEX)", "исправления, перенесённые в пакеты дистрибутивов, — для продуктов "
                                                 "из сборок Ubuntu и Debian на ваших сайтах"),
    "wordfence": ("Wordfence Intelligence", "уязвимости плагинов, тем и ядра WordPress с версиями (нужен ключ API)"),
    "crs": ("OWASP Core Rule Set (GitHub)", "последний выпуск правил ModSecurity"),
}
DISTRO_TTL = 3 * 86400

MAX_DOWNLOAD = 200 * 1024 * 1024
TEMPLATE_TTL = 30 * 86400
MAX_TEMPLATE_FETCH = 2500
MAX_PATH = 200          # длиннее — не в карту (ячейка хеш-таблицы map_hash_bucket_size)

# Пути, которые есть почти на любом сайте или общие для многих продуктов: точное совпадение с ними ничего не
# говорит об атаке
GENERIC_PATHS = {
    "/", "/index.php", "/index.html", "/index.htm", "/index.jsp", "/index.asp", "/index.aspx", "/default.aspx",
    "/login", "/login.php", "/login.html", "/login.jsp", "/signin", "/logout", "/admin", "/admin/", "/admin.php",
    "/api", "/api/", "/api/v1", "/api/v2", "/graphql", "/search", "/search.php", "/upload", "/upload.php",
    "/wp-login.php", "/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php", "/wp-admin/", "/wp-admin",
    "/xmlrpc.php", "/wp-json", "/wp-json/", "/user/login", "/user/register", "/register", "/cgi-bin/", "/console",
    "/robots.txt", "/sitemap.xml", "/favicon.ico", "/home", "/dashboard", "/portal", "/main", "/test",
}
STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map",
              ".txt", ".md", ".webp")
# Признаки атаки в параметрах: для уязвимостей, где эксплойт — в параметрах обычной страницы
PAYLOAD_RE = (r"(?:\.\./|%2e%2e|<script|%3cscript|union(?:\s|\+|%20)+(?:all(?:\s|\+|%20)+)?select|\$\{jndi|"
              r"%24%7bjndi|/etc/passwd|/etc/shadow|php://|file://|data://|expect://|sleep\(|sleep%28|benchmark\(|"
              r"waitfor(?:\s|\+|%20)+delay|[;|`]\s*(?:id|cat|wget|curl|uname|whoami)\b|%3b(?:id|cat|wget|curl)|"
              r"\$\(|%24%28|\{\{.*\}\}|%7b%7b|<\?php|%3c%3fphp|onerror=|javascript:)")


# =============================================================================
#  Разбор источников
# =============================================================================
def fetch_bytes(url: str, timeout: int = 90, limit: int = MAX_DOWNLOAD, headers: Optional[Dict[str, str]] = None
                ) -> bytes:
    if url.startswith("file://"):
        return Path(url[7:]).read_bytes()
    req = urllib.request.Request(url, headers={"User-Agent": "NginxManager-VulnDB/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — адреса источников фиксированы
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"файл больше {limit // 1048576} МБ")
    return data


def fetch_first(urls: Iterable[str], **kw) -> Tuple[bytes, str]:
    """Первый доступный из адресов (официальный, затем зеркала)."""
    errors = []
    for u in urls:
        try:
            return fetch_bytes(u, **kw), u
        except Exception as e:  # noqa: BLE001
            errors.append(f"{urllib.parse.urlparse(u).netloc}: {_err(e)}")
    raise ValueError("; ".join(errors))


def _err(e: Exception) -> str:
    from .service import feed_error
    return feed_error(e)


def parse_kev(data: bytes) -> Dict[str, Dict[str, Any]]:
    doc = json.loads(data)
    out = {}
    for v in doc.get("vulnerabilities") or []:
        cve = str(v.get("cveID") or "").upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
            continue
        out[cve] = {"vendor": v.get("vendorProject") or "", "product": v.get("product") or "",
                    "name": v.get("vulnerabilityName") or "", "description": v.get("shortDescription") or "",
                    "kev_added": v.get("dateAdded") or "", "kev_due": v.get("dueDate") or "",
                    "ransomware": 1 if str(v.get("knownRansomwareCampaignUse") or "").lower() == "known" else 0,
                    "kev_action": (v.get("requiredAction") or "")[:500], "cwe": ",".join(v.get("cwes") or [])}
    return out


def parse_nuclei_index(data: bytes) -> Dict[str, Dict[str, Any]]:
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        cve = str(r.get("ID") or "").upper()
        fp = r.get("file_path") or ""
        if not cve.startswith("CVE-") or not fp.startswith("http/"):
            continue
        info = r.get("Info") or {}
        try:
            cvss = float((info.get("Classification") or {}).get("CVSSScore") or 0)
        except ValueError:
            cvss = 0.0
        out[cve] = {"name": info.get("Name") or "", "severity": (info.get("Severity") or "").lower(),
                    "description": (info.get("Description") or "").strip(), "cvss": cvss, "template": fp}
    return out


def parse_epss(data: bytes) -> Dict[str, Tuple[float, float]]:
    """CSV FIRST EPSS (может быть сжат gzip): cve,epss,percentile; первая строка — комментарий с датой модели."""
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    out = {}
    for row in csv.reader(io.StringIO(data.decode("utf-8", "replace"))):
        if len(row) < 3 or not row[0].startswith("CVE-"):
            continue
        try:
            out[row[0].upper()] = (float(row[1]), float(row[2]))
        except ValueError:
            continue
    return out


def cvelist_url(cve: str) -> str:
    _, year, num = cve.split("-", 2)
    return CVELIST_RAW.format(year=year, group=int(num) // 1000, cve=cve)


def _cvss(metrics: List[Dict[str, Any]]) -> Tuple[float, str]:
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        for m in metrics or []:
            c = m.get(key)
            if isinstance(c, dict) and c.get("baseScore"):
                try:
                    return float(c["baseScore"]), str(c.get("vectorString") or "")
                except (TypeError, ValueError):
                    continue
    return 0.0, ""


def _ranges(items: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Затронутые версии в виде диапазонов: [{product, v, lt, lte}] (v — нижняя граница или точная версия)."""
    out: List[Dict[str, str]] = []
    for a in (items or [])[:6]:
        name = " ".join(x for x in (a.get("vendor"), a.get("product")) if x and x != "n/a")
        for v in (a.get("versions") or [])[:30]:
            if v.get("status") != "affected":
                continue
            r = {"product": name[:80], "v": str(v.get("version") or "")[:40]}
            if v.get("lessThan"):
                r["lt"] = str(v["lessThan"])[:40]
            if v.get("lessThanOrEqual"):
                r["lte"] = str(v["lessThanOrEqual"])[:40]
            if r["v"] or r.get("lt") or r.get("lte"):
                out.append(r)
    return out[:60]


def _vnum(v: str) -> List[int]:
    return [int(x) for x in re.findall(r"\d+", v)[:6]]


def _vcmp(a: List[int], b: List[int]) -> int:
    n = max(len(a), len(b))
    a, b = a + [0] * (n - len(a)), b + [0] * (n - len(b))
    return (a > b) - (a < b)


def version_affected(version: str, ranges: List[Dict[str, str]], product_words: Iterable[str] = ()
                     ) -> Optional[bool]:
    """Затронута ли версия: True / False / None (не с чем сравнить: нет версии или диапазонов)."""
    ver = _vnum(version or "")
    if not ver or not ranges:
        return None
    words = [w.strip().lower() for w in product_words if w.strip()]
    own = [r for r in ranges if any(w in f" {r.get('product', '')} ".lower().replace("_", " ") for w in words)]
    if words and not own:
        return None  # диапазоны только других продуктов записи (WP Squared в уязвимости cPanel — не WordPress)
    own = own or ranges
    usable = False
    for r in own:
        base = (r.get("v") or "").strip()
        wild = "*" in base or base.lower() in ("", "0", "n/a", "unspecified", "all")
        bnum = _vnum(base.split("*")[0]) if base else []
        prefix = bnum if "*" in base else []
        lt, lte = r.get("lt"), r.get("lte")
        if not lt and not lte:
            if not bnum or wild and not prefix:
                continue
            usable = True
            if (prefix and ver[:len(prefix)] == prefix) or (not prefix and _vcmp(ver, bnum) == 0):
                return True
            continue
        hi = _vnum(lt or lte or "")
        if not hi:
            continue
        usable = True
        if prefix and ver[:len(prefix)] != prefix:
            continue
        if bnum and not prefix and base.lower() not in ("0",) and _vcmp(ver, bnum) < 0:
            continue
        c = _vcmp(ver, hi)
        if (lt and c < 0) or (lte and c <= 0):
            return True
    return False if usable else None


def _affected(items: List[Dict[str, Any]]) -> str:
    out = []
    for a in (items or [])[:3]:
        name = " ".join(x for x in (a.get("vendor"), a.get("product")) if x and x != "n/a")
        vers = []
        for v in (a.get("versions") or [])[:6]:
            if v.get("status") != "affected":
                continue
            base = str(v.get("version") or "")
            low = "" if base in ("", "0", "*", "n/a", "unspecified") else base
            if v.get("lessThan"):
                vers.append(f"{low} … < {v['lessThan']}" if low else f"< {v['lessThan']}")
            elif v.get("lessThanOrEqual"):
                vers.append(f"{low} … ≤ {v['lessThanOrEqual']}" if low else f"≤ {v['lessThanOrEqual']}")
            elif low:
                vers.append(low)
        if name or vers:
            out.append(f"{name}: {', '.join(vers)}" if vers else name)
    return "; ".join(out)[:400]


def parse_cve_record(data: bytes) -> Dict[str, Any]:
    """Запись CVE JSON 5 (cvelistV5): CVSS (производитель, затем CISA-ADP), CWE, описание, затронутые версии."""
    d = json.loads(data)
    c = d.get("containers") or {}
    cna = c.get("cna") or {}
    adp = c.get("adp") or []
    cvss, vector = _cvss(cna.get("metrics") or [])
    for a in adp:
        if not cvss:
            cvss, vector = _cvss(a.get("metrics") or [])
    cwes = []
    for src in [cna] + adp:
        for pt in src.get("problemTypes") or []:
            for x in pt.get("descriptions") or []:
                cw = x.get("cweId") or ""
                if cw.startswith("CWE-") and cw not in cwes:
                    cwes.append(cw)
    desc = next((x.get("value") for x in cna.get("descriptions") or [] if str(x.get("lang", "")).startswith("en")),
                "") or ""
    affected = _affected(cna.get("affected") or []) or next(
        (_affected(a.get("affected") or []) for a in adp if a.get("affected")), "")
    ranges = _ranges(cna.get("affected") or []) or next(
        (_ranges(a.get("affected") or []) for a in adp if a.get("affected")), [])
    return {"cvss": cvss, "vector": vector, "cwe": ",".join(cwes[:4]), "description": desc.strip()[:2000],
            "published": str((d.get("cveMetadata") or {}).get("datePublished") or "")[:10], "affected": affected,
            "ranges": json.dumps(ranges, ensure_ascii=False)}


def parse_exploitdb(data: bytes) -> Dict[str, List[str]]:
    """files_exploits.csv из Exploit-DB: CVE → номера эксплойтов (EDB-ID)."""
    out: Dict[str, List[str]] = {}
    reader = csv.DictReader(io.StringIO(data.decode("utf-8", "replace")))
    for row in reader:
        for code in re.findall(r"CVE-\d{4}-\d{4,}", row.get("codes") or ""):
            lst = out.setdefault(code.upper(), [])
            if row.get("id") and len(lst) < 20:
                lst.append(row["id"])
    return out


_META = {k: re.compile(rx, re.M) for k, rx in {
    "cvss": r"^\s*cvss-score:\s*([\d.]+)", "epss": r"^\s*epss-score:\s*([\d.eE-]+)", "cwe": r"^\s*cwe-id:\s*(.+)$",
    "vendor": r"^\s*vendor:\s*['\"]?([^'\"\s]+)", "product": r"^\s*product:\s*['\"]?([^'\"\s]+)",
    "tags": r"^\s*tags:\s*(.+)$"}.items()}
_BASEURL_RE = re.compile(r"\{\{(?:BaseURL|RootURL)\}\}(/[^\"'\s]*)?")
_RAW_RE = re.compile(r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)\s+HTTP/", re.M)
_METHOD_RE = re.compile(r"^\s*-?\s*method:\s*(\w+)", re.M)


def parse_template(text: str) -> Dict[str, Any]:
    """Метаданные шаблона nuclei и HTTP-запросы: [(метод, путь с параметрами)]."""
    meta: Dict[str, Any] = {}
    for k, rx in _META.items():
        m = rx.search(text)
        if m:
            meta[k] = m.group(1).strip().strip("'\"")
    reqs: List[Tuple[str, str]] = []
    mm = _METHOD_RE.search(text)
    method = (mm.group(1).upper() if mm else "GET")
    for m in _BASEURL_RE.finditer(text):
        reqs.append((method, m.group(1) or "/"))
    for m in _RAW_RE.finditer(text):
        reqs.append((m.group(1), m.group(2)))
    meta["requests"] = reqs
    return meta


def norm_path(raw: str) -> Optional[str]:
    """Путь запроса → как его видит nginx в $uri: без параметров, декодирован, //→/, без «.» и «..»."""
    p = raw.split("?", 1)[0].split("#", 1)[0]
    if "{{" in p or not p.startswith("/"):
        return None
    p = urllib.parse.unquote(p)
    if any(c in p for c in "\"\\\x00\r\n\t{}"):
        return None
    trailing = p.endswith("/")
    parts: List[str] = []
    for seg in re.sub(r"/{2,}", "/", p).split("/")[1:]:
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    out = "/" + "/".join(parts)
    if trailing and out != "/":
        out += "/"
    return out


def exploit_paths(reqs: List[Tuple[str, str]]) -> Dict[str, str]:
    """Пути эксплойта шаблона → «a» (опасен сам путь: POST/PUT без видимых nginx параметров или путь без
    параметров) или «p» (нужен признак атаки в параметрах — эксплойт в параметрах обычной страницы)."""
    out: Dict[str, str] = {}
    for method, raw in reqs:
        p = norm_path(raw)
        if not p:
            continue
        has_query = "?" in raw and raw.split("?", 1)[1].strip() != ""
        traversal = ".." in raw or "%2e" in raw.lower()
        kind = "p" if has_query and method in ("GET", "HEAD") and not traversal else "a"
        if out.get(p) != "a":
            out[p] = kind
    return out


def usable_path(p: str) -> bool:
    low = p.lower()
    if low in GENERIC_PATHS or low.rstrip("/") in GENERIC_PATHS or not 5 <= len(p) <= MAX_PATH:
        return False
    if low.endswith(STATIC_EXT):
        return False
    if low.startswith("/.well-known/") or low.startswith("/.nm-"):
        return False
    return True


def builtin_coverage() -> Dict[str, List[str]]:
    """CVE → правила встроенного каталога фильтра запросов, которые закрывают уязвимость."""
    out: Dict[str, List[str]] = {}
    for r in W.RULES:
        for c in re.findall(r"CVE-\d{4}-\d{4,}", r.cve or ""):
            out.setdefault(c, []).append(r.id)
    return out


# =============================================================================
#  База
# =============================================================================
class VulnDB:
    def __init__(self, svc) -> None:
        self.svc = svc
        self.app = svc.app
        self.db = svc.db
        self.running = False
        self.progress = ""

    # ------------------------------------------------------------------ состояние
    def status(self) -> Dict[str, Any]:
        return self.db.kv_get("vulndb_status", {}) or {}

    def due(self, src: str, p, now: float, st: Optional[Dict[str, Any]] = None) -> bool:
        """Пора обновлять источник: прошёл интервал с удачного обновления, а после неудачной попытки — не чаще
        раза в час."""
        s = (st if st is not None else self.status()).get(src) or {}
        every = p.vulndb_update_hours * 3600
        return now - (s.get("updated") or 0) >= every and now - (s.get("tried") or 0) >= min(every, 3600)

    def _set_status(self, src: str, **kw) -> None:
        st = self.status()
        st[src] = {**(st.get(src) or {}), **kw}
        self.db.kv_set("vulndb_status", st)

    @staticmethod
    def dir() -> Path:
        d = settings.data_dir / "vulndb"
        (d / "tpl").mkdir(parents=True, exist_ok=True)
        return d

    def summary(self) -> Dict[str, Any]:
        q = self.db.one
        tot = q("SELECT COUNT(*) AS n, SUM(kev) AS kev, SUM(CASE WHEN paths!='' AND paths!='{}' THEN 1 ELSE 0 END) AS "
                "patched, SUM(CASE WHEN covered!='' THEN 1 ELSE 0 END) AS covered, SUM(ransomware) AS ransomware, "
                "SUM(CASE WHEN exploits!='' AND kev=1 THEN 1 ELSE 0 END) AS exploits FROM vulns") or {}
        week = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 7 * 86400))
        new = q("SELECT COUNT(*) AS n FROM vulns WHERE kev=1 AND kev_added>=?", (week,)) or {}
        live = q("SELECT COUNT(*) AS n FROM vulns WHERE active=1") or {}
        seen = q("SELECT COUNT(*) AS n, SUM(seen) AS hits FROM vulns WHERE seen>0") or {}
        kc, ka = self._kw_sql(self.watch_keywords())
        mine = q(f"SELECT COUNT(*) AS n, SUM(kev) AS kev FROM vulns WHERE {kc}", ka) or {}
        p = self.svc.settings()
        return {"total": tot.get("n") or 0, "kev": tot.get("kev") or 0, "patched": tot.get("patched") or 0,
                "covered": tot.get("covered") or 0, "ransomware": tot.get("ransomware") or 0,
                "exploits": tot.get("exploits") or 0,
                "kev_week": new.get("n") or 0, "active_paths": live.get("n") or 0,
                "seen": seen.get("n") or 0, "seen_hits": seen.get("hits") or 0,
                "mine": mine.get("n") or 0, "mine_kev": mine.get("kev") or 0, "watch": self.watch_keywords(),
                "map_entries": (self.db.kv_get("vulndb_map", {}) or {}).get("entries", 0),
                "sources": self.status(), "titles": SOURCES, "running": self.running, "progress": self.progress,
                "enabled": p.vulndb_enabled, "mode": p.mode("vuln"),
                "next": (max((s.get("updated") or 0) for s in self.status().values()) if self.status() else 0)
                + p.vulndb_update_hours * 3600}

    # ------------------------------------------------------------------ обновление
    async def update(self, force: bool = False, user: str = "system") -> Dict[str, Any]:
        if self.running:
            return {"ok": False, "error": "обновление уже идёт", "status": self.status()}
        self.running = True
        try:
            res = await asyncio.to_thread(self._update_sync, force)
            ok, out = await self.write_map()
            res["map"] = {"ok": ok, "output": "" if ok else out[-1500:]}
            if self.svc.settings().crs_source == "github":
                res["crs"] = await self.update_crs(force=force, user=user)
            return res
        finally:
            self.running = False
            self.progress = ""

    def _update_sync(self, force: bool) -> Dict[str, Any]:
        p = self.svc.settings()
        now = time.time()
        st = self.status()
        due = lambda src: force or self.due(src, p, now, st)  # noqa: E731
        kev: Dict[str, Dict[str, Any]] = {}
        nuc: Dict[str, Dict[str, Any]] = {}
        res: Dict[str, Any] = {"ok": True}
        # --- CISA KEV
        if p.vulndb_kev and due("kev"):
            self.progress = "CISA KEV"
            try:
                data, url = fetch_first(KEV_URLS, timeout=60, limit=50 * 1048576)
                kev = parse_kev(data)
                if not kev:
                    raise ValueError("каталог пуст")
                self._set_status("kev", ok=True, count=len(kev), updated=now, error="", url=url)
            except Exception as e:  # noqa: BLE001
                self._set_status("kev", ok=False, error=str(e)[:400], tried=now)
                res["ok"] = False
        # --- nuclei: индекс
        if p.vulndb_nuclei and due("nuclei"):
            self.progress = "nuclei-templates: индекс"
            try:
                nuc = parse_nuclei_index(fetch_bytes(NUCLEI_INDEX, timeout=90, limit=60 * 1048576))
                if not nuc:
                    raise ValueError("индекс пуст")
                self._set_status("nuclei", ok=True, count=len(nuc), updated=now, error="")
            except Exception as e:  # noqa: BLE001
                self._set_status("nuclei", ok=False, error=_err(e)[:400], tried=now)
                res["ok"] = False
        if kev or nuc:
            self._merge(kev, nuc, now)
        # --- шаблоны (пути эксплойтов) для выбранного охвата
        if p.vulndb_nuclei and (nuc or due("templates")):
            self.progress = "nuclei-templates: шаблоны"
            try:
                n = self._templates(p, now)
                self._set_status("templates", ok=True, count=n, updated=now, error="")
            except Exception as e:  # noqa: BLE001
                self._set_status("templates", ok=False, error=_err(e)[:400], tried=now)
        # --- EPSS
        if p.vulndb_epss and due("epss"):
            self.progress = "FIRST EPSS"
            try:
                data, url = fetch_first(EPSS_URLS, timeout=120, limit=100 * 1048576)
                ep = parse_epss(data)
                if not ep:
                    raise ValueError("файл пуст")
                rows = [(e, pc, cve) for cve, (e, pc) in ep.items()]
                self.db.executemany("UPDATE vulns SET epss=?, epss_pct=? WHERE cve=?", rows)
                self._set_status("epss", ok=True, count=len(ep), updated=now, error="", url=url)
            except Exception as e:  # noqa: BLE001
                self._set_status("epss", ok=False, error=str(e)[:400], tried=now)
        # --- CVE Program: CVSS, CWE и затронутые версии для эксплуатируемых уязвимостей
        if p.vulndb_cvelist and (kev or due("cvelist")):
            self.progress = "CVE Program: записи уязвимостей"
            try:
                n, failed = self._enrich(now)
                if n == 0 and failed:
                    raise ValueError(f"записи не загружены ({failed} ошибок)")
                total = (self.db.one("SELECT COUNT(*) AS n FROM vulns WHERE enriched IS NOT NULL") or {}).get("n", 0)
                self._set_status("cvelist", ok=True, count=total, updated=now, error="", failed=failed)
            except Exception as e:  # noqa: BLE001
                self._set_status("cvelist", ok=False, error=_err(e)[:400], tried=now)
        # --- Exploit-DB: опубликованные эксплойты
        if p.vulndb_exploitdb and due("exploitdb"):
            self.progress = "Exploit-DB"
            try:
                data, url = fetch_first(EXPLOITDB_URLS, timeout=120, limit=80 * 1048576)
                ex = parse_exploitdb(data)
                if not ex:
                    raise ValueError("в файле нет ссылок на CVE")
                self.db.execute("UPDATE vulns SET exploits=''")
                self.db.executemany("UPDATE vulns SET exploits=? WHERE cve=?",
                                    [(",".join(v), k) for k, v in ex.items()])
                self._set_status("exploitdb", ok=True, count=len(ex), updated=now, error="", url=url)
            except Exception as e:  # noqa: BLE001
                self._set_status("exploitdb", ok=False, error=str(e)[:400], tried=now)
        # --- Wordfence Intelligence: уязвимости плагинов, тем и ядра WordPress
        if p.wordfence_key and due("wordfence"):
            self.progress = "Wordfence Intelligence"
            try:
                n = self._wordfence(p.wordfence_key)
                self._set_status("wordfence", ok=True, count=n, updated=now, error="")
            except Exception as e:  # noqa: BLE001
                self._set_status("wordfence", ok=False, error=_err(e)[:400], tried=now)
        # --- дистрибутивы: исправления в пакетах Ubuntu и Debian
        if p.vulndb_distro:
            self.progress = "Ubuntu и Debian"
            self.update_distro(force=force)
        self.mark_coverage()
        return res

    def _wordfence(self, key: str) -> int:
        """Лента Wordfence (production) потоково → таблица wp_vulns (записи источника заменяются целиком)."""
        resp = WPM.open_feed(key)
        try:
            rows = list(WPM.feed_rows(WPM.iter_feed(WPM.Capped(resp))))
        finally:
            resp.close()
        if not rows:
            raise ValueError("лента пуста")
        with self.db.write_lock:
            c = self.db.conn()
            c.execute("BEGIN")
            try:
                c.execute("DELETE FROM wp_vulns WHERE source='wordfence'")
                c.executemany("INSERT OR REPLACE INTO wp_vulns(id,slug,type,name,title,cve,cvss,ranges,patched,"
                              "published,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows)
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        return len(rows)

    # ------------------------------------------------------------------ дистрибутивы
    def distro_data(self, cve: str, distro: str) -> Optional[Dict[str, Any]]:
        r = self.db.one("SELECT data, ok FROM distro_cve WHERE cve=? AND distro=?", (cve, distro))
        if not r or not r["ok"]:
            return None
        try:
            return json.loads(r["data"])
        except ValueError:
            return None

    def update_distro(self, force: bool = False) -> Dict[str, Any]:
        """Данные Ubuntu и Debian по уязвимостям, которые затрагивают основную версию продуктов из сборок
        дистрибутивов на ваших сайтах (раз в 3 суток на уязвимость, после ошибки — через час)."""
        now = time.time()
        need: Set[Tuple[str, str]] = set()
        for r in self.tech().values():
            for t in r.get("tech") or []:
                if t.get("distro") in DI.SUPPORTED and t.get("version"):
                    for a in self.upstream_affected(t):
                        need.add((a["cve"], t["distro"]))
        if not need:
            return {"ok": True, "count": 0}
        old = {(r["cve"], r["distro"]): r for r in self.db.query("SELECT cve, distro, fetched, ok FROM distro_cve")}
        todo = [k for k in sorted(need) if force or k not in old or
                now - old[k]["fetched"] >= (DISTRO_TTL if old[k]["ok"] else 3600)][:400]

        def one(key):
            cve, dist = key
            u = DI.urls(dist, cve)
            data: Dict[str, Any] = {"osv": [], "vex": []}
            got = False
            for kind, parse in (("osv", DI.parse_osv), ("vex", DI.parse_vex)):
                for url in u[kind]:
                    try:
                        data[kind] = parse(fetch_bytes(url, timeout=30, limit=8 * 1048576))
                        got = True
                        break
                    except urllib.error.HTTPError as e:
                        if e.code == 404:  # у дистрибутива нет записи — тоже ответ
                            got = True
                            break
                    except Exception:  # noqa: BLE001 — следующий адрес
                        continue
            return cve, dist, data, got
        with ThreadPoolExecutor(6) as ex:
            res = list(ex.map(one, todo))
        self.db.executemany("INSERT OR REPLACE INTO distro_cve(cve, distro, data, fetched, ok) VALUES(?,?,?,?,?)",
                            [(c, d, json.dumps(data), now, 1 if got else 0) for c, d, data, got in res])
        okn = sum(1 for *_x, got in res if got)
        total = (self.db.one("SELECT COUNT(*) AS n FROM distro_cve WHERE ok=1") or {}).get("n", 0)
        if todo and not okn:
            self._set_status("distro", ok=False, error="данные Ubuntu и Debian не загружены (нет связи с GitHub и "
                                                       "api.osv.dev)", tried=now)
        else:
            self._set_status("distro", ok=True, count=total, updated=now, error="")
        return {"ok": bool(okn) or not todo, "fetched": okn, "count": total}

    def _enrich(self, now: float) -> Tuple[int, int]:
        """Загрузить записи CVE (cvelistV5) для эксплуатируемых уязвимостей: новых и устаревших (старше 30 дней)."""
        rows = self.db.query("SELECT cve FROM vulns WHERE (kev=1 OR wp!='') AND (enriched IS NULL OR enriched<? OR "
                             "ranges='') "
                             "ORDER BY enriched IS NOT NULL, kev_added DESC LIMIT ?", (now - ENRICH_TTL, MAX_ENRICH))

        def one(cve: str):
            try:
                return cve, parse_cve_record(fetch_bytes(cvelist_url(cve), timeout=30, limit=4 * 1048576))
            except Exception:  # noqa: BLE001
                return cve, None
        with ThreadPoolExecutor(8) as ex:
            got = list(ex.map(one, [r["cve"] for r in rows]))
        ok = [{**r, "now": now, "cve": cve} for cve, r in got if r]
        self.db.executemany(
            "UPDATE vulns SET cvss=CASE WHEN :cvss>0 THEN :cvss ELSE cvss END, "
            "severity=CASE WHEN severity!='' THEN severity WHEN :cvss>=9 THEN 'critical' WHEN :cvss>=7 THEN 'high' "
            "WHEN :cvss>=4 THEN 'medium' WHEN :cvss>0 THEN 'low' ELSE '' END, cvss_vector=:vector, "
            "cwe=CASE WHEN :cwe!='' THEN :cwe ELSE cwe END, "
            "description=CASE WHEN length(description)<40 AND :description!='' THEN :description ELSE description END, "
            "published=:published, affected=:affected, ranges=:ranges, enriched=:now WHERE cve=:cve", ok)
        return len(ok), len(got) - len(ok)

    def _merge(self, kev: Dict[str, Dict[str, Any]], nuc: Dict[str, Dict[str, Any]], now: float) -> None:
        old_kev = {r["cve"] for r in self.db.query("SELECT cve FROM vulns WHERE kev=1")}
        rows = []
        existing = {r["cve"]: r for r in self.db.query("SELECT * FROM vulns")}
        for cve in set(kev) | set(nuc):
            k, n, e = kev.get(cve, {}), nuc.get(cve, {}), existing.get(cve, {})
            sev = n.get("severity") or e.get("severity") or ""
            rows.append((cve, n.get("name") or k.get("name") or e.get("name") or "",
                         k.get("vendor") or e.get("vendor") or "", k.get("product") or e.get("product") or "",
                         (n.get("description") or k.get("description") or e.get("description") or "")[:2000],
                         sev, n.get("cvss") or e.get("cvss") or 0, 1 if (k or (e.get("kev") and not kev)) else 0,
                         k.get("kev_added") or e.get("kev_added") or "", k.get("kev_due") or e.get("kev_due") or "",
                         k.get("ransomware", e.get("ransomware") or 0), k.get("kev_action") or e.get("kev_action") or "",
                         k.get("cwe") or e.get("cwe") or "", n.get("template") or e.get("template") or "", now))
        self.db.executemany(
            "INSERT INTO vulns(cve,name,vendor,product,description,severity,cvss,kev,kev_added,kev_due,ransomware,"
            "kev_action,cwe,template,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET "
            "name=excluded.name, vendor=CASE WHEN excluded.vendor!='' THEN excluded.vendor ELSE vendor END, "
            "product=CASE WHEN excluded.product!='' THEN excluded.product ELSE product END, "
            "description=excluded.description, severity=excluded.severity, cvss=excluded.cvss, kev=excluded.kev, "
            "kev_added=excluded.kev_added, kev_due=excluded.kev_due, ransomware=excluded.ransomware, "
            "kev_action=excluded.kev_action, cwe=CASE WHEN excluded.cwe!='' THEN excluded.cwe ELSE cwe END, "
            "template=excluded.template, updated=excluded.updated", rows)
        if kev and old_kev:
            new = sorted(set(kev) - old_kev)
            if new:
                self._announce_new(new, kev)

    # ------------------------------------------------------------------ технологии сайтов
    def tech(self) -> Dict[str, Any]:
        return self.db.kv_get("site_tech", {}) or {}

    def scan_tech(self, only: Optional[int] = None) -> Dict[str, Any]:
        """Определить технологии сайтов-прокси (по главной странице с бэкенда)."""
        from .fingerprint import scan_site
        res = self.tech()
        live = set()
        for sid, site in self.app.nginx.load_state().sites:
            if not site.enabled or (only is not None and sid != only):
                live.add(str(sid))
                continue
            live.add(str(sid))
            res[str(sid)] = {**scan_site(site, self.svc.settings().vulndb_tech_probe), "name": site.name}
        res = {k: v for k, v in res.items() if k in live}
        self.db.kv_set("site_tech", res)
        return res

    def tech_keywords(self) -> List[str]:
        from .fingerprint import keywords
        ids = sorted({t["id"] for r in self.tech().values() for t in r.get("tech") or []})
        return keywords(ids)

    def watch_keywords(self) -> List[str]:
        p = self.svc.settings()
        out = [w.lower() for w in p.vulndb_watch]
        if p.vulndb_watch_auto:
            out += [k for k in self.tech_keywords() if k not in out]
        return out

    @staticmethod
    def _kw_sql(keywords: List[str]) -> Tuple[str, List[str]]:
        if not keywords:
            return "0", []
        expr = "(' ' || lower(replace(vendor || ' ' || product, '_', ' ')) || ' ')"
        return "(" + " OR ".join(f"{expr} LIKE ?" for _ in keywords) + ")", [f"%{k}%" for k in keywords]

    def tech_vulns(self) -> List[Dict[str, Any]]:
        """Сайты → найденные продукты с числом эксплуатируемых уязвимостей и попыток их эксплуатации."""
        from .fingerprint import TECH_BY_ID
        cache: Dict[str, Dict[str, int]] = {}
        out = []
        for sid, r in sorted(self.tech().items(), key=lambda kv: kv[1].get("name", "")):
            items = []
            for t in r.get("tech") or []:
                tech = TECH_BY_ID.get(t["id"])
                if t["id"] not in cache:
                    cond, args = self._kw_sql(list(tech.keywords) if tech and tech.cat != "js" else [])
                    row = self.db.one(f"SELECT SUM(kev) AS kev, COUNT(*) AS n, SUM(seen) AS seen, "
                                      f"SUM(CASE WHEN kev=1 AND kev_added>=? THEN 1 ELSE 0 END) AS recent "
                                      f"FROM vulns WHERE {cond}",
                                      [time.strftime("%Y-%m-%d", time.gmtime(time.time() - 90 * 86400))] + args) or {}
                    cache[t["id"]] = {"kev": row.get("kev") or 0, "total": row.get("n") or 0,
                                      "seen": row.get("seen") or 0, "recent": row.get("recent") or 0}
                aff = self.installed_affected(t) if t.get("version") else []
                may = self.installed_affected(t, maybe=True) if t.get("version") else []
                items.append({**t, **cache[t["id"]], "affected": aff[:20], "affected_n": len(aff),
                              "maybe": may[:20], "maybe_n": len(may)})
            out.append({"site": sid, "name": r.get("name", sid), "ts": r.get("ts"), "error": r.get("error", ""),
                        "skipped": r.get("skipped", ""), "target": r.get("target", ""), "tech": items,
                        "wp": self.wp_installed(r.get("wp") or {})})
        return out

    # ------------------------------------------------------------------ плагины и темы WordPress
    def wp_vulns_for(self, kind: str, slug: str, version: str) -> List[Dict[str, Any]]:
        """Уязвимости плагина или темы: из Wordfence (по диапазонам версий) и из шаблонов nuclei (по записям CVE).
        affected: True — версия затронута, False — нет, None — версия неизвестна."""
        out: Dict[str, Dict[str, Any]] = {}
        for r in self.db.query("SELECT * FROM wp_vulns WHERE type=? AND slug=?", (kind, slug)):
            try:
                rng = json.loads(r["ranges"])
            except ValueError:
                rng = []
            key = r["cve"] or r["id"]
            out[key] = {"cve": r["cve"], "title": r["title"], "cvss": r["cvss"], "patched": r["patched"],
                        "name": r["name"], "affected": WPM.in_ranges(version, rng) if version else None,
                        "source": "wordfence", "exploit": False, "kev": False}
        for r in self.db.query("SELECT cve, name, cvss, kev, exploits, template, ranges FROM vulns WHERE wp=?",
                               (f"{kind}:{slug}",)):
            try:
                rng = json.loads(r["ranges"] or "[]")
            except ValueError:
                rng = []
            cur = out.get(r["cve"])
            if cur:
                cur.update(exploit=True, kev=bool(r["kev"]))
                continue
            aff = version_affected(version, rng) if version else None
            if aff is None and version:  # в записи CVE версий нет («n/a») — по названию шаблона
                aff = WPM.in_ranges(version, WPM.ranges_from_title(r["name"] or ""))
            out[r["cve"]] = {"cve": r["cve"], "title": r["name"], "cvss": r["cvss"], "patched": "", "name": "",
                             "affected": aff, "source": "nuclei", "exploit": True, "kev": bool(r["kev"])}
        return sorted(out.values(), key=lambda x: (x["affected"] is not True, -(x["cvss"] or 0), x["cve"]))

    def wp_installed(self, wp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Плагины и темы сайта с уязвимостями: затрагивают установленную версию, возможно (версия неизвестна)."""
        out = []
        for kind, items in (("plugin", wp.get("plugins") or []), ("theme", wp.get("themes") or [])):
            for it in items:
                vs = self.wp_vulns_for(kind, it["slug"], it.get("version", ""))
                aff = [v for v in vs if v["affected"] is True]
                may = [v for v in vs if v["affected"] is None]
                name = next((v["name"] for v in vs if v.get("name")), "")
                out.append({"type": kind, "slug": it["slug"], "name": name or it["slug"],
                            "version": it.get("version", ""), "evidence": it.get("evidence", ""),
                            "affected": aff[:20], "affected_n": len(aff), "maybe_n": len(may), "known": len(vs)})
        return sorted(out, key=lambda x: (-x["affected_n"], x["type"], x["slug"]))

    def installed_affected(self, t: Dict[str, Any], maybe: bool = False) -> List[Dict[str, Any]]:
        """Эксплуатируемые уязвимости, которым подвержена найденная версия продукта (с учётом исправлений
        дистрибутива). maybe=True — те, что «зависят от версии пакета» (заголовок называет дистрибутив, но не
        версию пакета, а дистрибутив исправил уязвимость в своей сборке)."""
        p = self.svc.settings()
        out = []
        for a in self.upstream_affected(t):
            note, state = "", True
            dist = t.get("distro") or ""
            if p.vulndb_distro and dist in DI.SUPPORTED:
                data = self.distro_data(a["cve"], dist)
                verd = DI.verdict(data, DI.packages(t["id"], t["version"]), t["version"], t.get("pkgver", "")) \
                    if data else None
                state = DI.affected_from(verd, True)
                note = DI.describe(verd)
            elif p.vulndb_distro and dist in ("rhel", "fedora", "alpine"):
                state, note = None, (f"сборка {DI.NAMES.get(dist, dist)}: исправления переносятся без смены версии — "
                                     f"проверьте журнал изменений пакета (rpm -q --changelog)")
            if state is True and not maybe:
                out.append({**a, "note": note})
            elif state is None and maybe:
                out.append({**a, "note": note})
        return out

    def upstream_affected(self, t: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Эксплуатируемые уязвимости по основной версии продукта (без учёта сборок дистрибутивов)."""
        from .fingerprint import TECH_BY_ID
        tech = TECH_BY_ID.get(t["id"])
        if not tech or tech.cat == "js" or not t.get("version"):
            return []
        cond, args = self._kw_sql(list(tech.keywords))
        out = []
        for r in self.db.query(f"SELECT cve, name, cvss, ransomware, kev_added, ranges FROM vulns "
                               f"WHERE kev=1 AND ranges NOT IN ('', '[]') AND {cond}", args):
            try:
                rng = json.loads(r["ranges"])
            except ValueError:
                continue
            if version_affected(t["version"], rng, tech.keywords):
                out.append({"cve": r["cve"], "name": r["name"], "cvss": r["cvss"], "ransomware": r["ransomware"],
                            "kev_added": r["kev_added"]})
        return sorted(out, key=lambda x: (-(x["cvss"] or 0), x["cve"]))

    def _announce_new(self, new: List[str], kev: Dict[str, Dict[str, Any]]) -> None:
        watch = self.watch_keywords()
        hits = [c for c in new if any(w in f" {kev[c]['vendor']} {kev[c]['product']} ".lower().replace("_", " ")
                                      for w in watch)]
        names = ", ".join(f"{c} ({kev[c]['vendor']} {kev[c]['product']})" for c in new[:6])
        self.db.event("warning" if hits else "info", "protection",
                      f"Новые эксплуатируемые уязвимости в каталоге CISA KEV: {len(new)} — {names}"
                      + (f"; среди них ваши продукты: {', '.join(hits[:6])}" if hits else ""),
                      {"cves": new[:100], "watch": hits[:100]})
        self.db.kv_set("vulndb_new", {"ts": time.time(), "cves": new[:200], "watch": hits[:200]})

    def selected(self, p) -> List[Dict[str, Any]]:
        """Уязвимости с шаблоном nuclei в выбранном охвате карты путей."""
        cond = "kev=1"
        if p.vulndb_scope in ("critical", "high"):
            cond += " OR severity='critical'"
        if p.vulndb_scope == "high":
            cond += " OR severity='high'"
        return self.db.query(f"SELECT cve, template FROM vulns WHERE template LIKE 'http/%' AND ({cond})")

    def _templates(self, p, now: float) -> int:
        """Скачать недостающие (или устаревшие) шаблоны выбранного охвата, разобрать пути эксплойтов."""
        sel = list(self.selected(p))
        have = {r["cve"] for r in sel}
        sel += [r for r in self.wp_candidates() if r["cve"] not in have]
        tdir = self.dir() / "tpl"
        need = [r for r in sel if not (tdir / f"{r['cve']}.yaml").exists()
                or now - (tdir / f"{r['cve']}.yaml").stat().st_mtime > TEMPLATE_TTL]
        if len(need) > 200:
            try:
                self._templates_tarball({r["template"]: r["cve"] for r in need})
                need = [r for r in need if not (tdir / f"{r['cve']}.yaml").exists()]
            except Exception as e:  # noqa: BLE001 — архив недоступен: шаблоны по одному
                log.info("архив nuclei-templates недоступен (%s), загрузка шаблонов по одному", _err(e))

        def one(r):
            try:
                data = fetch_bytes(NUCLEI_RAW.format(path=r["template"]), timeout=30, limit=2 * 1048576)
                (tdir / f"{r['cve']}.yaml").write_bytes(data)
                return True
            except Exception:  # noqa: BLE001
                return False
        if need:
            with ThreadPoolExecutor(8) as ex:
                list(ex.map(one, need[:MAX_TEMPLATE_FETCH]))
        rows = []
        for r in sel:
            f = tdir / f"{r['cve']}.yaml"
            if not f.exists():
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            meta = parse_template(text)
            paths = exploit_paths(meta["requests"])
            try:
                epss = float(meta.get("epss") or 0)
            except ValueError:
                epss = 0.0
            try:
                cvss = float(meta.get("cvss") or 0)
            except ValueError:
                cvss = 0.0
            tags = meta.get("tags", "")
            wp = WPM.slug_from_template(text) if "wordpress" in tags.lower() or "/wp-content/" in text else ""
            rows.append((json.dumps(paths, ensure_ascii=False), tags[:300], epss, cvss,
                         meta.get("cwe", "")[:100], meta.get("vendor", ""), meta.get("product", ""), wp, r["cve"]))
        self.db.executemany(
            "UPDATE vulns SET paths=?, tags=?, epss=CASE WHEN epss>0 THEN epss ELSE ? END, "
            "cvss=CASE WHEN ?>0 THEN ? ELSE cvss END, cwe=CASE WHEN cwe='' THEN ? ELSE cwe END, "
            "vendor=CASE WHEN vendor='' THEN ? ELSE vendor END, product=CASE WHEN product='' THEN ? ELSE product END, "
            "wp=? WHERE cve=?", [(a, b, c, d, d, e, f, g, h, i) for a, b, c, d, e, f, g, h, i in rows])
        return len(rows)

    def has_wordpress(self) -> bool:
        return any(t["id"] == "wordpress" for r in self.tech().values() for t in r.get("tech") or [])

    def wp_candidates(self) -> List[Dict[str, Any]]:
        """Шаблоны уязвимостей WordPress (плагины, темы) — загружаются, если WordPress есть на ваших сайтах:
        путь плагина в шаблоне даёт его slug для сверки с установленными плагинами."""
        if not self.has_wordpress():
            return []
        return self.db.query("SELECT cve, template FROM vulns WHERE template LIKE 'http/%' AND "
                             "(lower(name) LIKE '%wordpress%' OR lower(name) LIKE '%wp %' OR "
                             "lower(description) LIKE '%wordpress%')")

    def _templates_tarball(self, want: Dict[str, str]) -> None:
        tdir = self.dir() / "tpl"
        data = fetch_bytes(NUCLEI_TARBALL, timeout=300, limit=MAX_DOWNLOAD)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf:
                if not m.isfile() or not m.name.endswith(".yaml"):
                    continue
                rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
                cve = want.get(rel)
                if cve:
                    f = tf.extractfile(m)
                    if f:
                        (tdir / f"{cve}.yaml").write_bytes(f.read(2 * 1048576))

    def mark_coverage(self) -> None:
        cov = builtin_coverage()
        self.db.execute("UPDATE vulns SET covered=''")
        self.db.executemany("UPDATE vulns SET covered=? WHERE cve=?", [(",".join(v), k) for k, v in cov.items()])

    # ------------------------------------------------------------------ карта путей для nginx
    def legit_paths(self, days: int = 14, min_ips: int = 3) -> Set[str]:
        """Пути, которые сайты успешно отдают обычным посетителям: 2xx/3xx нескольким адресам, за которыми нет
        ни одного события защиты (сканеры получают 200 от приложений, отвечающих на любой путь)."""
        since = time.time() - days * 86400
        try:
            rows = self.db.query(
                "SELECT CASE WHEN instr(uri,'?')>0 THEN substr(uri,1,instr(uri,'?')-1) ELSE uri END AS path "
                "FROM requests WHERE ts>=? AND status>=200 AND status<400 "
                "AND ip NOT IN (SELECT DISTINCT ip FROM attack_log WHERE ts>=?) GROUP BY path "
                "HAVING COUNT(DISTINCT ip)>=?", (since, since, min_ips))
        except Exception:  # noqa: BLE001 — журнал запросов может быть выключен
            return set()
        return {norm_path(r["path"]) or r["path"] for r in rows}

    def build_map(self) -> Tuple[str, Dict[str, Any]]:
        p = self.svc.settings()
        lines = ["# Nginx Manager: пути эксплойтов известных уязвимостей (раздел «Защита → Уязвимости»).",
                 "# Файл обновляется панелью; значение — «CVE:a» (опасен путь) или «CVE:p» (нужен признак атаки)."]
        stats = {"entries": 0, "generic": 0, "shared": 0, "legit": 0, "excluded": 0}
        if not p.vulndb_enabled or p.mode("vuln") == "off":
            self.db.execute("UPDATE vulns SET active=0")
            return "\n".join(lines) + "\n", stats
        sel = {r["cve"] for r in self.selected(p)}
        by_path: Dict[str, List[Tuple[int, float, str, str]]] = {}
        for r in self.db.query("SELECT cve, kev, cvss, paths FROM vulns WHERE paths!='' AND paths!='{}'"):
            if r["cve"] not in sel:
                continue
            if r["cve"] in p.vulndb_exclude:
                stats["excluded"] += 1
                continue
            for path, kind in json.loads(r["paths"]).items():
                by_path.setdefault(path, []).append((-(r["kev"] or 0), -(r["cvss"] or 0), r["cve"], kind))
        legit = self.legit_paths() if p.vulndb_skip_legit else set()
        user_ex = [x for x in p.vulndb_exclude_paths]
        active: Set[str] = set()
        for path in sorted(by_path):
            cands = sorted(by_path[path])
            if not usable_path(path):
                stats["generic"] += 1
                continue
            if len({c[2] for c in cands}) >= 4:
                stats["shared"] += 1
                continue
            if path in legit or path.rstrip("/") in legit:
                stats["legit"] += 1
                continue
            if any(path.startswith(x) for x in user_ex):
                stats["excluded"] += 1
                continue
            best = cands[0]
            kind = "a" if any(c[3] == "a" for c in cands if c[2] == best[2]) else "p"
            lines.append(f"{W.nginx_quote(path)} \"{best[2]}:{kind}\";")
            active.add(best[2])
            stats["entries"] += 1
        self.db.execute("UPDATE vulns SET active=0")
        self.db.executemany("UPDATE vulns SET active=1 WHERE cve=?", [(c,) for c in active])
        stats["cves"] = len(active)
        stats["built"] = time.time()
        return "\n".join(lines) + "\n", stats

    async def write_map(self) -> Tuple[bool, str]:
        content, stats = await asyncio.to_thread(self.build_map)
        mgr = self.app.nginx
        async with mgr.lock:
            ok, out = await asyncio.to_thread(mgr.write_side_file, settings.vuln_file, content)
        stats["ok"] = ok
        self.db.kv_set("vulndb_map", stats)
        if not ok:
            self.db.event("error", "protection", "Не удалось подключить карту путей эксплойтов к nginx",
                          {"output": out[-1500:]})
        return ok, out

    # ------------------------------------------------------------------ OWASP CRS с GitHub
    @staticmethod
    def crs_root() -> Path:
        d = settings.data_dir / "crs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @classmethod
    def active_crs(cls) -> str:
        """Каталог правил CRS, скачанный с GitHub и выбранный панелью ('' — пакет дистрибутива)."""
        f = cls.crs_root() / "ACTIVE"
        try:
            d = f.read_text().strip()
        except OSError:
            return ""
        return d if (Path(d) / "rules" / "REQUEST-901-INITIALIZATION.conf").is_file() else ""

    def install_crs(self, data: bytes, tag: str) -> Path:
        """Распаковать архив выпуска CRS (rules/ и crs-setup.conf.example) в data_dir/crs/<tag>/."""
        if not re.match(r"^v?\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?$", tag):
            raise ValueError(f"неожиданная метка выпуска «{tag}»")
        dest = self.crs_root() / tag
        tmp = self.crs_root() / f".{tag}.tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        (tmp / "rules").mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf:
                parts = m.name.split("/")
                if not m.isfile() or len(parts) < 2 or ".." in parts:
                    continue
                rel = parts[1:]
                if rel[0] == "rules" and len(rel) == 2 and rel[1].endswith((".conf", ".data")) or \
                        rel == ["crs-setup.conf.example"]:
                    f = tf.extractfile(m)
                    if f:
                        (tmp / "/".join(rel)).write_bytes(f.read(20 * 1048576))
        if not (tmp / "rules" / "REQUEST-901-INITIALIZATION.conf").is_file():
            shutil.rmtree(tmp, ignore_errors=True)
            raise ValueError("в архиве нет правил CRS (rules/REQUEST-901-INITIALIZATION.conf)")
        shutil.rmtree(dest, ignore_errors=True)
        tmp.rename(dest)
        for x in dest.rglob("*"):
            x.chmod(0o755 if x.is_dir() else 0o644)
        dest.chmod(0o755)
        return dest

    @staticmethod
    def latest_crs_tag() -> str:
        """Последний выпуск CRS: API GitHub, а если он недоступен — git ls-remote (git есть почти везде)."""
        try:
            info = json.loads(fetch_bytes(CRS_LATEST, 30, 2 * 1048576, {"Accept": "application/vnd.github+json"}))
            if info.get("tag_name"):
                return str(info["tag_name"])
        except Exception as e:  # noqa: BLE001
            api_err = _err(e)
        else:
            api_err = "в ответе нет tag_name"
        if not shutil.which("git"):
            raise ValueError(f"api.github.com: {api_err}; git не установлен")
        r = subprocess.run(["git", "ls-remote", "--tags", "--refs", CRS_GIT], capture_output=True, text=True,
                           timeout=60, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        tags = re.findall(r"refs/tags/(v\d+\.\d+\.\d+)$", r.stdout, re.M)
        if r.returncode != 0 or not tags:
            raise ValueError(f"api.github.com: {api_err}; git ls-remote: {(r.stderr or 'выпусков нет').strip()[-200:]}")
        return max(tags, key=lambda t: tuple(int(x) for x in t[1:].split(".")))

    @staticmethod
    def crs_archive(tag: str) -> bytes:
        """Архив выпуска: с GitHub, а если он недоступен — git clone выпуска и упаковка rules/ и примера настроек."""
        try:
            return fetch_bytes(CRS_TARBALL.format(tag=tag), 300, 100 * 1048576)
        except Exception as e:  # noqa: BLE001
            if not shutil.which("git"):
                raise
            err = _err(e)
        with tempfile.TemporaryDirectory(prefix="nm-crs-") as tmp:
            r = subprocess.run(["git", "-c", "advice.detachedHead=false", "clone", "-q", "--depth", "1", "--branch",
                                tag, CRS_GIT, f"{tmp}/src"], capture_output=True, text=True, timeout=600,
                               env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"})
            if r.returncode != 0:
                raise ValueError(f"архив: {err}; git clone: {r.stderr.strip()[-200:]}")
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                src = Path(tmp) / "src"
                for f in sorted((src / "rules").iterdir()):
                    if f.is_file():
                        tf.add(str(f), arcname=f"coreruleset-{tag}/rules/{f.name}")
                ex = src / "crs-setup.conf.example"
                if ex.is_file():
                    tf.add(str(ex), arcname=f"coreruleset-{tag}/crs-setup.conf.example")
            return buf.getvalue()

    def prune_crs(self, keep: str = "") -> None:
        """Удалить старые скачанные выпуски CRS, кроме выбранного и последних CRS_KEEP."""
        root = self.crs_root()
        dirs = sorted((d for d in root.iterdir() if d.is_dir() and not d.name.startswith(".")),
                      key=lambda d: d.stat().st_mtime, reverse=True)
        active = {Path(x).name for x in (keep, self.active_crs()) if x}
        for d in dirs[CRS_KEEP:]:
            if d.name not in active:
                shutil.rmtree(d, ignore_errors=True)

    async def update_crs(self, force: bool = False, user: str = "system", url: str = "") -> Dict[str, Any]:
        """Скачать последний выпуск CRS и переключиться на него через применение конфигурации (nginx -t);
        при ошибке — вернуть прежний каталог."""
        now = time.time()
        st = (self.status().get("crs") or {})
        try:
            if url:
                tag = st.get("tag") or "local"
                m = re.search(r"(v?\d+\.\d+\.\d+)", url)
                tag = m.group(1) if m else tag
            else:
                tag = await asyncio.to_thread(self.latest_crs_tag)
            cur = self.active_crs()
            if not force and cur and Path(cur).name == tag:
                self._set_status("crs", ok=True, tag=tag, updated=now, error="", dir=cur)
                return {"ok": True, "tag": tag, "changed": False}
            data = await asyncio.to_thread(fetch_bytes, url, 300, 100 * 1048576) if url else \
                await asyncio.to_thread(self.crs_archive, tag)
            dest = await asyncio.to_thread(self.install_crs, data, tag)
        except Exception as e:  # noqa: BLE001
            self._set_status("crs", ok=False, error=_err(e)[:400], tried=now)
            return {"ok": False, "error": _err(e)}
        prev = (self.crs_root() / "ACTIVE").read_text().strip() if (self.crs_root() / "ACTIVE").exists() else ""
        (self.crs_root() / "ACTIVE").write_text(str(dest))
        self.app.nginx._crs = (0, ("", ""))  # сбросить кэш каталога CRS
        res: Optional[Dict[str, Any]] = None
        if self.app.nginx.last_applied():
            # переприменить последнюю применённую версию (неприменённые правки пользователя не затрагиваются)
            res = await self.app.apply_snapshot(f"Правила OWASP CRS {tag} (обновление с GitHub)", "protection")
            ok = bool(res and res.get("version"))
        else:
            ok = True
        if not ok:
            if prev:
                (self.crs_root() / "ACTIVE").write_text(prev)
            else:
                (self.crs_root() / "ACTIVE").unlink(missing_ok=True)
            self.app.nginx._crs = (0, ("", ""))
            err = f"nginx не принял правила CRS {tag} — остались прежние (подробности — в журнале событий)"
            self._set_status("crs", ok=False, error=err, tried=now)
            self.db.event("error", "protection", err)
            return {"ok": False, "error": err}
        self._set_status("crs", ok=True, tag=tag, updated=now, error="", dir=str(dest))
        self.db.event("info", "protection", f"Правила OWASP CRS обновлены до {tag}")
        await asyncio.to_thread(self.prune_crs, str(dest))
        return {"ok": True, "tag": tag, "changed": True}

    def use_package_crs(self) -> None:
        (self.crs_root() / "ACTIVE").unlink(missing_ok=True)
        self.app.nginx._crs = (0, ("", ""))

    # ------------------------------------------------------------------ запросы
    def search(self, q: str = "", flt: str = "", sort: str = "kev", limit: int = 100, offset: int = 0
               ) -> Dict[str, Any]:
        cond, args = ["1=1"], []
        if q:
            cond.append("(cve LIKE ? OR name LIKE ? OR vendor LIKE ? OR product LIKE ? OR description LIKE ?)")
            args += [f"%{q}%"] * 5
        flt_sql = {"kev": "kev=1", "patched": "active=1", "covered": "covered!=''",
                   "uncovered": "kev=1 AND active=0 AND covered=''", "ransomware": "ransomware=1",
                   "critical": "severity='critical'", "epss": "epss>=0.5", "seen": "seen>0",
                   "exploit": "exploits!=''"}
        if flt in flt_sql:
            cond.append(flt_sql[flt])
        elif flt == "mine":
            kc, ka = self._kw_sql(self.watch_keywords())
            cond.append(kc)
            args += ka
        order = {"kev": "kev DESC, kev_added DESC, cvss DESC", "epss": "epss DESC", "cvss": "cvss DESC, epss DESC",
                 "new": "COALESCE(NULLIF(kev_added,''), '0000') DESC, cve DESC", "seen": "seen DESC, last_seen DESC",
                 "cve": "cve DESC"}.get(sort, "kev DESC, kev_added DESC")
        where = " AND ".join(cond)
        total = (self.db.one(f"SELECT COUNT(*) AS n FROM vulns WHERE {where}", args) or {}).get("n", 0)
        rows = self.db.query(f"SELECT cve,name,vendor,product,severity,cvss,epss,epss_pct,kev,kev_added,kev_due,"
                             f"ransomware,covered,active,seen,last_seen,template,exploits FROM vulns WHERE {where} "
                             f"ORDER BY {order} LIMIT ? OFFSET ?", args + [min(limit, 500), offset])
        return {"total": total, "rows": rows}

    @staticmethod
    def map_paths(cve: str) -> Dict[str, str]:
        """Пути уязвимости, которые сейчас в карте nginx (остальные отсеяны как типовые, общие или законные)."""
        try:
            text = Path(settings.vuln_file).read_text(encoding="utf-8")
        except OSError:
            return {}
        out = {}
        for m in re.finditer(r'^"((?:[^"\\]|\\.)*)" "' + re.escape(cve) + r':([ap])";$', text, re.M):
            out[m.group(1).replace('\\"', '"').replace("\\\\", "\\")] = m.group(2)
        return out

    def get(self, cve: str) -> Optional[Dict[str, Any]]:
        r = self.db.one("SELECT * FROM vulns WHERE cve=?", (cve.upper(),))
        if not r:
            return None
        r = dict(r)
        r["paths"] = json.loads(r["paths"]) if r.get("paths") else {}
        r["in_map"] = self.map_paths(r["cve"]) if r["paths"] else {}
        r["covered"] = [x for x in (r.get("covered") or "").split(",") if x]
        r["rules"] = [{"id": x, "title": W.RULE_BY_ID[x].title, "cat": W.RULE_BY_ID[x].cat}
                      for x in r["covered"] if x in W.RULE_BY_ID]
        r["excluded"] = r["cve"] in self.svc.settings().vulndb_exclude
        r["exploits"] = [x for x in (r.get("exploits") or "").split(",") if x]
        from .fingerprint import TECH_BY_ID
        name = f" {r['vendor']} {r['product']} ".lower().replace("_", " ")
        try:
            rng = json.loads(r.get("ranges") or "[]")
        except ValueError:
            rng = []
        r["ranges"] = rng
        p = self.svc.settings()
        on_sites = []
        for sid, t in self.tech().items():
            for x in t.get("tech") or []:
                tech = TECH_BY_ID.get(x["id"])
                if not tech or tech.cat == "js" or not any(k in name for k in tech.keywords):
                    continue
                aff = version_affected(x.get("version", ""), rng, tech.keywords)
                note = ""
                dist = x.get("distro") or ""
                if aff and p.vulndb_distro and dist in DI.SUPPORTED:
                    data = self.distro_data(r["cve"], dist)
                    verd = DI.verdict(data, DI.packages(x["id"], x["version"]), x["version"], x.get("pkgver", "")) \
                        if data else None
                    aff, note = DI.affected_from(verd, aff), DI.describe(verd)
                elif aff and p.vulndb_distro and dist in ("rhel", "fedora", "alpine"):
                    aff, note = None, f"сборка {DI.NAMES.get(dist, dist)}: исправление могло быть перенесено в пакет"
                on_sites.append({"site": sid, "name": t.get("name", sid), "tech": x["name"],
                                 "version": x.get("pkgver") or x.get("version", ""), "affected": aff, "note": note})
            if r.get("wp"):
                kind, _, slug = r["wp"].partition(":")
                for it in (t.get("wp") or {}).get(f"{kind}s") or []:
                    if it["slug"] == slug:
                        on_sites.append({"site": sid, "name": t.get("name", sid),
                                         "tech": f"{'плагин' if kind == 'plugin' else 'тема'} {slug}",
                                         "version": it.get("version", ""), "note": "",
                                         "affected": version_affected(it.get("version", ""), rng)
                                         if it.get("version") else None})
        r["on_sites"] = on_sites
        r["hits"] = self.db.query("SELECT site, action, SUM(n) AS n, MIN(ts) AS first, MAX(ts) AS last "
                                  "FROM attack_minute WHERE kind='waf' AND rule=? GROUP BY site, action ORDER BY n DESC",
                                  (f"vuln/{r['cve']}",))
        r["events"] = self.svc.events(limit=20, q=f"vuln/{r['cve']}")
        r["links"] = {"nvd": f"https://nvd.nist.gov/vuln/detail/{r['cve']}",
                      "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" if r["kev"] else "",
                      "template": f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{r['template']}"
                      if r.get("template") else ""}
        return r

    def prune_templates(self, days: int = 90) -> int:
        """Удалить из кэша шаблоны, которые не обновлялись дольше срока (уязвимость вышла из охвата)."""
        cut, n = time.time() - days * 86400, 0
        for f in (self.dir() / "tpl").glob("*.yaml"):
            try:
                if f.stat().st_mtime < cut:
                    f.unlink()
                    n += 1
            except OSError:
                pass
        return n

    def record_seen(self) -> None:
        """Сколько раз уязвимость пытались эксплуатировать на сайтах (по журналу атак) — для сортировки и анализа."""
        rows = self.db.query("SELECT substr(rule, 6) AS cve, SUM(n) AS n, MAX(ts) AS last FROM attack_minute "
                             "WHERE rule LIKE 'vuln/CVE-%' GROUP BY rule")
        self.db.execute("UPDATE vulns SET seen=0")
        self.db.executemany("UPDATE vulns SET seen=?, last_seen=? WHERE cve=?",
                            [(r["n"], r["last"], r["cve"]) for r in rows])
