"""Сборки дистрибутивов: исправления, перенесённые без смены версии продукта.

Ubuntu и Debian исправляют уязвимости в пакетах, не меняя основную версию: Apache в Ubuntu 22.04 всегда
«2.4.52», а исправление CVE-2024-38475 пришло в пакете 2.4.52-1ubuntu4.10. Сверка только по основной версии
считала бы такой сервер уязвимым. Поэтому для продуктов, собранных дистрибутивом (заголовок
«Apache/2.4.52 (Ubuntu)», «PHP/8.1.2-1ubuntu2.14», «nginx/1.22.1 (Debian)»), панель смотрит данные самого
дистрибутива:

* Ubuntu — OSV и OpenVEX группы безопасности Canonical (github.com/canonical/ubuntu-security-notices), запасной
  путь — api.osv.dev;
* Debian — OSV (api.osv.dev, записи DEBIAN-CVE-…).

Итог по уязвимости: «затронута» / «исправлена в установленном пакете» / «не затронута (код отсутствует)» /
«зависит от версии пакета: исправлено в …» (когда заголовок называет дистрибутив, но не версию пакета).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

UBUNTU_OSV = ["https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/cve/{year}/UBUNTU-{cve}.json",
              "https://api.osv.dev/v1/vulns/UBUNTU-{cve}"]
UBUNTU_VEX = ["https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/vex/cve/{year}/{cve}.json"]
DEBIAN_OSV = ["https://api.osv.dev/v1/vulns/DEBIAN-{cve}"]
SUPPORTED = ("ubuntu", "debian")
NAMES = {"ubuntu": "Ubuntu", "debian": "Debian", "rhel": "RHEL-совместимая", "fedora": "Fedora", "alpine": "Alpine"}
CODENAMES = {"trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04",
             "noble": "24.04", "oracular": "24.10", "plucky": "25.04", "questing": "25.10"}


# =============================================================================
#  Сборка дистрибутива по заголовку
# =============================================================================
def distro_of(value: str) -> Tuple[str, str]:
    """(дистрибутив, полная версия пакета) по значению заголовка: «PHP/8.1.2-1ubuntu2.14» → ("ubuntu",
    "8.1.2-1ubuntu2.14"); «Apache/2.4.52 (Ubuntu)» → ("ubuntu", ""); «PHP/8.2.28» → ("", "")."""
    v = value or ""
    m = re.search(r"/(\d+:)?(\d[\w.+~]*-[\w.+~]*?(ubuntu|deb\d+u\d+|~deb\d+|\+deb\d+|\.el\d+|\.fc\d+)[\w.+~]*)", v,
                  re.I)
    if m:
        tag = m.group(3).lower()
        kind = "ubuntu" if tag == "ubuntu" else "debian" if "deb" in tag else "rhel" if ".el" in tag else "fedora"
        return kind, (m.group(1) or "") + m.group(2)
    m = re.search(r"\((Ubuntu|Debian|Raspbian|CentOS[^)]*|Red Hat[^)]*|Rocky[^)]*|AlmaLinux[^)]*|Oracle Linux[^)]*|"
                  r"Fedora|Alpine)\)", v, re.I)
    if m:
        w = m.group(1).lower()
        if w in ("ubuntu",):
            return "ubuntu", ""
        if w in ("debian", "raspbian"):
            return "debian", ""
        if w.startswith(("fedora",)):
            return "fedora", ""
        if w.startswith("alpine"):
            return "alpine", ""
        return "rhel", ""
    return "", ""


def packages(tech_id: str, version: str) -> List[str]:
    """Исходные пакеты Ubuntu и Debian для продукта."""
    nums = re.findall(r"\d+", version or "")
    if tech_id == "php":
        return [f"php{nums[0]}.{nums[1]}"] if len(nums) >= 2 else []
    return {"apache": ["apache2"], "nginx-backend": ["nginx"], "tomcat": ["tomcat10", "tomcat9", "tomcat8"],
            "openresty": [], "python": [f"python{nums[0]}.{nums[1]}"] if len(nums) >= 2 else []}.get(tech_id, [])


# =============================================================================
#  Сравнение версий Debian (как dpkg --compare-versions)
# =============================================================================
def _order(c: str) -> int:
    if not c or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first:
                first = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def _split(v: str) -> Tuple[int, str, str]:
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
    try:
        e = int(epoch)
    except ValueError:
        e = 0
    return e, up, rev


def deb_vcmp(a: str, b: str) -> int:
    """< 0, 0, > 0 — как dpkg --compare-versions: «2.4.52-1ubuntu4.9» < «2.4.52-1ubuntu4.10», «1.0~rc1» < «1.0»."""
    ea, ua, ra = _split(a.strip())
    eb, ub, rb = _split(b.strip())
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def upstream(v: str) -> str:
    """Основная версия из версии пакета: «1:2.4.52+dfsg-1ubuntu4.10» → «2.4.52»."""
    up = _split(v)[1]
    m = re.match(r"\d+(?:\.\d+)*", up)
    return m.group(0) if m else up


def _same_line(a: str, b: str) -> bool:
    """Одна и та же основная версия (8.1.2 и 8.1.2) — сборки одного выпуска дистрибутива."""
    return bool(a) and upstream(a) == upstream(b)


# =============================================================================
#  Данные дистрибутивов
# =============================================================================
def urls(distro: str, cve: str) -> Dict[str, List[str]]:
    year = cve.split("-")[1] if cve.count("-") >= 2 else ""
    if distro == "ubuntu":
        return {"osv": [u.format(year=year, cve=cve) for u in UBUNTU_OSV],
                "vex": [u.format(year=year, cve=cve) for u in UBUNTU_VEX]}
    if distro == "debian":
        return {"osv": [u.format(cve=cve) for u in DEBIAN_OSV], "vex": []}
    return {"osv": [], "vex": []}


def release_name(eco: str) -> str:
    """«Ubuntu:22.04:LTS» → «Ubuntu 22.04», «Ubuntu:Pro:18.04:LTS» → «Ubuntu Pro 18.04», «Debian:12» → «Debian 12»."""
    parts = [p for p in eco.split(":") if p and p != "LTS"]
    return " ".join(parts)


def parse_osv(data: bytes) -> List[Dict[str, Any]]:
    """Запись OSV → [{eco, pkg, fixed, versions}] (fixed — версия пакета с исправлением, "" — исправления нет)."""
    d = json.loads(data)
    out = []
    for a in d.get("affected") or []:
        p = a.get("package") or {}
        fixed = ""
        for r in a.get("ranges") or []:
            for ev in r.get("events") or []:
                if ev.get("fixed"):
                    fixed = str(ev["fixed"])
        out.append({"eco": str(p.get("ecosystem") or ""), "pkg": str(p.get("name") or ""), "fixed": fixed,
                    "versions": [str(x) for x in (a.get("versions") or [])][:400]})
    return out


def parse_vex(data: bytes) -> List[Dict[str, str]]:
    """OpenVEX Ubuntu → [{pkg, version, codename, status, why}] по исходным пакетам (arch=source)."""
    d = json.loads(data)
    out = []
    for s in d.get("statements") or []:
        for p in s.get("products") or []:
            pid = str(p.get("@id") or "") if isinstance(p, dict) else str(p)
            m = re.match(r"pkg:deb/ubuntu/([^@?]+)@([^?]+)\?(.*)$", pid)
            if not m or "arch=source" not in m.group(3):
                continue
            cm = re.search(r"distro=([^&]+)", m.group(3))
            out.append({"pkg": m.group(1), "version": m.group(2), "codename": cm.group(1) if cm else "",
                        "status": str(s.get("status") or ""), "why": str(s.get("justification") or "")})
    return out


def verdict(data: Dict[str, Any], pkgs: Iterable[str], version: str, pkgver: str) -> Optional[Dict[str, Any]]:
    """Итог по данным дистрибутива для установленного продукта.

    state: affected — версия пакета затронута; fixed — исправление уже в установленном пакете; not_affected —
    дистрибутив считает пакет незатронутым; depends — версия пакета неизвестна, исправлено в пакете …;
    None — данных по этим пакетам нет (вывод остаётся по основной версии)."""
    pkgs = list(pkgs)
    if not pkgs:
        return None
    osv = [e for e in data.get("osv") or [] if e["pkg"] in pkgs]
    vex = [s for s in data.get("vex") or [] if s["pkg"] in pkgs]
    base = pkgver or version
    if pkgver:
        for e in osv:
            if pkgver in e["versions"]:
                return {"state": "affected", "release": release_name(e["eco"]), "pkg": e["pkg"], "fixed": e["fixed"]}
        for e in osv:
            if e["fixed"] and _same_line(e["fixed"], pkgver):
                if deb_vcmp(pkgver, e["fixed"]) >= 0:
                    return {"state": "fixed", "release": release_name(e["eco"]), "pkg": e["pkg"], "fixed": e["fixed"]}
                return {"state": "affected", "release": release_name(e["eco"]), "pkg": e["pkg"], "fixed": e["fixed"]}
    for s in vex:
        if s["status"] == "not_affected" and _same_line(s["version"], base):
            code = s["codename"].rsplit("/", 1)[-1]
            rel = f"Ubuntu {CODENAMES[code]}" if code in CODENAMES else f"Ubuntu ({code})" if code else ""
            return {"state": "not_affected", "release": rel,
                    "pkg": s["pkg"], "fixed": "", "why": s["why"]}
    lines = [e for e in osv if e["fixed"] and _same_line(e["fixed"], base)]
    if lines and not pkgver:
        e = lines[0]
        return {"state": "depends", "release": release_name(e["eco"]), "pkg": e["pkg"], "fixed": e["fixed"],
                "also": [{"release": release_name(x["eco"]), "fixed": x["fixed"]} for x in lines[1:4]]}
    open_ = [e for e in osv if not e["fixed"] and any(_same_line(v, base) for v in e["versions"])]
    if open_:
        return {"state": "affected", "release": release_name(open_[0]["eco"]), "pkg": open_[0]["pkg"], "fixed": ""}
    return None


def affected_from(verd: Optional[Dict[str, Any]], upstream_affected: Optional[bool]) -> Optional[bool]:
    """Итог «затронута?» с учётом данных дистрибутива."""
    if not verd:
        return upstream_affected
    return {"affected": True, "fixed": False, "not_affected": False, "depends": None}.get(verd["state"],
                                                                                         upstream_affected)


def describe(verd: Optional[Dict[str, Any]]) -> str:
    """Пояснение для интерфейса: «Ubuntu 22.04: исправлено в пакете apache2 2.4.52-1ubuntu4.10»."""
    if not verd:
        return ""
    rel = f"{verd['release']}: " if verd.get("release") else ""
    st = verd["state"]
    if st == "fixed":
        return f"{rel}исправлено в установленном пакете {verd['pkg']} (исправление — с {verd['fixed']})"
    if st == "affected":
        return f"{rel}пакет {verd['pkg']} затронут" + (f", исправлено в {verd['fixed']}" if verd["fixed"]
                                                       else ", исправления в дистрибутиве пока нет")
    if st == "not_affected":
        why = {"vulnerable_code_not_present": "уязвимого кода нет в сборке",
               "component_not_present": "уязвимого компонента нет в сборке",
               "vulnerable_code_not_in_execute_path": "уязвимый код не выполняется"}.get(verd.get("why") or "", "")
        return f"{rel}пакет {verd['pkg']} не затронут" + (f" ({why})" if why else "")
    if st == "depends":
        return (f"{rel}исправлено в пакете {verd['pkg']} {verd['fixed']} — проверьте установленную версию "
                f"(dpkg -l {verd['pkg']})")
    return ""
