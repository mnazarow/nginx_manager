"""База уязвимостей 2.2: разбор источников (CISA KEV, nuclei-templates, FIRST EPSS, CVE Program, Exploit-DB),
нормализация путей эксплойтов, сборка карты для nginx с исключениями, новые уязвимости в каталоге, правила OWASP CRS
с GitHub и живая проверка карты на настоящем nginx."""
from __future__ import annotations

import asyncio
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from app.models import Backend, GlobalSettings, PanelSettings, ProtectionSettings, Site, SiteProtection
from app.nginx.generator import Generator, Paths, State
from app.protection import vulndb as V
from app.protection.nginx import find_crs
from tests.test_protection import Backend200, free_port
from tests.test_protection_ext import http

TMP = Path(os.environ["NM_TEST_TMP"]) / "vulndb"

KEV = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.11.16", "count": 4,
       "vulnerabilities": [
           {"cveID": "CVE-2018-13379", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName":
            "Fortinet FortiOS SSL VPN Path Traversal", "dateAdded": "2021-11-03", "shortDescription": "Path traversal",
            "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2022-05-03",
            "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-22"]},
           {"cveID": "CVE-2021-40539", "vendorProject": "Zoho", "product": "ManageEngine", "vulnerabilityName":
            "Zoho ManageEngine ADSelfService Plus Authentication Bypass", "dateAdded": "2021-11-03",
            "shortDescription": "x", "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Unknown", "cwes": []},
           {"cveID": "CVE-2024-4577", "vendorProject": "PHP Group", "product": "PHP", "vulnerabilityName":
            "PHP-CGI OS Command Injection", "dateAdded": "2024-06-12", "shortDescription": "short",
            "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-78"]},
           {"cveID": "CVE-2099-0001", "vendorProject": "Acme", "product": "Router", "vulnerabilityName": "Acme RCE",
            "dateAdded": "2099-01-01", "shortDescription": "x"},
           {"cveID": "not-a-cve", "vendorProject": "x"}]}

NUCLEI = [
    {"ID": "CVE-2018-13379", "Info": {"Name": "Fortinet FortiOS - Arbitrary File Read", "Severity": "critical",
                                      "Description": "FortiOS path traversal", "Classification": {"CVSSScore": "9.8"}},
     "file_path": "http/cves/2018/CVE-2018-13379.yaml"},
    {"ID": "CVE-2021-40539", "Info": {"Name": "Zoho ManageEngine ADSelfService Plus RCE", "Severity": "critical",
                                      "Classification": {"CVSSScore": "9.8"}},
     "file_path": "http/cves/2021/CVE-2021-40539.yaml"},
    {"ID": "CVE-2024-4577", "Info": {"Name": "PHP CGI - Argument Injection", "Severity": "critical",
                                     "Classification": {"CVSSScore": ""}}, "file_path": "http/cves/2024/CVE-2024-4577.yaml"},
    {"ID": "CVE-2023-1111", "Info": {"Name": "Shared path A", "Severity": "critical"},
     "file_path": "http/cves/2023/CVE-2023-1111.yaml"},
    {"ID": "CVE-2020-9999", "Info": {"Name": "Medium", "Severity": "medium"}, "file_path": "http/cves/2020/x.yaml"},
    {"ID": "CVE-2022-2222", "Info": {"Name": "network", "Severity": "critical"}, "file_path": "network/cves/x.yaml"},
]

TEMPLATES = {
    "CVE-2018-13379": """id: CVE-2018-13379
info:
  name: Fortinet FortiOS - Arbitrary File Read
  classification:
    cvss-score: 9.8
    epss-score: 0.97
    cwe-id: CWE-22
  metadata:
    vendor: fortinet
    product: fortios
  tags: cve,cve2018,fortinet,lfi,kev
http:
  - method: GET
    path:
      - "{{BaseURL}}/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
""",
    "CVE-2021-40539": """id: CVE-2021-40539
info:
  name: Zoho ManageEngine ADSelfService Plus RCE
  tags: cve,kev,zoho
http:
  - raw:
      - |
        POST /./RestAPI/LogonCustomization HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /help/admin-guide/test.jsp HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /login HTTP/1.1
        Host: {{Hostname}}
""",
    "CVE-2024-4577": """id: CVE-2024-4577
info:
  name: PHP CGI - Argument Injection
http:
  - method: GET
    path:
      - "{{BaseURL}}/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1"
      - "{{BaseURL}}/index.php?%ADd+allow_url_include%3d1"
      - "{{BaseURL}}/style.css"
""",
    "CVE-2023-1111": """id: CVE-2023-1111
http:
  - method: GET
    path:
      - "{{BaseURL}}/cgi-bin/shared.cgi"
      - "{{BaseURL}}/portal/page.do?file=x"
""",
}


def cve_record(cvss=None, adp_cvss=None, cwe="CWE-78"):
    cna = {"descriptions": [{"lang": "en", "value": "In PHP versions 8.1.* before 8.1.29 ... OS command injection."}],
           "problemTypes": [{"descriptions": [{"cweId": cwe, "lang": "en", "type": "CWE"}]}],
           "affected": [{"vendor": "PHP Group", "product": "PHP", "versions": [
               {"version": "8.1.*", "lessThan": "8.1.29", "status": "affected"},
               {"version": "8.3.0", "lessThanOrEqual": "8.3.7", "status": "affected"},
               {"version": "7.4", "status": "unaffected"}]}]}
    if cvss:
        cna["metrics"] = [{"cvssV3_1": {"baseScore": cvss, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]
    adp = [{"providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": [{"cvssV3_1": {"baseScore": adp_cvss, "vectorString": "CVSS:3.1/ADP"}}] if adp_cvss else []}]
    return json.dumps({"cveMetadata": {"cveId": "CVE-2024-4577", "datePublished": "2024-06-09T19:42:36.464Z"},
                       "containers": {"cna": cna, "adp": adp}}).encode()


# =============================================================================
#  Разбор источников
# =============================================================================
def test_parse_sources():
    kev = V.parse_kev(json.dumps(KEV).encode())
    assert set(kev) == {"CVE-2018-13379", "CVE-2021-40539", "CVE-2024-4577", "CVE-2099-0001"}
    assert kev["CVE-2018-13379"]["ransomware"] == 1 and kev["CVE-2021-40539"]["ransomware"] == 0
    assert kev["CVE-2018-13379"]["cwe"] == "CWE-22" and kev["CVE-2018-13379"]["kev_due"] == "2022-05-03"
    nuc = V.parse_nuclei_index("\n".join(json.dumps(r) for r in NUCLEI).encode() + b"\nnot json\n")
    assert "CVE-2022-2222" not in nuc and nuc["CVE-2018-13379"]["cvss"] == 9.8 and nuc["CVE-2024-4577"]["cvss"] == 0
    assert nuc["CVE-2018-13379"]["severity"] == "critical"
    csv = b'#model_version:v2025.03.14,score_date:2026-11-16T00:00:00Z\ncve,epss,percentile\nCVE-2024-4577,0.94,0.999\n' \
          b'CVE-2021-40539,0.97000,0.99950\nbad,row\n'
    ep = V.parse_epss(gzip.compress(csv))
    assert ep == {"CVE-2024-4577": (0.94, 0.999), "CVE-2021-40539": (0.97, 0.9995)} and V.parse_epss(csv) == ep
    r = V.parse_cve_record(cve_record(cvss=9.8))
    assert r["cvss"] == 9.8 and r["vector"].startswith("CVSS:3.1/AV:N") and r["cwe"] == "CWE-78"
    assert r["published"] == "2024-06-09" and "8.1.* … < 8.1.29" in r["affected"] and "8.3.0 … ≤ 8.3.7" in r["affected"]
    assert "7.4" not in r["affected"] and r["affected"].startswith("PHP Group PHP:")
    assert V.parse_cve_record(cve_record(adp_cvss=7.5))["cvss"] == 7.5  # нет оценки производителя — оценка CISA-ADP
    assert V.parse_cve_record(cve_record())["cvss"] == 0
    edb = V.parse_exploitdb(b'id,file,description,date_published,author,type,platform,port,date_added,date_updated,'
                            b'verified,codes,tags\n50000,x,"FortiOS",2021,a,webapps,hardware,,,,1,'
                            b'CVE-2018-13379;OSVDB-1,\n50001,y,z,2021,a,webapps,php,,,,0,"CVE-2024-4577",\n'
                            b'50002,y,z,2021,a,webapps,php,,,,0,CVE-2018-13379,\n')
    assert edb == {"CVE-2018-13379": ["50000", "50002"], "CVE-2024-4577": ["50001"]}
    assert V.cvelist_url("CVE-2024-4577").endswith("/cves/2024/4xxx/CVE-2024-4577.json")
    assert V.cvelist_url("CVE-2021-44228").endswith("/cves/2021/44xxx/CVE-2021-44228.json")


def test_templates_and_paths():
    t = V.parse_template(TEMPLATES["CVE-2018-13379"])
    assert t["cvss"] == "9.8" and t["epss"] == "0.97" and t["cwe"] == "CWE-22" and t["vendor"] == "fortinet"
    assert t["product"] == "fortios" and "kev" in t["tags"]
    # путь — как его видит nginx в $uri; обход каталогов в параметрах — опасен сам путь
    assert V.exploit_paths(t["requests"]) == {"/remote/fgt_lang": "a"}
    z = V.exploit_paths(V.parse_template(TEMPLATES["CVE-2021-40539"])["requests"])
    assert z == {"/RestAPI/LogonCustomization": "a", "/help/admin-guide/test.jsp": "a", "/login": "a"}
    php = V.exploit_paths(V.parse_template(TEMPLATES["CVE-2024-4577"])["requests"])
    assert php["/php-cgi/php-cgi.exe"] == "p" and php["/index.php"] == "p"  # эксплойт — в параметрах
    assert V.norm_path("/a//b/./c/../d%20e?x=1#f") == "/a/b/d e"
    assert V.norm_path("/x/%2e%2e/%2e%2e/etc/passwd") == "/etc/passwd"
    assert V.norm_path("/%2577eb%2575i") == "/%77eb%75i"  # двойное кодирование: nginx декодирует один раз
    assert V.norm_path("/dir/") == "/dir/" and V.norm_path("{{BaseURL}}") is None and V.norm_path("/a\"b") is None
    assert V.norm_path("relative") is None
    for bad in ("/", "/login", "/wp-login.php", "/index.php", "/a.css", "/app.js", "/x", "/" + "a" * 250,
                "/.well-known/x"):
        assert not V.usable_path(bad), bad
    assert V.usable_path("/remote/fgt_lang") and V.usable_path("/RestAPI/LogonCustomization")


# =============================================================================
#  База: обновление из источников, карта путей, новые уязвимости, поиск
# =============================================================================
@pytest.fixture()
def vapp(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import App
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    settings.ensure_dirs()
    src = tmp_path / "src"
    (src / "nuclei").mkdir(parents=True)
    (src / "kev.json").write_text(json.dumps(KEV))
    (src / "cves.json").write_text("\n".join(json.dumps(r) for r in NUCLEI))
    for r in NUCLEI:
        if r["ID"] in TEMPLATES:
            f = src / "nuclei" / r["file_path"]
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(TEMPLATES[r["ID"]])
    # второй шаблон с тем же путём: путь общий для нескольких продуктов только при ≥ 4 уязвимостях
    (src / "epss.csv.gz").write_bytes(gzip.compress(b"cve,epss,percentile\nCVE-2024-4577,0.94,0.999\n"))
    rec = src / "cvelist" / "cves" / "2024" / "4xxx"
    rec.mkdir(parents=True)
    (rec / "CVE-2024-4577.json").write_bytes(cve_record(cvss=9.8))
    (src / "edb.csv").write_text("id,file,description,codes\n50001,y,z,CVE-2024-4577\n")
    monkeypatch.setattr(V, "KEV_URLS", ["https://kev.invalid/known.json", f"file://{src}/kev.json"])
    monkeypatch.setattr(V, "NUCLEI_INDEX", f"file://{src}/cves.json")
    monkeypatch.setattr(V, "NUCLEI_RAW", f"file://{src}/nuclei/{{path}}")
    monkeypatch.setattr(V, "EPSS_URLS", [f"file://{src}/epss.csv.gz"])
    monkeypatch.setattr(V, "CVELIST_RAW", f"file://{src}/cvelist/cves/{{year}}/{{group}}xxx/{{cve}}.json")
    monkeypatch.setattr(V, "EXPLOITDB_URLS", [f"file://{src}/edb.csv"])
    app = App()
    yield app, src


def test_vulndb_update_and_map(vapp):
    app, src = vapp
    db = app.protection.vulndb
    p = app.protection.settings()
    app.protection.save(p.model_copy(update={"vulndb_scope": "critical", "vulndb_watch": ["acme"]}))
    res = db._update_sync(force=True)
    st = db.status()
    assert res["ok"] and st["kev"]["ok"] and st["kev"]["count"] == 4 and "kev.invalid" not in st["kev"]["url"]
    assert st["nuclei"]["count"] == 5 and st["templates"]["count"] == 4 and st["epss"]["count"] == 1
    assert st["cvelist"]["ok"] and st["exploitdb"]["count"] == 1
    v = db.get("cve-2024-4577")
    assert v["kev"] == 1 and v["ransomware"] == 1 and v["epss"] == 0.94 and v["epss_pct"] == 0.999
    assert v["cvss"] == 9.8 and v["severity"] == "critical" and v["cwe"] == "CWE-78" and v["exploits"] == ["50001"]
    assert v["published"] == "2024-06-09" and "8.1.29" in v["affected"]
    assert v["description"].startswith("In PHP")  # короткое описание KEV заменено описанием из записи CVE
    f = db.get("CVE-2018-13379")
    assert f["vendor"] == "Fortinet" and f["epss"] == 0.97 and f["paths"] == {"/remote/fgt_lang": "a"}
    assert f["links"]["kev"] and f["links"]["template"].endswith("CVE-2018-13379.yaml")
    assert db.get("CVE-2000-0000") is None
    # карта: типовые пути и статика не попадают
    content, stats = db.build_map()
    lines = [x for x in content.splitlines() if not x.startswith("#")]
    assert '"/remote/fgt_lang" "CVE-2018-13379:a";' in lines
    assert '"/RestAPI/LogonCustomization" "CVE-2021-40539:a";' in lines
    assert '"/php-cgi/php-cgi.exe" "CVE-2024-4577:p";' in lines
    assert '"/cgi-bin/shared.cgi" "CVE-2023-1111:a";' in lines and '"/portal/page.do" "CVE-2023-1111:p";' in lines
    assert not any('"/login"' in x or '"/index.php"' in x or "style.css" in x for x in lines)
    assert stats["entries"] == len(lines) == 6 and stats["generic"] == 3 and stats["cves"] == 4
    # охват «только эксплуатируемые» — без критической CVE-2023-1111 вне каталога KEV
    app.protection.save(app.protection.settings().model_copy(update={"vulndb_scope": "kev"}))
    content, stats = db.build_map()
    assert "CVE-2023-1111" not in content and stats["cves"] == 3
    # исключения: уязвимость, префикс пути, законный путь (успешные ответы трём адресам без событий защиты)
    app.protection.save(app.protection.settings().model_copy(update={"vulndb_exclude": ["CVE-2024-4577"],
                                                                      "vulndb_exclude_paths": ["/help/"]}))
    now = time.time()
    for i in range(3):
        app.db.execute("INSERT INTO requests(ts,site,host,ip,method,uri,proto,status,bytes,rt,ua,rid) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (now, "1", "a.test", f"198.51.100.{i}", "GET", "/RestAPI/LogonCustomization?x=1", "HTTP/1.1",
                        200, 10, 0.01, "Mozilla/5.0", f"r{i}"))
    # сканер получает 200 от приложения, отвечающего на любой путь, — это не законный путь
    for i in range(3):
        app.db.execute("INSERT INTO requests(ts,site,host,ip,method,uri,proto,status,bytes,rt,ua,rid) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (now, "1", "a.test", f"203.0.113.{i}", "GET", "/remote/fgt_lang", "HTTP/1.1", 200, 10, 0.01,
                        "x", f"s{i}"))
        app.db.execute("INSERT INTO attack_log(ts,site,ip,country,kind,rule,action,method,uri,ua,status,rid,host,test) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (now, "1", f"203.0.113.{i}", "", "waf",
                                                               "vuln/CVE-2018-13379", "detected", "GET",
                                                               "/remote/fgt_lang", "x", 200, f"s{i}", "a.test", 0))
    app.db.execute("INSERT INTO attack_minute(ts,site,kind,rule,action,n) VALUES(?,?,?,?,?,?)",
                   (int(now) // 60 * 60, "1", "waf", "vuln/CVE-2018-13379", "detected", 3))
    content, stats = db.build_map()
    assert "CVE-2024-4577" not in content and "/help/" not in content and "LogonCustomization" not in content
    assert '"/remote/fgt_lang"' in content and stats["legit"] == 1 and stats["excluded"] >= 2
    # поиск и фильтры
    assert db.search(q="fortinet")["rows"][0]["cve"] == "CVE-2018-13379"
    assert {r["cve"] for r in db.search(flt="ransomware")["rows"]} == {"CVE-2018-13379", "CVE-2024-4577"}
    assert [r["cve"] for r in db.search(flt="exploit")["rows"]] == ["CVE-2024-4577"]
    assert db.search(sort="new")["rows"][0]["cve"] == "CVE-2099-0001"
    db.record_seen()
    assert db.search(flt="seen")["rows"][0]["seen"] == 3
    s = db.summary()
    assert s["kev"] == 4 and s["exploits"] == 1 and s["seen"] == 1 and s["sources"]["kev"]["ok"]
    # новые уязвимости в каталоге: событие и подсказка анализа для продуктов из списка наблюдения
    kev2 = json.loads((src / "kev.json").read_text())
    kev2["vulnerabilities"].append({"cveID": "CVE-2099-0002", "vendorProject": "Acme", "product": "Router OS",
                                    "vulnerabilityName": "Acme Router OS auth bypass", "dateAdded": "2099-02-01"})
    (src / "kev.json").write_text(json.dumps(kev2))
    db._update_sync(force=True)
    new = app.db.kv_get("vulndb_new")
    assert new["cves"] == ["CVE-2099-0002"] and new["watch"] == ["CVE-2099-0002"]
    ev = app.db.query("SELECT level, message FROM events WHERE source='protection' AND message LIKE '%CISA KEV%'")
    assert ev and ev[-1]["level"] == "warning" and "Acme Router OS" in ev[-1]["message"]
    found = {x[0] for x in app.protection.analytics.insights()}
    assert "vuln_watch_new" in found
    # недоступный источник: ошибка у источника, остальные данные на месте, повтор — не раньше чем через час
    (src / "kev.json").unlink()
    db._update_sync(force=True)
    st = db.status()
    assert not st["kev"]["ok"] and "kev.invalid" in st["kev"]["error"] and db.summary()["kev"] == 5
    assert not db.due("kev", app.protection.settings(), time.time())


def test_vuln_api_and_rule_title(vapp):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.protection.service import rule_category
    from app.utils import hash_password
    api = create_app()
    with TestClient(api) as client:
        app = api.state.nm
        app.db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username='admin'",
                       (hash_password("Test-Passw0rd!"),))
        app.protection.vulndb._update_sync(force=True)
        assert app.protection.rule_title("waf", "vuln/CVE-2018-13379").startswith("Эксплойт CVE-2018-13379: Fortinet")
        assert rule_category("waf", "vuln/CVE-2018-13379") == "vuln"
        meta = app.protection.analytics.rule_detail("waf", "vuln/CVE-2018-13379")["meta"]
        assert meta["vuln"] == "CVE-2018-13379" and meta["category"].startswith("Эксплойты известных")
        r = client.post("/api/auth/login", json={"username": "admin", "password": "Test-Passw0rd!"})
        assert r.status_code == 200, r.text
        hdr = {"X-NM-CSRF": "1"}
        d = client.get("/api/protection/vulns", params={"filter": "kev", "limit": 2}).json()
        assert d["total"] == 4 and len(d["rows"]) == 2 and d["summary"]["kev"] == 4
        assert client.get("/api/protection/vulns/CVE-2018-13379").json()["vendor"] == "Fortinet"
        assert client.get("/api/protection/vulns/CVE-1999-0001").status_code == 404
        assert client.post("/api/protection/vulns/bad/exclude", json={}, headers=hdr).status_code == 400
        r = client.post("/api/protection/vulns/CVE-2018-13379/exclude", json={"exclude": True}, headers=hdr).json()
        assert r["excluded"] == ["CVE-2018-13379"] and app.protection.settings().vulndb_exclude == ["CVE-2018-13379"]
        src = client.get("/api/protection/sources").json()
        groups = {(x["group"], x["id"]) for x in src["rows"]}
        assert {("vulns", "kev"), ("vulns", "cvelist"), ("vulns", "exploitdb"), ("crs", "crs")} <= groups
        assert client.post("/api/protection/vulns/update", json={"what": "nothing"}, headers=hdr).json()["ok"]
        m = client.get("/metrics").text
        assert 'nm_vulndb_entries{set="kev"} 4' in m and 'nm_vulndb_source_age_seconds{source="kev"}' in m


# =============================================================================
#  Правила OWASP CRS с GitHub: установка выпуска и выбор каталога
# =============================================================================
def test_crs_install_and_prefer(vapp, tmp_path):
    app, _src = vapp
    db = app.protection.vulndb
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add(name, text):
            data = text.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        add("coreruleset-4.20.0/rules/REQUEST-901-INITIALIZATION.conf", "# OWASP CRS ver.4.20.0\nSecRule x\n")
        add("coreruleset-4.20.0/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "SecRule y\n")
        add("coreruleset-4.20.0/rules/sql-errors.data", "error\n")
        add("coreruleset-4.20.0/crs-setup.conf.example", "# setup\n")
        add("coreruleset-4.20.0/tests/regression/x.yaml", "skip\n")
        add("coreruleset-4.20.0/../../evil.conf", "evil\n")
    dest = db.install_crs(buf.getvalue(), "v4.20.0")
    assert (dest / "rules" / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf").is_file()
    assert (dest / "rules" / "sql-errors.data").is_file() and (dest / "crs-setup.conf.example").is_file()
    assert not (dest / "tests").exists() and not list(tmp_path.rglob("evil.conf"))
    assert find_crs(str(dest)) == (str(dest / "rules"), "4200")
    with pytest.raises(ValueError):
        db.install_crs(buf.getvalue(), "../x")
    bad = io.BytesIO()
    with tarfile.open(fileobj=bad, mode="w:gz"):
        pass
    with pytest.raises(ValueError):
        db.install_crs(bad.getvalue(), "v4.21.0")
    # переключение: конфигурация ещё не применялась — выпуск выбирается сразу; «пакет дистрибутива» — сброс
    tgz = tmp_path / "crs-v4.20.0.tar.gz"
    tgz.write_bytes(buf.getvalue())
    r = asyncio.run(db.update_crs(force=True, url=f"file://{tgz}"))
    assert r["ok"] and r["tag"] == "v4.20.0" and db.active_crs().endswith("v4.20.0")
    assert app.nginx.crs()[0].endswith("v4.20.0/rules")
    db.use_package_crs()
    assert db.active_crs() == ""


def test_crs_from_git_fallback(vapp, tmp_path, monkeypatch):
    """API GitHub и архив недоступны — последний выпуск через git ls-remote, правила — git clone выпуска."""
    if not shutil.which("git"):
        pytest.skip("нужен git")
    app, _src = vapp
    db = app.protection.vulndb
    repo = tmp_path / "crs-repo"
    (repo / "rules").mkdir(parents=True)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}

    def git(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, env=env)
    git("init", "-q")
    for ver in ("4.9.0", "4.10.0"):
        (repo / "rules" / "REQUEST-901-INITIALIZATION.conf").write_text(f"# OWASP CRS ver.{ver}\n")
        (repo / "rules" / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf").write_text("SecRule x\n")
        (repo / "crs-setup.conf.example").write_text("# setup\n")
        (repo / "README.md").write_text("не нужен\n")
        git("add", "-A")
        git("commit", "-qm", ver)
        git("tag", f"v{ver}")
    monkeypatch.setattr(V, "CRS_LATEST", "https://api.github.invalid/latest")
    monkeypatch.setattr(V, "CRS_TARBALL", "https://archive.invalid/{tag}.tar.gz")
    monkeypatch.setattr(V, "CRS_GIT", str(repo))
    assert V.VulnDB.latest_crs_tag() == "v4.10.0"  # сравнение версий, а не строк
    r = asyncio.run(db.update_crs())
    assert r["ok"] and r["tag"] == "v4.10.0" and r["changed"]
    from app.protection.nginx import crs_label
    rules = app.nginx.crs()[0]
    assert rules.endswith("v4.10.0/rules") and crs_label(rules) == "4.10.0" and app.nginx.crs()[1] == "4100"
    assert not (Path(rules).parent / "README.md").exists()
    st = db.status()["crs"]
    assert st["ok"] and st["tag"] == "v4.10.0"
    again = asyncio.run(db.update_crs())
    assert again["ok"] and not again["changed"]
    # старые выпуски удаляются, текущий и предыдущий остаются
    root = db.crs_root()
    for old in ("v4.1.0", "v4.2.0", "v4.3.0"):
        (root / old / "rules").mkdir(parents=True)
        os.utime(root / old, (1, 1))
    db.prune_crs()
    left = sorted(d.name for d in root.iterdir() if d.is_dir())
    assert "v4.10.0" in left and len(left) == V.CRS_KEEP


def test_nmctl_vulns(vapp, capsys):
    from app import cli
    assert cli.main(["vulns", "update"]) == 0
    out = capsys.readouterr().out
    assert "эксплуатируемых 4" in out and "CISA KEV" in out and "Карта путей эксплойтов" in out
    assert cli.main(["vulns", "search", "fortinet"]) == 0
    out = capsys.readouterr().out
    assert "CVE-2018-13379" in out and "KEV" in out and "Найдено: 1" in out
    assert cli.main(["vulns", "search", "--filter", "exploit"]) == 0 and "CVE-2024-4577" in capsys.readouterr().out
    assert cli.main(["vulns", "show", "cve-2024-4577"]) == 0
    out = capsys.readouterr().out
    assert "PHP Group PHP" in out and "EDB-50001" in out and "8.1.29" in out
    assert cli.main(["vulns", "show", "CVE-1999-0001"]) == 1
    assert cli.main(["vulns", "show"]) == 1


def test_vuln_alert_metric_and_probed_insight(vapp):
    app, _src = vapp
    db = app.protection.vulndb
    db._update_sync(force=True)
    pr = app.protection
    now = time.time()
    base = {"method": "GET", "status": 200, "host": "s.test", "ustatus": "", "ua": "Mozilla/5.0", "wa": "detect"}
    for i in range(6):
        pr.observe({**base, "ip": f"198.51.100.{i % 3}", "uri": "/remote/fgt_lang", "wf": "vuln/CVE-2018-13379",
                    "rid": f"v{i}"}, "1", "", now - 30)
    val, det = pr.alert_metric("vuln_attempts", "*", 300)  # до записи в базу — из счётчиков в памяти
    assert val > 0 and "CVE-2018-13379: 6" in det
    pr.flush()
    val, det = pr.alert_metric("vuln_attempts", "1", 300)
    assert "CVE-2018-13379: 6" in det and pr.alert_metric("vuln_attempts", "2", 300)[0] == 0
    an = pr.analytics.analytics(1)
    assert an["vulns"][0]["cve"] == "CVE-2018-13379" and an["vulns"][0]["n"] == 6 and an["vulns"][0]["ips"] == 3
    assert an["vulns"][0]["product"] == "Fortinet FortiOS" and an["vulns_total"] == 1
    found = {x[0]: x for x in pr.analytics.insights()}
    assert "vuln_probed" in found and found["vuln_probed"][2] == "1" and found["vuln_probed"][5] == 6
    v = db.get("CVE-2018-13379")
    assert v["hits"][0]["n"] == 6 and v["events"][0]["uri"] == "/remote/fgt_lang"
    # база не обновлялась больше трёх суток — подсказка
    st = db.status()
    st["kev"]["updated"] = now - 5 * 86400
    app.db.kv_set("vulndb_status", st)
    assert "vulndb_stale" in {x[0] for x in pr.analytics.insights()}


# =============================================================================
#  Живая проверка: карта путей эксплойтов на настоящем nginx
# =============================================================================
def test_live_vuln_map():
    if not shutil.which("nginx") or os.geteuid() != 0:
        pytest.skip("нужен nginx и root")
    from app.db import Database
    from app.nginx.manager import NginxManager
    TMP.mkdir(parents=True, exist_ok=True)
    os.chmod(TMP.parent, 0o755)
    os.chmod(TMP, 0o755)
    for d in ("logs", "cache/default", "live", "pages"):
        (TMP / d).mkdir(parents=True, exist_ok=True)
    mgr = NginxManager(Database(TMP / "t.db"))
    caps = mgr.caps()
    caps.pid_path = str(TMP / "nginx.pid")
    bport, port, stub, panel = free_port(), free_port(), free_port(), free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", bport), Backend200)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    long_path = "/" + "/".join(["segment-" + str(i) for i in range(18)])  # длинный ключ: map_hash_bucket_size
    vmap = ['"/remote/fgt_lang" "CVE-2018-13379:a";', '"/php-cgi/php-cgi.exe" "CVE-2024-4577:p";',
            f'"{long_path}" "CVE-2099-0003:a";'] + [f'"/generated/path-{i}/handler.do" "CVE-2099-{1000 + i}:a";'
                                                    for i in range(3000)]
    for name, text in (("threats.conf", ""), ("attack.conf", 'default "";\n'), ("bans.conf", ""),
                       ("vuln.conf", "\n".join(vmap) + "\n")):
        (TMP / name).write_text(text)
    prot = ProtectionSettings(waf_modes={"vuln": "block"})
    be = [Backend(address="127.0.0.1", port=bport)]
    s1 = Site(name="Блокировка", domains=["b.test"], http_port=port, backends=be,
              protection=SiteProtection(challenge="off", modsec="off"))
    s2 = Site(name="Запись", domains=["d.test"], http_port=port, backends=be,
              protection=SiteProtection(challenge="off", modsec="off", waf="detect"))
    state = State([(1, s1), (2, s2)], [], GlobalSettings(access_log_buffer=""), PanelSettings(), {}, protection=prot)
    p = Paths(str(TMP / "stage"), str(TMP / "stage"), "/var/acme", str(TMP / "logs"), str(TMP / "cache"), stub, panel,
              str(TMP), bans_file=str(TMP / "bans.conf"), threats_file=str(TMP / "threats.conf"),
              attack_file=str(TMP / "attack.conf"), challenge_secret="s", challenge_key="k",
              vuln_file=str(TMP / "vuln.conf"))
    files = Generator(state, caps, p).render()
    assert "map_hash_bucket_size 256;" in files["nginx.conf"]
    alt = {"80": str(free_port()), "443": str(free_port())}
    for rel, content in files.items():
        content = re.sub(r"(listen\s+(?:\[::\]:)?)(80|443)\b", lambda m: m.group(1) + alt[m.group(2)], content)
        (TMP / "stage" / rel).parent.mkdir(parents=True, exist_ok=True)
        (TMP / "stage" / rel).write_text(content)
    conf = str(TMP / "stage" / "nginx.conf")
    t = subprocess.run(["nginx", "-t", "-c", conf], capture_output=True, text=True)
    assert t.returncode == 0, t.stderr
    r = subprocess.run(["nginx", "-c", conf], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    time.sleep(0.3)
    log = TMP / "logs" / "nm-access.log"

    def last():
        time.sleep(0.2)  # nginx пишет строку журнала после отправки ответа
        return json.loads(log.read_text().strip().splitlines()[-1])
    try:
        assert http(port, "/remote/fgt_lang?lang=/../../x", host="b.test") == 403
        assert last()["wf"] == "vuln/CVE-2018-13379" and last()["wa"] == "block"
        assert http(port, "//remote/./fgt_lang", host="b.test") == 403  # нормализация пути nginx
        assert http(port, "/remote/%66gt_lang", host="b.test") == 403   # кодирование
        assert http(port, long_path, host="b.test") == 403
        assert http(port, "/generated/path-2999/handler.do", host="b.test") == 403
        # «p»: путь опасен только с признаком атаки в параметрах
        assert http(port, "/php-cgi/php-cgi.exe?page=1", host="b.test") == 200
        assert http(port, "/php-cgi/php-cgi.exe?x=%3C%3Fphp", host="b.test") == 403
        assert last()["wf"] == "vuln/CVE-2024-4577"
        assert http(port, "/remote/fgt_lang_other", host="b.test") == 200
        assert http(port, "/", host="b.test") == 200
        # режим «запись»: запрос проходит, событие в журнале
        assert http(port, "/remote/fgt_lang", host="d.test") == 200
        assert last()["wf"] == "vuln/CVE-2018-13379" and last()["wa"] == "detect"
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", conf], capture_output=True)
        srv.shutdown()
