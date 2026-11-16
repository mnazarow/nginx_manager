"""Плагины и темы WordPress: что установлено на сайтах и какие у них уязвимости.

Большинство атак на сайты WordPress идёт не на ядро, а на плагины. Панель находит плагины и темы по ссылкам
главной страницы (`/wp-content/plugins/<slug>/…?ver=…`), а при углублённой проверке уточняет версии по
`readme.txt` плагина («Stable tag») и `style.css` темы («Version»).

Уязвимости плагинов — из двух источников:

* шаблоны nuclei для уязвимостей WordPress (публичные эксплойты; путь плагина в шаблоне даёт его slug) с
  затронутыми версиями из записей CVE — без ключей;
* база Wordfence Intelligence (все известные уязвимости плагинов, тем и ядра с диапазонами версий) — нужен
  бесплатный ключ API wordfence.com.
"""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Any, Dict, Iterator, List, Optional, Tuple

WORDFENCE_URLS = {"production": "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
                  "scanner": "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner"}
MAX_FEED = 1024 * 1048576
MAX_ITEMS = 60          # плагинов и тем на сайт (защита от страниц-«свалок»)
SLUG = r"[a-z0-9][a-z0-9_.-]{0,99}"


# =============================================================================
#  Плагины и темы на странице
# =============================================================================
def detect(body: str, core_version: str = "") -> Dict[str, List[Dict[str, str]]]:
    """Плагины и темы по ссылкам страницы: {"plugins": [{slug, version, evidence}], "themes": [...]}.

    Версия — из параметра ver ссылок на файлы плагина, если она не совпадает с версией ядра WordPress (многие
    плагины подставляют в ver версию ядра)."""
    out: Dict[str, List[Dict[str, str]]] = {"plugins": [], "themes": []}
    for kind, folder in (("plugins", "plugins"), ("themes", "themes")):
        seen: Dict[str, Dict[str, str]] = {}
        for m in re.finditer(rf"/wp-content/{folder}/({SLUG})/([^\"'\s<>)]*)", body, re.I):
            slug = m.group(1).lower()
            if slug not in seen:
                if len(seen) >= MAX_ITEMS:
                    break
                seen[slug] = {"slug": slug, "version": "", "evidence": f"страница: /wp-content/{folder}/{slug}/"}
            vm = re.search(r"[?&]ver=(\d+(?:\.\d+){0,3})\b", m.group(2))
            if vm and not seen[slug]["version"] and vm.group(1) != core_version:
                seen[slug]["version"] = vm.group(1)
                seen[slug]["evidence"] = f"страница: …/{slug}/{m.group(2)[:60]}"
        out[kind] = list(seen.values())
    return out


def readme_version(text: str) -> str:
    """Версия плагина из readme.txt («Stable tag: 5.8.1») или темы из style.css («Version: 1.4»)."""
    m = re.search(r"^\s*(?:Stable tag|Version)\s*:\s*v?(\d+(?:\.\d+){0,3})\s*$", text[:20000], re.I | re.M)
    return m.group(1) if m else ""


def probe(target: Tuple[str, str, int, str], wp: Dict[str, List[Dict[str, str]]], fetch, limit: int = 40
          ) -> Dict[str, List[Dict[str, str]]]:
    """Уточнить версии по readme.txt плагинов и style.css тем (не больше limit запросов)."""
    n = 0
    for kind, path in (("plugins", "/wp-content/plugins/{slug}/readme.txt"),
                       ("themes", "/wp-content/themes/{slug}/style.css")):
        for item in wp.get(kind) or []:
            if n >= limit:
                return wp
            n += 1
            p = path.format(slug=item["slug"])
            try:
                st, _h, body = fetch(*target, p, 6.0, 1)
            except Exception:  # noqa: BLE001 — файл недоступен: версия остаётся прежней
                continue
            v = readme_version(body) if st == 200 else ""
            if v:
                item["version"], item["evidence"] = v, f"{p} (ответ 200)"
    return wp


# =============================================================================
#  Версии
# =============================================================================
def _vnum(v: str) -> List[int]:
    return [int(x) for x in re.findall(r"\d+", (v or "").split("-")[0])][:6]


def _cmp(a: List[int], b: List[int]) -> int:
    n = max(len(a), len(b))
    a, b = a + [0] * (n - len(a)), b + [0] * (n - len(b))
    return (a > b) - (a < b)


def in_ranges(version: str, ranges: List[List[Any]]) -> Optional[bool]:
    """Версия в одном из диапазонов [from, from_inclusive, to, to_inclusive] («*» — без границы)."""
    v = _vnum(version)
    if not v:
        return None
    if not ranges:
        return None
    for fr, fi, to, ti in ranges:
        lo_ok = fr in ("*", "", None) or (lambda c: c > 0 or (c == 0 and fi))(_cmp(v, _vnum(str(fr))))
        hi_ok = to in ("*", "", None) or (lambda c: c < 0 or (c == 0 and ti))(_cmp(v, _vnum(str(to))))
        if lo_ok and hi_ok:
            return True
    return False


# =============================================================================
#  Wordfence Intelligence
# =============================================================================
def iter_feed(stream, chunk: int = 1 << 20) -> Iterator[Dict[str, Any]]:
    """Записи ленты Wordfence из потока без загрузки всей ленты в память: объект {id: запись}, массив записей
    или NDJSON."""
    dec = json.JSONDecoder()
    buf, pos, eof = "", 0, False

    def more() -> bool:
        nonlocal buf, pos, eof
        if eof:
            return False
        data = stream.read(chunk)
        if not data:
            eof = True
            return False
        buf = buf[pos:] + (data.decode("utf-8", "replace") if isinstance(data, bytes) else data)
        pos = 0
        return True

    def skip(chars: str = " \t\r\n") -> None:
        nonlocal pos
        while True:
            while pos < len(buf) and buf[pos] in chars:
                pos += 1
            if pos < len(buf) or not more():
                return

    def value() -> Any:
        nonlocal pos
        while True:
            try:
                v, end = dec.raw_decode(buf, pos)
                pos = end
                return v
            except json.JSONDecodeError:
                if not more():
                    raise
    skip()
    if pos >= len(buf):
        return
    head = buf[pos]
    if head == "{":
        # объект: либо {id: запись, …}, либо NDJSON (первая строка — сама запись)
        first_key_pos = pos
        pos += 1
        skip()
        if pos < len(buf) and buf[pos] == '"':
            k = value()
            skip()
            if pos < len(buf) and buf[pos] == ":":
                pos += 1
                skip()
                v = value()
                if isinstance(v, dict) and isinstance(k, str) and ("software" in v or "title" in v):
                    yield {**v, "id": v.get("id") or k}
                    while True:
                        skip(" \t\r\n,")
                        if pos >= len(buf) or buf[pos] == "}":
                            return
                        k = value()
                        skip()
                        pos += 1  # «:»
                        skip()
                        v = value()
                        if isinstance(v, dict):
                            yield {**v, "id": v.get("id") or k}
                    return
        pos = first_key_pos  # NDJSON
        while True:
            skip(" \t\r\n,")
            if pos >= len(buf):
                return
            v = value()
            if isinstance(v, dict):
                yield v
    elif head == "[":
        pos += 1
        while True:
            skip(" \t\r\n,")
            if pos >= len(buf) or buf[pos] == "]":
                return
            v = value()
            if isinstance(v, dict):
                yield v


def feed_rows(records: Iterator[Dict[str, Any]]) -> Iterator[Tuple[Any, ...]]:
    """Записи ленты → строки таблицы wp_vulns (по одной на затронутое ПО)."""
    for r in records:
        if r.get("informational"):
            continue
        cvss = r.get("cvss") or {}
        try:
            score = float(cvss.get("score") or 0) if isinstance(cvss, dict) else 0.0
        except (TypeError, ValueError):
            score = 0.0
        cve = str(r.get("cve") or "").upper()
        for i, s in enumerate(r.get("software") or []):
            slug = str(s.get("slug") or "").lower()
            typ = str(s.get("type") or "plugin").lower()
            if not slug or typ not in ("plugin", "theme", "core"):
                continue
            ranges = []
            for rv in (s.get("affected_versions") or {}).values():
                if isinstance(rv, dict):
                    ranges.append([rv.get("from_version") or "*", bool(rv.get("from_inclusive", True)),
                                   rv.get("to_version") or "*", bool(rv.get("to_inclusive", True))])
            patched = ", ".join(str(x) for x in (s.get("patched_versions") or [])[:5])
            yield (f"{r.get('id')}:{i}", slug, typ, str(s.get("name") or slug)[:200],
                   str(r.get("title") or "")[:300], cve if cve.startswith("CVE-") else "", score,
                   json.dumps(ranges), patched[:200], str(r.get("published") or "")[:25], "wordfence")


def open_feed(key: str, feed: str = "production", timeout: int = 300):
    req = urllib.request.Request(WORDFENCE_URLS[feed], headers={
        "Authorization": f"Bearer {key}", "Accept": "application/json",
        "User-Agent": "NginxManager-VulnDB/1.0"})
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 — адрес фиксирован


class Capped:
    """Обёртка потока с ограничением объёма."""

    def __init__(self, stream, limit: int = MAX_FEED) -> None:
        self.stream, self.left = stream, limit

    def read(self, n: int) -> bytes:
        if self.left <= 0:
            raise ValueError("лента больше допустимого объёма")
        data = self.stream.read(min(n, self.left))
        self.left -= len(data)
        return data


def ranges_from_title(title: str) -> List[List[Any]]:
    """Затронутые версии из названия шаблона nuclei, если в записи CVE их нет: «File Manager 6.0-6.8 - RCE» →
    [6.0..6.8], «Forminator <= 1.24.6» → [*..1.24.6], «Events Calendar <1.4.5» → [*..1.4.5)."""
    head = title.split(" - ")[0]
    m = re.search(r"<=\s*v?(\d+(?:\.\d+){0,3})\b", head)
    if m:
        return [["*", True, m.group(1), True]]
    m = re.search(r"<\s*v?(\d+(?:\.\d+){0,3})\b", head)
    if m:
        return [["*", True, m.group(1), False]]
    m = re.search(r"\b(\d+(?:\.\d+){1,3})\s*-\s*(\d+(?:\.\d+){1,3})\b", head)
    if m:
        return [[m.group(1), True, m.group(2), True]]
    return []


def slug_from_template(text: str) -> str:
    """«plugin:slug» или «theme:slug» по путям шаблона nuclei."""
    m = re.search(rf"/wp-content/plugins/({SLUG})/", text, re.I)
    if m:
        return f"plugin:{m.group(1).lower()}"
    m = re.search(rf"/wp-content/themes/({SLUG})/", text, re.I)
    return f"theme:{m.group(1).lower()}" if m else ""
