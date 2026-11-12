"""Проверки кода веб-панели, которые можно выполнить без браузера (нужен node; иначе пропускаются)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="нужен node")


def run_highlight(lines):
    script = """
const fs = require('fs'); const s = fs.readFileSync(process.argv[1], 'utf8');
const src = s.slice(s.indexOf('export function highlightNginx'), s.indexOf('export function codeBlock'))
  .replace('export function highlightNginx', 'function hl');
const esc = s.match(/export function esc[^\\n]*/)[0].replace('export function', 'function');
const hl = new Function(esc + '\\n' + src + '\\nreturn hl;')();
console.log(JSON.stringify(JSON.parse(process.argv[2]).map(l => hl(l))));
"""
    out = subprocess.run(["node", "-e", script, str(ROOT / "web/js/ui.js"), json.dumps(lines)],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def test_highlight_escapes_markup_and_keeps_quotes():
    res = run_highlight([
        "deny <script>alert(1)</script>;",
        "add_header Content-Security-Policy \"default-src 'self'\" always;",
        "return 200 '<img src=x onerror=alert(1)>';",
        "# комментарий <b>",
    ])
    joined = "\n".join(res)
    assert "<script" not in joined and "<img" not in joined and "<b>" not in joined
    assert "&lt;script&gt;" in res[0]
    assert "'self'" in res[1] and "&#" not in res[1]
    assert '<span class="s">' in res[2] and "&lt;img" in res[2]


def test_no_raw_html_sinks_with_dynamic_data():
    """innerHTML допускается только в известных местах: документация, подсветка (экранирует сама), QR, графики."""
    allowed = {"ui.js", "docrender.js", "profile.js", "charts.js"}
    found = []
    for p in (ROOT / "web/js").rglob("*.js"):
        text = p.read_text(encoding="utf-8")
        if ("innerHTML" in text or "html:" in text or "insertAdjacentHTML" in text) and p.name not in allowed:
            found.append(p.name)
    assert not found, found
