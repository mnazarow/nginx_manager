"""Модульные тесты чистых функций интерфейса (tests/js/*.test.mjs) — через встроенный раннер Node.js."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(not shutil.which("node"), reason="нужен Node.js")
def test_js_units():
    files = sorted(str(p) for p in (ROOT / "tests" / "js").glob("*.test.mjs"))
    r = subprocess.run(["node", "--test", *files], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-2000:]
