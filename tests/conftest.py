"""Общая подготовка тестов: все пути сервиса — во временном каталоге (до импорта app.config)."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="nm-tests-"))
os.environ["NM_CONF_FILE"] = "/nonexistent"
os.environ.update(NM_DATA_DIR=str(TMP / "data"), NM_MANAGED_DIR=str(TMP / "managed"),
                  NM_NGINX_CONF=str(TMP / "nginx.conf"), NM_LOG_DIR=str(TMP / "logs"), NM_CACHE_DIR=str(TMP / "cache"),
                  NM_DISABLE_COLLECTOR="1", NM_TEST_TMP=str(TMP), NM_BIND_PORT="18088", NM_STUB_STATUS_PORT="18089")
for d in ("data", "managed", "logs", "cache"):
    (TMP / d).mkdir(parents=True, exist_ok=True)
