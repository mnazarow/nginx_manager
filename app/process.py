"""Управление процессом панели: самоперезапуск (после восстановления базы из копии).

Состояние хранится здесь, а не в app.main: при запуске `python -m app.main` модуль запуска — это __main__,
и `import app.main` из обработчиков получил бы его отдельную копию без ссылки на сервер."""
from __future__ import annotations

import logging
import os
import signal
from typing import Any, Optional

log = logging.getLogger("nm")
server: Optional[Any] = None  # uvicorn.Server, когда панель запущена через app.main.run() (сервис systemd)
restart = False


def can_restart() -> bool:
    """Может ли панель перезапустить сама себя: запущена через run() или под systemd (Restart=always)."""
    return server is not None or bool(os.environ.get("INVOCATION_ID"))


def request_restart() -> bool:
    """Корректно остановить uvicorn (фоновые задачи, соединения с базой) и запустить процесс заново через exec —
    PID не меняется, systemd ничего не замечает. Без run() под systemd — SIGTERM, перезапустит Restart=always.
    Иначе (uvicorn из консоли) — False: перезапустите вручную."""
    global restart
    if server is not None:
        restart = True
        server.should_exit = True
        return True
    if os.environ.get("INVOCATION_ID"):
        os.kill(os.getpid(), signal.SIGTERM)
        return True
    log.warning("Панель запущена не через сервис — перезапустите её вручную, чтобы завершить восстановление базы")
    return False
