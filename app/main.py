"""Точка входа веб-сервиса Nginx Manager."""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from .config import DOCS_DIR, VERSION, WEB_DIR, settings
from .nginx.generator import ConfigError
from .nginx.manager import ApplyError

log = logging.getLogger("nm")


def _fmt_errors(errors) -> list:
    out = []
    for e in errors:
        loc = ".".join(str(x) for x in e.get("loc", []) if x not in ("body",))
        msg = e.get("msg", "")
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, "):]
        out.append({"loc": loc, "msg": msg, "type": e.get("type")})
    return out


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .core import App
    nm = App()
    pw = nm.ensure_admin()
    if pw:
        log.warning("Создан администратор admin с паролем: %s (смените после входа)", pw)
    app.state.nm = nm
    await nm.start()
    try:
        yield
    finally:
        await nm.stop()


def create_app() -> FastAPI:
    app = FastAPI(title="Nginx Manager API", version=VERSION, lifespan=lifespan,
                  docs_url="/api/docs-ui", redoc_url=None, openapi_url="/api/openapi.json")
    from .api.routes import router
    app.include_router(router)

    @app.exception_handler(ValidationError)
    async def _pyd(request: Request, exc: ValidationError):
        errs = _fmt_errors(exc.errors())
        return JSONResponse({"detail": "; ".join(e["msg"] for e in errs), "errors": errs}, status_code=422)

    @app.exception_handler(RequestValidationError)
    async def _req(request: Request, exc: RequestValidationError):
        errs = _fmt_errors(exc.errors())
        return JSONResponse({"detail": "; ".join(f"{e['loc']}: {e['msg']}" for e in errs), "errors": errs},
                            status_code=422)

    @app.exception_handler(ApplyError)
    async def _apply(request: Request, exc: ApplyError):
        return JSONResponse({"detail": str(exc), "output": exc.output, "errors": exc.errors,
                             "site_id": exc.site_id}, status_code=409)

    @app.exception_handler(ConfigError)
    async def _cfg(request: Request, exc: ConfigError):
        return JSONResponse({"detail": str(exc), "site_id": exc.site_id}, status_code=409)

    @app.exception_handler(ValueError)
    async def _val(request: Request, exc: ValueError):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(PermissionError)
    async def _perm(request: Request, exc: PermissionError):
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(Exception)
    async def _any(request: Request, exc: Exception):
        log.exception("Необработанная ошибка: %s %s", request.method, request.url.path)
        # текст исключения может содержать пути и внутренние данные — он только в журнале сервиса
        return JSONResponse({"detail": f"Внутренняя ошибка сервера ({type(exc).__name__}). Подробности — в журнале "
                                       "сервиса: journalctl -u nginx-manager"}, status_code=500)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if not request.url.path.startswith("/api/docs-ui"):
            resp.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'")
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
    if DOCS_DIR.exists():
        app.mount("/docs-files", StaticFiles(directory=str(DOCS_DIR)), name="docs")

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return FileResponse(WEB_DIR / "favicon.svg", media_type="image/svg+xml")

    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request):
        nm = request.app.state.nm
        return {"ok": True, "version": VERSION, "nginx": nm.nginx.is_running()}

    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: Request):
        """Метрики Prometheus: доступ с IP из «Читать /metrics без токена» или по API-токену (Bearer)."""
        from fastapi.responses import PlainTextResponse
        from .auth import require
        from .services.bans import in_any
        from .services.metrics import render
        nm = request.app.state.nm
        p = nm.panel()
        if not p.metrics_enabled:
            return JSONResponse({"detail": "Метрики выключены в настройках панели"}, status_code=404)
        ip = nm.auth.client_ip(request)
        if not (p.metrics_allow and in_any(ip, list(p.metrics_allow))):
            require(request, "viewer")
        return PlainTextResponse(render(nm), media_type="text/plain; version=0.0.4; charset=utf-8")

    return app


def run() -> None:
    import os
    import uvicorn
    os.umask(0o022)  # файлы конфигурации должны читаться воркерами nginx
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout)
    kw = {}
    if settings.tls_cert and settings.tls_key:
        kw.update(ssl_certfile=settings.tls_cert, ssl_keyfile=settings.tls_key)
    uvicorn.run(create_app(), host=settings.bind_host, port=settings.bind_port, log_level=settings.log_level,
                proxy_headers=True, forwarded_allow_ips=",".join(settings.trust_proxy), access_log=False,
                ws_ping_interval=20, ws_ping_timeout=20, **kw)


app = create_app()

if __name__ == "__main__":
    run()
