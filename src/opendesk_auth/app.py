"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from opendesk_auth import __version__
from opendesk_auth.config import get_settings
from opendesk_auth.db import check_db_health, get_db, init_db
from opendesk_auth.middleware import RequestContextMiddleware, get_request_context
from opendesk_auth.rate_limit import RateLimiter
from opendesk_auth.routes import admin_router, auth_router, jwks_router, me_router, oauth_router, orgs_router

logger = logging.getLogger("opendesk_auth")


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    init_db()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="OpenDesk Auth",
        version=__version__,
        description="Shared identity microservice for OpenDesk Auth products (JWKS + OAuth + orgs).",
        lifespan=lifespan,
    )
    app.state.rate_limiter = RateLimiter(settings)

    # Request-ID + security headers middleware must come before CORS
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Structured error handler — all HTTPExceptions get a consistent
    # { error, code, request_id } envelope.
    # ------------------------------------------------------------------
    from fastapi.exception_handlers import http_exception_handler
    from fastapi.exceptions import HTTPException, RequestValidationError

    @app.exception_handler(HTTPException)
    async def structured_http_error(request: Request, exc: HTTPException):
        ctx = get_request_context()
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
                "code": f"HTTP_{exc.status_code}",
                "request_id": ctx.get("request_id"),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def structured_validation_error(request: Request, exc: RequestValidationError):
        ctx = get_request_context()
        return JSONResponse(
            status_code=422,
            content={
                "error": "Validation error",
                "code": "VALIDATION_ERROR",
                "request_id": ctx.get("request_id"),
                "detail": exc.errors(),
            },
        )

    # ------------------------------------------------------------------
    # Health — deep check (DB + key availability)
    # ------------------------------------------------------------------
    from opendesk_auth.crypto import get_key_material

    @app.get("/health")
    def health() -> JSONResponse:
        db_ok = check_db_health()
        try:
            get_key_material()
            keys_ok = True
        except Exception:
            keys_ok = False

        ready = db_ok and keys_ok
        body = {
            "status": "ok" if ready else "degraded",
            "service": "opendesk-auth",
            "version": __version__,
            "checks": {
                "database": "ok" if db_ok else "error",
                "jwt_keys": "ok" if keys_ok else "error",
            },
        }
        return JSONResponse(status_code=200 if ready else 503, content=body)

    @app.get("/metrics")
    def metrics() -> dict:
        from opendesk_auth.metrics import snapshot

        return {"service": "opendesk-auth", "counters": snapshot()}

    @app.get("/", include_in_schema=False)
    def landing_page() -> FileResponse:
        from pathlib import Path

        page = Path(__file__).resolve().parents[2] / "static" / "index.html"
        if not page.is_file():
            return JSONResponse(status_code=404, content={"error": "Landing page not packaged", "code": "HTTP_404"})
        resp = FileResponse(page, media_type="text/html")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:"
        )
        return resp

    @app.get("/robots.txt", include_in_schema=False)
    def robots_txt() -> FileResponse:
        from pathlib import Path

        file_path = Path(__file__).resolve().parents[2] / "static" / "robots.txt"
        if not file_path.is_file():
            return JSONResponse(status_code=404, content={"error": "robots.txt missing", "code": "HTTP_404"})
        return FileResponse(file_path, media_type="text/plain")

    @app.get("/sitemap.xml", include_in_schema=False)
    def sitemap_xml() -> FileResponse:
        from pathlib import Path

        file_path = Path(__file__).resolve().parents[2] / "static" / "sitemap.xml"
        if not file_path.is_file():
            return JSONResponse(status_code=404, content={"error": "sitemap.xml missing", "code": "HTTP_404"})
        return FileResponse(file_path, media_type="application/xml")

    @app.get("/admin/console", include_in_schema=False)
    def admin_console() -> FileResponse:
        from pathlib import Path

        page = Path(__file__).resolve().parents[2] / "static" / "admin.html"
        if not page.is_file():
            return JSONResponse(status_code=404, content={"error": "Admin console not packaged", "code": "HTTP_404"})
        resp = FileResponse(page, media_type="text/html")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:"
        )
        return resp

    @app.get("/auth", include_in_schema=False)
    @app.get("/auth/ui", include_in_schema=False)
    def auth_ui() -> FileResponse:
        from pathlib import Path

        page = Path(__file__).resolve().parents[2] / "static" / "auth.html"
        if not page.is_file():
            return JSONResponse(status_code=404, content={"error": "Auth UI not packaged", "code": "HTTP_404"})
        resp = FileResponse(page, media_type="text/html")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:"
        )
        return resp

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    app.include_router(jwks_router)
    app.include_router(auth_router, prefix="/v1")
    app.include_router(oauth_router, prefix="/v1")
    app.include_router(orgs_router, prefix="/v1")
    app.include_router(admin_router, prefix="/v1")
    app.include_router(me_router, prefix="/v1")
    return app


app = create_app()
