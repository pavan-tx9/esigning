"""The HTTP API. See docs/SPEC.md sections 9 and 10.

``create_app`` wires every module through ``esign.runtime.build_runtime`` and mounts the Host API,
the Signer API and (when it has been built) the signing UI. ``esign.api:app`` is resolved lazily so
importing this package never opens a database connection.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from esign.api.errors import install_error_handlers
from esign.api.middleware import AccessLog, BodySizeLimit, SecurityHeaders
from esign.api.ui import install_ui
from esign.config import Settings
from esign.db import ping
from esign.identity import parse_trusted_proxies
from esign.logging import configure_logging, get_logger
from esign.runtime import Runtime, build_runtime

__all__ = ["check_production_settings", "create_app"]

log = get_logger(__name__)


def check_production_settings(settings: Settings) -> None:
    """Fail at startup, not at the first signature. Production only."""
    parse_trusted_proxies(settings.trusted_proxy_cidrs)  # a typo here silently changes every recorded IP
    if settings.app_env != "prod":
        return
    problems: list[str] = []
    if settings.seal_profile == "PAdES-B-T":
        problems.append("SEAL_PROFILE must be PAdES-B-LT or PAdES-B-LTA in production")
    if settings.seal_key_backend != "aws_kms":
        problems.append("SEAL_KEY_BACKEND must be aws_kms in production (the local dev PKI is not a production key)")
    if settings.blob_backend != "s3":
        problems.append("BLOB_BACKEND must be s3 in production (the fs backend cannot enforce retention)")
    if not settings.trust_roots_path.is_file():
        problems.append("TRUST_ROOTS_PATH does not exist; every verification would fail")
    if not settings.tsa_url:
        problems.append("TSA_URL is required in production")
    if problems:
        raise RuntimeError("refusing to start: " + "; ".join(problems))


def create_app(settings: Settings | None = None, *, runtime: Runtime | None = None) -> FastAPI:
    rt = runtime or build_runtime(settings)
    check_production_settings(rt.settings)

    # No interactive docs: they need inline scripts and a CDN, which the CSP forbids on purpose.
    app = FastAPI(title="E-signing service", version="1", docs_url=None, redoc_url=None)
    app.state.runtime = rt

    from esign.api.host_routes import router as host_router
    from esign.api.signer_routes import router as signer_router

    app.include_router(host_router)
    app.include_router(signer_router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> JSONResponse:
        healthy = ping(rt.engine)
        return JSONResponse({"status": "ok" if healthy else "degraded"}, status_code=200 if healthy else 503)

    ui = install_ui(app, rt.settings.frontend_dist_dir)
    install_error_handlers(app)

    # Outermost first: the access log sees the final status, the headers cover error responses
    # (413 included), and the size limit runs before anything reads a body.
    app.add_middleware(BodySizeLimit, settings=rt.settings)
    app.add_middleware(SecurityHeaders, settings=rt.settings)
    app.add_middleware(AccessLog)
    log.info("api.started", app_env=rt.settings.app_env, component="api", ok=ui)
    return app


def __getattr__(name: str) -> Any:
    """``uvicorn esign.api:app``: built on first access, with logging configured for a server."""
    if name == "app":
        from esign.config import get_settings

        settings = get_settings()
        configure_logging(level=settings.log_level, json_output=settings.app_env != "dev", app_env=settings.app_env)
        application = create_app(settings)
        globals()["app"] = application
        return application
    raise AttributeError(name)
