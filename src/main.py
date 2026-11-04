"""FastAPI application entrypoint for SkillBench.

Startup is fail-closed: missing/placeholder identity, default or owner database
credentials, a relative artifact root in production, debug mode in production or
a local synthetic IdP in production all abort startup.
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.auth import local_idp_router, router as auth_router
from src.api.foundation import router as foundation_router
from src.api.skb import router as skb_router
from src.core.config import Settings, settings as default_settings, validate_runtime
from src.core.db import Database, set_database
from src.core.errors import Problem, problem_exception_handler, problem_response, unhandled_exception_handler
from src.core.oidc import LocalSyntheticIdP, OIDCClient
from src.services.storage import ArtifactStore

logger = logging.getLogger("skb.api")
SERVICE_VERSION = "0.2.0"


def create_app(config: Optional[Settings] = None, *, database: Optional[Database] = None) -> FastAPI:
    app_settings = config or default_settings

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        problems = validate_runtime(app_settings)
        if problems:
            logger.error("startup_refused invalid_configuration=%s", ",".join(problems))
            raise RuntimeError("startup_refused: " + ",".join(problems))
        store = app.state.store
        try:
            store.ensure_dirs()
        except OSError as exc:  # pragma: no cover - configuration error path
            raise RuntimeError("startup_refused: artifact_root_unusable") from exc
        if not await app.state.db.healthy():
            logger.warning("startup_db_unavailable readiness will report unavailable")
        yield
        await app.state.db.dispose()

    app = FastAPI(
        title="SkillBench",
        description=(
            "Private, fixture-first SkillBench: inert package intake, digest-bound approval, "
            "preregistered plans and deterministic paired analysis. Synthetic recorded trials "
            "only; no submitted skill code is executed and no model provider is called."
        ),
        version=SERVICE_VERSION,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = app_settings
    app.state.db = database or Database(app_settings)
    set_database(app.state.db)
    app.state.store = ArtifactStore(app_settings.ARTIFACT_ROOT or "./.data/artifacts")
    app.state.oidc = OIDCClient(app_settings)
    app.state.local_idp = LocalSyntheticIdP(app_settings) if app_settings.local_idp_enabled() else None

    if app_settings.local_idp_enabled():
        # Loopback synthetic identity provider: reach it through the ASGI app
        # instead of a network socket. Production clients use real HTTPS.
        from httpx import ASGITransport

        app.state.oidc.transport = ASGITransport(app=app)

    if app_settings.CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=app_settings.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Content-Type", "Idempotency-Key", "If-Match", "X-CSRF-Token", "X-API-Key"],
        )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("X-Request-ID")
        try:
            request_id = str(uuid.UUID(incoming)) if incoming else str(uuid.uuid4())
        except (ValueError, AttributeError):
            request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    app.add_exception_handler(Problem, problem_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    @app.exception_handler(404)
    async def not_found_handler(request: Request, _exc):
        return problem_response(request, Problem("not_found", "The requested resource does not exist."))

    app.include_router(auth_router, prefix="/api/v1", tags=["Auth"])
    app.include_router(foundation_router, prefix="/api/v1", tags=["Foundation"])
    app.include_router(skb_router, prefix="/api/v1", tags=["SKB"])
    if app_settings.local_idp_enabled():
        app.include_router(local_idp_router, prefix="/local-idp", tags=["LocalSyntheticIdP"])

    @app.get("/health/live", tags=["Health"])
    async def health_live():
        return {"status": "pass", "service": "skillbench", "version": SERVICE_VERSION}

    @app.get("/health/ready", tags=["Health"])
    async def health_ready():
        """Readiness: database reachable and migrations applied. No config dump."""
        ready = await app.state.db.healthy()
        body = {"status": "pass" if ready else "fail", "checks": {"database": "pass" if ready else "fail"}}
        return JSONResponse(body, status_code=200 if ready else 503, headers={"Cache-Control": "no-store"})

    @app.get("/healthz", tags=["Health"])
    async def healthz():
        return {"status": "pass", "service": "skillbench", "version": SERVICE_VERSION}

    @app.get("/", tags=["Root"])
    async def root():
        return {
            "service": "skillbench",
            "version": SERVICE_VERSION,
            "mode": "fixture-only private release",
            "disclaimer": (
                "Synthetic recorded trials test orchestration and analysis, not measured skill benefit. "
                "Submitted skill code is never executed and no paid model is called."
            ),
            "docs": "/docs",
            "health": "/health/live",
        }

    return app


app = create_app()
