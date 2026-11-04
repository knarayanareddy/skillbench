"""FastAPI dependencies: authentication, authorization, CSRF and preconditions.

Ordering is deliberate: authenticate -> authorize the project -> resolve the
object inside the authorized project -> (finally) consult idempotency state. A
revoked or unauthorized caller therefore never receives a replayed response.
"""
from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse

from fastapi import Depends, Header, HTTPException, Path, Request, status

from src.core.auth import (
    ApiKeyRecord,
    SessionRecord,
    api_key_context,
    resolve_api_key,
    resolve_session,
    resolve_user_identity,
    touch_session,
)
from src.core.config import Settings
from src.core.db import Database
from src.core.errors import Problem
from src.core.security import UserContext
from src.services.storage import ArtifactStore

_IDEMPOTENCY_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_store(request: Request) -> ArtifactStore:
    return request.app.state.store


def get_oidc(request: Request):
    return request.app.state.oidc


@dataclass
class AuthContext:
    user: UserContext
    principal_kind: str
    session: Optional[SessionRecord] = None
    api_key: Optional[ApiKeyRecord] = None


@dataclass
class ObjectScope:
    project_id: str
    auth: AuthContext

    @property
    def user(self) -> UserContext:
        return self.auth.user


def _unauthorized(detail: str) -> Problem:
    return Problem("unauthenticated", detail, headers={"WWW-Authenticate": "Session"})


async def authenticate(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    database: Database = Depends(get_db),
    app_settings: Settings = Depends(get_settings),
) -> AuthContext:
    """Authenticate a scoped machine key or a server-side browser session."""
    now = _utcnow()
    if x_api_key:
        record = await resolve_api_key(database, x_api_key)
        if record is None or record.revoked_at is not None or record.expires_at <= now:
            raise _unauthorized("Invalid, expired or revoked API key.")
        context = api_key_context(record)
        return AuthContext(user=context, principal_kind="api_key", api_key=record)

    token = request.cookies.get(app_settings.cookie_name())
    if not token:
        raise _unauthorized("Authentication credentials required.")
    record = await resolve_session(database, token)
    if record is None:
        raise _unauthorized("Session is invalid or revoked.")
    if record.absolute_expires_at <= now or record.idle_expires_at <= now:
        raise _unauthorized("Session expired.")
    if not await touch_session(database, record, app_settings, now=now):
        raise _unauthorized("Session expired.")
    identity = await resolve_user_identity(database, record.user_id, settings=app_settings)
    if identity is None:
        raise _unauthorized("Session subject is no longer provisioned.")
    context = identity.context()
    context.principal_kind = "session"
    context.session_id = record.session_id
    context.csrf_token = record.csrf_token
    context.session_expires_at = record.absolute_expires_at.isoformat()
    return AuthContext(user=context, principal_kind="session", session=record)


def _utcnow():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


async def get_current_user(auth: AuthContext = Depends(authenticate)) -> UserContext:
    return auth.user


async def require_org_admin(user: UserContext = Depends(get_current_user)) -> UserContext:
    """Organization administration is separate from project content access."""
    if not user.is_org_admin():
        raise Problem("forbidden", "Operation requires Organization Admin privilege.")
    return user


def require_project_capability(required_capability: str) -> Callable:
    """Enforce a capability on the project named in the path."""

    async def checker(
        project_id: str = Path(..., description="Target project identifier"),
        user: UserContext = Depends(get_current_user),
    ) -> UserContext:
        _assert_uuid(project_id, "project_id")
        if not user.has_project_capability(project_id, required_capability):
            raise Problem(
                "forbidden",
                f"Insufficient project privileges: requires '{required_capability}' capability.",
            )
        return user

    return checker


def require_object_capability(required_capability: str) -> Callable:
    """Authorize the caller-supplied project hint, then resolve the object inside it.

    ``X-Project-ID`` is only a hint: the handler always loads the object with a
    project-scoped query, so an object belonging to another project is a 404 even
    when the caller holds the claimed capability.
    """

    async def checker(
        request: Request,
        x_project_id: Optional[str] = Header(None, alias="X-Project-ID"),
        auth: AuthContext = Depends(authenticate),
    ) -> ObjectScope:
        if not x_project_id:
            raise Problem(
                "forbidden",
                f"Access denied: project context is required for object routes requiring '{required_capability}'.",
            )
        _assert_uuid(x_project_id, "X-Project-ID")
        if not auth.user.has_project_capability(x_project_id, required_capability):
            raise Problem(
                "forbidden",
                f"Insufficient project privileges: requires '{required_capability}' capability on the scoped project.",
            )
        return ObjectScope(project_id=str(uuid.UUID(x_project_id)), auth=auth)

    return checker


require_project_role = require_project_capability


def _assert_uuid(value: str, field: str) -> str:
    if not isinstance(value, str) or not _IDEMPOTENCY_UUID.match(value):
        raise Problem("invalid", f"{field} must be a UUID.", status_code=400, field_errors=[{"path": field, "code": "format"}])
    return str(uuid.UUID(value))


async def verify_idempotency_key(
    request: Request,
    auth: AuthContext = Depends(authenticate),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
) -> str:
    """Validate Idempotency-Key and CSRF/origin for cookie-authenticated mutations."""
    if not idempotency_key:
        raise Problem("invalid", "Missing required 'Idempotency-Key' header.", status_code=400)
    if not _IDEMPOTENCY_UUID.match(idempotency_key):
        raise Problem("invalid", "'Idempotency-Key' must be a UUID.", status_code=400)
    key = str(uuid.UUID(idempotency_key))

    if auth.principal_kind == "session" and request.method.upper() in _MUTATING_METHODS:
        csrf = request.headers.get("X-CSRF-Token")
        expected = auth.user.csrf_token or ""
        if not csrf or not expected or not secrets.compare_digest(csrf, expected):
            raise Problem("forbidden", "CSRF token missing or invalid.")
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if origin and not _same_origin(request, origin):
            raise Problem("forbidden", "Cross-origin mutation refused.")
    return key


def _same_origin(request: Request, origin: str) -> bool:
    """Exact-origin comparison against the request host or configured origins."""
    parsed = urlparse(origin)
    if not parsed.scheme or not parsed.netloc:
        return False
    settings: Settings = request.app.state.settings
    expected_hosts = {request.url.netloc, request.headers.get("host", "")}
    if parsed.netloc in {host for host in expected_hosts if host}:
        return True
    configured = set(getattr(settings, "CORS_ORIGINS", []) or [])
    return f"{parsed.scheme}://{parsed.netloc}" in configured


_ETAG_RE = re.compile(r'^(?:W/)?"?(\d+)"?$')


async def if_match_revision(if_match: Optional[str] = Header(None, alias="If-Match")) -> int:
    """Required optimistic-concurrency precondition (428 missing, 400 malformed)."""
    if if_match is None or not if_match.strip():
        raise Problem("precondition_failed", "If-Match header is required for this operation.", status_code=428)
    match = _ETAG_RE.match(if_match.strip())
    if not match:
        raise Problem("invalid", "If-Match must be an ETag revision.", status_code=400)
    revision = int(match.group(1))
    if revision < 1:
        raise Problem("invalid", "If-Match revision must be positive.", status_code=400)
    return revision


def etag_headers(revision: int) -> dict:
    return {"ETag": f'"{revision}"', "Cache-Control": "no-store"}
