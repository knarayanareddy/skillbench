"""Shared foundation API (9 contracted operations)."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse

from src.api.deps import (
    AuthContext,
    ObjectScope,
    authenticate,
    etag_headers,
    get_current_user,
    get_store,
    require_object_capability,
    require_org_admin,
    require_project_capability,
    verify_idempotency_key,
)
from src.core.canonical import normalize_request_hash
from src.core.db import Database
from src.core.errors import Problem, request_id_of
from src.core.security import UserContext
from src.services import common, foundation
from src.services.storage import ArtifactStore

router = APIRouter()

PROJECT_CREATE_KEYS = {"name", "content_capture", "external_transfer"}
UPLOAD_CREATE_KEYS = {"filename", "media_type", "byte_size", "sha256", "classification"}
UPLOAD_FINALIZE_KEYS = {"sha256", "byte_size"}


def _response(
    request: Request,
    body: Dict[str, Any],
    *,
    status_code: int,
    headers: Optional[Dict[str, str]] = None,
    replayed: bool = False,
) -> JSONResponse:
    merged = {"X-Request-ID": request_id_of(request), "Cache-Control": "no-store"}
    merged.update(headers or {})
    if replayed:
        merged["X-Idempotency-Replayed"] = "true"
    return JSONResponse(status_code=status_code, content=body, headers=merged)


async def _body(request: Request, expected_keys: set[str]) -> Dict[str, Any]:
    try:
        payload = await request.json()
    except Exception as exc:  # noqa: BLE001 - malformed JSON is a client error
        raise Problem("invalid", "Request body must be valid JSON.") from exc
    body = common.require_object(payload)
    common.reject_unknown_keys(body, expected_keys)
    return dict(body)


def _request_hash(request: Request, body: Any) -> str:
    return normalize_request_hash(
        method=request.method,
        path=request.url.path,
        query=dict(request.query_params),
        body=body,
    )


@router.post("/projects", status_code=201)
async def foundation_create_project(
    request: Request,
    user: UserContext = Depends(require_org_admin),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    """Create a project workspace. Organization/actor derive from identity."""
    body = await _body(request, PROJECT_CREATE_KEYS)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    result = None
    async with database.scoped(organization_id=user.organization_id) as session:
        result = await foundation.create_project(
            session,
            user=user,
            body=body,
            idempotency_key=idempotency_key,
            request_sha256=_request_hash(request, body),
            request_id=request_id_of(request),
            ttl_seconds=app_settings.IDEMPOTENCY_TTL_SECONDS,
        )
    return _response(
        request,
        result.body,
        status_code=result.status_code,
        headers=etag_headers(int(result.body.get("revision", 1))),
        replayed=result.replayed,
    )


@router.get("/projects", status_code=200)
async def foundation_list_projects(
    request: Request,
    limit: Optional[int] = None,
    cursor: Optional[str] = None,
    user: UserContext = Depends(get_current_user),
):
    database: Database = request.app.state.db
    async with database.scoped(organization_id=user.organization_id) as session:
        body = await foundation.list_projects(session, user=user, limit=limit, cursor=cursor)
    return _response(request, body, status_code=200)


@router.post("/projects/{project_id}/uploads", status_code=201)
async def foundation_create_upload(
    request: Request,
    project_id: str,
    user: UserContext = Depends(require_project_capability("analyst")),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, UPLOAD_CREATE_KEYS)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        result = await foundation.create_upload(
            session,
            user=user,
            project_id=project_id,
            body=body,
            idempotency_key=idempotency_key,
            request_sha256=_request_hash(request, body),
            request_id=request_id_of(request),
            ttl_seconds=app_settings.IDEMPOTENCY_TTL_SECONDS,
            upload_ttl_seconds=app_settings.UPLOAD_SESSION_TTL_SECONDS,
        )
    return _response(request, result.body, status_code=result.status_code, replayed=result.replayed)


@router.put("/uploads/{upload_id}/bytes", status_code=200)
async def foundation_put_upload(
    request: Request,
    upload_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
    idempotency_key: str = Depends(verify_idempotency_key),
    store: ArtifactStore = Depends(get_store),
):
    """Stream bytes into private quarantine with a hard size cap and running digest."""
    database: Database = request.app.state.db
    auth: AuthContext = scope.auth
    async with database.scoped(project_id=scope.project_id, organization_id=auth.user.organization_id) as session:
        body = await foundation.put_upload_bytes(
            session,
            store=store,
            project_id=scope.project_id,
            upload_id=upload_id,
            chunks=request.stream(),
            request_id=request_id_of(request),
            user=auth.user,
        )
    return _response(request, body, status_code=200)


@router.post("/uploads/{upload_id}:finalize", status_code=200)
async def foundation_finalize_upload(
    request: Request,
    upload_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
    idempotency_key: str = Depends(verify_idempotency_key),
    store: ArtifactStore = Depends(get_store),
):
    body = await _body(request, UPLOAD_FINALIZE_KEYS)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        result = await foundation.finalize_upload(
            session,
            store=store,
            user=scope.auth.user,
            project_id=scope.project_id,
            upload_id=upload_id,
            body=body,
            idempotency_key=idempotency_key,
            request_sha256=_request_hash(request, body),
            request_id=request_id_of(request),
            ttl_seconds=app_settings.IDEMPOTENCY_TTL_SECONDS,
        )
    return _response(request, result.body, status_code=result.status_code, replayed=result.replayed)


@router.get("/artifacts/{artifact_id}", status_code=200)
async def foundation_get_artifact(
    request: Request,
    artifact_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await foundation.get_artifact(session, project_id=scope.project_id, artifact_id=artifact_id)
    return _response(request, body, status_code=200)


@router.get("/artifacts/{artifact_id}/bytes", status_code=200)
async def foundation_download_artifact(
    request: Request,
    artifact_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
    store: ArtifactStore = Depends(get_store),
):
    """Authorized, bounded, attachment-only streaming. Never web-served directly."""
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        row = await foundation.load_artifact_row(session, project_id=scope.project_id, artifact_id=artifact_id)
    if row["state"] != "ready":
        raise Problem("not_found", "Artifact is not available.")
    headers = {
        "X-Request-ID": request_id_of(request),
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="{artifact_id}.bin"',
        "Cache-Control": "private, no-store",
        "Content-Length": str(int(row["byte_size"])),
    }
    return StreamingResponse(
        store.iter_chunks(scope.project_id, artifact_id),
        media_type="application/octet-stream",
        headers=headers,
    )


@router.get("/jobs/{job_id}", status_code=200)
async def foundation_get_job(
    request: Request,
    job_id: str,
    scope: ObjectScope = Depends(require_object_capability("viewer")),
):
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await foundation.get_job(session, project_id=scope.project_id, job_id=job_id)
    return _response(request, body, status_code=200)


@router.post("/jobs/{job_id}:cancel", status_code=202)
async def foundation_cancel_job(
    request: Request,
    job_id: str,
    scope: ObjectScope = Depends(require_object_capability("operator")),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = {"_": None}
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        result = await foundation.cancel_job(
            session,
            user=scope.auth.user,
            project_id=scope.project_id,
            job_id=job_id,
            idempotency_key=idempotency_key,
            request_sha256=_request_hash(request, body),
            request_id=request_id_of(request),
            ttl_seconds=app_settings.IDEMPOTENCY_TTL_SECONDS,
        )
    return _response(request, result.body, status_code=result.status_code, replayed=result.replayed)
