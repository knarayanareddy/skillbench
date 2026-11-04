"""SkillBench API (18 contracted operations).

Responses follow contracts/openapi.yaml exactly. Inspection internals are not
exposed as extra fields; a rejected scan is surfaced through the contracted
package state and the scan job's stable ``error_code``.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from src.api.deps import (
    ObjectScope,
    etag_headers,
    if_match_revision,
    require_object_capability,
    require_project_capability,
    verify_idempotency_key,
)
from src.core.canonical import normalize_request_hash
from src.core.db import Database
from src.core.errors import Problem, request_id_of
from src.core.security import UserContext
from src.services import common, skb

router = APIRouter()

PACKAGE_CREATE_KEYS = {"artifact_id", "name", "source_commit", "license_expression"}
REVIEW_KEYS = {"decision", "package_sha256", "reason"}
SUITE_CREATE_KEYS = {"name", "tasks", "rights_manifest_artifact_id"}
TASK_KEYS = {"id", "category", "input_artifact_id", "split", "scorer_id"}
PLAN_KEYS = {
    "package_id",
    "package_sha256",
    "suite_id",
    "suite_sha256",
    "harness",
    "model",
    "repetitions",
    "seed",
    "bootstrap_iterations",
    "practical_margin",
    "primary_metric",
    "missing_rule",
    "mode",
}
EXPERIMENT_KEYS = {"plan_id", "plan_sha256"}


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


async def _body(request: Request, allowed: set[str], *, optional: bool = False) -> Dict[str, Any]:
    raw = await request.body()
    if not raw:
        if optional:
            return {}
        raise Problem("invalid", "A JSON request body is required.")
    try:
        import json

        payload = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        raise Problem("invalid", "Request body must be valid JSON.") from exc
    body = common.require_object(payload)
    common.reject_unknown_keys(body, allowed)
    return dict(body)


def _request_hash(request: Request, body: Any) -> str:
    return normalize_request_hash(
        method=request.method, path=request.url.path, query=dict(request.query_params), body=body
    )


# --------------------------------------------------------------------------
# Packages
# --------------------------------------------------------------------------
@router.post("/projects/{project_id}/skb/packages", status_code=201)
async def skb_create_package(
    request: Request,
    project_id: str,
    user: UserContext = Depends(require_project_capability("analyst")),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, PACKAGE_CREATE_KEYS)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        result = await skb.create_package(
            session,
            user=user,
            project_id=project_id,
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


@router.get("/projects/{project_id}/skb/packages", status_code=200)
async def skb_list_packages(
    request: Request,
    project_id: str,
    limit: Optional[int] = None,
    cursor: Optional[str] = None,
    user: UserContext = Depends(require_project_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        body = await skb.list_packages(session, project_id=project_id, limit=limit, cursor=cursor)
    return _response(request, body, status_code=200)


@router.get("/skb/packages/{package_id}", status_code=200)
async def skb_get_package(
    request: Request,
    package_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await skb.get_package(session, project_id=scope.project_id, package_id=package_id)
    return _response(
        request, body, status_code=200, headers=etag_headers(int(body.get("revision", 1)))
    )


@router.get("/skb/packages/{package_id}/inspection", status_code=200)
async def skb_package_inspection(
    request: Request,
    package_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
):
    """Read-only inspection detail (scan summary, file inventory, findings).

    Extension beyond ``contracts/openapi.yaml``: read-only, no new write capability,
    needed by the UI evidence view; recorded as a pending contract review item.
    """
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await skb.package_detail(session, project_id=scope.project_id, package_id=package_id)
    return _response(request, body, status_code=200)


@router.post("/skb/packages/{package_id}:inspect", status_code=202)
async def skb_inspect_package(
    request: Request,
    package_id: str,
    scope: ObjectScope = Depends(require_object_capability("operator")),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, set(), optional=True)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        result = await skb.inspect_package(
            session,
            user=scope.auth.user,
            project_id=scope.project_id,
            package_id=package_id,
            idempotency_key=idempotency_key,
            request_sha256=_request_hash(request, body),
            request_id=request_id_of(request),
            ttl_seconds=app_settings.IDEMPOTENCY_TTL_SECONDS,
        )
    return _response(request, result.body, status_code=result.status_code, replayed=result.replayed)


@router.post("/skb/packages/{package_id}/reviews", status_code=200)
async def skb_review_package(
    request: Request,
    package_id: str,
    scope: ObjectScope = Depends(require_object_capability("maintainer")),
    expected_revision: int = Depends(if_match_revision),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, REVIEW_KEYS)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        result = await skb.review_package(
            session,
            user=scope.auth.user,
            project_id=scope.project_id,
            package_id=package_id,
            body=body,
            expected_revision=expected_revision,
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


# --------------------------------------------------------------------------
# Suites
# --------------------------------------------------------------------------
@router.post("/projects/{project_id}/skb/suites", status_code=201)
async def skb_create_suite(
    request: Request,
    project_id: str,
    user: UserContext = Depends(require_project_capability("maintainer")),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, SUITE_CREATE_KEYS)
    tasks = body.get("tasks")
    if isinstance(tasks, list):
        for task in tasks:
            if isinstance(task, dict):
                common.reject_unknown_keys(task, TASK_KEYS)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        result = await skb.create_suite(
            session,
            user=user,
            project_id=project_id,
            body=body,
            idempotency_key=idempotency_key,
            request_sha256=_request_hash(request, body),
            request_id=request_id_of(request),
            ttl_seconds=app_settings.IDEMPOTENCY_TTL_SECONDS,
        )
    return _response(request, result.body, status_code=result.status_code, replayed=result.replayed)


@router.get("/projects/{project_id}/skb/suites", status_code=200)
async def skb_list_suites(
    request: Request,
    project_id: str,
    limit: Optional[int] = None,
    cursor: Optional[str] = None,
    user: UserContext = Depends(require_project_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        body = await skb.list_suites(session, project_id=project_id, limit=limit, cursor=cursor)
    return _response(request, body, status_code=200)


@router.get("/skb/suites/{suite_id}", status_code=200)
async def skb_get_suite(
    request: Request,
    suite_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await skb.get_suite(session, project_id=scope.project_id, suite_id=suite_id)
    return _response(request, body, status_code=200)


# --------------------------------------------------------------------------
# Plans
# --------------------------------------------------------------------------
@router.post("/projects/{project_id}/skb/plans", status_code=201)
async def skb_create_plan(
    request: Request,
    project_id: str,
    user: UserContext = Depends(require_project_capability("analyst")),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, PLAN_KEYS)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        result = await skb.create_plan(
            session,
            user=user,
            project_id=project_id,
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


@router.get("/projects/{project_id}/skb/plans", status_code=200)
async def skb_list_plans(
    request: Request,
    project_id: str,
    limit: Optional[int] = None,
    cursor: Optional[str] = None,
    user: UserContext = Depends(require_project_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        body = await skb.list_plans(session, project_id=project_id, limit=limit, cursor=cursor)
    return _response(request, body, status_code=200)


@router.get("/skb/plans/{plan_id}", status_code=200)
async def skb_get_plan(
    request: Request,
    plan_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await skb.get_plan(session, project_id=scope.project_id, plan_id=plan_id)
    return _response(request, body, status_code=200, headers=etag_headers(int(body.get("revision", 1))))


@router.post("/skb/plans/{plan_id}:preregister", status_code=200)
async def skb_preregister(
    request: Request,
    plan_id: str,
    scope: ObjectScope = Depends(require_object_capability("maintainer")),
    expected_revision: int = Depends(if_match_revision),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, set(), optional=True)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        result = await skb.preregister_plan(
            session,
            user=scope.auth.user,
            project_id=scope.project_id,
            plan_id=plan_id,
            expected_revision=expected_revision,
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


# --------------------------------------------------------------------------
# Experiments and analysis
# --------------------------------------------------------------------------
@router.post("/projects/{project_id}/skb/experiments", status_code=202)
async def skb_create_experiment(
    request: Request,
    project_id: str,
    user: UserContext = Depends(require_project_capability("operator")),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, EXPERIMENT_KEYS)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        result = await skb.create_experiment(
            session,
            user=user,
            project_id=project_id,
            body=body,
            idempotency_key=idempotency_key,
            request_sha256=_request_hash(request, body),
            request_id=request_id_of(request),
            ttl_seconds=app_settings.IDEMPOTENCY_TTL_SECONDS,
        )
    return _response(request, result.body, status_code=result.status_code, replayed=result.replayed)


@router.get("/projects/{project_id}/skb/experiments", status_code=200)
async def skb_list_experiments(
    request: Request,
    project_id: str,
    limit: Optional[int] = None,
    cursor: Optional[str] = None,
    user: UserContext = Depends(require_project_capability("viewer")),
):
    database: Database = request.app.state.db
    async with database.scoped(project_id=project_id, organization_id=user.organization_id) as session:
        body = await skb.list_experiments(session, project_id=project_id, limit=limit, cursor=cursor)
    return _response(request, body, status_code=200)


@router.get("/skb/experiments/{experiment_id}", status_code=200)
async def skb_get_experiment(
    request: Request,
    experiment_id: str,
    scope: ObjectScope = Depends(require_object_capability("viewer")),
):
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await skb.get_experiment(session, project_id=scope.project_id, experiment_id=experiment_id)
    return _response(request, body, status_code=200)


@router.get("/skb/experiments/{experiment_id}/trials", status_code=200)
async def skb_list_trials(
    request: Request,
    experiment_id: str,
    limit: Optional[int] = None,
    cursor: Optional[str] = None,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await skb.list_trials(
            session,
            project_id=scope.project_id,
            experiment_id=experiment_id,
            limit=limit,
            cursor=cursor,
        )
    return _response(request, body, status_code=200)


@router.post("/skb/experiments/{experiment_id}/analyses", status_code=201)
async def skb_create_analysis(
    request: Request,
    experiment_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
    idempotency_key: str = Depends(verify_idempotency_key),
):
    body = await _body(request, set(), optional=True)
    database: Database = request.app.state.db
    app_settings = request.app.state.settings
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        result = await skb.create_analysis(
            session,
            user=scope.auth.user,
            project_id=scope.project_id,
            experiment_id=experiment_id,
            idempotency_key=idempotency_key,
            request_sha256=_request_hash(request, body),
            request_id=request_id_of(request),
            ttl_seconds=app_settings.IDEMPOTENCY_TTL_SECONDS,
        )
    return _response(request, result.body, status_code=result.status_code, replayed=result.replayed)


@router.get("/skb/analyses/{analysis_id}", status_code=200)
async def skb_get_analysis(
    request: Request,
    analysis_id: str,
    scope: ObjectScope = Depends(require_object_capability("analyst")),
):
    database: Database = request.app.state.db
    async with database.scoped(
        project_id=scope.project_id, organization_id=scope.auth.user.organization_id
    ) as session:
        body = await skb.get_analysis(session, project_id=scope.project_id, analysis_id=analysis_id)
    return _response(request, body, status_code=200)
