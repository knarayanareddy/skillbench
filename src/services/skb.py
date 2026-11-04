"""SkillBench domain service: intake, approval, suites, plans, experiments, analysis.

Never executes submitted package content and never calls a model provider. Trial
outcomes come only from the trusted, preinstalled synthetic fixture registry.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.canonical import sha256_hex
from src.core.db import ensure_uuid
from src.core.errors import Problem
from src.core.security import UserContext
from src.services import common, idempotency
from src.services.analysis import analysis_input_digest, analyze, select_last_attempts
from src.services.fixture_registry import FIXTURE_SCORER_IDS, KNOWN_TASK_IDS

OPERATIONS = {
    "create_package": "skb_create_package",
    "inspect": "skb_inspect_package",
    "review": "skb_review_package",
    "create_suite": "skb_create_suite",
    "create_plan": "skb_create_plan",
    "preregister": "skb_preregister",
    "create_experiment": "skb_create_experiment",
    "create_analysis": "skb_create_analysis",
}

ALLOWED_SPLITS = {"development", "validation", "holdout"}
FIXTURE_HARNESS = "fixture/1"
RECORDED_MODEL = "recorded/1"
PRIMARY_METRIC = "task_mean_success_delta"
MISSING_RULE = "report_bounds_no_silent_drop"


async def _load_package(session: AsyncSession, project_id: str, package_id: str) -> Mapping[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT id, project_id, artifact_id, name, sha256, state, revision, execution_profile,
                       inspection_sha256, inspection_summary, inspected_at, rejection_code, created_at
                FROM skb.packages WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": ensure_uuid(package_id, field="package_id"), "project_id": ensure_uuid(project_id, field="project_id")},
        )
    ).mappings().first()
    if row is None:
        raise Problem("not_found", "Package not found.")
    return row


async def _load_suite(session: AsyncSession, project_id: str, suite_id: str) -> Mapping[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT id, project_id, name, version, sha256, definition, task_count, created_at
                FROM skb.suites WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": ensure_uuid(suite_id, field="suite_id"), "project_id": ensure_uuid(project_id, field="project_id")},
        )
    ).mappings().first()
    if row is None:
        raise Problem("not_found", "Suite not found.")
    return row


async def _load_plan(session: AsyncSession, project_id: str, plan_id: str) -> Mapping[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT id, project_id, package_id, package_sha256, suite_id, suite_sha256, sha256,
                       state, revision, definition, created_at, preregistered_at
                FROM skb.plans WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": ensure_uuid(plan_id, field="plan_id"), "project_id": ensure_uuid(project_id, field="project_id")},
        )
    ).mappings().first()
    if row is None:
        raise Problem("not_found", "Plan not found.")
    return row


async def _load_experiment(session: AsyncSession, project_id: str, experiment_id: str) -> Mapping[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT id, project_id, plan_id, plan_sha256, plan_revision, state, job_id, created_at
                FROM skb.experiments WHERE id=:id AND project_id=:project_id
                """
            ),
            {
                "id": ensure_uuid(experiment_id, field="experiment_id"),
                "project_id": ensure_uuid(project_id, field="project_id"),
            },
        )
    ).mappings().first()
    if row is None:
        raise Problem("not_found", "Experiment not found.")
    return row


# --------------------------------------------------------------------------
# Packages
# --------------------------------------------------------------------------
async def create_package(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    body: Mapping[str, Any],
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")
    artifact_id = body.get("artifact_id")
    name = body.get("name")
    source_commit = body.get("source_commit")
    license_expression = body.get("license_expression")
    errors: List[Dict[str, str]] = []
    try:
        ensure_uuid(str(artifact_id), field="artifact_id")
    except ValueError:
        errors.append({"path": "artifact_id", "code": "format"})
    if not isinstance(name, str) or not 1 <= len(name) <= 120:
        errors.append({"path": "name", "code": "length"})
    if source_commit is not None and (not isinstance(source_commit, str) or len(source_commit) != 40):
        errors.append({"path": "source_commit", "code": "format"})
    if license_expression is not None and (not isinstance(license_expression, str) or len(license_expression) > 200):
        errors.append({"path": "license_expression", "code": "length"})
    if errors:
        raise Problem("invalid_semantic", "Package request is not valid.", field_errors=errors)

    async def handler() -> tuple[int, Dict[str, Any]]:
        artifact = (
            await session.execute(
                text(
                    """
                    SELECT id, project_id, sha256, byte_size, media_type, state, classification
                    FROM core.artifacts WHERE id=:id AND project_id=:project_id
                    """
                ),
                {"id": ensure_uuid(str(artifact_id), field="artifact_id"), "project_id": project},
            )
        ).mappings().first()
        if artifact is None:
            raise Problem("not_found", "Artifact not found.")
        if artifact["state"] != "ready":
            raise Problem("conflict", "Artifact is not ready for package intake.")
        if artifact["media_type"] != "application/zip":
            raise Problem("unsupported_media", "Skill packages must be application/zip artifacts.")
        if artifact["classification"] == "sensitive":
            # Sensitive archives are not a supported private-release intake class.
            raise Problem("forbidden", "Sensitive archives cannot be registered as skill packages.")

        package_id = str(uuid.uuid4())
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO skb.packages
                      (id, project_id, artifact_id, name, sha256, state, execution_profile,
                       source_commit, license_expression)
                    VALUES (:id, :project_id, :artifact_id, :name, :sha256, 'quarantined', 'fixture_only',
                            :source_commit, :license_expression)
                    RETURNING id, project_id, artifact_id, sha256, state, execution_profile, revision
                    """
                ),
                {
                    "id": package_id,
                    "project_id": project,
                    "artifact_id": str(artifact["id"]),
                    "name": name,
                    "sha256": artifact["sha256"],
                    "source_commit": source_commit,
                    "license_expression": license_expression,
                },
            )
        ).mappings().one()
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="skb.package.create",
            decision="allowed",
            request_id=request_id,
            target_id=package_id,
        )
        return 201, common.package_body(row)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=OPERATIONS["create_package"],
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def list_packages(
    session: AsyncSession, *, project_id: str, limit: Optional[int], cursor: Optional[str]
) -> Dict[str, Any]:
    rows, next_cursor = await _page_query(
        session,
        table="skb.packages",
        columns="id, project_id, artifact_id, sha256, state, execution_profile, revision, created_at",
        project_id=project_id,
        limit=limit,
        cursor=cursor,
    )
    return common.page_body([common.package_body(row) for row in rows], next_cursor)


async def get_package(session: AsyncSession, *, project_id: str, package_id: str) -> Dict[str, Any]:
    row = await _load_package(session, project_id, package_id)
    body = common.package_body(row)
    return body


async def package_detail(session: AsyncSession, *, project_id: str, package_id: str) -> Dict[str, Any]:
    """Internal detail used by the UI: inspection summary, entries and findings."""
    row = await _load_package(session, project_id, package_id)
    entries = (
        await session.execute(
            text(
                """
                SELECT path, entry_type, byte_size, compressed_size, ordinal
                FROM skb.package_entries WHERE package_id=:package_id AND project_id=:project_id
                ORDER BY ordinal
                """
            ),
            {"package_id": row["id"], "project_id": row["project_id"]},
        )
    ).mappings().all()
    findings = (
        await session.execute(
            text(
                """
                SELECT code, severity, detail FROM skb.package_findings
                WHERE package_id=:package_id AND project_id=:project_id ORDER BY code, detail
                """
            ),
            {"package_id": row["id"], "project_id": row["project_id"]},
        )
    ).mappings().all()
    reviews = (
        await session.execute(
            text(
                """
                SELECT id, package_sha256, package_revision, decision, reason, created_at
                FROM skb.package_reviews WHERE package_id=:package_id AND project_id=:project_id
                ORDER BY created_at DESC
                """
            ),
            {"package_id": row["id"], "project_id": row["project_id"]},
        )
    ).mappings().all()
    body = common.package_body(row)
    body.update(
        {
            "name": row["name"],
            "inspection_sha256": row["inspection_sha256"],
            "inspection_summary": row["inspection_summary"],
            "rejection_code": row["rejection_code"],
            "inspected_at": common.iso(row["inspected_at"]),
            "entries": [dict(entry) for entry in entries],
            "findings": [dict(finding) for finding in findings],
            "reviews": [
                {
                    "id": str(review["id"]),
                    "package_sha256": review["package_sha256"],
                    "package_revision": int(review["package_revision"]),
                    "decision": review["decision"],
                    "reason": review["reason"],
                    "created_at": common.iso(review["created_at"]),
                }
                for review in reviews
            ],
            "labels": ["synthetic-only", "inert-inspection", "not-executed"],
        }
    )
    return body


async def inspect_package(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    package_id: str,
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")

    async def handler() -> tuple[int, Dict[str, Any]]:
        row = (
            await session.execute(
                text(
                    """
                    SELECT id, state, sha256 FROM skb.packages
                    WHERE id=:id AND project_id=:project_id FOR UPDATE
                    """
                ),
                {"id": ensure_uuid(package_id, field="package_id"), "project_id": project},
            )
        ).mappings().first()
        if row is None:
            raise Problem("not_found", "Package not found.")
        if row["state"] in ("approved", "rejected"):
            raise Problem("conflict", "A reviewed package cannot be re-inspected; register a new package.")
        job_id = await common.enqueue_job(
            session,
            project_id=project,
            kind="skb.inspect",
            payload={"package_id": str(row["id"]), "package_sha256": row["sha256"]},
        )
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="skb.package.inspect",
            decision="queued",
            request_id=request_id,
            target_id=str(row["id"]),
        )
        job = (
            await session.execute(
                text(
                    """
                    SELECT id, project_id, kind, state, attempt, revision, created_at, result_id, error_code
                    FROM core.jobs WHERE id=:id AND project_id=:project_id
                    """
                ),
                {"id": job_id, "project_id": project},
            )
        ).mappings().one()
        return 202, common.job_body(job)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=OPERATIONS["inspect"],
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def review_package(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    package_id: str,
    body: Mapping[str, Any],
    expected_revision: int,
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")
    decision = body.get("decision")
    package_sha256 = body.get("package_sha256")
    reason = body.get("reason")
    errors = []
    if decision not in ("approved", "rejected"):
        errors.append({"path": "decision", "code": "enum"})
    if not isinstance(package_sha256, str) or len(package_sha256) != 64:
        errors.append({"path": "package_sha256", "code": "format"})
    if not isinstance(reason, str) or not 5 <= len(reason) <= 1000:
        errors.append({"path": "reason", "code": "length"})
    if errors:
        raise Problem("invalid_semantic", "Review request is not valid.", field_errors=errors)

    async def handler() -> tuple[int, Dict[str, Any]]:
        row = (
            await session.execute(
                text(
                    """
                    SELECT id, state, sha256, revision FROM skb.packages
                    WHERE id=:id AND project_id=:project_id FOR UPDATE
                    """
                ),
                {"id": ensure_uuid(package_id, field="package_id"), "project_id": project},
            )
        ).mappings().first()
        if row is None:
            raise Problem("not_found", "Package not found.")
        if int(row["revision"]) != expected_revision:
            raise Problem(
                "precondition_failed",
                "If-Match does not match the current package revision.",
                status_code=412,
                headers={"ETag": f'"{row["revision"]}"'},
            )
        if row["state"] in ("approved", "rejected"):
            raise Problem("conflict", "Package already has a final review decision.")
        if row["state"] != "inspected":
            raise Problem("conflict", "Approval requires a completed inspection of this exact digest.")
        if package_sha256 != row["sha256"]:
            raise Problem("conflict", "package_sha256 does not match the inspected digest.")
        review_id = str(uuid.uuid4())
        await session.execute(
            text(
                """
                INSERT INTO skb.package_reviews
                  (id, project_id, package_id, package_sha256, package_revision, actor_id, decision, reason)
                VALUES (:id, :project_id, :package_id, :sha256, :revision, :actor_id, :decision, :reason)
                """
            ),
            {
                "id": review_id,
                "project_id": project,
                "package_id": row["id"],
                "sha256": row["sha256"],
                "revision": int(row["revision"]),
                "actor_id": ensure_uuid(user.user_id, field="user_id"),
                "decision": decision,
                "reason": reason,
            },
        )
        updated = (
            await session.execute(
                text(
                    """
                    UPDATE skb.packages SET state=:state, revision=revision+1
                    WHERE id=:id AND project_id=:project_id AND revision=:revision
                    RETURNING id, project_id, artifact_id, sha256, state, execution_profile, revision
                    """
                ),
                {
                    "state": decision,
                    "id": row["id"],
                    "project_id": project,
                    "revision": int(row["revision"]),
                },
            )
        ).mappings().first()
        if updated is None:
            raise Problem("precondition_failed", "Package revision changed during review.", status_code=409)
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="skb.package.review",
            decision=decision,
            request_id=request_id,
            target_id=str(row["id"]),
        )
        return 200, common.package_body(updated)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=OPERATIONS["review"],
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


# --------------------------------------------------------------------------
# Suites
# --------------------------------------------------------------------------
def _validate_tasks(tasks: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= 1000:
        raise Problem("invalid_semantic", "tasks must contain 1-1000 entries.", field_errors=[{"path": "tasks", "code": "range"}])
    seen: set[str] = set()
    normalized: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    for index, task in enumerate(tasks):
        path = f"tasks[{index}]"
        if not isinstance(task, Mapping):
            errors.append({"path": path, "code": "type"})
            continue
        task_id = task.get("id")
        category = task.get("category")
        split = task.get("split")
        scorer = task.get("scorer_id")
        artifact_id = task.get("input_artifact_id")
        if not isinstance(task_id, str) or not 1 <= len(task_id) <= 100:
            errors.append({"path": f"{path}.id", "code": "length"})
            continue
        if task_id in seen:
            errors.append({"path": f"{path}.id", "code": "duplicate"})
        seen.add(task_id)
        if not isinstance(category, str) or len(category) > 100:
            errors.append({"path": f"{path}.category", "code": "length"})
        if split not in ALLOWED_SPLITS:
            errors.append({"path": f"{path}.split", "code": "enum"})
        if scorer not in FIXTURE_SCORER_IDS:
            errors.append({"path": f"{path}.scorer_id", "code": "not_in_fixture_registry"})
        try:
            ensure_uuid(str(artifact_id), field="input_artifact_id")
        except ValueError:
            errors.append({"path": f"{path}.input_artifact_id", "code": "format"})
        normalized.append(
            {
                "id": task_id,
                "category": category,
                "input_artifact_id": str(artifact_id),
                "split": split,
                "scorer_id": scorer,
            }
        )
    if errors:
        raise Problem("invalid_semantic", "Suite tasks are not valid.", field_errors=errors[:50])
    return normalized


async def create_suite(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    body: Mapping[str, Any],
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")
    name = body.get("name")
    if not isinstance(name, str) or not 1 <= len(name) <= 120:
        raise Problem("invalid_semantic", "Suite name must be 1-120 characters.", field_errors=[{"path": "name", "code": "length"}])
    tasks = _validate_tasks(body.get("tasks") or [])
    rights_id = body.get("rights_manifest_artifact_id")
    try:
        rights_artifact = ensure_uuid(str(rights_id), field="rights_manifest_artifact_id")
    except ValueError as exc:
        raise Problem(
            "invalid_semantic",
            "rights_manifest_artifact_id must be a UUID.",
            field_errors=[{"path": "rights_manifest_artifact_id", "code": "format"}],
        ) from exc

    async def handler() -> tuple[int, Dict[str, Any]]:
        rights_row = (
            await session.execute(
                text(
                    """
                    SELECT id, state, media_type FROM core.artifacts
                    WHERE id=:id AND project_id=:project_id
                    """
                ),
                {"id": rights_artifact, "project_id": project},
            )
        ).mappings().first()
        if rights_row is None:
            raise Problem("not_found", "Rights manifest artifact not found.")
        if rights_row["state"] != "ready":
            raise Problem("conflict", "Rights manifest artifact is not ready.")
        for task in tasks:
            exists = (
                await session.execute(
                    text(
                        "SELECT 1 FROM core.artifacts WHERE id=:id AND project_id=:project_id AND state='ready'"
                    ),
                    {"id": task["input_artifact_id"], "project_id": project},
                )
            ).first()
            if exists is None:
                raise Problem("not_found", "A task input artifact is missing or not ready.")

        definition = {
            "schema_version": "skb-suite/1",
            "name": name,
            "tasks": tasks,
            "rights_manifest_artifact_id": rights_artifact,
        }
        suite_sha = sha256_hex(definition)
        suite_id = str(uuid.uuid4())
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO skb.suites
                      (id, project_id, name, version, sha256, definition, task_count, rights_manifest_artifact_id)
                    VALUES (:id, :project_id, :name, 1, :sha256, CAST(:definition AS jsonb), :task_count, :rights)
                    RETURNING id, project_id, sha256, version, task_count, created_at
                    """
                ),
                {
                    "id": suite_id,
                    "project_id": project,
                    "name": name,
                    "sha256": suite_sha,
                    "definition": json.dumps(definition, sort_keys=True),
                    "task_count": len(tasks),
                    "rights": rights_artifact,
                },
            )
        ).mappings().one()
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="skb.suite.create",
            decision="allowed",
            request_id=request_id,
            target_id=suite_id,
        )
        return 201, common.suite_body(row)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=OPERATIONS["create_suite"],
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def list_suites(
    session: AsyncSession, *, project_id: str, limit: Optional[int], cursor: Optional[str]
) -> Dict[str, Any]:
    rows, next_cursor = await _page_query(
        session,
        table="skb.suites",
        columns="id, project_id, sha256, version, task_count, created_at",
        project_id=project_id,
        limit=limit,
        cursor=cursor,
    )
    return common.page_body([common.suite_body(row) for row in rows], next_cursor)


async def get_suite(session: AsyncSession, *, project_id: str, suite_id: str) -> Dict[str, Any]:
    return common.suite_body(await _load_suite(session, project_id, suite_id))


# --------------------------------------------------------------------------
# Plans
# --------------------------------------------------------------------------
def _validate_plan_request(body: Mapping[str, Any]) -> Dict[str, Any]:
    errors: List[Dict[str, str]] = []
    required = [
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
    ]
    for key in required:
        if key not in body:
            errors.append({"path": key, "code": "required"})
    if errors:
        raise Problem("invalid_semantic", "Plan definition is incomplete.", field_errors=errors)

    allowed_keys = set(required)
    unexpected = sorted(set(body) - allowed_keys)
    if unexpected:
        raise Problem(
            "invalid_semantic",
            "Plan definition contains unknown keys.",
            field_errors=[{"path": key, "code": "unexpected"} for key in unexpected],
        )
    if body["harness"] != FIXTURE_HARNESS:
        errors.append({"path": "harness", "code": "unsupported_harness"})
    if body["model"] != RECORDED_MODEL:
        errors.append({"path": "model", "code": "unsupported_model"})
    if body["mode"] != "fixture_only":
        errors.append({"path": "mode", "code": "unsupported_mode"})
    if body["primary_metric"] != PRIMARY_METRIC:
        errors.append({"path": "primary_metric", "code": "unsupported_metric"})
    if body["missing_rule"] != MISSING_RULE:
        errors.append({"path": "missing_rule", "code": "unsupported_missing_rule"})
    repetitions = body["repetitions"]
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or not 1 <= repetitions <= 20:
        errors.append({"path": "repetitions", "code": "range"})
    iterations = body["bootstrap_iterations"]
    if not isinstance(iterations, int) or isinstance(iterations, bool) or not 100 <= iterations <= 10000:
        errors.append({"path": "bootstrap_iterations", "code": "range"})
    seed = body["seed"]
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        errors.append({"path": "seed", "code": "range"})
    margin = body["practical_margin"]
    if not isinstance(margin, (int, float)) or isinstance(margin, bool) or not 0 <= float(margin) <= 1:
        errors.append({"path": "practical_margin", "code": "range"})
    for key in ("package_sha256", "suite_sha256"):
        value = body[key]
        if not isinstance(value, str) or len(value) != 64:
            errors.append({"path": key, "code": "format"})
    for key in ("package_id", "suite_id"):
        try:
            ensure_uuid(str(body[key]), field=key)
        except ValueError:
            errors.append({"path": key, "code": "format"})
    if errors:
        raise Problem("invalid_semantic", "Plan definition is not valid.", field_errors=errors)
    return {key: body[key] for key in required}


async def create_plan(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    body: Mapping[str, Any],
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")
    definition = _validate_plan_request(body)

    async def handler() -> tuple[int, Dict[str, Any]]:
        package = await _load_package(session, project, str(definition["package_id"]))
        suite = await _load_suite(session, project, str(definition["suite_id"]))
        if package["state"] != "approved":
            raise Problem("conflict", "Plan requires an approved package.")
        if package["sha256"] != definition["package_sha256"]:
            raise Problem("conflict", "package_sha256 does not match the approved package digest.")
        if suite["sha256"] != definition["suite_sha256"]:
            raise Problem("conflict", "suite_sha256 does not match the frozen suite digest.")
        plan_sha = sha256_hex(definition)
        plan_id = str(uuid.uuid4())
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO skb.plans
                      (id, project_id, package_id, package_sha256, suite_id, suite_sha256, sha256,
                       state, definition)
                    VALUES (:id, :project_id, :package_id, :package_sha256, :suite_id, :suite_sha256,
                            :sha256, 'draft', CAST(:definition AS jsonb))
                    RETURNING id, project_id, sha256, state, revision, definition, created_at
                    """
                ),
                {
                    "id": plan_id,
                    "project_id": project,
                    "package_id": str(package["id"]),
                    "package_sha256": package["sha256"],
                    "suite_id": str(suite["id"]),
                    "suite_sha256": suite["sha256"],
                    "sha256": plan_sha,
                    "definition": json.dumps(definition, sort_keys=True),
                },
            )
        ).mappings().one()
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="skb.plan.create",
            decision="allowed",
            request_id=request_id,
            target_id=plan_id,
        )
        return 201, common.plan_body(row)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=OPERATIONS["create_plan"],
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def list_plans(
    session: AsyncSession, *, project_id: str, limit: Optional[int], cursor: Optional[str]
) -> Dict[str, Any]:
    rows, next_cursor = await _page_query(
        session,
        table="skb.plans",
        columns="id, project_id, sha256, state, revision, definition, created_at",
        project_id=project_id,
        limit=limit,
        cursor=cursor,
    )
    return common.page_body([common.plan_body(row) for row in rows], next_cursor)


async def get_plan(session: AsyncSession, *, project_id: str, plan_id: str) -> Dict[str, Any]:
    return common.plan_body(await _load_plan(session, project_id, plan_id))


async def preregister_plan(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    plan_id: str,
    expected_revision: int,
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")

    async def handler() -> tuple[int, Dict[str, Any]]:
        plan = (
            await session.execute(
                text(
                    """
                    SELECT id, package_id, package_sha256, suite_id, suite_sha256, sha256, state, revision
                    FROM skb.plans WHERE id=:id AND project_id=:project_id FOR UPDATE
                    """
                ),
                {"id": ensure_uuid(plan_id, field="plan_id"), "project_id": project},
            )
        ).mappings().first()
        if plan is None:
            raise Problem("not_found", "Plan not found.")
        if int(plan["revision"]) != expected_revision:
            raise Problem(
                "precondition_failed",
                "If-Match does not match the current plan revision.",
                status_code=412,
                headers={"ETag": f'"{plan["revision"]}"'},
            )
        if plan["state"] != "draft":
            raise Problem("conflict", "Plan is already preregistered and immutable.")
        package = await _load_package(session, project, str(plan["package_id"]))
        suite = await _load_suite(session, project, str(plan["suite_id"]))
        if package["state"] != "approved":
            raise Problem("conflict", "Package approval is no longer valid for this digest.")
        if package["sha256"] != plan["package_sha256"]:
            raise Problem("conflict", "Package digest changed after the plan was drafted.")
        if suite["sha256"] != plan["suite_sha256"]:
            raise Problem("conflict", "Suite digest changed after the plan was drafted.")
        updated = (
            await session.execute(
                text(
                    """
                    UPDATE skb.plans
                       SET state='preregistered', preregistered_at=now(), revision=revision+1
                     WHERE id=:id AND project_id=:project_id AND revision=:revision AND state='draft'
                    RETURNING id, project_id, sha256, state, revision, definition, created_at
                    """
                ),
                {"id": plan["id"], "project_id": project, "revision": int(plan["revision"])},
            )
        ).mappings().first()
        if updated is None:
            raise Problem("conflict", "Plan changed during preregistration.")
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="skb.plan.preregister",
            decision="allowed",
            request_id=request_id,
            target_id=str(plan["id"]),
        )
        return 200, common.plan_body(updated)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=OPERATIONS["preregister"],
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


# --------------------------------------------------------------------------
# Experiments, trials, analyses
# --------------------------------------------------------------------------
async def create_experiment(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    body: Mapping[str, Any],
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")
    try:
        plan_id = ensure_uuid(str(body.get("plan_id")), field="plan_id")
    except ValueError as exc:
        raise Problem(
            "invalid_semantic", "plan_id must be a UUID.", field_errors=[{"path": "plan_id", "code": "format"}]
        ) from exc
    plan_sha256 = body.get("plan_sha256")
    if not isinstance(plan_sha256, str) or len(plan_sha256) != 64:
        raise Problem(
            "invalid_semantic",
            "plan_sha256 must be a hex digest.",
            field_errors=[{"path": "plan_sha256", "code": "format"}],
        )

    async def handler() -> tuple[int, Dict[str, Any]]:
        plan = (
            await session.execute(
                text(
                    """
                    SELECT id, sha256, state, revision, definition FROM skb.plans
                    WHERE id=:id AND project_id=:project_id FOR UPDATE
                    """
                ),
                {"id": plan_id, "project_id": project},
            )
        ).mappings().first()
        if plan is None:
            raise Problem("not_found", "Plan not found.")
        if plan["state"] != "preregistered":
            raise Problem("conflict", "Experiments require a preregistered plan.")
        if plan["sha256"] != plan_sha256:
            raise Problem("conflict", "plan_sha256 does not match the preregistered plan.")
        definition = plan["definition"]
        if isinstance(definition, str):
            definition = json.loads(definition)
        package = await _load_package(session, project, str(definition["package_id"]))
        suite = await _load_suite(session, project, str(definition["suite_id"]))
        if package["state"] != "approved" or package["sha256"] != definition["package_sha256"]:
            raise Problem("conflict", "The approved package for this plan is no longer valid.")
        if suite["sha256"] != definition["suite_sha256"]:
            raise Problem("conflict", "The frozen suite for this plan is no longer valid.")

        experiment_id = str(uuid.uuid4())
        job_id = await common.enqueue_job(
            session,
            project_id=project,
            kind="skb.experiment",
            payload={
                "experiment_id": experiment_id,
                "plan_id": str(plan["id"]),
                "plan_sha256": plan["sha256"],
            },
        )
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO skb.experiments
                      (id, project_id, plan_id, plan_sha256, plan_revision, state, job_id)
                    VALUES (:id, :project_id, :plan_id, :plan_sha256, :plan_revision, 'queued', :job_id)
                    RETURNING id, project_id, plan_id, plan_sha256, state, job_id, created_at
                    """
                ),
                {
                    "id": experiment_id,
                    "project_id": project,
                    "plan_id": str(plan["id"]),
                    "plan_sha256": plan["sha256"],
                    "plan_revision": int(plan["revision"]),
                    "job_id": job_id,
                },
            )
        ).mappings().one()
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="skb.experiment.create",
            decision="queued",
            request_id=request_id,
            target_id=experiment_id,
        )
        return 202, common.experiment_body(row)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=OPERATIONS["create_experiment"],
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def list_experiments(
    session: AsyncSession, *, project_id: str, limit: Optional[int], cursor: Optional[str]
) -> Dict[str, Any]:
    rows, next_cursor = await _page_query(
        session,
        table="skb.experiments",
        columns="id, project_id, plan_id, plan_sha256, state, job_id, created_at",
        project_id=project_id,
        limit=limit,
        cursor=cursor,
    )
    return common.page_body([common.experiment_body(row) for row in rows], next_cursor)


async def get_experiment(session: AsyncSession, *, project_id: str, experiment_id: str) -> Dict[str, Any]:
    return common.experiment_body(await _load_experiment(session, project_id, experiment_id))


async def list_trials(
    session: AsyncSession, *, project_id: str, experiment_id: str, limit: Optional[int], cursor: Optional[str]
) -> Dict[str, Any]:
    experiment = await _load_experiment(session, project_id, experiment_id)
    limit_value = common.page_limit(limit, default=100)
    rows = (
        await session.execute(
            text(
                """
                SELECT task_id, repeat, arm, outcome, cost_eur, currency, attempt, trace_artifact_id
                FROM skb.trials
                WHERE experiment_id=:experiment_id AND project_id=:project_id
                ORDER BY task_id, repeat, arm, attempt
                LIMIT :limit OFFSET :offset
                """
            ),
            {
                "experiment_id": experiment["id"],
                "project_id": experiment["project_id"],
                "limit": limit_value,
                "offset": 0,
            },
        )
    ).mappings().all()
    return common.page_body([common.trial_body(row) for row in rows], None)


async def create_analysis(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    experiment_id: str,
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")

    async def handler() -> tuple[int, Dict[str, Any]]:
        experiment = await _load_experiment(session, project, experiment_id)
        if experiment["state"] not in ("completed", "stopped", "failed"):
            raise Problem("conflict", "Analysis requires a finished experiment.")
        plan = await _load_plan(session, project, str(experiment["plan_id"]))
        definition = plan["definition"]
        if isinstance(definition, str):
            definition = json.loads(definition)
        suite = await _load_suite(session, project, str(definition["suite_id"]))
        suite_definition = suite["definition"]
        if isinstance(suite_definition, str):
            suite_definition = json.loads(suite_definition)
        task_ids = [task["id"] for task in suite_definition["tasks"]]
        repetitions = int(definition["repetitions"])

        rows = (
            await session.execute(
                text(
                    """
                    SELECT task_id, repeat, arm, attempt, outcome, cost_eur
                    FROM skb.trials WHERE experiment_id=:experiment_id AND project_id=:project_id
                    ORDER BY task_id, repeat, arm, attempt
                    """
                ),
                {"experiment_id": experiment["id"], "project_id": experiment["project_id"]},
            )
        ).mappings().all()
        selected = select_last_attempts([dict(row) for row in rows])
        input_sha = analysis_input_digest([dict(row) for row in rows])
        existing = (
            await session.execute(
                text(
                    """
                    SELECT id, experiment_id, input_sha256, version, status, result
                    FROM skb.analyses
                    WHERE project_id=:project_id AND experiment_id=:experiment_id
                      AND input_sha256=:input_sha256 AND version='paired-task-bootstrap/1'
                    """
                ),
                {
                    "project_id": project,
                    "experiment_id": str(experiment["id"]),
                    "input_sha256": input_sha,
                },
            )
        ).mappings().first()
        if existing is not None:
            # Same frozen input: replay the stored analysis rather than recomputing.
            return 200, common.analysis_body(existing)
        try:
            result = analyze(
                selected,
                task_ids,
                repetitions,
                seed=int(definition["seed"]),
                iterations=int(definition["bootstrap_iterations"]),
            )
        except ValueError as exc:
            raise Problem("invalid_semantic", "Analysis input is not valid for this plan.") from exc

        analysis_id = str(uuid.uuid4())
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO skb.analyses
                      (id, project_id, experiment_id, input_sha256, version, status, result)
                    VALUES (:id, :project_id, :experiment_id, :input_sha256, :version, :status,
                            CAST(:result AS jsonb))
                    RETURNING id, experiment_id, input_sha256, version, status, result
                    """
                ),
                {
                    "id": analysis_id,
                    "project_id": project,
                    "experiment_id": str(experiment["id"]),
                    "input_sha256": input_sha,
                    "version": result["analysis_version"],
                    "status": result["status"],
                    "result": json.dumps(result, sort_keys=True),
                },
            )
        ).mappings().one()
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="skb.analysis.create",
            decision="allowed",
            request_id=request_id,
            target_id=analysis_id,
        )
        return 201, common.analysis_body(row)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=OPERATIONS["create_analysis"],
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def get_analysis(session: AsyncSession, *, project_id: str, analysis_id: str) -> Dict[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT id, experiment_id, input_sha256, version, status, result
                FROM skb.analyses WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": ensure_uuid(analysis_id, field="analysis_id"), "project_id": ensure_uuid(project_id, field="project_id")},
        )
    ).mappings().first()
    if row is None:
        raise Problem("not_found", "Analysis not found.")
    return common.analysis_body(row)


async def plan_definition(session: AsyncSession, *, project_id: str, plan_id: str) -> Dict[str, Any]:
    plan = await _load_plan(session, project_id, plan_id)
    definition = plan["definition"]
    return json.loads(definition) if isinstance(definition, str) else definition


async def _page_query(
    session: AsyncSession,
    *,
    table: str,
    columns: str,
    project_id: str,
    limit: Optional[int],
    cursor: Optional[str],
) -> tuple[List[Mapping[str, Any]], Optional[str]]:
    limit_value = common.page_limit(limit)
    cursor_created, cursor_id = common.decode_cursor(cursor)
    params: Dict[str, Any] = {
        "project_id": ensure_uuid(project_id, field="project_id"),
        "limit": limit_value + 1,
    }
    clause = "project_id = :project_id"
    if cursor_created is not None and cursor_id is not None:
        clause += " AND (created_at, id) < (:cursor_created, :cursor_id)"
        params["cursor_created"] = cursor_created
        params["cursor_id"] = cursor_id
    rows = (
        await session.execute(
            text(f"SELECT {columns} FROM {table} WHERE {clause} ORDER BY created_at DESC, id DESC LIMIT :limit"),
            params,
        )
    ).mappings().all()
    next_cursor = None
    if len(rows) > limit_value:
        last = rows[limit_value - 1]
        next_cursor = common.encode_cursor(last["created_at"], last["id"])
    return list(rows[:limit_value]), next_cursor
