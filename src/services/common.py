"""Shared service helpers: serializers, audit records, jobs and pagination."""
from __future__ import annotations

import base64
import binascii
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.db import ensure_uuid
from src.core.errors import Problem

POLICY_VERSION = "baseline-0.2/skb"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def project_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "content_capture": row["content_capture"],
        "external_transfer": bool(row["external_transfer"]),
        "revision": int(row["revision"]),
        "created_at": iso(row["created_at"]),
    }


def artifact_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "sha256": row["sha256"],
        "byte_size": int(row["byte_size"]),
        "media_type": row["media_type"],
        "status": row["state"],
        "classification": row["classification"],
        "created_at": iso(row["created_at"]),
    }


def upload_body(row: Mapping[str, Any], api_prefix: str = "/api/v1") -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "artifact_id": str(row["artifact_id"]),
        "put_path": f"{api_prefix}/uploads/{row['id']}/bytes",
        "expires_at": iso(row["expires_at"]),
        "maximum_bytes": int(row["expected_size"]),
    }


def job_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "kind": row["kind"],
        "state": row["state"],
        "attempt": int(row["attempt"]),
        "revision": int(row["revision"]),
        "created_at": iso(row["created_at"]),
        "result_id": str(row["result_id"]) if row["result_id"] else None,
        "error_code": row["error_code"],
    }


def package_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "artifact_id": str(row["artifact_id"]),
        "sha256": row["sha256"],
        "state": row["state"],
        "execution_profile": row["execution_profile"],
        "revision": int(row["revision"]),
    }


def suite_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "sha256": row["sha256"],
        "version": int(row["version"]),
        "task_count": int(row["task_count"]),
        "created_at": iso(row["created_at"]),
    }


def plan_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    definition = row["definition"]
    if isinstance(definition, str):
        definition = json.loads(definition)
    return {
        "id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "sha256": row["sha256"],
        "state": row["state"],
        "revision": int(row["revision"]),
        "definition": definition,
        "created_at": iso(row["created_at"]),
    }


def experiment_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "plan_id": str(row["plan_id"]),
        "plan_sha256": row["plan_sha256"],
        "state": row["state"],
        "job_id": str(row["job_id"]),
        "created_at": iso(row["created_at"]),
    }


def trial_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    cost = row["cost_eur"]
    return {
        "task_id": row["task_id"],
        "repeat": int(row["repeat"]),
        "arm": row["arm"],
        "outcome": row["outcome"],
        "cost": None if cost is None else _decimal_str(cost),
        "currency": row["currency"],
        "attempt": int(row["attempt"]),
        "trace_artifact_id": str(row["trace_artifact_id"]) if row["trace_artifact_id"] else None,
    }


def _decimal_str(value: Any) -> str:
    from decimal import Decimal

    text_value = format(Decimal(str(value)), "f")
    return text_value


def analysis_body(row: Mapping[str, Any]) -> Dict[str, Any]:
    result = row["result"]
    if isinstance(result, str):
        result = json.loads(result)
    return {
        "id": str(row["id"]),
        "experiment_id": str(row["experiment_id"]),
        "analysis_version": row["version"],
        "input_sha256": row["input_sha256"],
        **{key: result[key] for key in (
            "status",
            "n_tasks",
            "n_complete_tasks",
            "delta",
            "ci_low",
            "ci_high",
            "bound_low",
            "bound_high",
            "interpretation",
            "missing_trials",
        ) if key in result},
    }


async def audit(
    session: AsyncSession,
    *,
    organization_id: str,
    project_id: Optional[str],
    actor_id: Optional[str],
    action: str,
    decision: str,
    request_id: str,
    target_id: Optional[str] = None,
) -> None:
    await session.execute(
        text(
            """
            INSERT INTO core.audit_events
              (organization_id, project_id, actor_id, action, target_id, decision, policy_version, request_id)
            VALUES (:organization_id, :project_id, :actor_id, :action, :target_id, :decision, :policy, :request_id)
            """
        ),
        {
            "organization_id": ensure_uuid(organization_id, field="organization_id"),
            "project_id": ensure_uuid(project_id, field="project_id") if project_id else None,
            "actor_id": ensure_uuid(actor_id, field="actor_id") if actor_id else None,
            "action": action[:120],
            "target_id": ensure_uuid(target_id, field="target_id") if target_id else None,
            "decision": decision[:60],
            "policy": POLICY_VERSION,
            "request_id": ensure_uuid(request_id, field="request_id"),
        },
    )


async def enqueue_job(
    session: AsyncSession,
    *,
    project_id: str,
    kind: str,
    payload: Dict[str, Any],
    outbox_kind: Optional[str] = None,
) -> str:
    """Create a job and its transactional outbox row atomically."""
    job_id = str(uuid.uuid4())
    await session.execute(
        text(
            """
            INSERT INTO core.jobs (id, project_id, kind, state, payload)
            VALUES (:id, :project_id, :kind, 'queued', CAST(:payload AS jsonb))
            """
        ),
        {
            "id": job_id,
            "project_id": ensure_uuid(project_id, field="project_id"),
            "kind": kind,
            "payload": json.dumps(payload, sort_keys=True),
        },
    )
    await session.execute(
        text(
            """
            INSERT INTO core.outbox (project_id, kind, body)
            VALUES (:project_id, :kind, CAST(:body AS jsonb))
            """
        ),
        {
            "project_id": ensure_uuid(project_id, field="project_id"),
            "kind": outbox_kind or f"job.{kind}",
            "body": json.dumps({"job_id": job_id, "kind": kind}, sort_keys=True),
        },
    )
    return job_id


def encode_cursor(created_at: datetime, row_id: uuid.UUID) -> str:
    payload = json.dumps({"c": iso(created_at), "id": str(row_id)}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def decode_cursor(cursor: Optional[str]) -> tuple[Optional[datetime], Optional[str]]:
    if not cursor:
        return None, None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
        created = datetime.fromisoformat(str(data["c"]).replace("Z", "+00:00"))
        return created, ensure_uuid(str(data["id"]), field="cursor")
    except (KeyError, ValueError, binascii.Error, json.JSONDecodeError) as exc:
        raise Problem("invalid", "The pagination cursor is malformed.") from exc


def page_limit(limit: Optional[int], *, default: int = 50) -> int:
    if limit is None:
        return default
    if limit < 1 or limit > 100:
        raise Problem("invalid", "limit must be between 1 and 100.")
    return int(limit)


def page_rows(rows: Sequence[Mapping[str, Any]]) -> tuple[list[Mapping[str, Any]], Optional[str]]:
    if len(rows) <= 100 and rows:
        return list(rows), None
    return list(rows), None


def page_body(items: list[Dict[str, Any]], next_cursor: Optional[str]) -> Dict[str, Any]:
    return {"items": items, "next_cursor": next_cursor}


def reject_unknown_keys(body: Mapping[str, Any], allowed: set[str]) -> None:
    """Contracts set additionalProperties:false; unknown request keys are refused."""
    unknown = sorted(str(key) for key in body if key not in allowed)
    if unknown:
        raise Problem(
            "invalid_semantic",
            "Request contains unknown keys.",
            field_errors=[{"path": key, "code": "unexpected"} for key in unknown][:50],
        )


def require_object(body: Any) -> Mapping[str, Any]:
    if not isinstance(body, Mapping):
        raise Problem("invalid_semantic", "Request body must be a JSON object.")
    return body
