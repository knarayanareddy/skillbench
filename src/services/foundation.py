"""Shared foundation service: projects, uploads, artifacts and jobs."""
from __future__ import annotations

import json
import uuid
from typing import Any, AsyncIterator, Dict, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.canonical import sha256_bytes
from src.core.config import Settings
from src.core.db import ensure_uuid
from src.core.errors import Problem
from src.core.security import UserContext
from src.services import common, idempotency
from src.services.storage import ArtifactStore, StorageError

PROJECT_OPERATION = "foundation_create_project"
UPLOAD_OPERATION = "foundation_create_upload"
FINALIZE_OPERATION = "foundation_finalize_upload"
CANCEL_OPERATION = "foundation_cancel_job"
MAX_ARTIFACT_BYTES = 104857600
ALLOWED_MEDIA_TYPES = {"application/pdf", "application/json", "application/zip", "text/plain"}


# --------------------------------------------------------------------------
# Projects
# --------------------------------------------------------------------------
async def create_project(
    session: AsyncSession,
    *,
    user: UserContext,
    body: Mapping[str, Any],
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    """Create a project. Organization and actor come from verified identity only."""
    organization_id = ensure_uuid(user.organization_id, field="organization_id")
    actor_id = ensure_uuid(user.user_id, field="user_id")
    name = str(body.get("name", "")).strip()
    if not 1 <= len(name) <= 120:
        raise Problem("invalid_semantic", "Project name must be 1-120 characters.", field_errors=[{"path": "name", "code": "length"}])
    content_capture = body.get("content_capture")
    if content_capture not in ("metadata_only", "redacted"):
        raise Problem(
            "invalid_semantic",
            "content_capture must be metadata_only or redacted.",
            field_errors=[{"path": "content_capture", "code": "enum"}],
        )
    external_transfer = body.get("external_transfer")
    if not isinstance(external_transfer, bool):
        raise Problem(
            "invalid_semantic",
            "external_transfer must be a boolean.",
            field_errors=[{"path": "external_transfer", "code": "type"}],
        )

    async def handler() -> tuple[int, Dict[str, Any]]:
        project_id = str(uuid.uuid4())
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO core.projects (id, organization_id, name, content_capture, external_transfer)
                    VALUES (:id, :organization_id, :name, :content_capture, :external_transfer)
                    RETURNING id, name, content_capture, external_transfer, revision, created_at
                    """
                ),
                {
                    "id": project_id,
                    "organization_id": organization_id,
                    "name": name,
                    "content_capture": content_capture,
                    "external_transfer": external_transfer,
                },
            )
        ).mappings().one()
        await common.audit(
            session,
            organization_id=organization_id,
            project_id=project_id,
            actor_id=actor_id,
            action="project.create",
            decision="allowed",
            request_id=request_id,
        )
        return 201, common.project_body(row)

    return await idempotency.perform(
        session,
        scope=idempotency.ORGANIZATION_SCOPE,
        scope_id=organization_id,
        actor_id=actor_id,
        operation=PROJECT_OPERATION,
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def list_projects(
    session: AsyncSession, *, user: UserContext, limit: Optional[int], cursor: Optional[str]
) -> Dict[str, Any]:
    limit_value = common.page_limit(limit)
    cursor_created, cursor_id = common.decode_cursor(cursor)
    params: Dict[str, Any] = {
        "organization_id": ensure_uuid(user.organization_id, field="organization_id"),
        "limit": limit_value + 1,
    }
    clause = "organization_id = :organization_id"
    if cursor_created is not None and cursor_id is not None:
        clause += " AND (created_at, id) < (:cursor_created, :cursor_id)"
        params["cursor_created"] = cursor_created
        params["cursor_id"] = cursor_id
    rows = (
        await session.execute(
            text(
                f"""
                SELECT id, name, content_capture, external_transfer, revision, created_at
                FROM core.projects WHERE {clause}
                ORDER BY created_at DESC, id DESC LIMIT :limit
                """
            ),
            params,
        )
    ).mappings().all()
    items = [common.project_body(row) for row in rows[:limit_value]]
    next_cursor = None
    if len(rows) > limit_value and rows:
        last = rows[limit_value - 1]
        next_cursor = common.encode_cursor(last["created_at"], last["id"])
    return common.page_body(items, next_cursor)


# --------------------------------------------------------------------------
# Uploads and artifacts
# --------------------------------------------------------------------------
def _validate_upload_create(body: Mapping[str, Any]) -> Dict[str, Any]:
    filename = body.get("filename")
    media_type = body.get("media_type")
    byte_size = body.get("byte_size")
    sha256 = body.get("sha256")
    classification = body.get("classification")
    errors = []
    if not isinstance(filename, str) or not 1 <= len(filename) <= 200:
        errors.append({"path": "filename", "code": "length"})
    elif "/" in filename or "\\" in filename:
        errors.append({"path": "filename", "code": "path_characters"})
    if media_type not in ALLOWED_MEDIA_TYPES:
        errors.append({"path": "media_type", "code": "enum"})
    if not isinstance(byte_size, int) or isinstance(byte_size, bool) or not 1 <= byte_size <= MAX_ARTIFACT_BYTES:
        errors.append({"path": "byte_size", "code": "range"})
    if not isinstance(sha256, str) or len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        errors.append({"path": "sha256", "code": "format"})
    if classification not in ("synthetic", "public_authorized", "sensitive"):
        errors.append({"path": "classification", "code": "enum"})
    if errors:
        raise Problem("invalid_semantic", "Upload request is not valid.", field_errors=errors)
    return {
        "filename": filename,
        "media_type": media_type,
        "byte_size": int(byte_size),
        "sha256": sha256,
        "classification": classification,
    }


async def create_upload(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    body: Mapping[str, Any],
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
    upload_ttl_seconds: int,
) -> idempotency.IdempotentResult:
    validated = _validate_upload_create(body)
    project = ensure_uuid(project_id, field="project_id")

    async def handler() -> tuple[int, Dict[str, Any]]:
        artifact_id = str(uuid.uuid4())
        upload_id = str(uuid.uuid4())
        await session.execute(
            text(
                """
                INSERT INTO core.artifacts
                  (id, project_id, sha256, byte_size, media_type, filename, classification, state, storage_key)
                VALUES (:id, :project_id, :sha256, :byte_size, :media_type, :filename, :classification,
                        'pending', :storage_key)
                """
            ),
            {
                "id": artifact_id,
                "project_id": project,
                "sha256": validated["sha256"],
                "byte_size": validated["byte_size"],
                "media_type": validated["media_type"],
                "filename": validated["filename"],
                "classification": validated["classification"],
                "storage_key": f"objects/{project}/{artifact_id}",
            },
        )
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO core.uploads
                      (id, project_id, artifact_id, expected_size, expected_sha256, media_type, expires_at)
                    VALUES (:id, :project_id, :artifact_id, :expected_size, :expected_sha256, :media_type,
                            now() + make_interval(secs => :ttl))
                    RETURNING id, project_id, artifact_id, expected_size, expected_sha256, expires_at
                    """
                ),
                {
                    "id": upload_id,
                    "project_id": project,
                    "artifact_id": artifact_id,
                    "expected_size": validated["byte_size"],
                    "expected_sha256": validated["sha256"],
                    "media_type": validated["media_type"],
                    "ttl": int(upload_ttl_seconds),
                },
            )
        ).mappings().one()
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="upload.create",
            decision="allowed",
            request_id=request_id,
            target_id=upload_id,
        )
        return 201, common.upload_body(row)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=UPLOAD_OPERATION,
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def put_upload_bytes(
    session: AsyncSession,
    *,
    store: ArtifactStore,
    project_id: str,
    upload_id: str,
    chunks: AsyncIterator[bytes],
    request_id: str,
    user: UserContext,
) -> Dict[str, Any]:
    upload = (
        await session.execute(
            text(
                """
                SELECT id, project_id, artifact_id, expected_size, expected_sha256, state, expires_at
                FROM core.uploads WHERE id=:id AND project_id=:project_id FOR UPDATE
                """
            ),
            {"id": ensure_uuid(upload_id, field="upload_id"), "project_id": ensure_uuid(project_id, field="project_id")},
        )
    ).mappings().first()
    if upload is None:
        raise Problem("not_found", "Upload not found.")
    if upload["state"] == "finalized":
        raise Problem("conflict", "Upload was already finalized.")
    if upload["expires_at"] <= common.utcnow():
        raise Problem("conflict", "Upload session expired; create a new upload.")

    try:
        staged = await store.write_async_chunks(
            upload_id, chunks, maximum_bytes=int(upload["expected_size"])
        )
    except StorageError as exc:
        if exc.code == "too_large":
            raise Problem("too_large", "Uploaded body exceeds the declared upload size.") from exc
        raise Problem("invalid", "Upload body was empty or unreadable.") from exc

    if staged.sha256 != upload["expected_sha256"] or staged.byte_size != int(upload["expected_size"]):
        store.discard(upload_id)
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project_id,
            actor_id=user.user_id,
            action="upload.put",
            decision="digest_mismatch",
            request_id=request_id,
            target_id=upload_id,
        )
        raise Problem("conflict", "Uploaded bytes do not match the declared digest or size.")

    await session.execute(
        text(
            """
            UPDATE core.uploads SET state='uploaded', staged_sha256=:sha256, staged_bytes=:size
            WHERE id=:id AND project_id=:project_id
            """
        ),
        {
            "sha256": staged.sha256,
            "size": staged.byte_size,
            "id": upload["id"],
            "project_id": upload["project_id"],
        },
    )
    return {"status": "uploaded", "sha256": staged.sha256, "byte_size": staged.byte_size}


async def finalize_upload(
    session: AsyncSession,
    *,
    store: ArtifactStore,
    user: UserContext,
    project_id: str,
    upload_id: str,
    body: Mapping[str, Any],
    idempotency_key: str,
    request_sha256: str,
    request_id: str,
    ttl_seconds: int,
) -> idempotency.IdempotentResult:
    project = ensure_uuid(project_id, field="project_id")
    claimed_sha = body.get("sha256")
    claimed_size = body.get("byte_size")
    if not isinstance(claimed_sha, str) or len(claimed_sha) != 64:
        raise Problem("invalid_semantic", "sha256 must be a lowercase hex digest.", field_errors=[{"path": "sha256", "code": "format"}])
    if not isinstance(claimed_size, int) or isinstance(claimed_size, bool) or claimed_size < 1:
        raise Problem("invalid_semantic", "byte_size must be a positive integer.", field_errors=[{"path": "byte_size", "code": "range"}])

    async def handler() -> tuple[int, Dict[str, Any]]:
        upload = (
            await session.execute(
                text(
                    """
                    SELECT id, project_id, artifact_id, expected_size, expected_sha256, state,
                           staged_sha256, staged_bytes
                    FROM core.uploads WHERE id=:id AND project_id=:project_id FOR UPDATE
                    """
                ),
                {"id": ensure_uuid(upload_id, field="upload_id"), "project_id": project},
            )
        ).mappings().first()
        if upload is None:
            raise Problem("not_found", "Upload not found.")
        if upload["state"] == "finalized":
            raise Problem("conflict", "Upload was already finalized.")
        if upload["state"] != "uploaded":
            raise Problem("conflict", "Upload has no staged bytes to finalize.")
        if claimed_sha != upload["staged_sha256"] or claimed_size != int(upload["staged_bytes"] or 0):
            raise Problem("conflict", "Finalize values do not match the staged bytes.")
        if upload["staged_sha256"] != upload["expected_sha256"]:
            raise Problem("conflict", "Staged digest does not match the declared digest.")

        try:
            store.promote(upload_id, project, str(upload["artifact_id"]))
        except StorageError as exc:
            raise Problem("conflict", "Staged bytes are no longer available.") from exc

        artifact = (
            await session.execute(
                text(
                    """
                    UPDATE core.artifacts
                       SET state='ready', sha256=:sha256, byte_size=:size
                     WHERE id=:artifact_id AND project_id=:project_id
                    RETURNING id, project_id, sha256, byte_size, media_type, state, classification, created_at
                    """
                ),
                {
                    "sha256": upload["staged_sha256"],
                    "size": int(upload["staged_bytes"]),
                    "artifact_id": upload["artifact_id"],
                    "project_id": project,
                },
            )
        ).mappings().one()
        await session.execute(
            text(
                """
                UPDATE core.uploads SET state='finalized', finalized_at=now()
                WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": upload["id"], "project_id": project},
        )
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="upload.finalize",
            decision="allowed",
            request_id=request_id,
            target_id=str(artifact["id"]),
        )
        return 200, common.artifact_body(artifact)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=FINALIZE_OPERATION,
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


async def get_artifact(session: AsyncSession, *, project_id: str, artifact_id: str) -> Dict[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT id, project_id, sha256, byte_size, media_type, state, classification, created_at
                FROM core.artifacts WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": ensure_uuid(artifact_id, field="artifact_id"), "project_id": ensure_uuid(project_id, field="project_id")},
        )
    ).mappings().first()
    if row is None:
        raise Problem("not_found", "Artifact not found.")
    return common.artifact_body(row)


async def load_artifact_row(session: AsyncSession, *, project_id: str, artifact_id: str) -> Mapping[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT id, project_id, sha256, byte_size, media_type, state, classification, created_at
                FROM core.artifacts WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": ensure_uuid(artifact_id, field="artifact_id"), "project_id": ensure_uuid(project_id, field="project_id")},
        )
    ).mappings().first()
    if row is None:
        raise Problem("not_found", "Artifact not found.")
    return row


# --------------------------------------------------------------------------
# Jobs
# --------------------------------------------------------------------------
async def get_job(session: AsyncSession, *, project_id: str, job_id: str) -> Dict[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT id, project_id, kind, state, attempt, revision, created_at, result_id, error_code
                FROM core.jobs WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": ensure_uuid(job_id, field="job_id"), "project_id": ensure_uuid(project_id, field="project_id")},
        )
    ).mappings().first()
    if row is None:
        raise Problem("not_found", "Job not found.")
    return common.job_body(row)


async def cancel_job(
    session: AsyncSession,
    *,
    user: UserContext,
    project_id: str,
    job_id: str,
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
                    UPDATE core.jobs
                       SET state='cancel_requested', revision=revision+1, updated_at=now()
                     WHERE id=:id AND project_id=:project_id
                       AND state IN ('queued','leased','running','cancel_requested')
                    RETURNING id, project_id, kind, state, attempt, revision, created_at, result_id, error_code
                    """
                ),
                {"id": ensure_uuid(job_id, field="job_id"), "project_id": project},
            )
        ).mappings().first()
        if row is None:
            existing = (
                await session.execute(
                    text(
                        """
                        SELECT id, project_id, kind, state, attempt, revision, created_at, result_id, error_code
                        FROM core.jobs WHERE id=:id AND project_id=:project_id
                        """
                    ),
                    {"id": ensure_uuid(job_id, field="job_id"), "project_id": project},
                )
            ).mappings().first()
            if existing is None:
                raise Problem("not_found", "Job not found.")
            # A terminal job stays terminal; cancellation is not rewritten as success.
            return 202, common.job_body(existing)
        await common.audit(
            session,
            organization_id=user.organization_id,
            project_id=project,
            actor_id=user.user_id,
            action="job.cancel",
            decision="allowed",
            request_id=request_id,
            target_id=job_id,
        )
        return 202, common.job_body(row)

    return await idempotency.perform(
        session,
        scope=idempotency.PROJECT_SCOPE,
        scope_id=project,
        actor_id=ensure_uuid(user.user_id, field="user_id"),
        operation=CANCEL_OPERATION,
        key=idempotency_key,
        request_sha256=request_sha256,
        ttl_seconds=ttl_seconds,
        handler=handler,
    )


def verify_download_digest(path_sha: str, chunks: bytes) -> None:
    if sha256_bytes(chunks) != path_sha:
        raise Problem("conflict", "Artifact bytes no longer match the recorded digest.")


def json_body(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def settings_store(settings: Settings) -> ArtifactStore:
    return ArtifactStore(settings.ARTIFACT_ROOT)
