"""Fixture-only job handlers. Submitted package content is never executed."""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.canonical import sha256_hex
from src.core.config import Settings
from src.core.db import ensure_uuid
from src.services import fixture_registry
from src.services.storage import ArtifactStore, StorageError
from src.services.zipscan import InspectionError, inspect_zip

SUPPORTED_JOB_KINDS = ("skb.inspect", "skb.experiment")


class HandlerError(Exception):
    """A safe, coded handler failure. Detail never contains raw exception text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Cancelled(Exception):
    """Cooperative cancellation observed between units of work."""


async def _cancelled(
    session: AsyncSession, project_id: str, job_id: str, flagged: bool = False
) -> bool:
    if flagged:
        return True
    row = (
        await session.execute(
            text("SELECT state FROM core.jobs WHERE id=:id AND project_id=:project_id"),
            {"id": job_id, "project_id": project_id},
        )
    ).first()
    return bool(row and row[0] == "cancel_requested")


# --------------------------------------------------------------------------
# Inspection
# --------------------------------------------------------------------------
async def handle_inspect(
    session: AsyncSession,
    *,
    project_id: str,
    job_id: str,
    payload: Mapping[str, Any],
    store: ArtifactStore,
    settings: Settings,
    cancel_requested: bool = False,
) -> tuple[Optional[str], Optional[str]]:
    """Inspect a quarantined ZIP. Returns (result_id, error_code)."""
    package_id = ensure_uuid(str(payload.get("package_id")), field="package_id")
    if await _cancelled(session, project_id, job_id, cancel_requested):
        raise Cancelled("cancelled")
    package = (
        await session.execute(
            text(
                """
                SELECT id, artifact_id, sha256, state FROM skb.packages
                WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": package_id, "project_id": project_id},
        )
    ).mappings().first()
    if package is None:
        raise HandlerError("package_not_found")
    if package["state"] in ("approved", "rejected"):
        raise HandlerError("package_already_reviewed")

    artifact = (
        await session.execute(
            text(
                """
                SELECT id, sha256, byte_size, media_type, state FROM core.artifacts
                WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": package["artifact_id"], "project_id": project_id},
        )
    ).mappings().first()
    if artifact is None or artifact["state"] != "ready":
        raise HandlerError("artifact_not_ready")
    if artifact["sha256"] != package["sha256"]:
        raise HandlerError("artifact_digest_changed")

    try:
        blob = store.read_bytes(project_id, str(artifact["id"]), maximum_bytes=settings.MAX_ARTIFACT_BYTES)
    except StorageError as exc:
        raise HandlerError(exc.code) from exc

    try:
        result = inspect_zip(
            blob,
            max_expanded=settings.ZIP_EXPANDED_BYTES,
            max_files=settings.ZIP_FILES,
            max_compressed=settings.ZIP_COMPRESSED_BYTES,
        )
    except InspectionError as exc:
        # A scanner failure is NOT a clean scan: the package stays quarantined.
        await session.execute(
            text(
                """
                UPDATE skb.packages
                   SET inspection_sha256=NULL, inspection_summary=CAST(:summary AS jsonb),
                       inspected_at=now()
                 WHERE id=:id AND project_id=:project_id AND state='quarantined'
                """
            ),
            {
                "summary": json.dumps({"policy": "skb-zip-inspection/1", "error": exc.code}),
                "id": package_id,
                "project_id": project_id,
            },
        )
        # Returned (not raised) so the recorded error summary commits: the package
        # stays quarantined and the job is honestly reported as failed.
        return None, f"inspection_{exc.code}"

    for entry in result.entries:
        await session.execute(
            text(
                """
                INSERT INTO skb.package_entries
                  (project_id, package_id, path, entry_type, byte_size, compressed_size, ordinal)
                VALUES (:project_id, :package_id, :path, :entry_type, :byte_size, :compressed_size, :ordinal)
                ON CONFLICT (package_id, path) DO NOTHING
                """
            ),
            {
                "project_id": project_id,
                "package_id": package_id,
                "path": entry.path,
                "entry_type": entry.entry_type,
                "byte_size": entry.byte_size,
                "compressed_size": entry.compressed_size,
                "ordinal": entry.ordinal,
            },
        )
    for finding in result.findings:
        await session.execute(
            text(
                """
                INSERT INTO skb.package_findings
                  (id, project_id, package_id, code, severity, detail)
                VALUES (:id, :project_id, :package_id, :code, :severity, :detail)
                ON CONFLICT (project_id, package_id, code, detail) DO NOTHING
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "project_id": project_id,
                "package_id": package_id,
                "code": finding.code,
                "severity": finding.severity,
                "detail": finding.detail[:500],
            },
        )

    summary = dict(result.summary)
    summary["entries_sha256"] = sha256_hex([entry.as_dict() for entry in result.entries])
    new_state = "inspected" if result.accepted else "rejected"
    await session.execute(
        text(
            """
            UPDATE skb.packages
               SET state=:state, inspection_sha256=:inspection_sha, inspected_at=now(),
                   inspection_summary=CAST(:summary AS jsonb),
                   rejection_code=:rejection_code
             WHERE id=:id AND project_id=:project_id AND state IN ('quarantined','inspected')
            """
        ),
        {
            "state": new_state,
            "inspection_sha": result.summary_sha256,
            "summary": json.dumps(summary, sort_keys=True),
            "rejection_code": None if result.accepted else ",".join(sorted(set(result.finding_codes())))[:120],
            "id": package_id,
            "project_id": project_id,
        },
    )
    error_code = None if result.accepted else "inspection_rejected"
    return package_id, error_code


# --------------------------------------------------------------------------
# Fixture experiment
# --------------------------------------------------------------------------
async def handle_experiment(
    session: AsyncSession,
    *,
    project_id: str,
    job_id: str,
    attempt: int,
    payload: Mapping[str, Any],
    settings: Settings,
    cancel_requested: bool = False,
) -> tuple[Optional[str], Optional[str]]:
    """Replay recorded synthetic trials for a preregistered plan.

    Nothing is executed: outcomes come from the trusted fixture registry. A task
    without a recorded fixture is persisted as ``infra_error`` (unknown), never as
    a pass. Cancellation stops between units and leaves unexecuted units absent.
    """
    experiment_id = ensure_uuid(str(payload.get("experiment_id")), field="experiment_id")
    experiment = (
        await session.execute(
            text(
                """
                SELECT id, plan_id, plan_sha256, state FROM skb.experiments
                WHERE id=:id AND project_id=:project_id
                """
            ),
            {"id": experiment_id, "project_id": project_id},
        )
    ).mappings().first()
    if experiment is None:
        raise HandlerError("experiment_not_found")
    plan = (
        await session.execute(
            text("SELECT id, sha256, definition FROM skb.plans WHERE id=:id AND project_id=:project_id"),
            {"id": experiment["plan_id"], "project_id": project_id},
        )
    ).mappings().first()
    if plan is None:
        raise HandlerError("plan_not_found")
    if plan["sha256"] != experiment["plan_sha256"]:
        raise HandlerError("plan_digest_changed")
    definition = plan["definition"]
    if isinstance(definition, str):
        definition = json.loads(definition)
    suite = (
        await session.execute(
            text("SELECT id, sha256, definition FROM skb.suites WHERE id=:id AND project_id=:project_id"),
            {"id": definition["suite_id"], "project_id": project_id},
        )
    ).mappings().first()
    if suite is None:
        raise HandlerError("suite_not_found")
    if suite["sha256"] != definition["suite_sha256"]:
        raise HandlerError("suite_digest_changed")
    suite_definition = suite["definition"]
    if isinstance(suite_definition, str):
        suite_definition = json.loads(suite_definition)

    await session.execute(
        text(
            """
            UPDATE skb.experiments SET state='running', updated_at=now()
             WHERE id=:id AND project_id=:project_id AND state='queued'
            """
        ),
        {"id": experiment_id, "project_id": project_id},
    )

    repetitions = int(definition["repetitions"])
    trials_inserted = 0
    for task in suite_definition["tasks"]:
        task_id = str(task["id"])
        for repeat in range(repetitions):
            for arm in ("baseline", "treatment"):
                if await _cancelled(session, project_id, job_id, cancel_requested):
                    await session.execute(
                        text(
                            """
                            UPDATE skb.experiments SET state='stopped', updated_at=now()
                             WHERE id=:id AND project_id=:project_id
                            """
                        ),
                        {"id": experiment_id, "project_id": project_id},
                    )
                    return experiment_id, "cancelled"
                recorded = fixture_registry.recorded_trial(task_id, repeat, arm)
                if recorded is None:
                    outcome = "infra_error"
                    cost = None
                    result_payload = {
                        "reason": "no_recorded_fixture",
                        "labels": fixture_registry.LABELS,
                        "harness": definition["harness"],
                    }
                else:
                    outcome = recorded.outcome
                    cost = recorded.cost
                    result_payload = {
                        "source": "synthetic_recorded_trial",
                        "fixture_sha256": fixture_registry.fixture_digest(),
                        "labels": fixture_registry.LABELS,
                        "harness": definition["harness"],
                    }
                await session.execute(
                    text(
                        """
                        INSERT INTO skb.trials
                          (id, project_id, experiment_id, task_id, repeat, arm, attempt, outcome,
                           cost_eur, currency, result)
                        VALUES (:id, :project_id, :experiment_id, :task_id, :repeat, :arm, :attempt,
                                :outcome, :cost, 'EUR', CAST(:result AS jsonb))
                        ON CONFLICT (experiment_id, task_id, repeat, arm, attempt) DO NOTHING
                        """
                    ),
                    {
                        "id": str(uuid.uuid4()),
                        "project_id": project_id,
                        "experiment_id": experiment_id,
                        "task_id": task_id,
                        "repeat": repeat,
                        "arm": arm,
                        "attempt": int(attempt),
                        "outcome": outcome,
                        "cost": cost,
                        "result": json.dumps(result_payload, sort_keys=True),
                    },
                )
                trials_inserted += 1

    state = "completed" if trials_inserted else "failed"
    await session.execute(
        text(
            """
            UPDATE skb.experiments SET state=:state, updated_at=now()
             WHERE id=:id AND project_id=:project_id AND state IN ('queued','running')
            """
        ),
        {"state": state, "id": experiment_id, "project_id": project_id},
    )
    return experiment_id, None if state == "completed" else "no_trials_recorded"


async def dispatch(
    session: AsyncSession,
    *,
    kind: str,
    project_id: str,
    job_id: str,
    attempt: int,
    payload: Mapping[str, Any],
    store: ArtifactStore,
    settings: Settings,
    cancel_requested: bool = False,
) -> tuple[Optional[str], Optional[str]]:
    if kind == "skb.inspect":
        return await handle_inspect(
            session,
            project_id=project_id,
            job_id=job_id,
            payload=payload,
            store=store,
            settings=settings,
            cancel_requested=cancel_requested,
        )
    if kind == "skb.experiment":
        return await handle_experiment(
            session,
            project_id=project_id,
            job_id=job_id,
            attempt=attempt,
            payload=payload,
            settings=settings,
            cancel_requested=cancel_requested,
        )
    raise HandlerError("unsupported_job_kind")
