"""Expiry, purge and backlog maintenance for SkillBench.

    python -m src.lifecycle.main --once [--dry-run]
    python -m src.lifecycle.main --check

The process is safe to run repeatedly and concurrently per project: the destructive
statements are guarded by state checks, and tombstones have a unique key per target.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from src.core.config import Settings, settings as default_settings, validate_runtime
from src.core.db import Database
from src.services.storage import ArtifactStore

logger = logging.getLogger("skb.lifecycle")

# "Unreferenced" means no package, suite, trial trace or open upload points at the
# artifact. The lifecycle role deliberately holds no SELECT on skb.trials/suites,
# so the four lookups live behind one SECURITY DEFINER predicate that answers a
# boolean for the current project and nothing else.
UNREFERENCED = "NOT core.artifact_is_referenced(a.project_id, a.id)"


@dataclass
class Report:
    """What one run observed and did. Counts only; never content."""

    projects: int = 0
    uploads_expired: int = 0
    staged_files_discarded: int = 0
    artifacts_purged: int = 0
    artifacts_skipped_referenced: int = 0
    deletions_completed: int = 0
    deletions_failed: int = 0
    sessions_pruned: int = 0
    auth_transactions_pruned: int = 0
    idempotency_records_pruned: int = 0
    outbox_backlog: int = 0
    outbox_delivered: int = 0
    dry_run: bool = False
    errors: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": "dry_run" if self.dry_run else "ok",
            **{
                key: value
                for key, value in self.__dict__.items()
                if key not in {"dry_run", "errors"}
            },
            "errors": self.errors,
        }


class Lifecycle:
    def __init__(
        self,
        settings: Settings,
        *,
        database: Optional[Database] = None,
        store: Optional[ArtifactStore] = None,
    ) -> None:
        self.settings = settings
        self.db = database or Database(settings)
        self.store = store or ArtifactStore(settings.ARTIFACT_ROOT or "./.data/artifacts")

    async def close(self) -> None:
        await self.db.dispose()

    # -- discovery ---------------------------------------------------------
    async def projects(self) -> List[Dict[str, str]]:
        async with self.db.session() as session:
            rows = (
                await session.execute(text("SELECT project_id, organization_id FROM core.lifecycle_projects()"))
            ).mappings().all()
        return [dict(row) for row in rows]

    # -- one project -------------------------------------------------------
    async def run_project(self, project: Dict[str, str], report: Report, *, dry_run: bool) -> None:
        project_id = str(project["project_id"])
        organization_id = str(project["organization_id"])
        try:
            async with self.db.scoped(project_id=project_id, organization_id=organization_id) as session:
                await self._expire_uploads(session, project_id, report, dry_run=dry_run)
                await self._purge_expired_artifacts(session, project_id, report, dry_run=dry_run)
                await self._complete_deletions(session, project_id, report, dry_run=dry_run)
                await self._prune_operational_state(session, project_id, organization_id, report, dry_run=dry_run)
                await self._outbox(session, project_id, report, dry_run=dry_run)
        except Exception as exc:  # noqa: BLE001 - one project must not block the rest
            logger.error("lifecycle_project_failed project_id=%s type=%s", project_id, type(exc).__name__)
            report.errors.append(f"project_failed:{type(exc).__name__}")

    async def _expire_uploads(self, session, project_id: str, report: Report, *, dry_run: bool) -> None:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT u.id, u.artifact_id
                    FROM core.uploads u
                    WHERE u.project_id=:project_id AND u.state IN ('created','uploaded')
                      AND u.expires_at <= now()
                    ORDER BY u.expires_at
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED
                    """
                ),
                {"project_id": project_id, "limit": self.settings.LIFECYCLE_BATCH},
            )
        ).mappings().all()
        for row in rows:
            upload_id = str(row["id"])
            artifact_id = str(row["artifact_id"])
            if dry_run:
                report.uploads_expired += 1
                continue
            await session.execute(
                text("UPDATE core.uploads SET state='expired' WHERE id=:id AND state IN ('created','uploaded')"),
                {"id": upload_id},
            )
            self.store.discard(upload_id)
            report.staged_files_discarded += 1
            # Retire the half-written artifact only when nothing else can reference it.
            retired = await session.execute(
                text(
                    f"""
                    UPDATE core.artifacts a SET state='deleting'
                    WHERE a.project_id=:project_id AND a.id=:artifact_id
                      AND a.state='pending' AND {UNREFERENCED}
                    RETURNING a.id
                    """
                ),
                {"project_id": project_id, "artifact_id": artifact_id},
            )
            if retired.rowcount == 1:
                await self._purge_artifact(session, project_id, artifact_id, report, reason="expired_upload")
            report.uploads_expired += 1

    async def _purge_expired_artifacts(self, session, project_id: str, report: Report, *, dry_run: bool) -> None:
        rows = (
            await session.execute(
                text(
                    f"""
                    SELECT a.id,
                           ({UNREFERENCED}) AS unreferenced
                    FROM core.artifacts a
                    WHERE a.project_id=:project_id AND a.state <> 'deleted'
                      AND a.expires_at IS NOT NULL AND a.expires_at <= now()
                    ORDER BY a.expires_at
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED
                    """
                ),
                {"project_id": project_id, "limit": self.settings.LIFECYCLE_BATCH},
            )
        ).mappings().all()
        for row in rows:
            artifact_id = str(row["id"])
            if not row["unreferenced"]:
                report.artifacts_skipped_referenced += 1
                continue
            if dry_run:
                report.artifacts_purged += 1
                continue
            await session.execute(
                text(
                    "UPDATE core.artifacts SET state='deleting' "
                    "WHERE project_id=:project_id AND id=:id AND state <> 'deleted'"
                ),
                {"project_id": project_id, "id": artifact_id},
            )
            await self._purge_artifact(session, project_id, artifact_id, report, reason="expired")

    async def _complete_deletions(self, session, project_id: str, report: Report, *, dry_run: bool) -> None:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT d.id, d.target_id, d.target_kind,
                           EXISTS (SELECT 1 FROM core.artifacts a
                                   WHERE a.project_id=d.project_id AND a.id=d.target_id) AS is_artifact
                    FROM core.deletions d
                    WHERE d.project_id=:project_id AND d.state IN ('requested','revoked','purging')
                    ORDER BY d.purge_deadline
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED
                    """
                ),
                {"project_id": project_id, "limit": self.settings.LIFECYCLE_BATCH},
            )
        ).mappings().all()
        for row in rows:
            deletion_id = str(row["id"])
            if dry_run:
                report.deletions_completed += 1
                continue
            if row["is_artifact"]:
                artifact_id = str(row["target_id"])
                try:
                    await session.execute(
                        text(
                            "UPDATE core.artifacts SET state='deleting' "
                            "WHERE project_id=:project_id AND id=:id AND state <> 'deleted'"
                        ),
                        {"project_id": project_id, "id": artifact_id},
                    )
                    await self._purge_artifact(
                        session, project_id, artifact_id, report, reason="requested"
                    )
                except Exception as exc:  # noqa: BLE001 - recorded, retried next run
                    logger.error("deletion_failed deletion_id=%s type=%s", deletion_id, type(exc).__name__)
                    report.deletions_failed += 1
                    continue
            await session.execute(
                text(
                    "UPDATE core.deletions SET state='complete', completed_at=now() "
                    "WHERE project_id=:project_id AND id=:id AND state IN ('requested','revoked','purging')"
                ),
                {"project_id": project_id, "id": deletion_id},
            )
            report.deletions_completed += 1

    async def _purge_artifact(
        self, session, project_id: str, artifact_id: str, report: Report, *, reason: str
    ) -> None:
        """Remove bytes, record a tombstone and mark the artifact deleted.

        Ordering matters: the row is already ``deleting`` (committed by this
        transaction when it commits) and byte removal is idempotent, so a crash
        between steps leaves the purge to be retried instead of losing intent.
        """
        self.store.delete(project_id, artifact_id)
        await session.execute(
            text(
                """
                INSERT INTO core.deletions
                  (id, project_id, target_kind, target_id, state, revoked_at, purge_deadline, completed_at)
                VALUES (gen_random_uuid(), :project_id, 'artifact', :target_id, 'complete',
                        now(), now(), now())
                ON CONFLICT (project_id, target_kind, target_id) DO NOTHING
                """
            ),
            {"project_id": project_id, "target_id": artifact_id},
        )
        await session.execute(
            text(
                "UPDATE core.deletions SET state='complete', completed_at=now() "
                "WHERE project_id=:project_id AND target_kind='artifact' AND target_id=:target_id "
                "AND state <> 'complete'"
            ),
            {"project_id": project_id, "target_id": artifact_id},
        )
        await session.execute(
            text(
                "UPDATE core.artifacts SET state='deleted' "
                "WHERE project_id=:project_id AND id=:id AND state <> 'deleted'"
            ),
            {"project_id": project_id, "id": artifact_id},
        )
        report.artifacts_purged += 1
        logger.info("artifact_purged artifact_id=%s reason=%s", artifact_id, reason)

    async def _prune_operational_state(
        self, session, project_id: str, organization_id: str, report: Report, *, dry_run: bool
    ) -> None:
        if dry_run:
            return
        pruned = await session.execute(
            text("DELETE FROM core.idempotency_project WHERE project_id=:project_id AND expires_at <= now()"),
            {"project_id": project_id},
        )
        report.idempotency_records_pruned += int(pruned.rowcount or 0)
        pruned_org = await session.execute(
            text(
                "DELETE FROM core.idempotency_organization "
                "WHERE organization_id=:organization_id AND expires_at <= now()"
            ),
            {"organization_id": organization_id},
        )
        report.idempotency_records_pruned += int(pruned_org.rowcount or 0)
        sessions = await session.execute(
            text(
                "DELETE FROM core.sessions "
                "WHERE organization_id=:organization_id "
                "AND (absolute_expires_at <= now() OR revoked_at IS NOT NULL)"
            ),
            {"organization_id": organization_id},
        )
        report.sessions_pruned += int(sessions.rowcount or 0)
        transactions = await session.execute(
            text(
                "DELETE FROM core.auth_transactions "
                "WHERE expires_at <= now() - make_interval(secs => :grace)"
            ),
            {"grace": float(self.settings.LIFECYCLE_AUTH_TRANSACTION_GRACE_SECONDS)},
        )
        report.auth_transactions_pruned += int(transactions.rowcount or 0)

    async def _outbox(self, session, project_id: str, report: Report, *, dry_run: bool) -> None:
        backlog = (
            await session.execute(
                text(
                    "SELECT count(*) FROM core.outbox "
                    "WHERE project_id=:project_id AND delivered_at IS NULL"
                ),
                {"project_id": project_id},
            )
        ).scalar_one()
        report.outbox_backlog += int(backlog)
        if not self.settings.LIFECYCLE_OUTBOX_DELIVER or dry_run:
            return
        delivered = await session.execute(
            text(
                """
                UPDATE core.outbox SET delivered_at=now()
                WHERE project_id=:project_id AND delivered_at IS NULL
                  AND created_at <= now() - make_interval(secs => :grace)
                """
            ),
            {"project_id": project_id, "grace": float(self.settings.LIFECYCLE_OUTBOX_GRACE_SECONDS)},
        )
        report.outbox_delivered += int(delivered.rowcount or 0)

    # -- full pass ---------------------------------------------------------
    async def run_once(self, *, dry_run: bool = False) -> Report:
        report = Report(dry_run=dry_run)
        # Enumeration itself can be refused (wrong role, missing grant). That is a
        # configuration fault, not a per-project one: record it and stop, so the
        # CLI exits non-zero instead of silently reporting an empty, clean run.
        try:
            projects = await self.projects()
        except Exception as exc:  # noqa: BLE001 - reported as a typed failure
            logger.error("lifecycle enumeration failed (%s)", type(exc).__name__)
            report.errors.append(f"projects_failed:{type(exc).__name__}")
            return report
        report.projects = len(projects)
        for project in projects:
            await self.run_project(project, report, dry_run=dry_run)
        return report

    async def run_forever(self, *, interval: float) -> int:
        runs = 0
        while True:
            report = await self.run_once()
            print(json.dumps(report.as_dict(), sort_keys=True), flush=True)
            runs += 1
            await asyncio.sleep(interval)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SkillBench lifecycle (expiry, purge, backlog)")
    parser.add_argument("--once", action="store_true", help="Run one pass and exit")
    parser.add_argument("--dry-run", action="store_true", help="Report what would change; change nothing")
    parser.add_argument("--interval", type=float, default=300.0, help="Seconds between passes (default 300)")
    parser.add_argument("--check", action="store_true", help="Validate configuration and exit")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    problems = validate_runtime(default_settings, require_identity=False)
    if problems:
        print(json.dumps({"status": "refused", "problems": problems}), file=sys.stderr)
        return 2
    if args.check:
        print(json.dumps({"status": "ok"}))
        return 0

    lifecycle = Lifecycle(default_settings)

    async def run() -> int:
        try:
            if args.once or args.dry_run:
                report = await lifecycle.run_once(dry_run=args.dry_run)
                print(json.dumps(report.as_dict(), sort_keys=True))
                return 1 if report.errors else 0
            await lifecycle.run_forever(interval=args.interval)
            return 0
        finally:
            await lifecycle.close()

    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
