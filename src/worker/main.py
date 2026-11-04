"""Lease-based fixture worker (trusted dispatcher).

One active fenced attempt per job. A lease-expired attempt is abandoned by the
claim function and retried with a higher attempt/fence number; a stale completion
(fence mismatch) never overwrites a newer attempt and is never reported as success.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Any, Dict, Optional

from sqlalchemy import text

from src.core.config import Settings, settings as default_settings, validate_runtime
from src.core.db import Database, apply_scope, ensure_uuid
from src.services.storage import ArtifactStore
from src.worker.handlers import SUPPORTED_JOB_KINDS, Cancelled, HandlerError, dispatch

logger = logging.getLogger("skb.worker")
LEASE_SECONDS = 60


class Worker:
    def __init__(self, settings: Settings, *, database: Optional[Database] = None) -> None:
        self.settings = settings
        self.db = database or Database(settings)
        self.store = ArtifactStore(settings.ARTIFACT_ROOT or "./.data/artifacts")

    async def claim(self) -> Optional[Dict[str, Any]]:
        async with self.db.session() as session:
            row = (
                await session.execute(
                    text("SELECT * FROM core.claim_job(:kinds, :lease)"),
                    {"kinds": list(SUPPORTED_JOB_KINDS), "lease": LEASE_SECONDS},
                )
            ).mappings().first()
        return dict(row) if row else None

    async def run_once(self) -> bool:
        """Claim and execute at most one job. Returns True when work was done."""
        claimed = await self.claim()
        if claimed is None:
            return False
        await self.execute(claimed)
        return True

    async def execute(self, claimed: Dict[str, Any]) -> None:
        """Run one already-claimed job to completion (fenced)."""
        project_id = str(claimed["project_id"])
        job_id = str(claimed["job_id"])
        fence = int(claimed["fence"])
        attempt = int(claimed["attempt"])
        payload = claimed["payload"]
        cancel_requested = bool(claimed.get("cancel_requested"))
        if isinstance(payload, str):
            payload = json.loads(payload)
        state = "failed"
        result_id: Optional[str] = None
        error_code: Optional[str] = None

        try:
            async with self.db.scoped(project_id=project_id) as session:
                await session.execute(
                    text(
                        """
                        UPDATE core.jobs SET state='running', revision=revision+1, updated_at=now()
                         WHERE id=:id AND project_id=:project_id AND fence=:fence
                           AND state='leased'
                        """
                    ),
                    {"id": job_id, "project_id": project_id, "fence": fence},
                )
                result_id, error_code = await dispatch(
                    session,
                    kind=str(claimed["kind"]),
                    project_id=project_id,
                    job_id=job_id,
                    attempt=attempt,
                    payload=payload,
                    store=self.store,
                    settings=self.settings,
                    cancel_requested=cancel_requested,
                )
                if error_code == "cancelled":
                    state = "cancelled"
                elif error_code is None:
                    state = "succeeded"
                else:
                    state = "failed"
        except (HandlerError, Cancelled) as exc:
            error_code = exc.code if isinstance(exc, HandlerError) else "cancelled"
            state = "cancelled" if error_code == "cancelled" else "failed"
            logger.warning("job_failed job_id=%s attempt=%s code=%s", job_id, attempt, error_code)
        except Exception as exc:  # noqa: BLE001 - unknown effect must be recorded honestly
            error_code = "handler_error"
            state = "failed_unknown_effect"
            logger.error("job_error job_id=%s attempt=%s type=%s", job_id, attempt, type(exc).__name__)

        await self._complete(project_id, job_id, fence, attempt, state, result_id, error_code)

    async def _complete(
        self,
        project_id: str,
        job_id: str,
        fence: int,
        attempt: int,
        state: str,
        result_id: Optional[str],
        error_code: Optional[str],
    ) -> None:
        async with self.db.scoped(project_id=project_id) as session:
            updated = await session.execute(
                text(
                    """
                    UPDATE core.jobs
                       SET state=:state, result_id=:result_id, error_code=:error_code,
                           lease_until=NULL, revision=revision+1, updated_at=now()
                     WHERE id=:id AND project_id=:project_id AND fence=:fence
                       AND state IN ('leased','running')
                       AND lease_until > now()
                    RETURNING id
                    """
                ),
                {
                    "state": state,
                    "result_id": result_id,
                    "error_code": error_code,
                    "id": job_id,
                    "project_id": project_id,
                    "fence": fence,
                },
            )
            if updated.rowcount != 1:
                # Stale fence/expired lease: never report a completion we do not own.
                logger.warning("stale_completion job_id=%s fence=%s attempt=%s", job_id, fence, attempt)
            await session.execute(
                text(
                    """
                    UPDATE core.job_attempts SET state=:attempt_state, finished_at=now()
                     WHERE job_id=:id AND attempt=:attempt AND state='running'
                    """
                ),
                {
                    "attempt_state": "abandoned" if state == "failed_unknown_effect" else state,
                    "id": job_id,
                    "attempt": attempt,
                },
            )

    async def run_forever(self, *, max_jobs: Optional[int] = None, idle_exit: float = 0.0) -> int:
        processed = 0
        idle_since = asyncio.get_event_loop().time()
        while True:
            did = await self.run_once()
            if did:
                processed += 1
                idle_since = asyncio.get_event_loop().time()
                if max_jobs is not None and processed >= max_jobs:
                    return processed
                continue
            if max_jobs is not None and processed >= max_jobs:
                return processed
            now = asyncio.get_event_loop().time()
            if idle_exit and now - idle_since >= idle_exit:
                return processed
            await asyncio.sleep(0.5)

    async def close(self) -> None:
        await self.db.dispose()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SkillBench fixture worker")
    parser.add_argument("--max-jobs", type=int, default=None, help="Exit after N jobs (0 = idle exit)")
    parser.add_argument("--idle-exit", type=float, default=0.0, help="Exit after N idle seconds (0 = never)")
    parser.add_argument("--check", action="store_true", help="Validate configuration and exit")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    problems = validate_runtime(default_settings)
    if problems:
        print(json.dumps({"status": "refused", "problems": problems}), file=sys.stderr)
        return 2
    if args.check:
        print(json.dumps({"status": "ok"}))
        return 0

    worker = Worker(default_settings)

    async def run() -> int:
        try:
            return await worker.run_forever(max_jobs=args.max_jobs, idle_exit=args.idle_exit)
        finally:
            await worker.close()

    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
