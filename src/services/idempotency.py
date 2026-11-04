"""Scoped, atomic idempotency for mutating operations.

Guarantees (docs/06 and docs/Baseline_Revision_r2.md):
  * the scope is always explicit: project mutations use
    ``core.idempotency_project`` (project, actor, operation, key) and project
    creation uses ``core.idempotency_organization`` (organization, actor,
    operation, key);
  * authorization happens before this module is called, so a revoked caller is
    denied rather than replayed;
  * same key + same normalized request replays the original response;
  * same key + different normalized request is a 409 conflict;
  * the domain write and the replay record commit in one transaction;
  * a record is reusable after its 24h window expires.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.errors import Problem

PROJECT_SCOPE = "project"
ORGANIZATION_SCOPE = "organization"

Handler = Callable[[], Awaitable[Tuple[int, Dict[str, Any]]]]


@dataclass
class IdempotentResult:
    status_code: int
    body: Dict[str, Any]
    replayed: bool


def _table_and_column(scope: str) -> Tuple[str, str]:
    if scope == PROJECT_SCOPE:
        return "core.idempotency_project", "project_id"
    if scope == ORGANIZATION_SCOPE:
        return "core.idempotency_organization", "organization_id"
    raise ValueError("invalid_idempotency_scope")


async def perform(
    session: AsyncSession,
    *,
    scope: str,
    scope_id: str,
    actor_id: str,
    operation: str,
    key: str,
    request_sha256: str,
    ttl_seconds: int,
    handler: Handler,
) -> IdempotentResult:
    table, scope_column = _table_and_column(scope)
    insert = text(
        f"""
        INSERT INTO {table}
          ({scope_column}, actor_id, operation, key, request_sha256, state, expires_at)
        VALUES (:scope_id, :actor_id, :operation, :key, :request_sha256, 'in_progress',
                now() + make_interval(secs => :ttl))
        ON CONFLICT DO NOTHING
        """
    )
    select = text(
        f"""
        SELECT request_sha256, state, response_status, response_body,
               (expires_at <= now()) AS expired
        FROM {table}
        WHERE {scope_column} = :scope_id AND actor_id = :actor_id
          AND operation = :operation AND key = :key
        FOR UPDATE
        """
    )
    params = {
        "scope_id": scope_id,
        "actor_id": actor_id,
        "operation": operation,
        "key": key,
        "request_sha256": request_sha256,
        "ttl": int(ttl_seconds),
    }

    for _ in range(4):
        inserted = await session.execute(insert, params)
        if inserted.rowcount == 1:
            return await _execute(session, table, scope_column, params, handler)

        row = (await session.execute(select, params)).mappings().first()
        if row is None:
            # The competing transaction rolled back; retry the insert.
            continue
        if row["expired"]:
            takeover = await session.execute(
                text(
                    f"""
                    UPDATE {table}
                       SET state='in_progress', request_sha256=:request_sha256,
                           response_status=NULL, response_body=NULL,
                           created_at=now(), expires_at=now() + make_interval(secs => :ttl)
                     WHERE {scope_column} = :scope_id AND actor_id = :actor_id
                       AND operation = :operation AND key = :key
                       AND expires_at <= now()
                    """
                ),
                params,
            )
            if takeover.rowcount == 1:
                return await _execute(session, table, scope_column, params, handler)
            continue
        if row["request_sha256"] != request_sha256:
            raise Problem(
                "conflict",
                "Idempotency-Key was already used with a different request payload.",
            )
        if row["state"] == "completed":
            return IdempotentResult(
                status_code=int(row["response_status"]),
                body=row["response_body"],
                replayed=True,
            )
        # In progress by a competing transaction that has not committed yet.
        # The FOR UPDATE lock guarantees this only appears after a takeover race.
        continue

    raise Problem("unavailable", "Could not resolve the idempotent request; retry later.")


async def _execute(
    session: AsyncSession,
    table: str,
    scope_column: str,
    params: Dict[str, Any],
    handler: Handler,
) -> IdempotentResult:
    status_code, body = await handler()
    await session.execute(
        text(
            f"""
            UPDATE {table}
               SET state='completed', response_status=:status, response_body=CAST(:body AS jsonb)
             WHERE {scope_column} = :scope_id AND actor_id = :actor_id
               AND operation = :operation AND key = :key AND state='in_progress'
            """
        ),
        {**params, "status": status_code, "body": _json(body)},
    )
    return IdempotentResult(status_code=status_code, body=body, replayed=False)


def _json(value: Dict[str, Any]) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


async def replay_headers(result: IdempotentResult) -> Dict[str, str]:
    return {"X-Idempotency-Replayed": "true"} if result.replayed else {}


async def purge_expired(session: AsyncSession, *, scope: str, older_than_seconds: int = 0) -> None:
    """Lifecycle helper. Not exposed over HTTP; used by the inline prune path."""
    table, _ = _table_and_column(scope)
    await session.execute(
        text(f"DELETE FROM {table} WHERE expires_at <= now() - make_interval(secs => :extra)"),
        {"extra": int(older_than_seconds)},
    )


def optional_ttl(value: Optional[int]) -> int:
    return int(value) if value else 86400
