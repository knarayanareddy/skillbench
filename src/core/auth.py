"""Runtime authentication: server-side sessions, scoped API keys, membership.

Identity is resolved from preprovisioned rows only. There is no password path and
no public registration. Membership is cached for at most MEMBERSHIP_CACHE_SECONDS
so that a revoked grant stops working within the documented bound.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import Settings
from src.core.db import Database, ensure_uuid
from src.core.security import UserContext, api_key_digest, capability_names, new_csrf_token, new_session_token, token_digest


@dataclass
class Identity:
    user_id: str
    organization_id: str
    org_role: str
    project_roles: Dict[str, set] = field(default_factory=dict)

    def context(self) -> UserContext:
        return UserContext(
            user_id=self.user_id,
            organization_id=self.organization_id,
            org_role=self.org_role,
            project_roles={k: set(v) for k, v in self.project_roles.items()},
        )


class _MembershipCache:
    def __init__(self) -> None:
        self._entries: Dict[str, Tuple[float, Optional[Identity]]] = {}

    def get(self, key: str, ttl: float) -> Optional[Optional[Identity]]:
        entry = self._entries.get(key)
        if entry is None:
            return None
        stored_at, identity = entry
        if ttl <= 0 or time.monotonic() - stored_at > ttl:
            self._entries.pop(key, None)
            return None
        return identity

    def put(self, key: str, identity: Optional[Identity], ttl: float) -> None:
        if ttl <= 0:
            return
        self._entries[key] = (time.monotonic(), identity)

    def clear(self) -> None:
        self._entries.clear()


membership_cache = _MembershipCache()


async def resolve_identity(
    db: Database, issuer: str, subject: str, *, settings: Settings
) -> Optional[Identity]:
    """Resolve a verified (issuer, subject) to its preprovisioned membership."""
    cache_key = f"idp:{issuer}:{subject}"
    cached = membership_cache.get(cache_key, settings.MEMBERSHIP_CACHE_SECONDS)
    if cached is not None:
        return cached
    async with db.session() as session:
        rows = (
            await session.execute(
                text("SELECT * FROM core.resolve_identity(:issuer, :subject)"),
                {"issuer": issuer, "subject": subject},
            )
        ).mappings().all()
    identity = _build_identity(rows)
    membership_cache.put(cache_key, identity, settings.MEMBERSHIP_CACHE_SECONDS)
    return identity


async def resolve_user_identity(db: Database, user_id: str, *, settings: Settings) -> Optional[Identity]:
    """Resolve capability context for an authenticated session user (bounded cache)."""
    cache_key = f"user:{user_id}"
    cached = membership_cache.get(cache_key, settings.MEMBERSHIP_CACHE_SECONDS)
    if cached is not None:
        return cached
    async with db.session() as session:
        rows = (
            await session.execute(
                text("SELECT * FROM core.resolve_user_context(:user_id)"),
                {"user_id": ensure_uuid(user_id, field="user_id")},
            )
        ).mappings().all()
    identity = _build_identity(rows)
    membership_cache.put(cache_key, identity, settings.MEMBERSHIP_CACHE_SECONDS)
    return identity


def _build_identity(rows: List[Mapping]) -> Optional[Identity]:
    if not rows:
        return None
    first = rows[0]
    project_roles: Dict[str, set] = {}
    for row in rows:
        if row["project_id"] is None or row["project_role"] is None:
            continue
        project_roles.setdefault(str(row["project_id"]), set()).add(str(row["project_role"]))
    return Identity(
        user_id=str(first["user_id"]),
        organization_id=str(first["organization_id"]),
        org_role=str(first["org_role"]),
        project_roles=project_roles,
    )


async def create_session(
    db: Database, *, identity: Identity, settings: Settings
) -> Tuple[str, str]:
    """Create a server-side session; returns (cookie token, csrf token)."""
    token = new_session_token()
    csrf = new_csrf_token()
    async with db.scoped(organization_id=identity.organization_id) as session:
        await session.execute(
            text(
                """
                INSERT INTO core.sessions
                  (id, organization_id, user_id, token_digest, csrf_token,
                   idle_expires_at, absolute_expires_at)
                VALUES (gen_random_uuid(), :organization_id, :user_id, :token_digest, :csrf_token,
                        now() + make_interval(secs => :idle),
                        now() + make_interval(secs => :absolute))
                """
            ),
            {
                "organization_id": ensure_uuid(identity.organization_id, field="organization_id"),
                "user_id": ensure_uuid(identity.user_id, field="user_id"),
                "token_digest": token_digest(token),
                "csrf_token": csrf,
                "idle": settings.SESSION_IDLE_SECONDS,
                "absolute": settings.SESSION_ABSOLUTE_SECONDS,
            },
        )
    return token, csrf


@dataclass
class SessionRecord:
    session_id: str
    user_id: str
    organization_id: str
    csrf_token: str
    idle_expires_at: object
    absolute_expires_at: object
    revoked_at: object


async def resolve_session(db: Database, token: str) -> Optional[SessionRecord]:
    async with db.session() as session:
        row = (
            await session.execute(
                text(
                    "SELECT * FROM core.resolve_session(:digest)"
                ),
                {"digest": token_digest(token)},
            )
        ).mappings().first()
    if row is None or row["revoked_at"] is not None:
        return None
    return SessionRecord(
        session_id=str(row["session_id"]),
        user_id=str(row["user_id"]),
        organization_id=str(row["organization_id"]),
        csrf_token=str(row["csrf_token"]),
        idle_expires_at=row["idle_expires_at"],
        absolute_expires_at=row["absolute_expires_at"],
        revoked_at=row["revoked_at"],
    )


async def touch_session(db: Database, record: SessionRecord, settings: Settings, *, now) -> bool:
    """Slide the idle window; refused when the session is expired."""
    if record.absolute_expires_at <= now or record.idle_expires_at <= now:
        return False
    async with db.scoped(organization_id=record.organization_id) as session:
        result = await session.execute(
            text(
                """
                UPDATE core.sessions
                   SET last_seen_at=now(),
                       idle_expires_at=LEAST(now() + make_interval(secs => :idle), absolute_expires_at)
                 WHERE id=:id AND organization_id=:organization_id
                   AND revoked_at IS NULL AND idle_expires_at > now() AND absolute_expires_at > now()
                """
            ),
            {
                "id": ensure_uuid(record.session_id, field="session_id"),
                "organization_id": ensure_uuid(record.organization_id, field="organization_id"),
                "idle": settings.SESSION_IDLE_SECONDS,
            },
        )
        return result.rowcount == 1


async def revoke_session(db: Database, record: SessionRecord) -> None:
    async with db.scoped(organization_id=record.organization_id) as session:
        await session.execute(
            text(
                """
                UPDATE core.sessions SET revoked_at=now()
                 WHERE id=:id AND organization_id=:organization_id AND revoked_at IS NULL
                """
            ),
            {
                "id": ensure_uuid(record.session_id, field="session_id"),
                "organization_id": ensure_uuid(record.organization_id, field="organization_id"),
            },
        )


async def create_auth_transaction(
    db: Database,
    *,
    state: str,
    nonce: str,
    code_verifier: str,
    return_to: str,
) -> None:
    async with db.session() as session:
        await session.execute(
            text(
                """
                INSERT INTO core.auth_transactions
                  (id, state_digest, nonce, code_verifier, return_to, expires_at)
                VALUES (gen_random_uuid(), :state_digest, :nonce, :code_verifier, :return_to,
                        now() + interval '10 minutes')
                """
            ),
            {
                "state_digest": token_digest(state),
                "nonce": nonce,
                "code_verifier": code_verifier,
                "return_to": return_to,
            },
        )


async def consume_auth_transaction(db: Database, state: str) -> Optional[Mapping]:
    """One-use consumption of the login transaction."""
    async with db.session() as session:
        row = (
            await session.execute(
                text(
                    """
                    UPDATE core.auth_transactions SET consumed_at=now()
                     WHERE state_digest=:digest AND consumed_at IS NULL AND expires_at > now()
                    RETURNING nonce, code_verifier, return_to
                    """
                ),
                {"digest": token_digest(state)},
            )
        ).mappings().first()
    return row


@dataclass
class ApiKeyRecord:
    key_id: str
    actor_id: str
    project_id: str
    organization_id: str
    scopes: Tuple[str, ...]
    expires_at: object
    revoked_at: object


async def resolve_api_key(db: Database, raw_key: str) -> Optional[ApiKeyRecord]:
    if not raw_key or len(raw_key) < 20:
        return None
    async with db.session() as session:
        row = (
            await session.execute(
                text("SELECT * FROM core.resolve_api_key(:digest)"),
                {"digest": api_key_digest(raw_key)},
            )
        ).mappings().first()
    if row is None or row["revoked_at"] is not None:
        return None
    return ApiKeyRecord(
        key_id=str(row["key_id"]),
        actor_id=str(row["actor_id"]),
        project_id=str(row["project_id"]),
        organization_id=str(row["organization_id"]),
        scopes=tuple(row["scopes"] or ()),
        expires_at=row["expires_at"],
        revoked_at=row["revoked_at"],
    )


def api_key_context(record: ApiKeyRecord, *, org_role: str = "member") -> UserContext:
    capabilities = capability_names(record.scopes)
    return UserContext(
        user_id=record.actor_id,
        organization_id=record.organization_id,
        org_role=org_role,
        project_roles={record.project_id: capabilities},
        principal_kind="api_key",
        api_key_id=record.key_id,
        scoped_project_id=record.project_id,
    )
