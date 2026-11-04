#!/usr/bin/env python3
"""Seed a disposable development world (idempotent).

This creates synthetic organizations, users, memberships, projects, project roles
and one scoped machine key for local development against the loopback IdP.

Guards:
  * refuses to run unless ``SKB_ENV`` is ``development``;
  * refuses a non-loopback database host unless ``SKB_SEED_CONFIRM_DISPOSABLE=1``;
  * uses the migration owner DSN only (never the runtime app/worker DSNs);
  * prints identifiers and role names, never secrets.

Usage:
    SKB_ENV=development SKB_OWNER_DATABASE_URL=postgresql://postgres@/skb?host=/tmp/pg \\
      python scripts/seed_dev.py
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ORG = "11111111-1111-4111-8111-111111111111"
PROJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ISSUER = "http://127.0.0.1:8000/local-idp"

USERS: List[Tuple[str, str, str]] = [
    (str(uuid.UUID(int=0x3000000000000000000000000000001)), "skb-dev-admin", "admin"),
    (str(uuid.UUID(int=0x3000000000000000000000000000002)), "skb-dev-maintainer", "member"),
    (str(uuid.UUID(int=0x3000000000000000000000000000003)), "skb-dev-analyst", "member"),
    (str(uuid.UUID(int=0x3000000000000000000000000000004)), "skb-dev-viewer", "member"),
    (str(uuid.UUID(int=0x3000000000000000000000000000005)), "skb-dev-operator", "member"),
]

ROLES: Dict[str, List[str]] = {
    "skb-dev-admin": ["maintainer"],
    "skb-dev-maintainer": ["maintainer"],
    "skb-dev-analyst": ["analyst"],
    "skb-dev-viewer": ["viewer"],
    "skb-dev-operator": ["operator"],
}

DEV_API_KEY = "skb_dev_key_local_only_0123456789abcdef"


def owner_dsn() -> str:
    dsn = os.getenv("SKB_OWNER_DATABASE_URL", "").strip() or os.getenv("DATABASE_URL", "").strip()
    if not dsn:
        raise SystemExit("SKB_OWNER_DATABASE_URL is required (migration-owner DSN).")
    return dsn


def preflight(dsn: str) -> None:
    environment = os.getenv("SKB_ENV", "development")
    if environment != "development":
        raise SystemExit(f"Refusing to seed: SKB_ENV={environment!r} is not 'development'.")
    import urllib.parse

    parsed = urllib.parse.urlparse(dsn.replace("postgresql+asyncpg://", "postgresql://"))
    host = parsed.hostname or ""
    query = urllib.parse.parse_qs(parsed.query)
    socket = query.get("host", [""])[0]
    loopback = host in {"", "127.0.0.1", "localhost"} or socket.startswith("/tmp")
    if not loopback and os.getenv("SKB_SEED_CONFIRM_DISPOSABLE") != "1":
        raise SystemExit(
            "Refusing to seed a non-loopback database. Set SKB_SEED_CONFIRM_DISPOSABLE=1 "
            "only for a disposable environment."
        )


def async_dsn(dsn: str) -> str:
    if dsn.startswith("postgresql+asyncpg://"):
        return dsn
    return dsn.replace("postgresql://", "postgresql+asyncpg://", 1)


async def seed(dsn: str) -> None:
    engine = create_async_engine(async_dsn(dsn), pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    """
                    INSERT INTO core.organizations(id, name, created_at)
                    VALUES (:id, 'Synthetic development organization', now())
                    ON CONFLICT (id) DO NOTHING
                    """
                ),
                {"id": ORG},
            )
            for user_id, subject, role in USERS:
                await connection.execute(
                    text(
                        """
                        INSERT INTO core.users(id, issuer, subject) VALUES (:id, :issuer, :subject)
                        ON CONFLICT (issuer, subject) DO NOTHING
                        """
                    ),
                    {"id": user_id, "issuer": ISSUER, "subject": subject},
                )
                await connection.execute(
                    text(
                        """
                        INSERT INTO core.memberships(organization_id, user_id, org_role)
                        VALUES (:org, :user, :role)
                        ON CONFLICT (organization_id, user_id) DO NOTHING
                        """
                    ),
                    {"org": ORG, "user": user_id, "role": role},
                )
            await connection.execute(
                text(
                    """
                    INSERT INTO core.projects(id, organization_id, name, content_capture, external_transfer)
                    VALUES (:id, :org, 'Synthetic skill lab', 'metadata_only', false)
                    ON CONFLICT (id) DO NOTHING
                    """
                ),
                {"id": PROJECT, "org": ORG},
            )
            for user_id, subject, _role in USERS:
                for role in ROLES.get(subject, []):
                    await connection.execute(
                        text(
                            """
                            INSERT INTO core.project_roles(project_id, user_id, role)
                            VALUES (:project, :user, :role)
                            ON CONFLICT (project_id, user_id, role) DO NOTHING
                            """
                        ),
                        {"project": PROJECT, "user": user_id, "role": role},
                    )
            digest = hashlib.sha256(DEV_API_KEY.encode("utf-8")).digest()
            service_user = USERS[2][0]
            await connection.execute(
                text(
                    """
                    INSERT INTO core.api_keys(id, project_id, actor_id, key_digest, scopes, expires_at)
                    VALUES (:id, :project, :actor, decode(:digest, 'hex'), ARRAY['analyst'], now() + interval '7 days')
                    ON CONFLICT (key_digest) DO NOTHING
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "project": PROJECT,
                    "actor": service_user,
                    "digest": digest.hex(),
                },
            )
    finally:
        await engine.dispose()


def main() -> int:
    dsn = owner_dsn()
    preflight(dsn)
    asyncio.run(seed(dsn))
    print("Seeded synthetic development world (idempotent):")
    print(f"  organization : {ORG}")
    print(f"  project      : {PROJECT}")
    print(f"  issuer       : {ISSUER}")
    print("  subjects     : " + ", ".join(subject for _, subject, _ in USERS))
    print("  project roles: " + ", ".join(f"{s}={','.join(r)}" for s, r in ROLES.items()))
    print("  machine key  : printed to the operator only when created; not stored in this repo")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
