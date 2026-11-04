"""Core schema metadata. Kept in lockstep with database/migrations by tests."""
from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

metadata = MetaData(schema="core")

organizations = Table(
    "organizations", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("name", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

users = Table(
    "users", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("issuer", Text, nullable=False),
    Column("subject", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("issuer", "subject", name="users_issuer_subject_key"),
)

memberships = Table(
    "memberships", metadata,
    Column("organization_id", UUID(as_uuid=True), nullable=False),
    Column("user_id", UUID(as_uuid=True), nullable=False),
    Column("org_role", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("organization_id", "user_id"),
)

projects = Table(
    "projects", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("organization_id", UUID(as_uuid=True), nullable=False),
    Column("name", Text, nullable=False),
    Column("content_capture", Text, nullable=False),
    Column("external_transfer", Boolean, nullable=False),
    Column("revision", BigInteger, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

project_roles = Table(
    "project_roles", metadata,
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("user_id", UUID(as_uuid=True), nullable=False),
    Column("role", Text, nullable=False),
    Column("granted_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("project_id", "user_id", "role"),
)

api_keys = Table(
    "api_keys", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("actor_id", UUID(as_uuid=True), nullable=False),
    Column("key_digest", LargeBinary, nullable=False),
    Column("scopes", ARRAY(Text), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
)

sessions = Table(
    "sessions", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("organization_id", UUID(as_uuid=True), nullable=False),
    Column("user_id", UUID(as_uuid=True), nullable=False),
    Column("token_digest", LargeBinary, nullable=False),
    Column("csrf_token", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("idle_expires_at", DateTime(timezone=True), nullable=False),
    Column("absolute_expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
)

auth_transactions = Table(
    "auth_transactions", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("state_digest", LargeBinary, nullable=False),
    Column("nonce", Text, nullable=False),
    Column("code_verifier", Text, nullable=False),
    Column("return_to", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True)),
)

idempotency_project = Table(
    "idempotency_project", metadata,
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("actor_id", UUID(as_uuid=True), nullable=False),
    Column("operation", Text, nullable=False),
    Column("key", UUID(as_uuid=True), nullable=False),
    Column("request_sha256", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("response_status", Integer),
    Column("response_body", JSONB),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("project_id", "actor_id", "operation", "key"),
)

idempotency_organization = Table(
    "idempotency_organization", metadata,
    Column("organization_id", UUID(as_uuid=True), nullable=False),
    Column("actor_id", UUID(as_uuid=True), nullable=False),
    Column("operation", Text, nullable=False),
    Column("key", UUID(as_uuid=True), nullable=False),
    Column("request_sha256", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("response_status", Integer),
    Column("response_body", JSONB),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("organization_id", "actor_id", "operation", "key"),
)

artifacts = Table(
    "artifacts", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("sha256", Text, nullable=False),
    Column("byte_size", BigInteger, nullable=False),
    Column("media_type", Text, nullable=False),
    Column("filename", Text),
    Column("classification", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("storage_key", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True)),
)

uploads = Table(
    "uploads", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("artifact_id", UUID(as_uuid=True), nullable=False),
    Column("expected_size", BigInteger, nullable=False),
    Column("expected_sha256", Text, nullable=False),
    Column("media_type", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("staged_sha256", Text),
    Column("staged_bytes", BigInteger),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("finalized_at", DateTime(timezone=True)),
)

artifact_links = Table(
    "artifact_links", metadata,
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("parent_id", UUID(as_uuid=True), nullable=False),
    Column("child_id", UUID(as_uuid=True), nullable=False),
    Column("relation", Text, nullable=False),
    PrimaryKeyConstraint("project_id", "parent_id", "child_id", "relation"),
)

jobs = Table(
    "jobs", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("kind", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("attempt", Integer, nullable=False),
    Column("fence", BigInteger, nullable=False),
    Column("revision", BigInteger, nullable=False),
    Column("lease_until", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("result_id", UUID(as_uuid=True)),
    Column("error_code", Text),
)

job_attempts = Table(
    "job_attempts", metadata,
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("job_id", UUID(as_uuid=True), nullable=False),
    Column("attempt", Integer, nullable=False),
    Column("fence", BigInteger, nullable=False),
    Column("state", Text, nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("finished_at", DateTime(timezone=True)),
    PrimaryKeyConstraint("job_id", "attempt"),
)

outbox = Table(
    "outbox", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("kind", Text, nullable=False),
    Column("body", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("delivered_at", DateTime(timezone=True)),
)

budget_reservations = Table(
    "budget_reservations", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("job_id", UUID(as_uuid=True), nullable=False),
    Column("token_limit", BigInteger, nullable=False),
    Column("call_limit", Integer, nullable=False),
    Column("reserved_eur", Numeric(20, 8)),
    Column("observed_eur", Numeric(20, 8)),
    Column("state", Text, nullable=False),
)

audit_events = Table(
    "audit_events", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("organization_id", UUID(as_uuid=True), nullable=False),
    Column("project_id", UUID(as_uuid=True)),
    Column("actor_id", UUID(as_uuid=True)),
    Column("action", Text, nullable=False),
    Column("target_id", UUID(as_uuid=True)),
    Column("decision", Text, nullable=False),
    Column("policy_version", Text, nullable=False),
    Column("request_id", UUID(as_uuid=True), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

deletions = Table(
    "deletions", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("target_kind", Text, nullable=False),
    Column("target_id", UUID(as_uuid=True), nullable=False),
    Column("state", Text, nullable=False),
    Column("revoked_at", DateTime(timezone=True), nullable=False),
    Column("purge_deadline", DateTime(timezone=True), nullable=False),
    Column("completed_at", DateTime(timezone=True)),
)
