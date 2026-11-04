"""SkillBench schema metadata. Kept in lockstep with database/migrations by tests."""
from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    Numeric,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata = MetaData(schema="skb")

packages = Table(
    "packages", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("artifact_id", UUID(as_uuid=True), nullable=False),
    Column("name", Text, nullable=False),
    Column("sha256", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("revision", BigInteger, nullable=False),
    Column("execution_profile", Text, nullable=False),
    Column("source_commit", Text),
    Column("license_expression", Text),
    Column("inspection_sha256", Text),
    Column("inspection_summary", JSONB),
    Column("inspected_at", DateTime(timezone=True)),
    Column("rejection_code", Text),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

package_entries = Table(
    "package_entries", metadata,
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("package_id", UUID(as_uuid=True), nullable=False),
    Column("path", Text, nullable=False),
    Column("entry_type", Text, nullable=False),
    Column("byte_size", BigInteger, nullable=False),
    Column("compressed_size", BigInteger, nullable=False),
    Column("ordinal", Integer, nullable=False),
    PrimaryKeyConstraint("package_id", "path"),
)

package_findings = Table(
    "package_findings", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("package_id", UUID(as_uuid=True), nullable=False),
    Column("code", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("detail", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

package_reviews = Table(
    "package_reviews", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("package_id", UUID(as_uuid=True), nullable=False),
    Column("package_sha256", Text, nullable=False),
    Column("package_revision", BigInteger, nullable=False),
    Column("actor_id", UUID(as_uuid=True), nullable=False),
    Column("decision", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

suites = Table(
    "suites", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("name", Text, nullable=False),
    Column("version", Integer, nullable=False),
    Column("sha256", Text, nullable=False),
    Column("definition", JSONB, nullable=False),
    Column("task_count", Integer, nullable=False),
    Column("rights_manifest_artifact_id", UUID(as_uuid=True), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

hidden_answers = Table(
    "hidden_answers", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("suite_id", UUID(as_uuid=True), nullable=False),
    Column("artifact_id", UUID(as_uuid=True), nullable=False),
)

plans = Table(
    "plans", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("package_id", UUID(as_uuid=True), nullable=False),
    Column("package_sha256", Text, nullable=False),
    Column("suite_id", UUID(as_uuid=True), nullable=False),
    Column("suite_sha256", Text, nullable=False),
    Column("sha256", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("revision", BigInteger, nullable=False),
    Column("definition", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("preregistered_at", DateTime(timezone=True)),
)

experiments = Table(
    "experiments", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("plan_id", UUID(as_uuid=True), nullable=False),
    Column("plan_sha256", Text, nullable=False),
    Column("plan_revision", BigInteger, nullable=False),
    Column("state", Text, nullable=False),
    Column("job_id", UUID(as_uuid=True), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

trials = Table(
    "trials", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("experiment_id", UUID(as_uuid=True), nullable=False),
    Column("task_id", Text, nullable=False),
    Column("repeat", Integer, nullable=False),
    Column("arm", Text, nullable=False),
    Column("attempt", Integer, nullable=False),
    Column("outcome", Text, nullable=False),
    Column("cost_eur", Numeric(20, 8)),
    Column("currency", Text, nullable=False),
    Column("trace_artifact_id", UUID(as_uuid=True)),
    Column("result", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

analyses = Table(
    "analyses", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("project_id", UUID(as_uuid=True), nullable=False),
    Column("experiment_id", UUID(as_uuid=True), nullable=False),
    Column("input_sha256", Text, nullable=False),
    Column("version", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("result", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
