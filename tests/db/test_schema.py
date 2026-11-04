"""Schema, role, RLS and immutability guarantees of the migrated database."""
from __future__ import annotations

import pytest
from src.models import metadata


def _tables(pg_env) -> set[str]:
    rows = pg_env.query(
        "SELECT table_schema || '.' || table_name FROM information_schema.tables "
        "WHERE table_schema IN ('core','skb') AND table_type='BASE TABLE'"
    )
    return {row[0] for row in rows}


def test_all_contract_tables_exist(pg_env):
    tables = _tables(pg_env)
    expected = {f"{table.schema}.{table.name}" for table in metadata.tables.values()}
    assert expected <= tables, sorted(expected - tables)


def test_core_metadata_matches_migrated_schema(pg_env):
    """No silent drift between the SQL migrations and the ORM mirror."""
    for table in metadata.tables.values():
        rows = pg_env.query(
            "SELECT column_name FROM information_schema.columns "
            f"WHERE table_schema='{table.schema}' AND table_name='{table.name}'"
        )
        columns = {row[0] for row in rows}
        declared = {column.name for column in table.columns}
        assert declared == columns, f"{table.schema}.{table.name}: {declared ^ columns}"


def test_content_tables_force_row_level_security(pg_env):
    forced = {
        row[0]
        for row in pg_env.query(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname IN ('core','skb') AND c.relrowsecurity AND c.relforcerowsecurity"
        )
    }
    for required in (
        "artifacts",
        "packages",
        "package_entries",
        "package_findings",
        "suites",
        "plans",
        "experiments",
        "trials",
        "analyses",
        "idempotency_project",
    ):
        assert required in forced, sorted(forced)


def test_runtime_roles_are_not_superusers_and_cannot_bypass_rls(pg_env):
    rows = pg_env.query(
        "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
        "WHERE rolname IN ('baseline_app','baseline_dispatcher','baseline_lifecycle')"
    )
    assert len(rows) == 3
    for row in rows:
        assert row[1] == "f" and row[2] == "f"


def test_app_role_appends_but_never_rewrites_evidence(pg_env):
    for schema, table in (
        ("core", "audit_events"),
        ("skb", "package_reviews"),
        ("skb", "trials"),
        ("skb", "analyses"),
        ("skb", "package_findings"),
    ):
        insert = pg_env.query(
            f"SELECT has_table_privilege('baseline_app', '{schema}.{table}', 'INSERT')"
        )
        rewrite = pg_env.query(
            f"SELECT has_table_privilege('baseline_app', '{schema}.{table}', 'UPDATE'), "
            f"has_table_privilege('baseline_app', '{schema}.{table}', 'DELETE')"
        )
        assert insert == [["t"]], (table, insert)
        assert rewrite == [["f", "f"]], (table, rewrite)


def test_app_role_can_only_finalize_artifact_identity(pg_env):
    rows = pg_env.query(
        "SELECT privilege_type, column_name FROM information_schema.column_privileges "
        "WHERE grantee='baseline_app' AND table_schema='core' AND table_name='artifacts' "
        "AND privilege_type='UPDATE'"
    )
    assert {row[1] for row in rows} == {"sha256", "byte_size", "state"}


def test_artifact_identity_is_frozen_after_finalize(pg_env, world):
    pg_env.run_sql(
        "INSERT INTO core.artifacts(id, project_id, sha256, byte_size, media_type, storage_key, "
        "state, classification) VALUES ('aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', "
        "'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', repeat('a',64), 1, 'application/zip', 'k', "
        "'ready', 'synthetic')"
    )
    with pytest.raises(RuntimeError):
        pg_env.run_sql(
            "UPDATE core.artifacts SET sha256=repeat('b',64) "
            "WHERE id='aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa'"
        )


def test_preregistered_plans_and_reviews_are_immutable(pg_env):
    triggers = {
        row[0]
        for row in pg_env.query(
            "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal"
        )
    }
    assert {"no_review_mutation", "no_trial_mutation", "no_analysis_mutation", "no_audit_mutation"} <= triggers
    assert {"freeze_plan", "freeze_plan_delete", "freeze_artifact_identity"} <= triggers
    with pytest.raises(RuntimeError):
        pg_env.run_sql(
            "INSERT INTO skb.packages(id, project_id, artifact_id, name, sha256, state) VALUES "
            "(gen_random_uuid(), 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', gen_random_uuid(), 'x', "
            "repeat('a',64), 'quarantined')"
        )


def test_trial_identity_includes_attempt(pg_env):
    rows = pg_env.query(
        "SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid "
        "AND a.attnum = ANY(i.indkey) WHERE i.indrelid='skb.trials'::regclass AND i.indisunique"
    )
    names = {row[0] for row in rows}
    assert {"experiment_id", "task_id", "repeat", "arm", "attempt"} <= names


def test_idempotency_scopes_are_separate_tables(pg_env):
    organsiation = pg_env.query(
        "SELECT indexdef FROM pg_indexes WHERE tablename='idempotency_organization'"
    )
    project = pg_env.query("SELECT indexdef FROM pg_indexes WHERE tablename='idempotency_project'")
    assert any("organization_id" in row[0] and "actor_id" in row[0] for row in organsiation)
    assert any("project_id" in row[0] and "actor_id" in row[0] for row in project)


def test_claim_job_is_security_definer_and_publicly_revoked(pg_env):
    rows = pg_env.query(
        "SELECT p.prosecdef, has_function_privilege('baseline_dispatcher', p.oid, 'EXECUTE'), "
        "has_function_privilege('public', p.oid, 'EXECUTE') FROM pg_proc p "
        "WHERE p.proname='claim_job'"
    )
    assert rows == [["t", "t", "f"]]


def test_migrations_are_ordered_and_transactional(pg_env):
    for name in ("001_baseline.sql", "002_roles.sql"):
        text = open(f"database/migrations/{name}", encoding="utf-8").read()
        assert "BEGIN;" in text and "COMMIT;" in text
        assert "BEGIN;" in text.split("COMMIT;")[0]
