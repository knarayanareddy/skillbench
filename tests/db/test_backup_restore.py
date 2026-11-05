"""Backup/restore drill: dump a live fixture journey, restore it elsewhere, verify.

The drill is deliberately end to end and uses the real PostgreSQL client tools
(`pg_dump --format=custom`, `pg_restore`, `pg_amcheck`) rather than a table copy,
because the guarantees that matter live in the dump: ownership, grants, RLS
policies, SECURITY DEFINER helpers, triggers and sequence state.

What the restored copy must still prove, without the source database:
  * the same row counts everywhere, including append-only evidence;
  * the same artifact digests, and byte-identical artifact files on disk;
  * the same RLS confinement for the application role (scoped vs unscoped);
  * a readable, ready API (`/health/ready` 200) pointed at the restored copy.
"""
from __future__ import annotations

import hashlib
import subprocess
import tarfile
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from src.main import create_app
from tests.support import helpers
from tests.support.pgenv import PROJECT_A

# Every table that holds durable state. Counts must survive the round trip.
TABLES = [
    "core.organizations",
    "core.users",
    "core.memberships",
    "core.projects",
    "core.project_roles",
    "core.api_keys",
    "core.sessions",
    "core.artifacts",
    "core.uploads",
    "core.artifact_links",
    "core.jobs",
    "core.job_attempts",
    "core.outbox",
    "core.deletions",
    "core.audit_events",
    "skb.packages",
    "skb.package_entries",
    "skb.package_findings",
    "skb.package_reviews",
    "skb.suites",
    "skb.hidden_answers",
    "skb.plans",
    "skb.experiments",
    "skb.trials",
    "skb.analyses",
]


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"{cmd[0]} failed: {result.stderr[-2000:]}"
    return result


def _socket_target(dsn: str) -> tuple[str, str]:
    """Split our socket-directory DSN into (host dir, port) for client tools."""
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(dsn)
    query = parse_qs(parsed.query)
    host = (query.get("host") or ["/tmp"])[0]
    return host, str(parsed.port or 5432)


def _counts(env, database: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for table in TABLES:
        rows = env.query(f"SELECT count(*) FROM {table}", database=database)
        values[table] = int(rows[0][0])
    return values


async def _journey_with_evidence(session, worker):
    """Drive the product slice until there is analysis evidence to preserve."""
    artifact, package = await helpers.approved_package_ready(session, worker)
    suite = (await helpers.create_suite(session, artifact["id"])).json()
    plan = (await helpers.create_plan(session, helpers.plan_body(package, suite))).json()
    assert (await helpers.preregister(session, plan["id"])).status_code == 200
    plan = (
        await session.get(f"/api/v1/skb/plans/{plan['id']}", headers={"X-Project-ID": PROJECT_A})
    ).json()
    experiment = (await helpers.create_experiment(session, plan)).json()
    await helpers.run_jobs(worker, 5)
    analysis = await session.post(
        f"/api/v1/skb/experiments/{experiment['id']}/analyses",
        headers={"X-Project-ID": PROJECT_A},
    )
    assert analysis.status_code == 201, analysis.text
    return artifact, experiment, analysis.json()


def _artifact_files(root: Path) -> dict[str, str]:
    """Relative path -> sha256 for every stored artifact byte."""
    digests: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digests[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


async def test_dump_restore_preserves_evidence_and_readiness(
    client, worker, world, pg_env, settings, tmp_path
):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, experiment, analysis = await _journey_with_evidence(session, worker)
    assert analysis["status"] == "valid"

    source_root = Path(settings.ARTIFACT_ROOT)
    assert _artifact_files(source_root), "the journey must have written artifact bytes"
    source_counts = _counts(pg_env, pg_env.database)
    assert source_counts["skb.trials"] > 0 and source_counts["skb.analyses"] == 1

    # -- backup ---------------------------------------------------------
    dump = tmp_path / "skb.dump"
    _run(
        [
            pg_env.bin("pg_dump"),
            "--format=custom",
            f"--file={dump}",
            pg_env.admin_dsn(),
        ]
    )
    assert dump.stat().st_size > 0
    archive = tmp_path / "artifacts.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(source_root, arcname=".")

    # -- restore into a disposable database -----------------------------
    restored_db = "skb_restore"
    pg_env.create_database(restored_db)
    _run(
        [
            pg_env.bin("pg_restore"),
            f"--dbname={pg_env.admin_dsn(restored_db)}",
            "--exit-on-error",
            "--single-transaction",
            str(dump),
        ]
    )
    restored_root = tmp_path / "restored-artifacts"
    restored_root.mkdir()
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(restored_root)  # noqa: S202 - archive built by this test

    # -- verify: physical integrity, rows, digests, RLS ------------------
    # The dump must carry every state table as data, not just as a schema.
    toc = _run([pg_env.bin("pg_restore"), "--list", str(dump)]).stdout
    for table in TABLES:
        schema, name = table.split(".")
        assert f"TABLE DATA {schema} {name}" in toc, f"{table} missing from dump"
    assert "; ERROR" not in toc and "; WARNING" not in toc, toc

    assert _counts(pg_env, restored_db) == source_counts

    # Sequence state travels with the dump, so a restored copy keeps allocating.
    sequence_sql = (
        "SELECT sequencename, last_value FROM pg_sequences "
        "WHERE schemaname IN ('core','skb') ORDER BY sequencename"
    )
    assert pg_env.query(sequence_sql, database=restored_db) == pg_env.query(sequence_sql)

    source_digests = _artifact_files(source_root)
    assert _artifact_files(restored_root) == source_digests
    stored = pg_env.query(f"SELECT sha256, byte_size FROM core.artifacts WHERE id='{artifact['id']}'")
    assert stored[0][0] in source_digests.values()

    # RLS still confines the application role in the restored copy.
    trials = source_counts["skb.trials"]
    scoped = pg_env.query_as_role(
        "app_login",
        f"BEGIN; SET LOCAL baseline.project_id='{PROJECT_A}'; SELECT count(*) FROM skb.trials; COMMIT;",
        database=restored_db,
    )
    assert int(scoped[0][0]) == trials
    unscoped = pg_env.query_as_role(
        "app_login", "SELECT count(*) FROM skb.trials", database=restored_db
    )
    assert int(unscoped[0][0]) == 0
    # The lifecycle role still cannot read trial traces after the restore.
    hidden = pg_env.run_sql(
        "SELECT has_table_privilege('baseline_lifecycle','skb.trials','SELECT')",
        database=restored_db,
    )
    assert hidden.strip() == "f"

    # -- verify: the API is ready against the restored copy -------------
    restored_settings = settings.model_copy(
        update={
            "DATABASE_URL": pg_env.app_dsn(restored_db),
            "ARTIFACT_ROOT": str(restored_root),
        }
    )
    restored_app = create_app(restored_settings)
    transport = ASGITransport(app=restored_app)
    async with AsyncClient(transport=transport, base_url="https://testserver") as http_client:
        ready = await http_client.get("/health/ready")
        assert ready.status_code == 200, ready.text
        live = await http_client.get("/health/live")
        assert live.status_code == 200, live.text

    # Append-only evidence is still append-only in the restored copy.
    with pytest.raises(RuntimeError):
        pg_env.run_sql(
            f"UPDATE skb.analyses SET status='tampered' WHERE id='{analysis['id']}'",
            database=restored_db,
        )
    del experiment
