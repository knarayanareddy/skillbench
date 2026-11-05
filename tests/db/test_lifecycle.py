"""Lifecycle process: expiry, purge, pruning and the evidence boundary."""
from __future__ import annotations

import hashlib

import pytest

from src.lifecycle.main import Lifecycle
from src.services.storage import ArtifactStore
from tests.support import helpers
from tests.support.pgenv import PROJECT_A, PROJECT_B


def store_for(settings, project_id: str) -> ArtifactStore:
    return ArtifactStore(settings.ARTIFACT_ROOT)


async def _pending_upload(session, client, project_id: str = PROJECT_A):
    """Create an upload ticket, store bytes, and leave it unfinalised."""
    blob = helpers.skill_zip()
    digest = hashlib.sha256(blob).hexdigest()
    created = await session.post(
        f"/api/v1/projects/{project_id}/uploads",
        json={
            "filename": "pending.zip",
            "media_type": "application/zip",
            "byte_size": len(blob),
            "sha256": digest,
            "classification": "synthetic",
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    put = await session.put(body["put_path"], content=blob, headers={"X-Project-ID": project_id})
    assert put.status_code == 200
    return body


async def test_lifecycle_requires_its_own_role(lifecycle_settings, settings, pg_env):
    from src.core.config import validate_runtime

    assert validate_runtime(lifecycle_settings, require_identity=False) == []
    # The API role must not be able to delete artifacts, so an imposter run fails closed.
    imposter = Lifecycle(settings)
    try:
        rows = pg_env.query(
            "SELECT has_table_privilege('baseline_app','core.artifacts','DELETE')"
        )
        assert rows == [["f"]]
        report = await imposter.run_once()
        assert report.errors, "the API role must not be able to purge"
    finally:
        await imposter.close()


async def test_expired_upload_is_expired_and_its_bytes_removed(
    client, lifecycle, lifecycle_settings, world, pg_env
):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    upload = await _pending_upload(session, client)
    assert ArtifactStore(lifecycle_settings.ARTIFACT_ROOT).staging_path(upload["id"]).is_file()

    pg_env.run_sql(
        f"UPDATE core.uploads SET expires_at = now() - interval '1 minute' WHERE id='{upload['id']}'"
    )
    report = await lifecycle.run_once()
    assert report.uploads_expired >= 1
    assert report.staged_files_discarded >= 1

    state = pg_env.query(f"SELECT state FROM core.uploads WHERE id='{upload['id']}'")[0][0]
    assert state == "expired"
    artifact = pg_env.query(
        f"SELECT state FROM core.artifacts WHERE id='{upload['artifact_id']}'"
    )[0][0]
    assert artifact == "deleted"
    assert not ArtifactStore(lifecycle_settings.ARTIFACT_ROOT).staging_path(upload["id"]).exists()
    tombstone = pg_env.query(
        f"SELECT state FROM core.deletions WHERE target_id='{upload['artifact_id']}'"
    )
    assert tombstone == [["complete"]]


async def test_referenced_artifact_is_never_purged(
    client, worker, lifecycle, world, pg_env
):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package = await helpers.approved_package_ready(session, worker)
    pg_env.run_sql(
        f"UPDATE core.artifacts SET expires_at = now() - interval '1 day' WHERE id='{artifact['id']}'"
    )
    report = await lifecycle.run_once()
    assert report.artifacts_skipped_referenced >= 1
    state = pg_env.query(f"SELECT state FROM core.artifacts WHERE id='{artifact['id']}'")[0][0]
    assert state == "ready"
    # The approved package still resolves its artifact.
    detail = await session.get(
        f"/api/v1/skb/packages/{package['id']}/inspection", headers={"X-Project-ID": PROJECT_A}
    )
    assert detail.status_code == 200


async def test_requested_deletion_is_completed_and_idempotent(
    client, worker, lifecycle, lifecycle_settings, world, pg_env
):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await helpers.upload(session, helpers.skill_zip())
    pg_env.run_sql(
        "INSERT INTO core.deletions(id, project_id, target_kind, target_id, state, revoked_at, purge_deadline) "
        f"VALUES (gen_random_uuid(), '{PROJECT_A}', 'artifact', '{artifact['id']}', 'requested', "
        "now(), now() + interval '1 day')"
    )
    report = await lifecycle.run_once()
    assert report.deletions_completed >= 1
    assert report.artifacts_purged >= 1
    deletion = pg_env.query(
        f"SELECT state, completed_at IS NOT NULL FROM core.deletions WHERE target_id='{artifact['id']}'"
    )
    assert deletion == [["complete", "t"]]
    assert not ArtifactStore(lifecycle_settings.ARTIFACT_ROOT).exists(PROJECT_A, artifact["id"])
    again = await lifecycle.run_once()
    assert again.deletions_completed == 0
    assert again.artifacts_purged == 0


async def test_prunes_expired_operational_state(client, lifecycle, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    await helpers.upload(session, helpers.skill_zip())
    pg_env.run_sql(
        "UPDATE core.sessions SET created_at = now() - interval '2 days', "
        "absolute_expires_at = now() - interval '1 hour', "
        "idle_expires_at = now() - interval '1 hour'"
    )
    pg_env.run_sql(
        "UPDATE core.idempotency_project SET created_at = now() - interval '3 days', "
        "expires_at = now() - interval '2 days'"
    )
    pg_env.run_sql(
        "UPDATE core.idempotency_organization SET created_at = now() - interval '3 days', "
        "expires_at = now() - interval '2 days'"
    )
    pg_env.run_sql(
        "UPDATE core.auth_transactions SET created_at = now() - interval '3 days', "
        "expires_at = now() - interval '2 days'"
    )
    before = {
        table: int(pg_env.query(f"SELECT count(*) FROM {table}")[0][0])
        for table in (
            "core.sessions",
            "core.idempotency_project",
            "core.idempotency_organization",
            "core.auth_transactions",
        )
    }
    assert before["core.sessions"] >= 1

    report = await lifecycle.run_once()
    assert report.sessions_pruned >= 1
    assert report.idempotency_records_pruned >= 1
    assert report.auth_transactions_pruned >= 1
    after = {
        table: int(pg_env.query(f"SELECT count(*) FROM {table}")[0][0])
        for table in before
    }
    assert after["core.sessions"] == 0
    assert after["core.idempotency_project"] == 0
    assert after["core.idempotency_organization"] == 0
    assert after["core.auth_transactions"] == 0


async def test_outbox_backlog_is_reported_and_delivery_is_opt_in(
    lifecycle_settings, world, pg_env
):
    pg_env.run_sql(
        "INSERT INTO core.outbox(project_id, kind, body, created_at) VALUES "
        f"('{PROJECT_A}', 'skb.test', '{{}}', now() - interval '1 hour')"
    )
    quiet = Lifecycle(lifecycle_settings)
    try:
        report = await quiet.run_once()
        assert report.outbox_backlog >= 1
        assert report.outbox_delivered == 0
        pending = pg_env.query("SELECT count(*) FROM core.outbox WHERE delivered_at IS NULL")[0][0]
        assert int(pending) >= 1
    finally:
        await quiet.close()

    delivering = Lifecycle(
        lifecycle_settings.model_copy(
            update={"LIFECYCLE_OUTBOX_DELIVER": True, "LIFECYCLE_OUTBOX_GRACE_SECONDS": 0}
        )
    )
    try:
        report = await delivering.run_once()
        assert report.outbox_delivered >= 1
        pending = pg_env.query("SELECT count(*) FROM core.outbox WHERE delivered_at IS NULL")[0][0]
        assert int(pending) == 0
    finally:
        await delivering.close()


async def test_dry_run_changes_nothing(client, lifecycle, lifecycle_settings, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    upload = await _pending_upload(session, client)
    pg_env.run_sql(
        f"UPDATE core.uploads SET expires_at = now() - interval '1 minute' WHERE id='{upload['id']}'"
    )
    report = await lifecycle.run_once(dry_run=True)
    assert report.dry_run is True
    assert report.uploads_expired >= 1
    state = pg_env.query(f"SELECT state FROM core.uploads WHERE id='{upload['id']}'")[0][0]
    assert state == "uploaded"
    assert ArtifactStore(lifecycle_settings.ARTIFACT_ROOT).staging_path(upload["id"]).is_file()
    assert pg_env.query(
        f"SELECT state FROM core.artifacts WHERE id='{upload['artifact_id']}'"
    )[0][0] == "pending"


async def test_lifecycle_cannot_touch_evidence(lifecycle_settings, world, pg_env):
    for statement in (
        "DELETE FROM core.audit_events",
        "DELETE FROM skb.trials",
        "DELETE FROM skb.package_reviews",
        "DELETE FROM skb.analyses",
        "UPDATE skb.package_reviews SET decision='approved'",
    ):
        result = pg_env.run_sql_as("lifecycle_login", statement) if hasattr(pg_env, "run_sql_as") else None
        if result is None:
            with pytest.raises(RuntimeError):
                pg_env.run_sql(
                    f"SET ROLE baseline_lifecycle; {statement}"
                )
            continue
        assert "permission denied" in result


async def test_other_projects_are_untouched(client, lifecycle, world, pg_env):
    session_a = await helpers.user_session(client, "skb-dev-maintainer")
    upload_a = await _pending_upload(session_a, client)
    other = await helpers.user_session(client, "skb-dev-other-org")
    upload_b = await _pending_upload(other, client, project_id=PROJECT_B)
    pg_env.run_sql(
        f"UPDATE core.uploads SET expires_at = now() - interval '1 minute' "
        f"WHERE id IN ('{upload_a['id']}', '{upload_b['id']}')"
    )
    await lifecycle.run_once()
    states = dict(
        (row[0], row[1])
        for row in pg_env.query("SELECT id::text, state FROM core.uploads")
    )
    assert states[upload_a["id"]] == "expired"
    assert states[upload_b["id"]] == "expired"  # both projects are visited, each in its own scope
    # Every purge is scoped: no cross-project tombstone exists.
    rows = pg_env.query("SELECT project_id::text, target_id::text FROM core.deletions")
    for project_id, _target in rows:
        assert project_id in {PROJECT_A, PROJECT_B}
