"""Scoped idempotency and RLS guarantees, exercised on real PostgreSQL 16."""
from __future__ import annotations

import asyncio
import uuid

import pytest

from tests.support import helpers
from tests.support.pgenv import ORG_A, ORG_B, PROJECT_A, PROJECT_A2, PROJECT_B


def _project_count(pg_env, project_id: str) -> int:
    return int(
        pg_env.query(f"SELECT count(*) FROM core.projects WHERE id='{project_id}'")[0][0]
    )


async def test_same_key_is_scoped_per_project(client, world):
    session = await helpers.user_session(client, "skb-dev-admin")
    key = str(uuid.uuid4())
    body = {"name": "scoped", "content_capture": "metadata_only", "external_transfer": False}

    first = await session.post("/api/v1/projects", json=body, idempotency_key=key)
    replay = await session.post("/api/v1/projects", json=body, idempotency_key=key)
    assert first.status_code == replay.status_code == 201
    assert first.json()["id"] == replay.json()["id"]
    assert replay.headers.get("x-idempotency-replayed") == "true"

    # A different project has its own idempotency scope: the same key is accepted
    # there and creates a distinct package.
    analyst = await helpers.user_session(client, "skb-dev-analyst")
    artifact_a = await helpers.upload(analyst, helpers.skill_zip(), project_id=PROJECT_A)
    artifact_a2 = await helpers.upload(analyst, helpers.skill_zip(), project_id=PROJECT_A2)
    first_package = await analyst.post(
        f"/api/v1/projects/{PROJECT_A}/skb/packages",
        json={
            "artifact_id": artifact_a["id"],
            "name": "scoped package",
            "source_commit": "c" * 40,
            "license_expression": "MIT",
        },
        idempotency_key=key,
    )
    second_package = await analyst.post(
        f"/api/v1/projects/{PROJECT_A2}/skb/packages",
        json={
            "artifact_id": artifact_a2["id"],
            "name": "scoped package",
            "source_commit": "c" * 40,
            "license_expression": "MIT",
        },
        idempotency_key=key,
    )
    assert first_package.status_code == 201, first_package.text
    assert second_package.status_code == 201, second_package.text
    assert first_package.json()["id"] != second_package.json()["id"]
    assert first_package.json()["project_id"] == PROJECT_A
    assert second_package.json()["project_id"] == PROJECT_A2


async def test_organization_scope_is_separate_from_project_scope(client, worker, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-admin")
    key = str(uuid.uuid4())
    body = {"name": "org scope", "content_capture": "metadata_only", "external_transfer": False}
    response = await session.post("/api/v1/projects", json=body, idempotency_key=key)
    assert response.status_code == 201
    rows = pg_env.query(
        f"SELECT operation, response_status FROM core.idempotency_organization WHERE key='{key}'"
    )
    assert len(rows) == 1
    assert pg_env.query(
        f"SELECT count(*) FROM core.idempotency_project WHERE key='{key}'"
    ) == [["0"]]


async def test_concurrent_duplicates_create_one_resource(client, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-admin")
    key = str(uuid.uuid4())
    body = {"name": "concurrent", "content_capture": "metadata_only", "external_transfer": False}

    async def submit():
        return await session.post("/api/v1/projects", json=body, idempotency_key=key)

    responses = await asyncio.gather(submit(), submit(), submit())
    assert {response.status_code for response in responses} == {201}
    ids = {response.json()["id"] for response in responses}
    assert len(ids) == 1
    count = pg_env.query(
        f"SELECT count(*) FROM core.projects WHERE name='concurrent'"
    )[0][0]
    assert int(count) == 1
    replays = [r.headers.get("x-idempotency-replayed") for r in responses]
    assert replays.count("true") >= 1


async def test_conflicting_payload_under_same_key_is_rejected(client, world):
    session = await helpers.user_session(client, "skb-dev-admin")
    key = str(uuid.uuid4())
    body = {"name": "first", "content_capture": "metadata_only", "external_transfer": False}
    assert (await session.post("/api/v1/projects", json=body, idempotency_key=key)).status_code == 201
    conflict = await session.post(
        "/api/v1/projects", json={**body, "name": "second"}, idempotency_key=key
    )
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "conflict"


async def test_expired_record_can_be_reused_after_the_replay_window(client, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-admin")
    key = str(uuid.uuid4())
    body = {"name": "expiring", "content_capture": "metadata_only", "external_transfer": False}
    first = await session.post("/api/v1/projects", json=body, idempotency_key=key)
    assert first.status_code == 201

    # Age the record beyond the documented 24h window.
    pg_env.run_sql(
        f"UPDATE core.idempotency_organization SET created_at = created_at - interval '25 hours', "
        f"expires_at = now() - interval '1 hour' WHERE key='{key}'"
    )
    again = await session.post("/api/v1/projects", json=body, idempotency_key=key)
    assert again.status_code == 201
    assert again.json()["id"] != first.json()["id"]
    rows = pg_env.query(
        f"SELECT state, expires_at > now() FROM core.idempotency_organization WHERE key='{key}'"
    )
    assert rows == [["completed", "t"]]


async def test_revoked_actor_is_denied_not_replayed(client, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-admin")
    key = str(uuid.uuid4())
    body = {"name": "revoked", "content_capture": "metadata_only", "external_transfer": False}
    assert (await session.post("/api/v1/projects", json=body, idempotency_key=key)).status_code == 201
    pg_env.run_sql(
        "DELETE FROM core.memberships WHERE user_id="
        "(SELECT id FROM core.users WHERE subject='skb-dev-admin')"
    )
    replay = await session.post("/api/v1/projects", json=body, idempotency_key=key)
    assert replay.status_code in (401, 403)


async def test_rollback_leaves_no_replay_record(client, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-admin")
    key = str(uuid.uuid4())
    # Invalid body: the request fails before any domain write.
    response = await session.post(
        "/api/v1/projects", json={"name": "x", "content_capture": "all_content"}, idempotency_key=key
    )
    assert response.status_code == 422
    assert pg_env.query(
        f"SELECT count(*) FROM core.idempotency_organization WHERE key='{key}'"
    ) == [["0"]]


async def test_project_rls_hides_other_projects_for_the_app_role(pg_env):
    rows = pg_env.query_as(
        "baseline_app",
        f"SET LOCAL ROLE baseline_app; SELECT set_config('baseline.organization_id', '{ORG_A}', true);"
        f"SELECT set_config('baseline.project_id', '{PROJECT_A}', true);"
        "SELECT count(*) FROM skb.packages",
    )
    assert rows[-1] == ["0"]


async def test_scoped_context_is_reset_between_transactions(pg_env):
    query = (
        "SELECT count(*) FROM core.projects"
    )
    with_scope = pg_env.query_as(
        "baseline_app",
        f"SET LOCAL ROLE baseline_app; SELECT set_config('baseline.organization_id', '{ORG_A}', true);"
        f"SELECT set_config('baseline.project_id', '{PROJECT_A}', true);"
        f"SELECT count(*) FROM core.projects WHERE id='{PROJECT_A}'",
    )
    assert with_scope[-1] == ["1"]
    without_scope = pg_env.query_as("baseline_app", "SET LOCAL ROLE baseline_app;" + query)
    assert without_scope[-1] == ["0"]


async def test_wrong_organization_context_hides_rows(pg_env):
    rows = pg_env.query_as(
        "baseline_app",
        f"SET LOCAL ROLE baseline_app; SELECT set_config('baseline.organization_id', '{ORG_B}', true);"
        f"SELECT set_config('baseline.project_id', '{PROJECT_A}', true);"
        "SELECT count(*) FROM skb.packages",
    )
    assert rows[-1] == ["0"]


async def test_app_role_cannot_read_another_projects_artifacts(pg_env):
    rows = pg_env.query_as(
        "baseline_app",
        f"SET LOCAL ROLE baseline_app; SELECT set_config('baseline.organization_id', '{ORG_B}', true);"
        f"SELECT set_config('baseline.project_id', '{PROJECT_B}', true);"
        f"SELECT count(*) FROM core.artifacts WHERE project_id='{PROJECT_A}'",
    )
    assert rows[-1] == ["0"]


async def test_audit_rows_are_append_only(client, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-admin")
    created = await session.post(
        "/api/v1/projects",
        json={"name": "audit", "content_capture": "metadata_only", "external_transfer": False},
    )
    assert created.status_code == 201
    with pytest.raises(RuntimeError):
        pg_env.run_sql("UPDATE core.audit_events SET decision='denied'")
    assert pg_env.query("SELECT count(*) FROM core.audit_events WHERE decision='denied'") == [["0"]]
