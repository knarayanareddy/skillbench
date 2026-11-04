"""Worker lease, retry, crash and cancellation semantics against PostgreSQL."""
from __future__ import annotations

import asyncio
import uuid

import pytest

from tests.support import helpers
from tests.support.pgenv import PROJECT_A


async def _queue_inspect(session, package_id: str) -> str:
    """Queue an inspect job through the API and return its job id."""
    response = await session.post(
        f"/api/v1/skb/packages/{package_id}:inspect",
        headers={"X-Project-ID": PROJECT_A},
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


async def test_claim_leases_exactly_one_attempt(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await helpers.upload(session, helpers.skill_zip())
    package = (await helpers.create_package(session, artifact["id"])).json()
    job_id = await _queue_inspect(session, package["id"])

    first = await worker.claim()
    assert first is not None
    assert str(first["job_id"]) == job_id
    assert first["attempt"] == 1 and first["fence"] == 1
    # The lease is exclusive: a second claim (another worker) sees nothing.
    other = worker.settings.model_copy(update={"DATABASE_URL": worker.settings.DATABASE_URL})
    from src.worker.main import Worker

    second_worker = Worker(other)
    try:
        assert await second_worker.claim() is None
    finally:
        await second_worker.close()


async def test_expired_lease_is_abandoned_and_retried_once(client, worker, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await helpers.upload(session, helpers.skill_zip())
    package = (await helpers.create_package(session, artifact["id"])).json()
    job_id = await _queue_inspect(session, package["id"])

    crashed = await worker.claim()
    assert crashed is not None
    # Simulate a worker that died while holding the lease.
    pg_env.run_sql(
        f"UPDATE core.jobs SET lease_until = now() - interval '5 seconds' WHERE id='{job_id}'"
    )
    retried = await worker.claim()
    assert retried is not None
    assert str(retried["job_id"]) == job_id
    assert retried["attempt"] == 2
    assert retried["fence"] == 2

    states = pg_env.query(
        f"SELECT attempt, state FROM core.job_attempts WHERE job_id='{job_id}' ORDER BY attempt"
    )
    assert [(int(row[0]), row[1]) for row in states] == [(1, "abandoned"), (2, "running")]

    await worker.execute(retried)
    final = pg_env.query(
        f"SELECT state, attempt, error_code FROM core.jobs WHERE id='{job_id}'"
    )[0]
    assert final[0] == "succeeded"
    attempts = pg_env.query(
        f"SELECT attempt, state FROM core.job_attempts WHERE job_id='{job_id}' ORDER BY attempt"
    )
    assert [(int(row[0]), row[1]) for row in attempts] == [(1, "abandoned"), (2, "succeeded")]
    package_state = pg_env.query(
        f"SELECT state FROM skb.packages WHERE id='{package['id']}'"
    )[0][0]
    assert package_state == "inspected"


async def test_stale_completion_never_overwrites_a_newer_attempt(client, worker, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await helpers.upload(session, helpers.skill_zip())
    package = (await helpers.create_package(session, artifact["id"])).json()
    job_id = await _queue_inspect(session, package["id"])

    crashed = await worker.claim()
    assert crashed is not None
    stale_fence = int(crashed["fence"])
    stale_attempt = int(crashed["attempt"])
    pg_env.run_sql(
        f"UPDATE core.jobs SET lease_until = now() - interval '5 seconds' WHERE id='{job_id}'"
    )
    fresh = await worker.claim()
    assert fresh is not None and int(fresh["fence"]) == stale_fence + 1

    # The old attempt completes late and must be refused.
    await worker._complete(PROJECT_A, job_id, stale_fence, stale_attempt, "succeeded", None, None)
    row = pg_env.query(f"SELECT state, attempt FROM core.jobs WHERE id='{job_id}'")[0]
    assert row[0] == "leased"  # untouched by the stale completion
    assert int(row[1]) == stale_attempt + 1


async def test_cancel_requested_stops_between_trials_without_double_counting(
    client, worker, world, pg_env
):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package = await helpers.approved_package_ready(session, worker)
    suite = (await helpers.create_suite(session, artifact["id"])).json()
    plan = (await helpers.create_plan(session, helpers.plan_body(package, suite))).json()
    assert (await helpers.preregister(session, plan["id"])).status_code == 200
    plan = (
        await session.get(f"/api/v1/skb/plans/{plan['id']}", headers={"X-Project-ID": PROJECT_A})
    ).json()
    experiment = (await helpers.create_experiment(session, plan)).json()

    # Operators request cancellation at the queue level before the worker starts.
    pg_env.run_sql(
        f"UPDATE core.jobs SET state='cancel_requested' WHERE id='{experiment['job_id']}'"
    )
    assert await worker.run_once() is True
    state = pg_env.query(
        f"SELECT state FROM skb.experiments WHERE id='{experiment['id']}'"
    )[0][0]
    assert state == "stopped"
    trials = pg_env.query(
        f"SELECT count(*) FROM skb.trials WHERE experiment_id='{experiment['id']}'"
    )[0][0]
    assert int(trials) == 0
    job_state = pg_env.query(f"SELECT state FROM core.jobs WHERE id='{experiment['job_id']}'")[0][0]
    assert job_state == "cancelled"


async def test_retry_after_delivery_keeps_one_row_per_unit_and_attempt(
    client, worker, world, pg_env
):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package = await helpers.approved_package_ready(session, worker)
    suite = (await helpers.create_suite(session, artifact["id"])).json()
    plan = (await helpers.create_plan(session, helpers.plan_body(package, suite))).json()
    assert (await helpers.preregister(session, plan["id"])).status_code == 200
    plan = (
        await session.get(f"/api/v1/skb/plans/{plan['id']}", headers={"X-Project-ID": PROJECT_A})
    ).json()
    experiment = (await helpers.create_experiment(session, plan)).json()

    assert await worker.run_once() is True
    units = 12 * 3 * 2
    assert int(
        pg_env.query(f"SELECT count(*) FROM skb.trials WHERE experiment_id='{experiment['id']}'")[0][0]
    ) == units

    # A duplicate delivery (reconciled retry) replays the same units. Because the
    # attempt number is part of the identity, the second attempt is stored as a new
    # attempt and never overwrites or removes attempt 1.
    pg_env.run_sql(
        f"UPDATE core.jobs SET state='queued', lease_until=NULL, error_code=NULL, updated_at=now() "
        f"WHERE id='{experiment['job_id']}'"
    )
    assert await worker.run_once() is True
    rows = pg_env.query(
        f"SELECT attempt, count(*) FROM skb.trials WHERE experiment_id='{experiment['id']}' "
        f"GROUP BY attempt ORDER BY attempt"
    )
    assert [(int(row[0]), int(row[1])) for row in rows] == [(1, units), (2, units)]

    # Analysis reconciles to the last attempt: still 12 tasks, never 24.
    analysis = await session.post(
        f"/api/v1/skb/experiments/{experiment['id']}/analyses",
        headers={"X-Project-ID": PROJECT_A},
    )
    assert analysis.status_code == 201, analysis.text
    body = analysis.json()
    assert body["status"] == "valid"
    assert body["n_tasks"] == 12
    assert body["missing_trials"] == 0
    assert body["delta"] == pytest.approx(0.5)


async def test_unsupported_job_kind_fails_safely(worker, world, pg_env):
    job_id = str(uuid.uuid4())
    pg_env.run_sql(
        f"""INSERT INTO core.jobs(id, project_id, kind, state, payload)
            VALUES ('{job_id}', '{PROJECT_A}', 'skb.execute_arbitrary', 'queued', '{{}}')"""
    )
    assert await worker.run_once() is False  # not a supported kind, never claimed
    state = pg_env.query(f"SELECT state FROM core.jobs WHERE id='{job_id}'")[0][0]
    assert state == "queued"


async def test_worker_requires_its_own_database_role(worker_settings, pg_env):
    from src.core.config import validate_runtime

    problems = validate_runtime(worker_settings)
    assert problems == []
    # The API identity must not be able to claim jobs at all.
    from src.worker.main import Worker

    import dataclasses

    imposter = worker_settings.model_copy(update={"DATABASE_URL": pg_env.app_dsn()})
    instance = Worker(imposter)
    try:
        with pytest.raises(Exception):
            await asyncio.wait_for(instance.claim(), timeout=10)
    finally:
        await instance.close()
