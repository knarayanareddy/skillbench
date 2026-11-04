"""The SkillBench slice end to end plus its adversarial cases (real PostgreSQL)."""
from __future__ import annotations

import asyncio
import hashlib
import uuid

import pytest

from tests.support import helpers
from tests.support.helpers import (
    FIXTURE_TASKS,
    approved_package_ready,
    create_package,
    create_experiment,
    create_plan,
    create_suite,
    get_package,
    inspect_package,
    plan_body,
    preregister,
    skill_zip,
    upload,
)
from tests.support.pgenv import PROJECT_A, PROJECT_B


async def inspection_detail(session, package_id: str) -> dict:
    response = await session.get(
        f"/api/v1/skb/packages/{package_id}/inspection", headers={"X-Project-ID": PROJECT_A}
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _journey_to_experiment(session, worker):
    artifact, package = await approved_package_ready(session, worker)
    suite = (await create_suite(session, artifact["id"])).json()
    plan = (await create_plan(session, plan_body(package, suite))).json()
    assert (await preregister(session, plan["id"])).status_code == 200
    plan = (
        await session.get(f"/api/v1/skb/plans/{plan['id']}", headers={"X-Project-ID": PROJECT_A})
    ).json()
    experiment = (await create_experiment(session, plan)).json()
    return artifact, package, suite, plan, experiment


async def test_full_fixture_journey_produces_descriptive_analysis(client, worker, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package, suite, plan, experiment = await _journey_to_experiment(session, worker)

    assert package["execution_profile"] == "fixture_only"
    assert package["state"] == "approved"
    assert suite["task_count"] == len(FIXTURE_TASKS)
    assert plan["state"] == "preregistered"
    assert experiment["state"] == "queued"

    await helpers.run_jobs(worker, 5)

    experiment_body = (
        await session.get(
            f"/api/v1/skb/experiments/{experiment['id']}", headers={"X-Project-ID": PROJECT_A}
        )
    ).json()
    assert experiment_body["state"] == "completed"

    trials = (
        await session.get(
            f"/api/v1/skb/experiments/{experiment['id']}/trials",
            headers={"X-Project-ID": PROJECT_A},
        )
    ).json()
    assert len(trials["items"]) == len(FIXTURE_TASKS) * 3 * 2
    first = trials["items"][0]
    assert first["currency"] == "EUR"
    assert first["outcome"] in {"pass", "fail"}

    analysis_response = await session.post(
        f"/api/v1/skb/experiments/{experiment['id']}/analyses",
        headers={"X-Project-ID": PROJECT_A},
    )
    assert analysis_response.status_code == 201, analysis_response.text
    analysis = analysis_response.json()
    assert analysis["analysis_version"] == "paired-task-bootstrap/1"
    assert analysis["status"] == "valid"
    assert analysis["n_tasks"] == 12 and analysis["n_complete_tasks"] == 12
    assert analysis["delta"] == pytest.approx(0.5)
    assert analysis["ci_low"] is not None and analysis["ci_low"] <= analysis["delta"] <= analysis["ci_high"]
    assert analysis["interpretation"] == "descriptive_no_certification"
    assert analysis["missing_trials"] == 0

    # Re-analysis of the same frozen input is reproducible.
    replayed = await session.post(
        f"/api/v1/skb/experiments/{experiment['id']}/analyses",
        headers={"X-Project-ID": PROJECT_A},
    )
    assert replayed.json() == analysis

    audit = pg_env.query(
        f"SELECT action FROM core.audit_events WHERE project_id='{PROJECT_A}' ORDER BY created_at"
    )
    actions = {row[0] for row in audit}
    for expected in (
        "skb.package.create",
        "skb.package.inspect",
        "skb.package.review",
        "skb.suite.create",
        "skb.plan.create",
        "skb.plan.preregister",
        "skb.experiment.create",
        "skb.analysis.create",
    ):
        assert expected in actions, sorted(actions)


async def test_package_inspection_records_entries_and_digest(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(session, skill_zip())
    package = (await create_package(session, artifact["id"])).json()
    assert package["state"] == "quarantined"
    assert (await inspect_package(session, package["id"])).status_code == 202
    await helpers.run_jobs(worker, 1)
    inspected = (await get_package(session, package["id"])).json()
    assert inspected["state"] == "inspected"
    detail = (
        await session.get(
            f"/api/v1/skb/packages/{package['id']}/inspection", headers={"X-Project-ID": PROJECT_A}
        )
    ).json()
    assert detail["inspection_summary"]["accepted"] is True
    assert {entry["path"] for entry in detail["entries"]} == {"SKILL.md", "notes/readme.txt"}
    assert detail["findings"] == []


@pytest.mark.parametrize(
    ("entries", "expected_code"),
    [
        ([("../escape.txt", b"x")], "unsafe_path"),
        ([("/etc/passwd", b"x")], "unsafe_path"),
        ([("ok.txt", b"x"), ("ok.txt", b"y")], "duplicate_path"),
        ([("bin/tool", b"\x7fELF")], "executable_payload"),
    ],
)
async def test_malicious_archives_are_rejected_and_never_approvable(
    client, worker, world, entries, expected_code
):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(session, helpers.make_zip(entries))
    package = (await create_package(session, artifact["id"])).json()
    assert (await inspect_package(session, package["id"])).status_code == 202
    await helpers.run_jobs(worker, 1)
    rejected = (await get_package(session, package["id"])).json()
    assert rejected["state"] == "rejected"
    detail = await inspection_detail(session, package["id"])
    assert expected_code in detail["rejection_code"]
    codes = {finding["code"] for finding in detail["findings"]}
    assert expected_code in codes

    review = await helpers.approve_package(session, package["id"])
    assert review.status_code == 409
    suite = (await create_suite(session, artifact["id"])).json()
    plan = await create_plan(session, plan_body(rejected, suite))
    assert plan.status_code == 409


async def test_symlink_entry_is_rejected(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(
        session, helpers.make_zip([("link", b"/etc/passwd")], mode=0o120777)
    )
    package = (await create_package(session, artifact["id"])).json()
    await inspect_package(session, package["id"])
    await helpers.run_jobs(worker, 1)
    rejected = (await get_package(session, package["id"])).json()
    assert rejected["state"] == "rejected"
    detail = await inspection_detail(session, package["id"])
    assert "unsafe_entry_type" in {finding["code"] for finding in detail["findings"]}


async def test_non_zip_bytes_fail_inspection_without_passing(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(session, b"not a zip at all")
    package = (await create_package(session, artifact["id"])).json()
    await inspect_package(session, package["id"])
    await helpers.run_jobs(worker, 1)
    body = (await get_package(session, package["id"])).json()
    assert body["state"] == "quarantined"
    detail = await inspection_detail(session, package["id"])
    assert "error" in detail["inspection_summary"]
    assert (await helpers.approve_package(session, package["id"])).status_code == 409


async def test_approval_requires_inspection_matching_etag_and_digest(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(session, skill_zip())
    package = (await create_package(session, artifact["id"])).json()

    # Not inspected yet.
    early = await helpers.approve_package(session, package["id"])
    assert early.status_code == 409

    await inspect_package(session, package["id"])
    await helpers.run_jobs(worker, 1)

    # Wrong digest.
    current = await get_package(session, package["id"])
    wrong = await session.post(
        f"/api/v1/skb/packages/{package['id']}/reviews",
        json={"decision": "approved", "package_sha256": "0" * 64, "reason": "digest mismatch test"},
        headers={"X-Project-ID": PROJECT_A, "If-Match": current.headers["etag"]},
    )
    assert wrong.status_code == 409

    # Missing If-Match.
    missing = await session.post(
        f"/api/v1/skb/packages/{package['id']}/reviews",
        json={"decision": "approved", "package_sha256": package["sha256"], "reason": "no precondition"},
        headers={"X-Project-ID": PROJECT_A},
    )
    assert missing.status_code == 428

    # Stale If-Match.
    stale = await session.post(
        f"/api/v1/skb/packages/{package['id']}/reviews",
        json={"decision": "approved", "package_sha256": package["sha256"], "reason": "stale revision"},
        headers={"X-Project-ID": PROJECT_A, "If-Match": '"99"'},
    )
    assert stale.status_code == 412

    approved = await helpers.approve_package(session, package["id"])
    assert approved.status_code == 200
    assert approved.json()["state"] == "approved"
    assert approved.json()["revision"] == 2

    # A final decision is final.
    again = await helpers.approve_package(session, package["id"], decision="rejected")
    assert again.status_code == 409


async def test_concurrent_review_races_yield_one_decision(client, worker, world, pg_env):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(session, skill_zip())
    package = (await create_package(session, artifact["id"])).json()
    await inspect_package(session, package["id"])
    await helpers.run_jobs(worker, 1)
    current = await get_package(session, package["id"])
    etag = current.headers["etag"]
    body = {"decision": "approved", "package_sha256": package["sha256"], "reason": "race approval"}

    async def approve():
        return await session.post(
            f"/api/v1/skb/packages/{package['id']}/reviews",
            json=body,
            headers={"X-Project-ID": PROJECT_A, "If-Match": etag},
        )

    first, second = await asyncio.gather(approve(), approve())
    statuses = sorted([first.status_code, second.status_code])
    assert statuses == [200, 412] or statuses == [200, 409]
    reviews = int(
        session  # noqa: B018 - keep the actor in scope for readability
        and pg_env.query(
            f"SELECT count(*) FROM skb.package_reviews WHERE package_id='{package['id']}'"
        )[0][0]
    )
    assert reviews == 1


async def test_registered_digest_cannot_be_swapped_after_approval(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(session, skill_zip())
    package = (await create_package(session, artifact["id"])).json()
    await inspect_package(session, package["id"])
    await helpers.run_jobs(worker, 1)
    assert (await helpers.approve_package(session, package["id"])).status_code == 200

    other = await upload(session, skill_zip([("extra.txt", b"different")]))
    swapped = await create_package(session, other["id"], name="swapped")
    assert swapped.status_code == 201
    assert swapped.json()["sha256"] != package["sha256"]

    # The original approval still binds the original digest.
    suite = (await create_suite(session, artifact["id"])).json()
    plan = await create_plan(
        session, plan_body({**package, "sha256": "f" * 64}, suite)
    )
    assert plan.status_code == 409

    # And the approved package cannot be repointed at another artifact.
    repointed = await session.post(
        f"/api/v1/skb/packages/{package['id']}/reviews",
        json={"decision": "approved", "package_sha256": other["sha256"], "reason": "swap digest"},
        headers={"X-Project-ID": PROJECT_A, "If-Match": '"2"'},
    )
    assert repointed.status_code == 409


async def test_plan_requires_matching_suite_and_preregistration_once(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package = await approved_package_ready(session, worker)
    suite = (await create_suite(session, artifact["id"])).json()

    mismatched_suite = await create_plan(
        session, plan_body(package, {**suite, "sha256": "a" * 64})
    )
    assert mismatched_suite.status_code == 409

    plan = (await create_plan(session, plan_body(package, suite))).json()
    assert plan["state"] == "draft"

    # An experiment cannot run from a draft plan.
    draft_experiment = await create_experiment(session, plan)
    assert draft_experiment.status_code == 409

    assert (await preregister(session, plan["id"])).status_code == 200
    duplicate = await session.post(
        f"/api/v1/skb/plans/{plan['id']}:preregister",
        headers={"X-Project-ID": PROJECT_A, "If-Match": '"2"'},
    )
    assert duplicate.status_code == 409

    # Preregistration is revision-fenced.
    second_plan = (await create_plan(session, plan_body(package, suite))).json()
    stale = await session.post(
        f"/api/v1/skb/plans/{second_plan['id']}:preregister",
        headers={"X-Project-ID": PROJECT_A, "If-Match": '"7"'},
    )
    assert stale.status_code == 412


async def test_experiment_requires_exact_preregistered_digest(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package, suite, plan, experiment = await _journey_to_experiment(session, worker)
    forged = await session.post(
        f"/api/v1/projects/{PROJECT_A}/skb/experiments",
        json={"plan_id": plan["id"], "plan_sha256": "b" * 64},
    )
    assert forged.status_code == 409
    unknown = await session.post(
        f"/api/v1/projects/{PROJECT_A}/skb/experiments",
        json={"plan_id": str(uuid.uuid4()), "plan_sha256": plan["sha256"]},
    )
    assert unknown.status_code == 404


async def test_unrecorded_task_is_missing_never_a_pass(client, worker, world, pg_env):
    """A task with no recorded fixture is persisted as infra_error, not as success."""
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package = await approved_package_ready(session, worker)
    task_ids = [*FIXTURE_TASKS[:11], "task-99"]  # no fixture is recorded for task-99
    suite = (await create_suite(session, artifact["id"], task_ids=task_ids)).json()
    plan = (await create_plan(session, plan_body(package, suite))).json()
    assert (await preregister(session, plan["id"])).status_code == 200
    plan = (
        await session.get(f"/api/v1/skb/plans/{plan['id']}", headers={"X-Project-ID": PROJECT_A})
    ).json()
    experiment = (await create_experiment(session, plan)).json()
    await helpers.run_jobs(worker, 2)

    outcomes = pg_env.query(
        f"SELECT DISTINCT outcome FROM skb.trials WHERE experiment_id='{experiment['id']}' "
        f"AND task_id='task-99'"
    )
    assert [row[0] for row in outcomes] == ["infra_error"]
    reason = pg_env.query(
        f"SELECT result->>'reason' FROM skb.trials WHERE experiment_id='{experiment['id']}' "
        f"AND task_id='task-99' LIMIT 1"
    )
    assert reason == [["no_recorded_fixture"]]

    response = await session.post(
        f"/api/v1/skb/experiments/{experiment['id']}/analyses",
        headers={"X-Project-ID": PROJECT_A},
    )
    body = response.json()
    assert body["status"] == "partial"
    assert body["n_tasks"] == 12 and body["n_complete_tasks"] == 11
    assert body["missing_trials"] == 6
    assert body["bound_low"] is not None and body["bound_high"] is not None


async def test_analysis_is_insufficient_below_ten_tasks(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package = await approved_package_ready(session, worker)
    suite = (await create_suite(session, artifact["id"], task_ids=FIXTURE_TASKS[:9])).json()
    plan = (await create_plan(session, plan_body(package, suite))).json()
    assert (await preregister(session, plan["id"])).status_code == 200
    plan = (
        await session.get(f"/api/v1/skb/plans/{plan['id']}", headers={"X-Project-ID": PROJECT_A})
    ).json()
    experiment = (await create_experiment(session, plan)).json()
    await helpers.run_jobs(worker, 2)
    response = await session.post(
        f"/api/v1/skb/experiments/{experiment['id']}/analyses",
        headers={"X-Project-ID": PROJECT_A},
    )
    body = response.json()
    assert body["status"] == "insufficient"
    assert body["n_tasks"] == 9
    assert body["ci_low"] is None and body["ci_high"] is None


async def test_analysis_requires_a_finished_experiment(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact, package, suite, plan, experiment = await _journey_to_experiment(session, worker)
    response = await session.post(
        f"/api/v1/skb/experiments/{experiment['id']}/analyses",
        headers={"X-Project-ID": PROJECT_A},
    )
    assert response.status_code == 409
    assert "finished" in response.json()["detail"]


async def test_cross_project_objects_are_invisible(client_factory, worker, world):
    owner = await helpers.user_session(client_factory(), "skb-dev-maintainer")
    stranger = await helpers.user_session(client_factory(), "skb-dev-other-org")
    artifact, package = await approved_package_ready(owner, worker)

    for path in (
        f"/api/v1/skb/packages/{package['id']}",
        f"/api/v1/skb/plans/{uuid.uuid4()}",
        f"/api/v1/skb/experiments/{uuid.uuid4()}",
    ):
        denied = await stranger.get(path, headers={"X-Project-ID": PROJECT_A})
        assert denied.status_code == 403
        foreign = await stranger.get(path, headers={"X-Project-ID": PROJECT_B})
        assert foreign.status_code == 404


async def test_role_matrix_on_the_slice(client_factory, worker, world):
    maintainer = await helpers.user_session(client_factory(), "skb-dev-maintainer")
    artifact, package = await approved_package_ready(maintainer, worker)

    viewer = await helpers.user_session(client_factory(), "skb-dev-viewer")
    operator = await helpers.user_session(client_factory(), "skb-dev-operator")
    analyst = await helpers.user_session(client_factory(), "skb-dev-analyst")

    assert (await create_package(viewer, artifact["id"])).status_code == 403
    # A fresh package (not yet inspected) for the capability checks.
    second_artifact = await upload(maintainer, skill_zip([("extra.txt", b"role-matrix")]))
    fresh = (await create_package(maintainer, second_artifact["id"], name="roles")).json()
    assert (await inspect_package(analyst, fresh["id"])).status_code == 403
    assert (await inspect_package(viewer, fresh["id"])).status_code == 403
    assert (await inspect_package(operator, fresh["id"])).status_code == 202
    await helpers.run_jobs(worker, 1)
    assert (await helpers.approve_package(analyst, fresh["id"])).status_code == 403
    operator_review = await operator.post(
        f"/api/v1/skb/packages/{fresh['id']}/reviews",
        json={"decision": "approved", "package_sha256": fresh["sha256"], "reason": "operator cannot approve"},
        headers={"X-Project-ID": PROJECT_A, "If-Match": '"1"'},
    )
    assert operator_review.status_code == 403
    assert (await create_suite(viewer, artifact["id"])).status_code == 403
    assert (await create_experiment(viewer, {"id": str(uuid.uuid4()), "sha256": "a" * 64})).status_code == 403

    suite = (await create_suite(maintainer, artifact["id"])).json()
    assert (await create_plan(viewer, plan_body(package, suite))).status_code == 403
    approved = await helpers.approve_package(maintainer, fresh["id"])
    assert approved.status_code == 200 and approved.json()["state"] == "approved"


async def test_suite_rejects_unknown_and_duplicate_tasks(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(session, skill_zip())
    duplicate = await create_suite(session, artifact["id"], task_ids=["task-00", "task-00"])
    assert duplicate.status_code == 422
    empty = await session.post(
        f"/api/v1/projects/{PROJECT_A}/skb/suites",
        json={"name": "empty", "tasks": [], "rights_manifest_artifact_id": artifact["id"]},
    )
    assert empty.status_code == 422
    foreign_artifact = await session.post(
        f"/api/v1/projects/{PROJECT_A}/skb/suites",
        json={
            "name": "foreign",
            "tasks": [
                {
                    "id": "task-00",
                    "category": "synthetic",
                    "input_artifact_id": str(uuid.uuid4()),
                    "split": "validation",
                    "scorer_id": "exact_match",
                }
            ],
            "rights_manifest_artifact_id": artifact["id"],
        },
    )
    assert foreign_artifact.status_code in (404, 422)


async def test_conflicting_and_repeated_idempotent_requests(client, worker, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    artifact = await upload(session, skill_zip())
    key = str(uuid.uuid4())
    body = {"artifact_id": artifact["id"], "name": "idem", "source_commit": "b" * 40, "license_expression": "MIT"}
    first = await session.post(f"/api/v1/projects/{PROJECT_A}/skb/packages", json=body, idempotency_key=key)
    replay = await session.post(f"/api/v1/projects/{PROJECT_A}/skb/packages", json=body, idempotency_key=key)
    assert first.status_code == replay.status_code == 201
    assert first.json()["id"] == replay.json()["id"]
    conflict = await session.post(
        f"/api/v1/projects/{PROJECT_A}/skb/packages",
        json={**body, "name": "changed"},
        idempotency_key=key,
    )
    assert conflict.status_code == 409


async def test_package_cannot_reference_a_pending_artifact(client, world):
    session = await helpers.user_session(client, "skb-dev-maintainer")
    blob = skill_zip()
    created = await session.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={
            "filename": "x.zip",
            "media_type": "application/zip",
            "byte_size": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "classification": "synthetic",
        },
    )
    body = created.json()
    pending = await create_package(session, body["artifact_id"])
    assert pending.status_code == 409
