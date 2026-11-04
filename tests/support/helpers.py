"""Shared test helpers for the SKB journeys (synthetic data only)."""
from __future__ import annotations

import hashlib
import io
import uuid
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from src.core.config import Settings
from src.core.db import Database
from src.worker.main import Worker
from tests.support.pgenv import PROJECT_A

FIXTURE_TASKS = [f"task-{index:02d}" for index in range(12)]


def make_zip(entries: Iterable[Tuple[str, bytes]], *, mode: Optional[int] = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in entries:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            archive.writestr(info, body)
    return buffer.getvalue()


def skill_zip(extra: Optional[List[Tuple[str, bytes]]] = None) -> bytes:
    entries: List[Tuple[str, bytes]] = [
        ("SKILL.md", b"---\nname: synthetic-demo\ndescription: synthetic demo\n---\nbody\n"),
        ("notes/readme.txt", b"synthetic notes\n"),
    ]
    entries.extend(extra or [])
    return make_zip(entries)


async def upload(
    session,
    blob: bytes,
    *,
    project_id: str = PROJECT_A,
    media_type: str = "application/zip",
    filename: str = "package.zip",
    classification: str = "synthetic",
    expect_status: int = 200,
):
    sha = hashlib.sha256(blob).hexdigest()
    created = await session.post(
        f"/api/v1/projects/{project_id}/uploads",
        json={
            "filename": filename,
            "media_type": media_type,
            "byte_size": len(blob),
            "sha256": sha,
            "classification": classification,
        },
    )
    assert created.status_code == 201, created.text
    upload_body = created.json()
    put = await session.put(
        upload_body["put_path"], content=blob, headers={"X-Project-ID": project_id}
    )
    assert put.status_code == expect_status if expect_status != 200 else put.status_code == 200, put.text
    if expect_status != 200:
        return upload_body, put
    finalized = await session.post(
        f"/api/v1/uploads/{upload_body['id']}:finalize",
        json={"sha256": sha, "byte_size": len(blob)},
        headers={"X-Project-ID": project_id},
    )
    assert finalized.status_code == 200, finalized.text
    return finalized.json()


async def create_package(session, artifact_id: str, *, project_id: str = PROJECT_A, **overrides):
    body = {
        "artifact_id": artifact_id,
        "name": "synthetic skill",
        "source_commit": "a" * 40,
        "license_expression": "MIT",
    }
    body.update(overrides)
    return await session.post(f"/api/v1/projects/{project_id}/skb/packages", json=body)


async def inspect_package(session, package_id: str, *, project_id: str = PROJECT_A):
    return await session.post(
        f"/api/v1/skb/packages/{package_id}:inspect", headers={"X-Project-ID": project_id}
    )


async def get_package(session, package_id: str, *, project_id: str = PROJECT_A):
    return await session.get(
        f"/api/v1/skb/packages/{package_id}", headers={"X-Project-ID": project_id}
    )


async def approve_package(session, package_id: str, *, project_id: str = PROJECT_A, decision="approved"):
    current = await get_package(session, package_id, project_id=project_id)
    assert current.status_code == 200, current.text
    package = current.json()
    return await session.post(
        f"/api/v1/skb/packages/{package_id}/reviews",
        json={
            "decision": decision,
            "package_sha256": package["sha256"],
            "reason": "maintainer reviewed the synthetic package inventory",
        },
        headers={"X-Project-ID": project_id, "If-Match": current.headers["etag"]},
    )


async def create_suite(
    session,
    artifact_id: str,
    *,
    project_id: str = PROJECT_A,
    task_ids: Optional[Sequence[str]] = None,
    name: str = "synthetic suite",
):
    tasks = [
        {
            "id": task_id,
            "category": "synthetic",
            "input_artifact_id": artifact_id,
            "split": "validation",
            "scorer_id": "exact_match",
        }
        for task_id in (task_ids or FIXTURE_TASKS)
    ]
    return await session.post(
        f"/api/v1/projects/{project_id}/skb/suites",
        json={"name": name, "tasks": tasks, "rights_manifest_artifact_id": artifact_id},
    )


def plan_body(package: Dict[str, Any], suite: Dict[str, Any], **overrides) -> Dict[str, Any]:
    body = {
        "package_id": package["id"],
        "package_sha256": package["sha256"],
        "suite_id": suite["id"],
        "suite_sha256": suite["sha256"],
        "harness": "fixture/1",
        "model": "recorded/1",
        "repetitions": 3,
        "seed": 17,
        "bootstrap_iterations": 2000,
        "practical_margin": 0.05,
        "primary_metric": "task_mean_success_delta",
        "missing_rule": "report_bounds_no_silent_drop",
        "mode": "fixture_only",
    }
    body.update(overrides)
    return body


async def create_plan(session, body: Dict[str, Any], *, project_id: str = PROJECT_A):
    return await session.post(f"/api/v1/projects/{project_id}/skb/plans", json=body)


async def preregister(session, plan_id: str, *, project_id: str = PROJECT_A):
    current = await session.get(
        f"/api/v1/skb/plans/{plan_id}", headers={"X-Project-ID": project_id}
    )
    assert current.status_code == 200, current.text
    return await session.post(
        f"/api/v1/skb/plans/{plan_id}:preregister",
        headers={"X-Project-ID": project_id, "If-Match": current.headers["etag"]},
    )


async def create_experiment(session, plan: Dict[str, Any], *, project_id: str = PROJECT_A):
    return await session.post(
        f"/api/v1/projects/{project_id}/skb/experiments",
        json={"plan_id": plan["id"], "plan_sha256": plan["sha256"]},
    )


async def run_jobs(worker: Worker, count: int = 10) -> int:
    processed = 0
    for _ in range(count):
        if not await worker.run_once():
            break
        processed += 1
    return processed


async def approved_package_ready(session, worker: Worker, *, project_id: str = PROJECT_A):
    """Upload, register, inspect and approve a synthetic package."""
    artifact = await upload(session, skill_zip(), project_id=project_id)
    package_response = await create_package(session, artifact["id"], project_id=project_id)
    assert package_response.status_code == 201, package_response.text
    package = package_response.json()
    assert (await inspect_package(session, package["id"], project_id=project_id)).status_code == 202
    await run_jobs(worker, 1)
    approved = await approve_package(session, package["id"], project_id=project_id)
    assert approved.status_code == 200, approved.text
    return artifact, approved.json()


async def user_session(client, subject: str):
    from tests.conftest import login

    return await login(client, subject)
