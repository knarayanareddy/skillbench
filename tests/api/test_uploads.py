"""Artifact upload, finalisation, digest binding and authorized download."""
from __future__ import annotations

import hashlib
import uuid

import pytest

from tests.conftest import api_key_headers, login
from tests.support.helpers import skill_zip, upload
from tests.support.pgenv import PROJECT_A, PROJECT_A2, PROJECT_B


async def test_upload_finalize_and_download_roundtrip(client, app):
    session = await login(client, "skb-dev-analyst")
    blob = skill_zip()
    artifact = await upload(session, blob)
    assert artifact["sha256"] == hashlib.sha256(blob).hexdigest()
    assert artifact["status"] == "ready"
    assert artifact["classification"] == "synthetic"

    metadata = await session.get(
        f"/api/v1/artifacts/{artifact['id']}", headers={"X-Project-ID": PROJECT_A}
    )
    assert metadata.status_code == 200
    assert metadata.json() == artifact

    download = await session.get(
        f"/api/v1/artifacts/{artifact['id']}/bytes", headers={"X-Project-ID": PROJECT_A}
    )
    assert download.status_code == 200
    assert download.content == blob
    assert download.headers["content-disposition"].startswith("attachment;")
    assert download.headers["x-content-type-options"] == "nosniff"
    assert download.headers["cache-control"] == "private, no-store"
    assert download.headers["content-type"] == "application/octet-stream"


async def test_finalize_rejects_digest_mismatch_and_keeps_artifact_unreadable(client, app):
    session = await login(client, "skb-dev-analyst")
    blob = skill_zip()
    sha = hashlib.sha256(blob).hexdigest()
    created = await session.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={
            "filename": "x.zip",
            "media_type": "application/zip",
            "byte_size": len(blob),
            "sha256": sha,
            "classification": "synthetic",
        },
    )
    upload_body = created.json()
    put = await session.put(
        upload_body["put_path"], content=blob, headers={"X-Project-ID": PROJECT_A}
    )
    assert put.status_code == 200
    forged = await session.post(
        f"/api/v1/uploads/{upload_body['id']}:finalize",
        json={"sha256": "0" * 64, "byte_size": len(blob)},
        headers={"X-Project-ID": PROJECT_A},
    )
    assert forged.status_code == 409
    assert forged.json()["code"] == "conflict"
    # The artifact never became readable.
    read = await session.get(
        f"/api/v1/artifacts/{upload_body['artifact_id']}", headers={"X-Project-ID": PROJECT_A}
    )
    assert read.json()["status"] == "pending"
    download = await session.get(
        f"/api/v1/artifacts/{upload_body['artifact_id']}/bytes", headers={"X-Project-ID": PROJECT_A}
    )
    assert download.status_code == 404


async def test_declared_digest_mismatch_at_put_is_refused(client):
    session = await login(client, "skb-dev-analyst")
    blob = skill_zip()
    created = await session.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={
            "filename": "x.zip",
            "media_type": "application/zip",
            "byte_size": len(blob),
            "sha256": "1" * 64,
            "classification": "synthetic",
        },
    )
    upload_body = created.json()
    put = await session.put(
        upload_body["put_path"], content=blob, headers={"X-Project-ID": PROJECT_A}
    )
    assert put.status_code == 409
    finalized = await session.post(
        f"/api/v1/uploads/{upload_body['id']}:finalize",
        json={"sha256": "1" * 64, "byte_size": len(blob)},
        headers={"X-Project-ID": PROJECT_A},
    )
    assert finalized.status_code == 409


async def test_upload_over_declared_size_is_refused(client):
    session = await login(client, "skb-dev-analyst")
    blob = skill_zip()
    created = await session.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={
            "filename": "x.zip",
            "media_type": "application/zip",
            "byte_size": 10,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "classification": "synthetic",
        },
    )
    upload_body = created.json()
    put = await session.put(
        upload_body["put_path"], content=blob, headers={"X-Project-ID": PROJECT_A}
    )
    assert put.status_code == 413


async def test_upload_rejects_disallowed_media_type(client):
    session = await login(client, "skb-dev-analyst")
    response = await session.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={
            "filename": "x.exe",
            "media_type": "application/x-msdownload",
            "byte_size": 10,
            "sha256": "2" * 64,
            "classification": "synthetic",
        },
    )
    assert response.status_code == 422
    assert response.json()["field_errors"][0]["path"] == "media_type"


async def test_upload_rejects_path_characters_in_filename(client):
    session = await login(client, "skb-dev-analyst")
    response = await session.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={
            "filename": "../escape.zip",
            "media_type": "application/zip",
            "byte_size": 10,
            "sha256": "2" * 64,
            "classification": "synthetic",
        },
    )
    assert response.status_code == 422


async def test_same_idempotency_key_returns_same_upload(client):
    session = await login(client, "skb-dev-analyst")
    key = str(uuid.uuid4())
    blob = skill_zip()
    body = {
        "filename": "x.zip",
        "media_type": "application/zip",
        "byte_size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "classification": "synthetic",
    }
    first = await session.post(f"/api/v1/projects/{PROJECT_A}/uploads", json=body, idempotency_key=key)
    second = await session.post(f"/api/v1/projects/{PROJECT_A}/uploads", json=body, idempotency_key=key)
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert second.headers.get("x-idempotency-replayed") == "true"
    conflict = await session.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={**body, "filename": "different.zip"},
        idempotency_key=key,
    )
    assert conflict.status_code == 409


async def test_duplicate_finalize_is_a_conflict_not_a_second_promotion(client):
    session = await login(client, "skb-dev-analyst")
    blob = skill_zip()
    sha = hashlib.sha256(blob).hexdigest()
    created = await session.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={
            "filename": "x.zip",
            "media_type": "application/zip",
            "byte_size": len(blob),
            "sha256": sha,
            "classification": "synthetic",
        },
    )
    upload_body = created.json()
    await session.put(upload_body["put_path"], content=blob, headers={"X-Project-ID": PROJECT_A})
    first = await session.post(
        f"/api/v1/uploads/{upload_body['id']}:finalize",
        json={"sha256": sha, "byte_size": len(blob)},
        headers={"X-Project-ID": PROJECT_A},
    )
    assert first.status_code == 200
    duplicate = await session.post(
        f"/api/v1/uploads/{upload_body['id']}:finalize",
        json={"sha256": sha, "byte_size": len(blob)},
        headers={"X-Project-ID": PROJECT_A, "Idempotency-Key": str(uuid.uuid4())},
    )
    assert duplicate.status_code == 409


async def test_cross_project_artifact_access_is_not_found(client_factory):
    other = await login(client_factory(), "skb-dev-other-org")
    analyst = await login(client_factory(), "skb-dev-analyst")
    artifact = await upload(analyst, skill_zip())
    # The foreign project exists and the caller may read it, yet the object is
    # looked up (and RLS-filtered) inside that project only.
    response = await other.get(
        f"/api/v1/artifacts/{artifact['id']}", headers={"X-Project-ID": PROJECT_B}
    )
    assert response.status_code == 404
    # The caller without any grant on the owning project is denied outright.
    denied = await other.get(
        f"/api/v1/artifacts/{artifact['id']}", headers={"X-Project-ID": PROJECT_A}
    )
    assert denied.status_code == 403
    no_scope = await analyst.get(f"/api/v1/artifacts/{artifact['id']}")
    assert no_scope.status_code == 403


async def test_object_route_ignores_foreign_project_hint(client):
    session = await login(client, "skb-dev-analyst")
    artifact = await upload(session, skill_zip())
    # The caller may read PROJECT_A but the hinted project is another project.
    mismatched = await session.get(
        f"/api/v1/artifacts/{artifact['id']}", headers={"X-Project-ID": PROJECT_A2}
    )
    assert mismatched.status_code == 404


async def test_api_key_upload_path_requires_project_scope_header(client):
    blob = skill_zip()
    sha = hashlib.sha256(blob).hexdigest()
    headers = api_key_headers(api_key="skb_test_key_A_0123456789abcdefghijklmnop", project_id=PROJECT_A)
    created = await client.post(
        f"/api/v1/projects/{PROJECT_A}/uploads",
        json={
            "filename": "x.zip",
            "media_type": "application/zip",
            "byte_size": len(blob),
            "sha256": sha,
            "classification": "synthetic",
        },
        headers=headers,
    )
    assert created.status_code == 201
    upload_body = created.json()
    missing_scope = await client.put(
        upload_body["put_path"], content=blob, headers={**headers, "X-Project-ID": ""}
    )
    assert missing_scope.status_code == 403
