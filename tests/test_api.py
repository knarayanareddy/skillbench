"""Baseline API behaviour: fail-closed authentication, scoping and capability checks.

This module replaces the B00-era stub expectations (``POST /projects`` returning
501, synthetic ``Bearer test-token-*`` identities). The reviewed change is:
identity now comes from the real OIDC flow or a scoped machine key, and project
creation is implemented (201) instead of disabled (501). The negative guarantees
are preserved one-for-one and extend to the object routes.
"""
from __future__ import annotations

import uuid

import pytest

from src.core.security import verify_token
from tests.support import helpers
from tests.support.pgenv import PROJECT_A, PROJECT_B

TEST_PROJ = PROJECT_A
OTHER_PROJ = PROJECT_B
UNKNOWN_ID = str(uuid.uuid4())


def test_production_verifier_rejects_test_tokens():
    """The runtime verifier fails closed and never accepts synthetic tokens."""
    for token in (
        "Bearer test-token-admin",
        "Bearer test-token-maintainer",
        "Bearer test-token-operator",
        "Bearer test-token-analyst",
        "Bearer test-token-viewer",
        "Bearer test-token-analyst-operator",
        "Bearer nonsense",
        "",
    ):
        assert verify_token(token) is None


async def test_health_endpoints_are_public(client):
    live = await client.get("/healthz")
    assert live.status_code == 200
    body = live.json()
    assert body["status"] == "pass"
    assert "database" not in body.get("checks", {})


async def test_unauthenticated_requests_are_rejected(client):
    for path in (
        "/api/v1/projects",
        f"/api/v1/projects/{TEST_PROJ}/skb/packages",
        f"/api/v1/skb/packages/{UNKNOWN_ID}",
    ):
        assert (await client.get(path)).status_code == 401


async def test_invalid_token_is_rejected(client):
    response = await client.get(
        "/api/v1/projects", headers={"Authorization": "Bearer test-token-admin"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "unauthenticated"


async def test_create_project_requires_idempotency_key(client):
    session = await helpers.user_session(client, "skb-dev-admin")
    response = await client.post(
        "/api/v1/projects",
        json={"name": "No key", "content_capture": "metadata_only", "external_transfer": False},
        headers={"X-CSRF-Token": session.csrf_token, "Origin": "https://testserver"},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid"


async def test_create_project_requires_org_admin(client):
    session = await helpers.user_session(client, "skb-dev-viewer")
    response = await session.post(
        "/api/v1/projects",
        json={"name": "Not admin", "content_capture": "metadata_only", "external_transfer": False},
    )
    assert response.status_code == 403


async def test_create_project_now_returns_201(client):
    session = await helpers.user_session(client, "skb-dev-admin")
    response = await session.post(
        "/api/v1/projects",
        json={"name": "Created", "content_capture": "metadata_only", "external_transfer": False},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["revision"] == 1
    uuid.UUID(body["id"])


async def test_project_route_unauthenticated_denied(client):
    assert (await client.get(f"/api/v1/projects/{TEST_PROJ}/skb/packages")).status_code == 401


async def test_project_route_insufficient_capability_denied(client):
    session = await helpers.user_session(client, "skb-dev-analyst")
    # Suites require maintainer; an analyst is rejected before any body parsing.
    response = await session.post(
        f"/api/v1/projects/{TEST_PROJ}/skb/suites",
        json={"name": "nope", "tasks": [], "rights_manifest_artifact_id": UNKNOWN_ID},
    )
    assert response.status_code == 403


async def test_project_route_unauthorized_project_denied(client):
    session = await helpers.user_session(client, "skb-dev-analyst")
    assert (await session.get(f"/api/v1/projects/{OTHER_PROJ}/skb/packages")).status_code == 403


async def test_project_route_authorized_capability_passes(client):
    session = await helpers.user_session(client, "skb-dev-analyst")
    response = await session.get(f"/api/v1/projects/{TEST_PROJ}/skb/packages")
    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}


async def test_object_route_unauthenticated_denied(client):
    assert (await client.get(f"/api/v1/skb/packages/{UNKNOWN_ID}")).status_code == 401


async def test_object_route_absent_scope_denied(client):
    session = await helpers.user_session(client, "skb-dev-analyst")
    assert (await session.get(f"/api/v1/skb/packages/{UNKNOWN_ID}")).status_code == 403


async def test_object_route_unauthorized_scope_denied(client):
    session = await helpers.user_session(client, "skb-dev-analyst")
    response = await session.get(
        f"/api/v1/skb/packages/{UNKNOWN_ID}", headers={"X-Project-ID": OTHER_PROJ}
    )
    assert response.status_code == 403


async def test_object_route_insufficient_capability_denied(client):
    session = await helpers.user_session(client, "skb-dev-viewer")
    response = await session.post(
        f"/api/v1/skb/packages/{UNKNOWN_ID}:inspect", headers={"X-Project-ID": TEST_PROJ}
    )
    assert response.status_code == 403


async def test_object_route_authorized_scope_returns_not_found(client):
    session = await helpers.user_session(client, "skb-dev-analyst")
    response = await session.get(
        f"/api/v1/skb/packages/{UNKNOWN_ID}", headers={"X-Project-ID": TEST_PROJ}
    )
    # Authorization succeeded; the object simply does not exist in that project.
    assert response.status_code == 404


async def test_capability_union_across_roles(client):
    """A maintainer inherits analyst + operator + viewer capabilities."""
    session = await helpers.user_session(client, "skb-dev-maintainer")
    read = await session.get(f"/api/v1/skb/packages/{UNKNOWN_ID}", headers={"X-Project-ID": TEST_PROJ})
    assert read.status_code == 404  # analyst capability satisfied
    inspect = await session.post(
        f"/api/v1/skb/packages/{UNKNOWN_ID}:inspect", headers={"X-Project-ID": TEST_PROJ}
    )
    assert inspect.status_code == 404  # operator capability satisfied, object absent
