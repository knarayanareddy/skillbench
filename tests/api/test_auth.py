"""Identity, session, CSRF and machine-key behaviour (real DB, real OIDC flow)."""
from __future__ import annotations

import uuid
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from tests.conftest import api_key_headers, login
from tests.support.pgenv import (
    API_KEY_A,
    API_KEY_B,
    API_KEY_EXPIRED,
    API_KEY_REVOKED,
    ORG_A,
    ORG_B,
    PROJECT_A,
    PROJECT_B,
    USER_ANALYST,
)


async def test_login_establishes_server_side_session(client):
    session = await login(client, "skb-dev-analyst")
    cookie = client.cookies.get("__Host-baseline-session")
    assert cookie and len(cookie) >= 32
    assert session.body["actor_id"] == USER_ANALYST
    assert session.body["organization_id"] == ORG_A
    assert session.body["projects"] == [
        {"project_id": PROJECT_A, "roles": ["analyst"]},
        {"project_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "roles": ["analyst"]},
    ]
    assert session.csrf_token
    response = await client.get("/api/v1/auth/session")
    assert response.headers["cache-control"] == "no-store"


async def test_session_cookie_is_httponly_secure_and_host_prefixed(client):
    response = await client.get("/api/v1/auth/login", params={"return_to": "/skb/packages/x"})
    assert response.status_code == 302
    authorize = urlparse(response.headers["location"])
    params = {k: v[0] for k, v in parse_qs(authorize.query).items()}
    params["login_hint"] = "skb-dev-analyst"
    redirect = await client.get(f"{authorize.path}?{urlencode(params)}")
    callback = urlparse(redirect.headers["location"])
    completed = await client.get(f"{callback.path}?{callback.query}")
    assert completed.status_code == 303
    set_cookie = ",".join(
        value for key, value in completed.headers.multi_items() if key.lower() == "set-cookie"
    )
    assert "__Host-baseline-session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=lax" in set_cookie


async def test_login_rejects_absolute_return_to(client):
    response = await client.get("/api/v1/auth/login", params={"return_to": "https://evil.example/x"})
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/problem+json")


async def test_callback_requires_matching_transaction_and_single_use(client):
    response = await client.get("/api/v1/auth/login")
    authorize = urlparse(response.headers["location"])
    params = {k: v[0] for k, v in parse_qs(authorize.query).items()}
    params["login_hint"] = "skb-dev-analyst"
    redirect = await client.get(f"{authorize.path}?{urlencode(params)}")
    callback = urlparse(redirect.headers["location"])
    first = await client.get(f"{callback.path}?{callback.query}")
    assert first.status_code == 303
    replay = await client.get(f"{callback.path}?{callback.query}")
    assert replay.status_code in (400, 401)


async def test_callback_rejects_state_mismatch(client):
    response = await client.get("/api/v1/auth/login")
    authorize = urlparse(response.headers["location"])
    params = {k: v[0] for k, v in parse_qs(authorize.query).items()}
    params["login_hint"] = "skb-dev-analyst"
    redirect = await client.get(f"{authorize.path}?{urlencode(params)}")
    callback = urlparse(redirect.headers["location"])
    forged = await client.get(f"{callback.path}?code=abc&state=not-the-state")
    assert forged.status_code == 400


async def test_unprovisioned_subject_is_denied(client, pg_env):
    """A verified IdP subject without a preprovisioned membership cannot log in."""
    pg_env.run_sql(
        f"DELETE FROM core.project_roles WHERE user_id='{USER_ANALYST}';"
        f"DELETE FROM core.memberships WHERE user_id='{USER_ANALYST}';"
        f"DELETE FROM core.users WHERE id='{USER_ANALYST}';"
    )
    response = await client.get("/api/v1/auth/login")
    authorize = urlparse(response.headers["location"])
    params = {k: v[0] for k, v in parse_qs(authorize.query).items()}
    params["login_hint"] = "skb-dev-analyst"
    redirect = await client.get(f"{authorize.path}?{urlencode(params)}")
    callback = urlparse(redirect.headers["location"])
    denied = await client.get(f"{callback.path}?{callback.query}")
    assert denied.status_code == 403
    assert denied.json()["code"] == "forbidden"
    assert (await client.get("/api/v1/auth/session")).status_code == 401


async def test_csrf_required_for_cookie_mutations(client):
    session = await login(client, "skb-dev-admin")
    response = await client.post(
        "/api/v1/projects",
        json={"name": "No csrf", "content_capture": "metadata_only", "external_transfer": False},
        headers={"Idempotency-Key": str(uuid.uuid4())},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"


async def test_cross_origin_mutation_refused(client):
    session = await login(client, "skb-dev-admin")
    response = await session.post(
        "/api/v1/projects",
        json={"name": "Cross origin", "content_capture": "metadata_only", "external_transfer": False},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


async def test_org_admin_required_for_project_creation(client):
    session = await login(client, "skb-dev-maintainer")
    response = await session.post(
        "/api/v1/projects",
        json={"name": "Not allowed", "content_capture": "metadata_only", "external_transfer": False},
    )
    assert response.status_code == 403


async def test_org_role_is_not_project_content_access(client):
    """An organization admin without a project grant cannot read project content."""
    session = await login(client, "skb-dev-admin")
    # The admin has maintainer on PROJECT_A only; PROJECT_A2 has no grant.
    response = await session.get(
        "/api/v1/projects/cccccccc-cccc-4ccc-8ccc-cccccccccccc/skb/packages"
    )
    assert response.status_code == 403


async def test_machine_key_scope_is_limited_to_its_project(client):
    response = await client.get(
        "/api/v1/projects/%s/skb/packages" % PROJECT_B,
        headers={"X-API-Key": API_KEY_A},
    )
    assert response.status_code == 403
    allowed = await client.get(
        "/api/v1/projects/%s/skb/packages" % PROJECT_A, headers={"X-API-Key": API_KEY_A}
    )
    assert allowed.status_code == 200
    assert allowed.json() == {"items": [], "next_cursor": None}


async def test_api_key_does_not_accept_object_scope_override(client):
    response = await client.get(
        "/api/v1/skb/packages/%s" % uuid.uuid4(),
        headers={"X-API-Key": API_KEY_A, "X-Project-ID": PROJECT_B},
    )
    assert response.status_code == 403


async def test_revoked_and_expired_api_keys_are_rejected(client):
    for key in (API_KEY_REVOKED, API_KEY_EXPIRED):
        response = await client.get(
            "/api/v1/projects/%s/skb/packages" % PROJECT_A, headers={"X-API-Key": key}
        )
        assert response.status_code == 401
    unknown = await client.get(
        "/api/v1/projects/%s/skb/packages" % PROJECT_A, headers={"X-API-Key": "skb_unknown_key_value"}
    )
    assert unknown.status_code == 401


async def test_bearer_token_is_not_an_accepted_scheme(client):
    for token in ("test-token-admin", "any-oidc-access-token"):
        response = await client.get("/api/v1/projects", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401


async def test_login_requires_credentials(client):
    assert (await client.get("/api/v1/projects")).status_code == 401
    assert (await client.get("/api/v1/auth/session")).status_code == 401


async def test_logout_revokes_session_and_requires_csrf(client):
    session = await login(client, "skb-dev-analyst")
    assert (await client.get("/api/v1/auth/session")).status_code == 200
    refused = await client.post("/api/v1/auth/logout", headers={"Idempotency-Key": str(uuid.uuid4())})
    assert refused.status_code == 403
    revoked = await session.post("/api/v1/auth/logout")
    assert revoked.status_code == 204
    assert (await client.get("/api/v1/auth/session")).status_code == 401


async def test_session_expiry_is_enforced(client, pg_env):
    session = await login(client, "skb-dev-analyst")
    pg_env.run_sql(
        "UPDATE core.sessions SET created_at = now() - interval '1 hour', "
        "idle_expires_at = now() - interval '30 minutes', "
        "absolute_expires_at = now() + interval '1 hour'"
    )
    response = await client.get("/api/v1/auth/session")
    assert response.status_code == 401


async def test_revoked_membership_denies_access(client, pg_env):
    session = await login(client, "skb-dev-analyst")
    assert (await client.get(f"/api/v1/projects/{PROJECT_A}/skb/packages")).status_code == 200
    pg_env.run_sql(
        f"DELETE FROM core.project_roles WHERE project_id='{PROJECT_A}' AND user_id='{USER_ANALYST}'"
    )
    denied = await client.get(f"/api/v1/projects/{PROJECT_A}/skb/packages")
    assert denied.status_code == 403


async def test_api_key_requests_do_not_require_csrf(client):
    response = await client.post(
        f"/api/v1/projects/{PROJECT_A}/skb/suites",
        json={"name": "nope", "tasks": [], "rights_manifest_artifact_id": str(uuid.uuid4())},
        headers=api_key_headers(API_KEY_A, PROJECT_A),
    )
    # Authenticated and authorized; rejected on semantics, not on CSRF.
    assert response.status_code == 422


async def test_health_endpoints_are_public_and_do_not_leak_config(client):
    live = await client.get("/health/live")
    ready = await client.get("/health/ready")
    assert live.status_code == 200
    assert ready.status_code == 200
    assert set(ready.json()["checks"]) == {"database"}
    assert "secret" not in ready.text.lower()


async def test_unknown_route_returns_problem_not_framework_html(client):
    response = await client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "not_found"


async def test_local_idp_lists_subjects_instead_of_impersonating(client):
    """Development chooser: no silent default identity, no password form."""
    response = await client.get("/api/v1/auth/login")
    authorize = urlparse(response.headers["location"])
    page = await client.get(f"{authorize.path}?{authorize.query}")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "skb-dev-maintainer" in page.text
    assert 'type="password"' not in page.text
    # Every listed subject is a preprovisioned synthetic identity.
    assert "Development and test only" in page.text
