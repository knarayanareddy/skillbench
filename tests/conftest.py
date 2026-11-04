"""Test fixtures: real PostgreSQL 16, real OIDC flow against the loopback IdP.

No synthetic identity is injected by dependency override: tests authenticate by
performing the contracted authorization-code + PKCE flow and then exercise the
API exactly as a browser session or a scoped machine key would.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import AsyncIterator, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from httpx import ASGITransport, AsyncClient

from src.core.config import Settings
from src.main import create_app
from tests.support.pgenv import (
    API_KEY_A,
    API_KEY_B,
    API_KEY_EXPIRED,
    API_KEY_REVOKED,
    ORG_A,
    ORG_B,
    PROJECT_A,
    PROJECT_A2,
    PROJECT_B,
    SUBJECTS,
    TEST_ISSUER,
    PgEnv,
    PostgresUnavailable,
)

pytest_plugins: list[str] = []

CLIENT_ID = "skb-test-client"
CLIENT_SECRET = "skb-test-client-secret-0123456789"
REDIRECT_URI = "https://testserver/api/v1/auth/callback"


@pytest.fixture(scope="session")
def pg_env() -> PgEnv:
    if os.getenv("SKB_TEST_PG_OPTIONAL") == "1":
        pytest.skip("SKB_TEST_PG_OPTIONAL=1: PostgreSQL tests explicitly opted out")
    env = PgEnv()
    try:
        env.start()
        env.migrate()
    except PostgresUnavailable as exc:
        pytest.fail(f"PostgreSQL 16 test server unavailable: {exc}")
    except Exception as exc:  # noqa: BLE001 - never silently skip a database guarantee
        pytest.fail(f"PostgreSQL test environment could not start: {type(exc).__name__}: {exc}")
    yield env
    env.stop()


@pytest.fixture()
def world(pg_env: PgEnv) -> PgEnv:
    """Fresh deterministic world per test (identities, projects, API keys)."""
    pg_env.seed_world()
    return pg_env


@pytest.fixture()
def settings(pg_env: PgEnv, tmp_path: Path) -> Settings:
    return Settings(
        SKB_ENV="test",
        DATABASE_URL=pg_env.app_dsn(),
        ARTIFACT_ROOT=str(tmp_path / "artifacts"),
        OIDC_ISSUER=TEST_ISSUER,
        OIDC_CLIENT_ID=CLIENT_ID,
        OIDC_CLIENT_SECRET=CLIENT_SECRET,
        OIDC_REDIRECT_URI=REDIRECT_URI,
        SKB_LOCAL_IDP=True,
        MEMBERSHIP_CACHE_SECONDS=0,
    )


@pytest.fixture()
def app(settings: Settings, world: PgEnv):
    application = create_app(settings)
    application.state.store.ensure_dirs()
    yield application


@pytest.fixture()
def worker_settings(pg_env: PgEnv, settings: Settings) -> Settings:
    """Worker identity (baseline_dispatcher), never the API or owner role."""
    return settings.model_copy(update={"DATABASE_URL": pg_env.worker_dsn()})


@pytest.fixture()
async def worker(worker_settings: Settings):
    from src.worker.main import Worker

    instance = Worker(worker_settings)
    yield instance
    await instance.close()


@pytest.fixture()
def client_factory(app):
    """Independent cookie jars for cross-actor tests."""
    clients: list[AsyncClient] = []

    def make() -> AsyncClient:
        instance = AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver")
        clients.append(instance)
        return instance

    yield make


@pytest.fixture()
async def client(app) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://testserver") as http_client:
        yield http_client


class Session:
    """An authenticated browser session with its CSRF token."""

    def __init__(self, client: AsyncClient, subject: str, csrf_token: str, session_body: Dict) -> None:
        self.client = client
        self.subject = subject
        self.csrf_token = csrf_token
        self.body = session_body

    def mutation_headers(self, idempotency_key: Optional[str] = None) -> Dict[str, str]:
        return {
            "Idempotency-Key": idempotency_key or str(uuid.uuid4()),
            "X-CSRF-Token": self.csrf_token,
            "Origin": "https://testserver",
        }

    async def get(self, url: str, **kwargs):
        return await self.client.get(url, **kwargs)

    async def post(self, url: str, *, idempotency_key: Optional[str] = None, **kwargs):
        headers = {**self.mutation_headers(idempotency_key), **(kwargs.pop("headers", {}) or {})}
        return await self.client.post(url, headers=headers, **kwargs)

    async def put(self, url: str, *, idempotency_key: Optional[str] = None, **kwargs):
        headers = {**self.mutation_headers(idempotency_key), **(kwargs.pop("headers", {}) or {})}
        return await self.client.put(url, headers=headers, **kwargs)

    async def delete(self, url: str, *, idempotency_key: Optional[str] = None, **kwargs):
        headers = {**self.mutation_headers(idempotency_key), **(kwargs.pop("headers", {}) or {})}
        return await self.client.delete(url, headers=headers, **kwargs)


def dispose_clients(clients) -> None:  # pragma: no cover - helper for fixtures
    for instance in clients:
        instance.cookies.clear()


async def login(client: AsyncClient, subject: str = "skb-dev-analyst", return_to: str = "/") -> Session:
    """Perform the real authorization-code + PKCE login against the loopback IdP."""
    response = await client.get("/api/v1/auth/login", params={"return_to": return_to})
    assert response.status_code == 302, response.text
    authorize = urlparse(response.headers["location"])
    assert authorize.path.endswith("/authorize"), response.headers["location"]
    params = {key: value[0] for key, value in parse_qs(authorize.query).items()}
    params["login_hint"] = subject
    authorize_redirect = await client.get(f"{authorize.path}?{urlencode(params)}")
    assert authorize_redirect.status_code == 302, authorize_redirect.text
    callback = urlparse(authorize_redirect.headers["location"])
    completed = await client.get(f"{callback.path}?{callback.query}")
    assert completed.status_code == 303, completed.text
    session_response = await client.get("/api/v1/auth/session")
    assert session_response.status_code == 200, session_response.text
    body = session_response.json()
    return Session(client, subject, body["csrf_token"], body)


def api_key_headers(api_key: str, project_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, str]:
    return {
        "X-API-Key": api_key,
        "X-Project-ID": project_id,
        "Idempotency-Key": idempotency_key or str(uuid.uuid4()),
    }
