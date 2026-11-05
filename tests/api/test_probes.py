"""Platform probe semantics: liveness never depends on the database, readiness does.

The deployed probes are only useful if a restarted or half-configured API is
*not* reported ready. That is what these two cases pin down.
"""
from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from src.main import create_app


async def _client_for(settings):
    app = create_app(settings)
    return AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver")


async def test_live_is_200_and_ready_is_200_when_the_database_answers(settings):
    async with await _client_for(settings) as client:
        live = await client.get("/health/live")
        assert live.status_code == 200
        assert live.json()["status"] == "pass"
        ready = await client.get("/health/ready")
        assert ready.status_code == 200


async def test_ready_is_503_when_the_database_is_unreachable(settings):
    broken = settings.model_copy(
        update={
            "DATABASE_URL": "postgresql://app_login@/skb_absent_0000?host=/tmp/skb-no-such-cluster",
        }
    )
    async with await _client_for(broken) as client:
        live = await client.get("/health/live")
        assert live.status_code == 200, "liveness must not depend on the database"
        ready = await client.get("/health/ready")
        assert ready.status_code == 503
        body = ready.json()
        assert body["status"] == "fail" and body["checks"]["database"] == "fail"
        # A probe must not leak configuration: no DSNs, hosts or credentials.
        assert "postgres" not in ready.text.lower()
        assert "skb_absent_0000" not in ready.text
