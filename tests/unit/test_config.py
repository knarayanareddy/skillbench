"""Startup configuration is fail-closed; no default credentials exist."""
from __future__ import annotations

import pytest

from src.core.config import Settings, validate_runtime

BASE = {
    "SKB_ENV": "development",
    "DATABASE_URL": "postgresql://app_login@/skb?host=/tmp/socket",
    "ARTIFACT_ROOT": "/srv/artifacts",
    "SKB_LOCAL_IDP": True,
}


def make(**overrides) -> Settings:
    values = {**BASE, **overrides}
    return Settings(**values)


def test_development_defaults_with_local_idp_are_acceptable():
    assert validate_runtime(make()) == []


def test_missing_database_and_artifact_root_are_refused():
    problems = validate_runtime(make(DATABASE_URL="", ARTIFACT_ROOT=""))
    assert "database_dsn_missing" in problems
    assert "artifact_root_missing" in problems


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://app_login:app_password@db/skb",
        "postgresql://postgres:postgres@db/skb",
        "postgresql://migration_owner@db/skb",
        "postgresql://skb:skb@db/skb",
    ],
)
def test_owner_or_default_credentials_are_refused(dsn):
    assert "database_dsn_uses_default_or_owner_credentials" in validate_runtime(make(DATABASE_URL=dsn))


def test_static_test_api_key_is_refused():
    problems = validate_runtime(make(DEV_API_KEY="test-token-admin"))
    assert "static_test_credential_forbidden" in problems


def test_production_requires_real_oidc_and_https():
    problems = validate_runtime(
        make(
            SKB_ENV="production",
            ARTIFACT_ROOT="/srv/artifacts",
            OIDC_ISSUER="https://auth.example.com",
            OIDC_CLIENT_ID="skb-client",
            OIDC_CLIENT_SECRET="",
            OIDC_REDIRECT_URI="http://insecure/callback",
        )
    )
    assert "oidc_issuer_invalid" in problems
    assert "oidc_client_id_missing" in problems
    assert "oidc_client_secret_missing" in problems
    assert "oidc_redirect_uri_invalid" in problems


def test_production_forbids_local_idp_debug_and_dev_keys():
    problems = validate_runtime(
        make(
            SKB_ENV="production",
            DEBUG=True,
            SKB_LOCAL_IDP=True,
            DEV_API_KEY="dev-key",
            OIDC_ISSUER="https://idp.internal.example",
            OIDC_CLIENT_ID="skb-prod",
            OIDC_CLIENT_SECRET="s" * 32,
            OIDC_REDIRECT_URI="https://skb.internal.example/api/v1/auth/callback",
        )
    )
    assert "debug_forbidden_in_production" in problems
    assert "local_idp_forbidden_in_production" in problems
    assert "dev_api_key_forbidden_in_production" in problems


def test_production_accepts_a_complete_configuration():
    problems = validate_runtime(
        make(
            SKB_ENV="production",
            SKB_LOCAL_IDP=False,
            OIDC_ISSUER="https://idp.internal.example",
            OIDC_CLIENT_ID="skb-prod",
            OIDC_CLIENT_SECRET="s" * 32,
            OIDC_REDIRECT_URI="https://skb.internal.example/api/v1/auth/callback",
        )
    )
    assert problems == []


def test_local_idp_is_ignored_outside_development_and_test():
    settings = make(SKB_ENV="production", SKB_LOCAL_IDP=True)
    assert settings.local_idp_enabled() is False


def test_cookie_posture_follows_environment():
    development = make()
    production = make(SKB_ENV="production")
    assert development.cookie_name() == "skb-dev-session"
    assert development.cookie_secure() is False
    assert production.cookie_name() == "__Host-baseline-session"
    assert production.cookie_secure() is True


def test_dsn_file_takes_precedence_and_fails_safely(tmp_path):
    secret = tmp_path / "dsn"
    secret.write_text("postgresql://app_login@/skb?host=/tmp/other\n")
    settings = make(DATABASE_DSN_FILE=str(secret), DATABASE_URL="postgresql://wrong@/x")
    assert settings.dsn().endswith("host=/tmp/other")
    missing = make(DATABASE_DSN_FILE=str(tmp_path / "absent"))
    with pytest.raises(RuntimeError, match="database_dsn_file_unreadable"):
        missing.dsn()


def test_unimplemented_capabilities_report_503_mode_disabled():
    from src.core.errors import Problem

    problem = Problem("mode_disabled", "Live model execution is disabled in fixture-only mode.")
    assert problem.status_code == 503
    assert problem.code == "mode_disabled"
