"""Runtime configuration with fail-closed startup validation.

There are no working default credentials. Production startup refuses to run with
missing, placeholder or static-test identity/database configuration. The local
synthetic IdP is a development/test-only capability and is refused in production.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PLACEHOLDER_VALUES = {
    "",
    "UNCONFIGURED",
    "changeme",
    "change-me",
    "example",
    "https://auth.example.com",
    "skb-client",
}

# Static test credentials from the old scaffold must never authenticate a runtime.
FORBIDDEN_STATIC_TOKENS = {
    "test-token-admin",
    "test-token-maintainer",
    "test-token-operator",
    "test-token-analyst",
    "test-token-viewer",
    "test-token-analyst-operator",
    "insecure-dev-secret-change-in-production-00000000",
}

ENVIRONMENTS = {"development", "test", "production"}


class Settings(BaseSettings):
    """Process configuration. Values come from the environment, never from code."""

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    PROJECT_NAME: str = "SkillBench"
    ENVIRONMENT: str = Field(default="development", alias="SKB_ENV")
    DEBUG: bool = False

    API_V1_PREFIX: str = "/api/v1"

    # Database: DSN is supplied by environment or a mounted secret file.
    DATABASE_URL: str = ""
    DATABASE_DSN_FILE: Optional[str] = None
    DB_POOL_SIZE: int = 5
    DB_ECHO: bool = False

    # Artifact storage: private local volume, never web-served directly.
    ARTIFACT_ROOT: str = ""
    ARTIFACT_STAGING_QUARANTINE: bool = True

    # Browser session/identity.
    OIDC_ISSUER: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_CLIENT_SECRET_FILE: Optional[str] = None
    OIDC_REDIRECT_URI: Optional[str] = None
    OIDC_SCOPES: str = "openid profile email"
    OIDC_JWKS_URI: Optional[str] = None
    OIDC_DISCOVERY_URL: Optional[str] = None
    OIDC_HTTP_TIMEOUT_SECONDS: float = 5.0

    # Local synthetic identity provider. Development/test only, loopback only.
    LOCAL_IDP: bool = Field(default=False, alias="SKB_LOCAL_IDP")
    LOCAL_IDP_ALLOWED_HOSTS: List[str] = ["127.0.0.1", "localhost", "testserver"]

    # An explicitly injected development API key (never a default/static token).
    DEV_API_KEY: Optional[str] = None

    # Liveness/readiness and CORS. Same-origin deployment is the default.
    CORS_ORIGINS: List[str] = []

    UPLOAD_SESSION_TTL_SECONDS: int = 3600
    IDEMPOTENCY_TTL_SECONDS: int = 86400
    SESSION_IDLE_SECONDS: int = 1800
    SESSION_ABSOLUTE_SECONDS: int = 28800
    MEMBERSHIP_CACHE_SECONDS: int = 30

    MAX_ARTIFACT_BYTES: int = 104857600

    # Contract limits from infra/runtime-policy.yaml.
    ZIP_COMPRESSED_BYTES: int = 20971520
    ZIP_EXPANDED_BYTES: int = 104857600
    ZIP_FILES: int = 2000

    def dsn(self) -> str:
        """Return the database DSN, preferring a mounted secret file."""
        if self.DATABASE_DSN_FILE:
            try:
                return Path(self.DATABASE_DSN_FILE).read_text().strip()
            except OSError as exc:  # pragma: no cover - configuration error path
                raise RuntimeError("database_dsn_file_unreadable") from exc
        return self.DATABASE_URL.strip()

    def client_secret(self) -> str:
        if self.OIDC_CLIENT_SECRET_FILE:
            try:
                return Path(self.OIDC_CLIENT_SECRET_FILE).read_text().strip()
            except OSError as exc:  # pragma: no cover
                raise RuntimeError("oidc_client_secret_unreadable") from exc
        return self.OIDC_CLIENT_SECRET.strip()

    def cookie_name(self) -> str:
        """`__Host-` prefixed secure cookie in every non-development environment."""
        return "skb-dev-session" if self.ENVIRONMENT == "development" else "__Host-baseline-session"

    def cookie_secure(self) -> bool:
        return self.ENVIRONMENT != "development"

    def local_idp_enabled(self) -> bool:
        return bool(self.LOCAL_IDP) and self.ENVIRONMENT in {"development", "test"}


def _looks_placeholder(value: str) -> bool:
    return value.strip() in PLACEHOLDER_VALUES or value.strip().lower().startswith("unconfigured")


def validate_runtime(settings: Settings, *, require_identity: bool = True) -> List[str]:
    """Return a list of fail-closed startup problems (empty means acceptable).

    Called from the application lifespan; a non-empty list aborts startup. The worker
    performs no authentication, so it passes ``require_identity=False`` and validates
    only the database/artifact surface it actually uses.
    """
    problems: List[str] = []
    env = settings.ENVIRONMENT
    if env not in ENVIRONMENTS:
        problems.append(f"invalid_environment:{env}")

    dsn = settings.dsn()
    if not dsn:
        problems.append("database_dsn_missing")
    else:
        lowered = dsn.lower()
        for banned in ("app_password", ":postgres@", "migration_owner", "password@", "skb:skb@"):
            if banned in lowered:
                problems.append("database_dsn_uses_default_or_owner_credentials")
                break

    if not settings.ARTIFACT_ROOT:
        problems.append("artifact_root_missing")
    elif env == "production" and not Path(settings.ARTIFACT_ROOT).is_absolute():
        problems.append("artifact_root_must_be_absolute")

    if settings.DEV_API_KEY:
        if env == "production":
            problems.append("dev_api_key_forbidden_in_production")
        elif settings.DEV_API_KEY in FORBIDDEN_STATIC_TOKENS:
            problems.append("static_test_credential_forbidden")

    if env == "production":
        if settings.DEBUG:
            problems.append("debug_forbidden_in_production")
        if settings.LOCAL_IDP:
            problems.append("local_idp_forbidden_in_production")
    if not require_identity:
        return problems
    if env == "production":
        if _looks_placeholder(settings.OIDC_ISSUER) or not settings.OIDC_ISSUER.startswith("https://"):
            problems.append("oidc_issuer_invalid")
        if _looks_placeholder(settings.OIDC_CLIENT_ID):
            problems.append("oidc_client_id_missing")
        if _looks_placeholder(settings.client_secret()):
            problems.append("oidc_client_secret_missing")
        if not settings.OIDC_REDIRECT_URI or not settings.OIDC_REDIRECT_URI.startswith("https://"):
            problems.append("oidc_redirect_uri_invalid")
    else:
        # Non-production still requires a real issuer unless the local IdP is on.
        if not settings.local_idp_enabled():
            if _looks_placeholder(settings.OIDC_ISSUER) or _looks_placeholder(settings.OIDC_CLIENT_ID):
                problems.append("oidc_configuration_missing")
    return problems


def allowed_host_for_local_idp(settings: Settings, host: str) -> bool:
    host = (host or "").split(":")[0]
    return host in set(settings.LOCAL_IDP_ALLOWED_HOSTS)


settings = Settings()
