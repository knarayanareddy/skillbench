"""Identity context, capability unions, tokens and metadata redaction.

Rules enforced here:
  * Static test tokens never authenticate a runtime; ``verify_token`` is fail-closed.
  * Organization administration is NOT project content access.
  * Capabilities for a project are the union of the caller's granted project roles.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Set

from pydantic import BaseModel, field_validator

PROJECT_CAPABILITIES = ("viewer", "analyst", "operator", "maintainer")
ORG_ROLES = ("member", "admin")

# A role grants the listed capabilities; capabilities are cumulative per project.
CAPABILITY_EXPANSION: Dict[str, Set[str]] = {
    "viewer": {"viewer"},
    "analyst": {"viewer", "analyst"},
    "operator": {"viewer", "operator"},
    "maintainer": {"viewer", "analyst", "operator", "maintainer"},
}

FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "authorization",
    "access_token",
    "refresh_token",
    "password",
    "client_secret",
    "cookie",
    "secret",
}

ALLOWED_METADATA_KEYS = {
    "operation_id",
    "name",
    "outcome",
    "input_tokens",
    "output_tokens",
    "redacted",
    "reason",
}

_SESSION_TOKEN_BYTES = 32


def new_session_token() -> str:
    return secrets.token_urlsafe(_SESSION_TOKEN_BYTES)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(_SESSION_TOKEN_BYTES)


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def api_key_digest(raw_key: str) -> bytes:
    return hashlib.sha256(raw_key.encode("utf-8")).digest()


class UserContext(BaseModel):
    """Authorized caller context derived from a verified session or scoped key."""

    user_id: str
    organization_id: str
    org_role: str = "member"
    project_roles: Dict[str, Set[str]] = {}
    principal_kind: str = "session"
    session_id: Optional[str] = None
    api_key_id: Optional[str] = None
    scoped_project_id: Optional[str] = None
    csrf_token: Optional[str] = None
    session_expires_at: Optional[str] = None

    model_config = {"extra": "forbid"}

    @field_validator("project_roles", mode="before")
    @classmethod
    def normalize_project_roles(cls, v: Any) -> Dict[str, Set[str]]:
        if not isinstance(v, Mapping):
            return {}
        normalized: Dict[str, Set[str]] = {}
        for project_id, roles in v.items():
            if isinstance(roles, str):
                normalized[str(project_id)] = {roles}
            elif isinstance(roles, (list, tuple, set, frozenset)):
                normalized[str(project_id)] = {str(role) for role in roles}
            else:
                normalized[str(project_id)] = set()
        return normalized

    def capabilities_for(self, project_id: str) -> Set[str]:
        roles = self.project_roles.get(str(project_id), set())
        capabilities: Set[str] = set()
        for role in roles:
            capabilities |= CAPABILITY_EXPANSION.get(role, set())
        if self.scoped_project_id is not None:
            # A machine key can never act outside its own project scope.
            if str(project_id) != self.scoped_project_id:
                return set()
            capabilities &= set(self.project_roles.get(self.scoped_project_id, set()))
        return capabilities

    def has_project_capability(self, project_id: str, required_capability: str) -> bool:
        """True when the union of granted roles covers the required capability."""
        if required_capability not in PROJECT_CAPABILITIES:
            return False
        return required_capability in self.capabilities_for(project_id)

    def is_org_admin(self) -> bool:
        return self.org_role == "admin"


def redact_metadata(value: Dict[str, Any]) -> Dict[str, Any]:
    """Allowlisted metadata scrubbing; strips credentials and free text."""
    if not isinstance(value, dict):
        raise ValueError("Metadata must be a dictionary")

    sanitized: Dict[str, Any] = {}
    for key, raw in value.items():
        key_lower = key.lower()
        if key_lower in FORBIDDEN_METADATA_KEYS:
            continue
        if key not in ALLOWED_METADATA_KEYS:
            continue
        if key == "reason":
            # Free text can contain content or credentials; metadata capture omits it.
            continue
        if isinstance(raw, (dict, list, tuple, set)):
            raise ValueError("Nested metadata structures are forbidden")
        sanitized[key] = raw
    return sanitized


def redact_for_log(value: str) -> str:
    """Bounded, credential-free log text. Never log raw exception text."""
    return (value or "").replace("\n", " ")[:200]


def verify_token(token: str) -> Optional[UserContext]:
    """Bearer-token identity is not an accepted authentication scheme.

    The scoped contract authenticates browsers by server-side session cookie and
    machines by ``X-API-Key``. This function is fail-closed by construction and
    never accepts static test credentials.
    """
    return None


def capability_names(values: Iterable[str]) -> Set[str]:
    return {v for v in values if v in PROJECT_CAPABILITIES}
