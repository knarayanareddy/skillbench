"""OIDC authorization-code client (PKCE S256) and a loopback synthetic test IdP.

The production path speaks ordinary OIDC discovery/JWKS to an operator-provided
issuer. The local IdP exists so development and tests exercise the same code
path (state, nonce, PKCE, signature, issuer, audience, expiry) without
production credentials. It is never mounted in production.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError

from src.core.config import Settings

LOCAL_IDP_SUBJECTS = {
    # Synthetic, preprovisioned development subjects. No passwords, no registration.
    "skb-dev-admin": "Org admin (synthetic)",
    "skb-dev-maintainer": "Project maintainer (synthetic)",
    "skb-dev-analyst": "Project analyst (synthetic)",
    "skb-dev-viewer": "Project viewer (synthetic)",
    "skb-dev-operator": "Project operator (synthetic)",
    "skb-dev-other-org": "Other-organization analyst (synthetic)",
}


class OIDCError(Exception):
    """Authentication failed. The message is safe for logs but not for clients."""


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class JWKSCache:
    jwks: Optional[Dict[str, Any]] = None
    fetched_at: float = 0.0
    unknown_kid_refresh_at: float = 0.0


@dataclass
class OIDCClient:
    """Discovery/JWKS/token client with bounded caching.

    ``transport`` is only supplied by tests/local development so the loopback
    synthetic IdP is reached in-process; production uses ordinary HTTPS with
    environment trust disabled.
    """

    settings: Settings
    transport: Any = None
    _discovery: Optional[Dict[str, Any]] = None
    _discovery_at: float = 0.0
    _jwks_cache: JWKSCache = field(default_factory=JWKSCache)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.settings.OIDC_HTTP_TIMEOUT_SECONDS,
            trust_env=False,
            transport=self.transport,
        )

    def issuer(self) -> str:
        return self.settings.OIDC_ISSUER.rstrip("/")

    def redirect_uri(self) -> str:
        if self.settings.OIDC_REDIRECT_URI:
            return self.settings.OIDC_REDIRECT_URI
        return "/api/v1/auth/callback"

    async def discovery(self) -> Dict[str, Any]:
        now = time.monotonic()
        if self._discovery and now - self._discovery_at < 3600:
            return self._discovery
        url = self.settings.OIDC_DISCOVERY_URL or f"{self.issuer()}/.well-known/openid-configuration"
        async with self._client() as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        if str(data.get("issuer", "")).rstrip("/") != self.issuer():
            raise OIDCError("issuer_mismatch")
        self._discovery = data
        self._discovery_at = now
        return data

    async def jwks(self, *, force: bool = False) -> Dict[str, Any]:
        now = time.monotonic()
        cache = self._jwks_cache
        if cache.jwks and not force and now - cache.fetched_at < 3600:
            return cache.jwks
        if force and now - cache.unknown_kid_refresh_at < 30:
            # Bounded refresh: unknown kid cannot be used to hammer the IdP.
            if cache.jwks:
                return cache.jwks
        meta = await self.discovery()
        uri = self.settings.OIDC_JWKS_URI or meta.get("jwks_uri")
        if not uri:
            raise OIDCError("jwks_uri_missing")
        async with self._client() as client:
            response = await client.get(uri)
            response.raise_for_status()
            cache.jwks = response.json()
        cache.fetched_at = now
        if force:
            cache.unknown_kid_refresh_at = now
        return cache.jwks

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        meta = self._discovery or {}
        if self.settings.local_idp_enabled():
            # The loopback IdP is served by this same application. The browser must
            # stay on its own origin, so the authorize URL is relative (dev/test only;
            # production uses a real issuer and never reaches this branch).
            endpoint = "/local-idp/authorize"
        else:
            endpoint = meta.get("authorization_endpoint") or f"{self.issuer()}/authorize"
        params = {
            "response_type": "code",
            "client_id": self.settings.OIDC_CLIENT_ID,
            "redirect_uri": self.redirect_uri(),
            "scope": self.settings.OIDC_SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{endpoint}?{urlencode(params)}"

    async def exchange_code(self, *, code: str, code_verifier: str) -> Dict[str, Any]:
        meta = await self.discovery()
        endpoint = meta.get("token_endpoint") or f"{self.issuer()}/token"
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri(),
            "client_id": self.settings.OIDC_CLIENT_ID,
            "client_secret": self.settings.client_secret(),
            "code_verifier": code_verifier,
        }
        async with self._client() as client:
            response = await client.post(endpoint, data=payload)
        if response.status_code != 200:
            raise OIDCError("token_exchange_failed")
        return response.json()

    @staticmethod
    def _header(token: str) -> Dict[str, Any]:
        import json

        try:
            raw = token.split(".")[0]
            padded = raw + "=" * (-len(raw) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception as exc:  # noqa: BLE001 - malformed token is an auth failure
            raise OIDCError("malformed_token") from exc

    async def verify_id_token(self, token: str, *, nonce: str) -> Dict[str, Any]:
        """Verify signature, issuer, audience, expiry and nonce. Returns safe claims."""
        header = self._header(token)
        alg = header.get("alg")
        if alg not in {"RS256", "ES256"}:
            raise OIDCError("unsupported_algorithm")
        kid = header.get("kid")
        if not kid:
            raise OIDCError("kid_missing")
        jwks = await self.jwks()
        if kid not in {k.get("kid") for k in jwks.get("keys", [])}:
            jwks = await self.jwks(force=True)
            if kid not in {k.get("kid") for k in jwks.get("keys", [])}:
                raise OIDCError("kid_unknown")
        key_set = JsonWebKey.import_key_set(jwks)
        try:
            claims = JsonWebToken([alg]).decode(token, key_set)
            claims.validate(leeway=60)
        except JoseError as exc:
            raise OIDCError("token_invalid") from exc
        if str(claims.get("iss", "")).rstrip("/") != self.issuer():
            raise OIDCError("issuer_mismatch")
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self.settings.OIDC_CLIENT_ID not in audiences:
            raise OIDCError("audience_mismatch")
        if claims.get("nonce") != nonce:
            raise OIDCError("nonce_mismatch")
        if not claims.get("sub"):
            raise OIDCError("subject_missing")
        return dict(claims)


# ---------------------------------------------------------------------------
# Loopback synthetic IdP (development/test only)
# ---------------------------------------------------------------------------
@dataclass
class _AuthCode:
    subject: str
    redirect_uri: str
    nonce: str
    code_challenge: str
    client_id: str
    expires_at: float


class LocalSyntheticIdP:
    """Minimal OIDC provider for loopback development and tests.

    Subjects are synthetic and must already exist in `core.users` with the
    configured issuer. This provider issues no refresh tokens and stores codes
    in memory only; it is not a production identity system.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        self.kid = f"local-{uuid.uuid4()}"
        self.codes: Dict[str, _AuthCode] = {}

    def jwks(self) -> Dict[str, Any]:
        public = self.key.as_dict(is_private=False)
        public["kid"] = self.kid
        public["use"] = "sig"
        public["alg"] = "RS256"
        return {"keys": [public]}

    def metadata(self) -> Dict[str, Any]:
        base = self.settings.OIDC_ISSUER.rstrip("/")
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": f"{base}/jwks",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
        }

    def issue_code(
        self,
        *,
        subject: str,
        client_id: str,
        redirect_uri: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        if subject not in LOCAL_IDP_SUBJECTS:
            raise OIDCError("subject_not_authorized")
        if client_id != self.settings.OIDC_CLIENT_ID:
            raise OIDCError("client_mismatch")
        if redirect_uri != (self.settings.OIDC_REDIRECT_URI or "/api/v1/auth/callback"):
            raise OIDCError("redirect_mismatch")
        code = secrets.token_urlsafe(24)
        self.codes[code] = _AuthCode(
            subject=subject,
            redirect_uri=redirect_uri,
            nonce=nonce,
            code_challenge=code_challenge,
            client_id=client_id,
            expires_at=time.time() + 60,
        )
        return code

    def exchange(
        self,
        *,
        code: str,
        code_verifier: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        record = self.codes.pop(code, None)  # one use, even on failure
        if record is None or record.expires_at < time.time():
            raise OIDCError("code_invalid")
        if client_id != record.client_id or client_secret != self.settings.client_secret():
            raise OIDCError("client_auth_failed")
        if redirect_uri != record.redirect_uri:
            raise OIDCError("redirect_mismatch")
        challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
        if not secrets.compare_digest(challenge, record.code_challenge):
            raise OIDCError("pkce_failed")
        now = int(time.time())
        claims = {
            "iss": self.settings.OIDC_ISSUER.rstrip("/"),
            "aud": client_id,
            "sub": record.subject,
            "iat": now,
            "exp": now + 300,
            "nonce": record.nonce,
            "email": f"{record.subject}@synthetic.invalid",
        }
        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        token = JsonWebToken(["RS256"]).encode(header, claims, self.key)
        return {
            "access_token": secrets.token_urlsafe(32),
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": token.decode() if isinstance(token, bytes) else token,
        }
