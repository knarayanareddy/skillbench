"""Browser identity routes (contracts/auth-flow.yaml) and the loopback test IdP."""
from __future__ import annotations

import secrets
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from src.api.deps import authenticate, get_db, get_oidc, get_settings, verify_idempotency_key
from src.api.deps import AuthContext
from src.core.auth import (
    consume_auth_transaction,
    create_auth_transaction,
    create_session,
    resolve_identity,
    revoke_session,
)
from src.core.config import Settings
from src.core.db import Database
from src.core.errors import Problem
from src.core.oidc import LOCAL_IDP_SUBJECTS, LocalSyntheticIdP, OIDCClient, OIDCError, pkce_pair

router = APIRouter()
local_idp_router = APIRouter()

AUTH_TX_COOKIE = "skb-auth-tx"


def _validate_return_to(value: str) -> str:
    if not value:
        return "/"
    if len(value) > 512:
        raise Problem("invalid", "return_to is too long.")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        raise Problem("invalid", "return_to must be a same-origin relative route.")
    if not value.startswith("/") or value.startswith("//"):
        raise Problem("invalid", "return_to must be a same-origin relative route.")
    return value


@router.get("/auth/login")
async def auth_login(
    request: Request,
    return_to: str = Query("/"),
    app_settings: Settings = Depends(get_settings),
    database: Database = Depends(get_db),
    oidc: OIDCClient = Depends(get_oidc),
):
    target = _validate_return_to(return_to)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = pkce_pair()
    await create_auth_transaction(
        database, state=state, nonce=nonce, code_verifier=verifier, return_to=target
    )
    try:
        await oidc.discovery()
    except Exception as exc:  # noqa: BLE001 - identity provider unavailable
        raise Problem("unavailable", "Identity provider is unavailable.") from exc
    location = oidc.authorization_url(state=state, nonce=nonce, code_challenge=challenge)
    response = RedirectResponse(location, status_code=302)
    response.set_cookie(
        AUTH_TX_COOKIE,
        state,
        max_age=600,
        httponly=True,
        secure=app_settings.cookie_secure(),
        samesite="lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/auth/callback")
async def auth_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    app_settings: Settings = Depends(get_settings),
    database: Database = Depends(get_db),
    oidc: OIDCClient = Depends(get_oidc),
):
    cookie_state = request.cookies.get(AUTH_TX_COOKIE)
    if not cookie_state or not secrets.compare_digest(cookie_state, state):
        raise Problem("invalid", "Authentication transaction mismatch.")
    if len(code) > 4096:
        raise Problem("invalid", "authorization code is invalid.")
    transaction = await consume_auth_transaction(database, state)
    if transaction is None:
        raise Problem("invalid", "Authentication transaction expired or already used.")
    try:
        tokens = await oidc.exchange_code(code=code, code_verifier=transaction["code_verifier"])
        claims = await oidc.verify_id_token(tokens["id_token"], nonce=transaction["nonce"])
    except (OIDCError, KeyError) as exc:
        raise Problem("unauthenticated", "Authentication failed.") from exc

    identity = await resolve_identity(
        database, app_settings.OIDC_ISSUER.rstrip("/"), str(claims["sub"]), settings=app_settings
    )
    if identity is None:
        raise Problem("forbidden", "Subject is not provisioned for this deployment.")

    token, _csrf = await create_session(database, identity=identity, settings=app_settings)
    response = RedirectResponse(transaction["return_to"], status_code=303)
    response.set_cookie(
        app_settings.cookie_name(),
        token,
        max_age=app_settings.SESSION_ABSOLUTE_SECONDS,
        httponly=True,
        secure=app_settings.cookie_secure(),
        samesite="lax",
        path="/",
    )
    response.delete_cookie(AUTH_TX_COOKIE, path="/")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/auth/session")
async def auth_session(auth: AuthContext = Depends(authenticate)):
    """Current actor, explicitly authorized projects/roles, expiry and CSRF token."""
    user = auth.user
    body = {
        "actor_id": user.user_id,
        "organization_id": user.organization_id,
        "org_role": user.org_role,
        "projects": [
            {"project_id": project_id, "roles": sorted(roles)}
            for project_id, roles in sorted(user.project_roles.items())
        ],
        "expires_at": user.session_expires_at,
        "csrf_token": user.csrf_token,
        "principal": auth.principal_kind,
    }
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


@router.post("/auth/logout", status_code=204)
async def auth_logout(
    request: Request,
    auth: AuthContext = Depends(authenticate),
    _idempotency_key: str = Depends(verify_idempotency_key),
):
    app_settings: Settings = request.app.state.settings
    if auth.principal_kind == "api_key":
        raise Problem("forbidden", "Machine API keys cannot use the browser logout route.")
    if auth.session is not None:
        database: Database = request.app.state.db
        await revoke_session(database, auth.session)
    response = Response(status_code=204)
    response.delete_cookie(app_settings.cookie_name(), path="/")
    response.headers["Cache-Control"] = "no-store"
    return response


# --------------------------------------------------------------------------
# Loopback synthetic IdP (mounted only when explicitly enabled outside prod)
# --------------------------------------------------------------------------
def _idp(request: Request) -> LocalSyntheticIdP:
    provider = getattr(request.app.state, "local_idp", None)
    if provider is None:
        raise Problem("not_found", "Not found.")
    return provider


@local_idp_router.get("/.well-known/openid-configuration")
async def local_idp_metadata(request: Request):
    return JSONResponse(_idp(request).metadata(), headers={"Cache-Control": "no-store"})


@local_idp_router.get("/jwks")
async def local_idp_jwks(request: Request):
    return JSONResponse(_idp(request).jwks(), headers={"Cache-Control": "no-store"})


@local_idp_router.get("/authorize")
async def local_idp_authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
    response_type: str = "code",
    code_challenge_method: str = "S256",
    login_hint: str = "skb-dev-analyst",
    scope: str = "openid",
):
    provider = _idp(request)
    if response_type != "code" or code_challenge_method != "S256":
        raise Problem("invalid", "Unsupported authorization request.")
    if login_hint not in LOCAL_IDP_SUBJECTS:
        raise Problem("forbidden", "Subject is not provisioned for the synthetic identity provider.")
    try:
        code = provider.issue_code(
            subject=login_hint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            nonce=nonce,
            code_challenge=code_challenge,
        )
    except OIDCError as exc:
        raise Problem("invalid", "Authorization request rejected.") from exc
    location = f"{redirect_uri}?{urlencode({'code': code, 'state': state})}"
    response = RedirectResponse(location, status_code=302)
    response.headers["Cache-Control"] = "no-store"
    return response


@local_idp_router.post("/token")
async def local_idp_token(request: Request):
    provider = _idp(request)
    raw = (await request.body()).decode("utf-8", "replace")
    form = {key: values[0] for key, values in parse_qs(raw).items()}
    try:
        tokens = provider.exchange(
            code=str(form.get("code", "")),
            code_verifier=str(form.get("code_verifier", "")),
            client_id=str(form.get("client_id", "")),
            client_secret=str(form.get("client_secret", "")),
            redirect_uri=str(form.get("redirect_uri", "")),
        )
    except OIDCError as exc:
        raise Problem("unauthenticated", "Token exchange failed.") from exc
    return JSONResponse(tokens, headers={"Cache-Control": "no-store"})
