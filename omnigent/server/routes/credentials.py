"""
Per-user external-service credential routes (Settings → Credentials).

``GET /v1/credentials`` lists the caller's connected credentials (masked —
never the token). ``GET /v1/credentials/github/repos`` lists the caller's
GitHub repos (requires a stored, decrypted token).
``POST /v1/credentials/github/connect`` starts the GitHub OAuth authorize
flow; ``GET /auth/github/credential-callback`` finishes it (code → token
exchange, identity fetch, encrypted upsert);
``DELETE /v1/credentials/github`` disconnects.

The GitHub OAuth App is configured via
``OMNIGENT_GITHUB_CREDENTIAL_CLIENT_ID`` /
``OMNIGENT_GITHUB_CREDENTIAL_CLIENT_SECRET``. The feature also requires the
credential store's encryption key; with either missing, the connect route
returns 409 ``credentials_disabled`` and the rest of the app is unaffected.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from omnigent.errors import ErrorCode, OmnigentError
from omnigent.server.auth import AuthProvider
from omnigent.server.routes._auth_helpers import require_user
from omnigent.stores.user_credential_store import (
    CredentialStore,
    credential_encryption_enabled,
)

logger = logging.getLogger(__name__)

_CLIENT_ID_ENV = "OMNIGENT_GITHUB_CREDENTIAL_CLIENT_ID"
_CLIENT_SECRET_ENV = "OMNIGENT_GITHUB_CREDENTIAL_CLIENT_SECRET"
_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_TOKEN_URL = "https://github.com/login/oauth/access_token"
_USER_URL = "https://api.github.com/user"
_SCOPES = "repo"
_STATE_TTL_S = 600
# Single-user deployments (no auth provider) store under this sentinel.
_LOCAL_USER = "local"
_SETTINGS_PATH = "/settings/credentials"


@dataclass
class _PendingGrok:
    """In-flight xAI device-code login. Replica count is 1, so memory is enough."""

    device_code: str
    expires_at: float


_pending_grok: dict[str, _PendingGrok] = {}


def _client_id() -> str:
    return os.environ.get(_CLIENT_ID_ENV, "").strip()


def _client_secret() -> str:
    return os.environ.get(_CLIENT_SECRET_ENV, "").strip()


def _feature_enabled() -> bool:
    return bool(_client_id()) and bool(_client_secret()) and credential_encryption_enabled()


def _state_key() -> bytes:
    # Reuse the credential encryption key as the state-HMAC key; the feature
    # gate guarantees it exists whenever a flow can start.
    return os.environ.get("OMNIGENT_CREDENTIAL_ENCRYPTION_KEY", "").strip().encode()


def _mint_state(user_id: str) -> str:
    ts = str(int(time.time()))
    mac = hmac.new(_state_key(), f"{user_id}:{ts}".encode(), hashlib.sha256).hexdigest()
    raw = f"{user_id}:{ts}:{mac}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _check_state(state: str) -> str | None:
    """Validate a callback state; returns the user id, or ``None``."""
    try:
        user_id, ts, mac = base64.urlsafe_b64decode(state.encode()).decode().rsplit(":", 2)
    except (ValueError, UnicodeDecodeError):
        return None
    expected = hmac.new(_state_key(), f"{user_id}:{ts}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return None
    if time.time() - int(ts) > _STATE_TTL_S:
        return None
    return user_id


async def _exchange_code(code: str) -> dict[str, Any]:
    """Exchange the authorize code for a token payload (raises on HTTP error)."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            _TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": _client_id(),
                "client_secret": _client_secret(),
                "code": code,
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _fetch_github_user(token: str) -> dict[str, Any]:
    """Fetch the token owner's GitHub profile (raises on HTTP error)."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            _USER_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _fetch_github_repos(token: str) -> list[dict[str, Any]]:
    """Fetch repos the token can access — owner, collaborator, and org member
    affiliations, most-recently-pushed first, capped at GitHub's 100/page
    maximum (raises on HTTP error)."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"{_USER_URL}/repos",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            params={
                "affiliation": "owner,collaborator,organization_member",
                "sort": "pushed",
                "per_page": 100,
            },
        )
        resp.raise_for_status()
        return resp.json()


def create_credentials_router(
    credential_store: CredentialStore,
    auth_provider: AuthProvider | None = None,
) -> APIRouter:
    """Build the credentials router (mounted at the app root)."""
    router = APIRouter()

    def _user(request: Request) -> str:
        user_id = require_user(request, auth_provider)
        return user_id if user_id is not None else _LOCAL_USER

    @router.get("/v1/credentials")
    async def list_credentials(request: Request) -> dict[str, Any]:
        """The caller's connected credentials — masked, never the token."""
        user_id = _user(request)
        creds = []
        for provider in ("github", "grok"):
            cred = credential_store.get(user_id, provider)
            if cred is not None:
                creds.append(
                    {
                        "provider": cred.provider,
                        "login": cred.login,
                        "scopes": cred.scopes,
                        "connected_at": cred.updated_at,
                    }
                )
        return {
            "credentials": creds,
            "enabled": _feature_enabled(),
            "grok_enabled": credential_encryption_enabled(),
        }

    @router.get("/v1/credentials/github/repos")
    async def list_github_repos(request: Request) -> dict[str, Any]:
        """The caller's GitHub repos — owner, collaborator, and org member."""
        if not _feature_enabled():
            raise OmnigentError("credentials_disabled", code=ErrorCode.CONFLICT)
        user_id = _user(request)
        cred = credential_store.get(user_id, "github")
        if cred is None:
            raise OmnigentError("github_not_connected", code=ErrorCode.CONFLICT)
        token = credential_store.decrypt_token(cred)
        if token is None:
            raise OmnigentError("github_not_connected", code=ErrorCode.CONFLICT)
        try:
            repos = await _fetch_github_repos(token)
        except httpx.HTTPError as exc:
            logger.warning("github repo listing failed for %s", user_id, exc_info=True)
            raise OmnigentError(
                "github_repos_fetch_failed", code=ErrorCode.INTERNAL_ERROR
            ) from exc
        return {
            "repos": [
                {
                    "full_name": r["full_name"],
                    "clone_url": r["clone_url"],
                    "default_branch": r["default_branch"],
                    "private": r["private"],
                }
                for r in repos
            ]
        }

    @router.post("/v1/credentials/github/connect")
    async def connect_github(request: Request) -> dict[str, str]:
        """Start the OAuth flow; the client navigates to ``authorize_url``."""
        user_id = _user(request)
        if not _feature_enabled():
            raise OmnigentError(
                "credentials_disabled",
                code=ErrorCode.CONFLICT,
            )
        query = urlencode(
            {
                "client_id": _client_id(),
                "scope": _SCOPES,
                "state": _mint_state(user_id),
            }
        )
        return {"authorize_url": f"{_AUTHORIZE_URL}?{query}"}

    @router.get("/auth/github/credential-callback")
    async def credential_callback(
        code: str = "", state: str = "", error: str = ""
    ) -> RedirectResponse:
        """Finish the OAuth flow and land back on Settings → Credentials."""
        if error:
            return RedirectResponse(f"{_SETTINGS_PATH}?error=github_denied", status_code=302)
        if not _feature_enabled():
            return RedirectResponse(f"{_SETTINGS_PATH}?error=disabled", status_code=302)
        user_id = _check_state(state) if state else None
        if user_id is None or not code:
            return RedirectResponse(f"{_SETTINGS_PATH}?error=state_mismatch", status_code=302)
        try:
            payload = await _exchange_code(code)
            token = str(payload.get("access_token") or "")
            if not token:
                raise ValueError("no access_token in exchange response")
            profile = await _fetch_github_user(token)
        except (httpx.HTTPError, ValueError, KeyError):
            logger.warning("github credential exchange failed for %s", user_id, exc_info=True)
            return RedirectResponse(f"{_SETTINGS_PATH}?error=exchange_failed", status_code=302)
        credential_store.upsert(
            user_id,
            "github",
            token=token,
            login=str(profile.get("login") or "unknown"),
            scopes=str(payload.get("scope") or _SCOPES),
        )
        return RedirectResponse(f"{_SETTINGS_PATH}?connected=github", status_code=302)

    @router.delete("/v1/credentials/github")
    async def disconnect_github(request: Request) -> dict[str, bool]:
        """Remove the caller's GitHub credential."""
        user_id = _user(request)
        credential_store.delete(user_id, "github")
        return {"ok": True}

    @router.post("/v1/credentials/grok/connect")
    async def connect_grok(request: Request) -> dict[str, Any]:
        """Start xAI device-code login; the client shows the user code."""
        user_id = _user(request)
        if not credential_encryption_enabled():
            raise OmnigentError("credentials_disabled", code=ErrorCode.CONFLICT)
        from omnigent.onboarding.xai_oauth import request_device_code

        try:
            started = await request_device_code()
        except httpx.HTTPError as exc:
            logger.warning("xAI device-code start failed for %s", user_id, exc_info=True)
            raise OmnigentError("grok_connect_failed", code=ErrorCode.INTERNAL_ERROR) from exc
        _pending_grok[user_id] = _PendingGrok(
            device_code=started.device_code,
            expires_at=time.time() + started.expires_in,
        )
        return {
            "user_code": started.user_code,
            "verification_uri": started.verification_uri,
            "verification_uri_complete": started.verification_uri_complete,
            "expires_in": started.expires_in,
            "interval": started.interval,
        }

    @router.post("/v1/credentials/grok/poll")
    async def poll_grok(request: Request) -> dict[str, Any]:
        """One poll of the in-flight Grok device-code login."""
        user_id = _user(request)
        if not credential_encryption_enabled():
            raise OmnigentError("credentials_disabled", code=ErrorCode.CONFLICT)
        pending = _pending_grok.get(user_id)
        if pending is None or time.time() > pending.expires_at:
            _pending_grok.pop(user_id, None)
            return {"status": "expired"}
        from omnigent.onboarding.xai_oauth import (
            build_grok_auth_json,
            email_from_access_token,
            request_tokens,
        )

        status, payload = await request_tokens(pending.device_code)
        if status == "pending":
            return {"status": "pending"}
        _pending_grok.pop(user_id, None)
        if status != "complete" or payload is None:
            return {"status": status}
        email = email_from_access_token(payload.access_token)
        blob = build_grok_auth_json(
            access_token=payload.access_token,
            refresh_token=payload.refresh_token,
            expires_in=payload.expires_in,
            email=email,
        )
        credential_store.upsert(
            user_id,
            "grok",
            token=blob,
            login=email,
            scopes="openid profile email offline_access grok-cli:access api:access",
        )
        return {"status": "connected", "login": email}

    @router.delete("/v1/credentials/grok")
    async def disconnect_grok(request: Request) -> dict[str, bool]:
        """Remove the caller's Grok session."""
        user_id = _user(request)
        _pending_grok.pop(user_id, None)
        credential_store.delete(user_id, "grok")
        return {"ok": True}

    return router
