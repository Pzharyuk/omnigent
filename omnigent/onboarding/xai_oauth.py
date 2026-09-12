"""xAI device-code OAuth for Grok Build (SuperGrok / X Premium+).

Uses the public Grok CLI OAuth client so the resulting session is a
``~/.grok/auth.json`` blob the grok CLI will accept. Settings → Credentials
runs the RFC 8628 device-code flow in the browser; managed sandboxes get
the session file injected at launch.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)

XAI_ISSUER = "https://auth.x.ai"
XAI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
XAI_SCOPE = "openid profile email offline_access grok-cli:access api:access"
XAI_DEVICE_CODE_URL = f"{XAI_ISSUER}/oauth2/device/code"
XAI_TOKEN_URL = f"{XAI_ISSUER}/oauth2/token"

TokenStatus = Literal["pending", "complete", "denied", "expired", "error"]


@dataclass(frozen=True)
class DeviceCodeStart:
    """One RFC 8628 device-authorization response."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None
    expires_in: int
    interval: int


@dataclass(frozen=True)
class TokenPayload:
    """Access + refresh tokens from the device or refresh grant."""

    access_token: str
    refresh_token: str
    expires_in: int


def _jwt_payload(access_token: str) -> dict[str, object]:
    """Decode a JWT payload without verifying the signature."""
    try:
        payload = access_token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()))
        return data if isinstance(data, dict) else {}
    except (IndexError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def email_from_access_token(access_token: str) -> str:
    """Best-effort email from a JWT access token; ``grok`` when unknown."""
    data = _jwt_payload(access_token)
    email = data.get("email") or data.get("preferred_username")
    if isinstance(email, str) and email.strip():
        return email.strip()
    return "grok"


def _identity_from_access_token(access_token: str) -> dict[str, str]:
    """CLI-required identity fields from the access-token JWT.

    Grok 1.0.30's ``auth.json`` deserializer requires ``user_id`` (the
    token ``sub``). ``principal_id`` / ``principal_type`` / ``team_id``
    are copied when present so the blob matches ``grok login``.
    """
    data = _jwt_payload(access_token)
    out: dict[str, str] = {}
    sub = data.get("sub")
    if isinstance(sub, str) and sub.strip():
        out["user_id"] = sub.strip()
    for field in ("principal_id", "principal_type", "team_id"):
        value = data.get(field)
        if isinstance(value, str) and value.strip():
            out[field] = value.strip()
    return out


def _rfc3339(ts: int | float | str) -> str:
    """Format a unix timestamp the way grok CLI 1.0+ deserializes ``auth.json``.

    Grok rejects integer ``expires_at``/``create_time`` (``invalid type:
    integer, expected an RFC 3339 formatted date and time string``) and
    then reports ACP ``Authentication required``.
    """
    if isinstance(ts, str) and "T" in ts:
        return ts
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def normalize_grok_auth_json(raw: str) -> str:
    """Rewrite unix ``create_time``/``expires_at`` to RFC 3339 strings.

    Already-correct blobs and non-JSON values are returned unchanged so
    a stored session from before this fix still injects into sandboxes.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    if not isinstance(data, dict):
        return raw
    changed = False
    for entry in data.values():
        if not isinstance(entry, dict):
            continue
        for field in ("create_time", "expires_at"):
            value = entry.get(field)
            if isinstance(value, (int, float)):
                entry[field] = _rfc3339(value)
                changed = True
        if not entry.get("user_id"):
            token = entry.get("key")
            if isinstance(token, str):
                identity = _identity_from_access_token(token)
                if identity:
                    entry.update(identity)
                    changed = True
            if not entry.get("user_id"):
                email = entry.get("email")
                if isinstance(email, str) and email.strip():
                    entry["user_id"] = email.strip()
                    changed = True
    if not changed:
        return raw
    return json.dumps(data, separators=(",", ":"))


def build_grok_auth_json(
    *,
    access_token: str,
    refresh_token: str,
    expires_in: int,
    email: str,
    now: int | None = None,
) -> str:
    """Serialize a grok CLI ``auth.json`` for the public Grok CLI client."""
    minted = int(now if now is not None else time.time())
    key = f"{XAI_ISSUER}::{XAI_CLIENT_ID}"
    entry: dict[str, str] = {
        "key": access_token,
        "auth_mode": "oidc",
        "create_time": _rfc3339(minted),
        "expires_at": _rfc3339(minted + int(expires_in)),
        "refresh_token": refresh_token,
        "oidc_issuer": XAI_ISSUER,
        "oidc_client_id": XAI_CLIENT_ID,
        "email": email,
        "user_id": email,
    }
    entry.update(_identity_from_access_token(access_token))
    if not entry.get("user_id"):
        entry["user_id"] = email
    return json.dumps({key: entry}, separators=(",", ":"))


async def request_device_code() -> DeviceCodeStart:
    """Start an xAI device-code login (RFC 8628)."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            XAI_DEVICE_CODE_URL,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            content=urlencode(
                {
                    "client_id": XAI_CLIENT_ID,
                    "scope": XAI_SCOPE,
                }
            ),
        )
        resp.raise_for_status()
        data = resp.json()
    interval = data.get("interval")
    complete = data.get("verification_uri_complete")
    return DeviceCodeStart(
        device_code=str(data["device_code"]),
        user_code=str(data["user_code"]),
        verification_uri=str(data["verification_uri"]),
        verification_uri_complete=str(complete) if complete else None,
        expires_in=int(data["expires_in"]),
        interval=int(interval) if isinstance(interval, (int, float)) and interval > 0 else 5,
    )


async def request_tokens(device_code: str) -> tuple[TokenStatus, TokenPayload | None]:
    """One poll of the device-code token endpoint."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            XAI_TOKEN_URL,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            content=urlencode(
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": XAI_CLIENT_ID,
                    "device_code": device_code,
                }
            ),
        )
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return "error", None
    if resp.is_success:
        access = str(data.get("access_token") or "")
        refresh = str(data.get("refresh_token") or "")
        if not access or not refresh:
            return "error", None
        expires_in = data.get("expires_in")
        return "complete", TokenPayload(
            access_token=access,
            refresh_token=refresh,
            expires_in=int(expires_in) if isinstance(expires_in, (int, float)) else 3600,
        )
    error = str(data.get("error") or "")
    if error == "authorization_pending":
        return "pending", None
    if error == "slow_down":
        return "pending", None
    if error in {"access_denied", "authorization_denied"}:
        return "denied", None
    if error == "expired_token":
        return "expired", None
    logger.warning("xAI device token poll failed: %s", error or resp.status_code)
    return "error", None
