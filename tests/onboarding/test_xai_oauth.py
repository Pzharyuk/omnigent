"""xAI device-code OAuth used by Settings → Credentials → Connect Grok."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from omnigent.onboarding.xai_oauth import (
    XAI_CLIENT_ID,
    XAI_ISSUER,
    build_grok_auth_json,
    email_from_access_token,
    normalize_grok_auth_json,
    request_device_code,
    request_tokens,
)


def _jwt(payload: dict) -> str:
    import base64

    raw = json.dumps(payload, separators=(",", ":")).encode()
    return "hdr." + base64.urlsafe_b64encode(raw).decode().rstrip("=") + ".sig"


def test_email_from_access_token_reads_jwt_email() -> None:
    token = _jwt({"email": "alice@x.ai", "sub": "u1"})
    assert email_from_access_token(token) == "alice@x.ai"


def test_email_from_access_token_falls_back() -> None:
    assert email_from_access_token("not-a-jwt") == "grok"


def test_build_grok_auth_json_uses_cli_scope_key() -> None:
    blob = build_grok_auth_json(
        access_token="tok",
        refresh_token="ref",
        expires_in=3600,
        email="alice@x.ai",
        now=1_700_000_000,
    )
    data = json.loads(blob)
    key = f"{XAI_ISSUER}::{XAI_CLIENT_ID}"
    assert key in data
    entry = data[key]
    assert entry["key"] == "tok"
    assert entry["refresh_token"] == "ref"
    assert entry["auth_mode"] == "oidc"
    assert entry["email"] == "alice@x.ai"
    assert entry["oidc_issuer"] == XAI_ISSUER
    assert entry["oidc_client_id"] == XAI_CLIENT_ID
    assert entry["create_time"] == "2023-11-14T22:13:20.000000Z"
    assert entry["expires_at"] == "2023-11-14T23:13:20.000000Z"


def test_normalize_grok_auth_json_converts_unix_timestamps() -> None:
    key = f"{XAI_ISSUER}::{XAI_CLIENT_ID}"
    raw = json.dumps(
        {
            key: {
                "key": "tok",
                "create_time": 1_700_000_000,
                "expires_at": 1_700_003_600,
            }
        }
    )
    data = json.loads(normalize_grok_auth_json(raw))
    assert data[key]["create_time"] == "2023-11-14T22:13:20.000000Z"
    assert data[key]["expires_at"] == "2023-11-14T23:13:20.000000Z"


def test_normalize_grok_auth_json_leaves_rfc3339_and_non_json() -> None:
    rfc = '{"k":{"expires_at":"2026-09-13T01:38:00.909413Z"}}'
    assert normalize_grok_auth_json(rfc) == rfc
    assert normalize_grok_auth_json("not-json") == "not-json"


@pytest.mark.asyncio
async def test_request_device_code_posts_public_client() -> None:
    with respx.mock(assert_all_called=True) as router:
        router.post("https://auth.x.ai/oauth2/device/code").mock(
            return_value=httpx.Response(
                200,
                json={
                    "device_code": "dev-1",
                    "user_code": "ABCD-1234",
                    "verification_uri": "https://auth.x.ai/device",
                    "verification_uri_complete": "https://auth.x.ai/device?user_code=ABCD-1234",
                    "expires_in": 600,
                    "interval": 5,
                },
            )
        )
        started = await request_device_code()
    assert started.device_code == "dev-1"
    assert started.user_code == "ABCD-1234"
    assert started.verification_uri == "https://auth.x.ai/device"
    assert started.interval == 5


@pytest.mark.asyncio
async def test_request_tokens_pending() -> None:
    with respx.mock(assert_all_called=True) as router:
        router.post("https://auth.x.ai/oauth2/token").mock(
            return_value=httpx.Response(400, json={"error": "authorization_pending"})
        )
        status, payload = await request_tokens("dev-1")
    assert status == "pending"
    assert payload is None


@pytest.mark.asyncio
async def test_request_tokens_complete() -> None:
    with respx.mock(assert_all_called=True) as router:
        router.post("https://auth.x.ai/oauth2/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "atk",
                    "refresh_token": "rtk",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            )
        )
        status, payload = await request_tokens("dev-1")
    assert status == "complete"
    assert payload is not None
    assert payload.access_token == "atk"
    assert payload.refresh_token == "rtk"
    assert payload.expires_in == 3600


@pytest.mark.asyncio
async def test_request_tokens_denied() -> None:
    with respx.mock(assert_all_called=True) as router:
        router.post("https://auth.x.ai/oauth2/token").mock(
            return_value=httpx.Response(400, json={"error": "access_denied"})
        )
        status, payload = await request_tokens("dev-1")
    assert status == "denied"
    assert payload is None
