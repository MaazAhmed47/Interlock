"""Fail-closed configuration tests for the experimental EMA resource server."""

from __future__ import annotations

import base64
import json

import pytest


def _secret(byte: bytes) -> str:
    return base64.urlsafe_b64encode(byte * 32).decode("ascii").rstrip("=")


def _ring(key_id: str, byte: bytes) -> str:
    return json.dumps(
        {
            "active_key_id": key_id,
            "keys": {key_id: _secret(byte)},
        }
    )


def valid_raw_config() -> dict[str, str]:
    return {
        "INTERLOCK_EXPERIMENTAL_EMA_ENABLED": "true",
        "INTERLOCK_EMA_RESOURCE_URI": "https://interlock.example/experimental/mcp",
        "INTERLOCK_EMA_ISSUER_METADATA": json.dumps(
            {
                "issuer": "https://issuer.example",
                "jwks_uri": "https://issuer.example/.well-known/jwks.json",
            }
        ),
        "INTERLOCK_EMA_SERVER_ID": "trusted-filesystem",
        "INTERLOCK_EMA_SERVICE_PRINCIPAL_ID": "interlock-gateway-prod",
        "INTERLOCK_EMA_DOWNSTREAM_SERVICE_PRINCIPAL_ID": "mcp-files-service",
        "INTERLOCK_EMA_ROLE": "readonly_agent",
        "INTERLOCK_EMA_ALLOWED_CLIENT_IDS": json.dumps(
            ["https://client.example/oauth/client.json"]
        ),
        "INTERLOCK_EMA_TOOL_SCOPES": json.dumps(
            {
                "trusted-filesystem": {
                    "read_file": ["files:read"],
                    "list_directory": ["files:list"],
                }
            }
        ),
        "INTERLOCK_EMA_ALLOWED_ORIGINS": json.dumps(["https://client.example"]),
        "INTERLOCK_EMA_OAUTH_CLIENT_HMAC_KEYS": _ring("client-2026-07", b"c"),
        "INTERLOCK_EMA_DELEGATED_SUBJECT_HMAC_KEYS": _ring("subject-2026-07", b"s"),
        "INTERLOCK_EMA_TOKEN_HMAC_KEYS": _ring("token-2026-07", b"t"),
    }


def test_disabled_configuration_registers_no_profile():
    from core.ema_config import load_experimental_ema_settings

    assert (
        load_experimental_ema_settings({"INTERLOCK_EXPERIMENTAL_EMA_ENABLED": "false"})
        is None
    )


@pytest.mark.parametrize(
    "missing",
    [
        "INTERLOCK_EMA_RESOURCE_URI",
        "INTERLOCK_EMA_ISSUER_METADATA",
        "INTERLOCK_EMA_SERVER_ID",
        "INTERLOCK_EMA_SERVICE_PRINCIPAL_ID",
        "INTERLOCK_EMA_ROLE",
        "INTERLOCK_EMA_ALLOWED_CLIENT_IDS",
        "INTERLOCK_EMA_TOOL_SCOPES",
        "INTERLOCK_EMA_OAUTH_CLIENT_HMAC_KEYS",
        "INTERLOCK_EMA_DELEGATED_SUBJECT_HMAC_KEYS",
        "INTERLOCK_EMA_TOKEN_HMAC_KEYS",
    ],
)
def test_enabled_configuration_requires_every_security_field(missing):
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw.pop(missing)
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)


@pytest.mark.parametrize(
    "field,value",
    [
        ("INTERLOCK_EMA_RESOURCE_URI", "http://interlock.example/experimental/mcp"),
        ("INTERLOCK_EMA_RESOURCE_URI", "https://interlock.example/mcp?tenant=x"),
        ("INTERLOCK_EMA_RESOURCE_URI", "https://interlock.example/mcp#fragment"),
        ("INTERLOCK_EMA_RESOURCE_URI", "https://INTERLOCK.example/experimental/mcp"),
        (
            "INTERLOCK_EMA_RESOURCE_URI",
            "https://interlock.example:443/experimental/mcp",
        ),
        (
            "INTERLOCK_EMA_RESOURCE_URI",
            "https://interlock.example/experimental/../mcp",
        ),
        (
            "INTERLOCK_EMA_RESOURCE_URI",
            "https://interlock.example/experimental/%6dcp",
        ),
        (
            "INTERLOCK_EMA_ISSUER_METADATA",
            '{"issuer":"http://issuer.example","jwks_uri":"https://issuer.example/jwks"}',
        ),
        (
            "INTERLOCK_EMA_ISSUER_METADATA",
            '{"issuer":"https://issuer.example","jwks_uri":"http://issuer.example/jwks"}',
        ),
    ],
)
def test_resource_issuer_and_jwks_are_exact_https_uris(field, value):
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw[field] = value
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)


@pytest.mark.parametrize(
    "field,value",
    [
        ("INTERLOCK_EMA_ALLOWED_CLIENT_IDS", '["*"]'),
        (
            "INTERLOCK_EMA_TOOL_SCOPES",
            '{"trusted-filesystem":{"*":["files:read"]}}',
        ),
        (
            "INTERLOCK_EMA_TOOL_SCOPES",
            '{"*":{"read_file":["files:read"]}}',
        ),
        (
            "INTERLOCK_EMA_TOOL_SCOPES",
            '{"trusted-filesystem":{"read_file":["*"]}}',
        ),
        (
            "INTERLOCK_EMA_TOOL_SCOPES",
            '{"trusted-filesystem":{"read_file":[]}}',
        ),
    ],
)
def test_wildcard_or_empty_authority_mapping_is_rejected(field, value):
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw[field] = value
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)


def test_only_the_configured_server_may_have_tool_scope_mappings():
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw["INTERLOCK_EMA_TOOL_SCOPES"] = json.dumps(
        {"other-server": {"read_file": ["files:read"]}}
    )
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)


@pytest.mark.parametrize(
    "field",
    [
        "INTERLOCK_EMA_OAUTH_CLIENT_HMAC_KEYS",
        "INTERLOCK_EMA_DELEGATED_SUBJECT_HMAC_KEYS",
        "INTERLOCK_EMA_TOKEN_HMAC_KEYS",
    ],
)
def test_each_hmac_ring_requires_an_active_256_bit_key(field):
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw[field] = json.dumps(
        {
            "active_key_id": "short-key",
            "keys": {"short-key": _secret(b"x")[:20]},
        }
    )
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)


def test_hmac_key_material_cannot_be_reused_across_identity_or_token_rings():
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw["INTERLOCK_EMA_DELEGATED_SUBJECT_HMAC_KEYS"] = _ring("subject-2026-07", b"c")
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)


def test_valid_settings_pin_the_only_profile_and_algorithm():
    from core.ema_config import load_experimental_ema_settings

    settings = load_experimental_ema_settings(valid_raw_config())
    assert settings is not None
    assert settings.profile == "interlock-experimental-ema-jwt-at-v1"
    assert settings.allowed_algorithms == ("RS256",)
    assert settings.resource_path == "/experimental/mcp"
    assert (
        settings.protected_resource_metadata_path
        == "/.well-known/oauth-protected-resource/experimental/mcp"
    )
    assert settings.tool_scopes == {
        ("trusted-filesystem", "list_directory"): frozenset({"files:list"}),
        ("trusted-filesystem", "read_file"): frozenset({"files:read"}),
    }
    assert (
        settings.oauth_client_keys.active_key_id
        != settings.delegated_subject_keys.active_key_id
    )
    assert settings.session_lifetime_seconds > 0
    assert settings.authorization_header_max_bytes == 16 * 1024
    assert settings.json_rpc_body_max_bytes == 256 * 1024
    assert settings.unauthenticated_rate_limit == 20
    assert settings.authenticated_rate_limit == 120
    assert settings.rate_limit_window_seconds == 60
    assert settings.rate_limit_max_keys == 4096


@pytest.mark.parametrize("value", ["0", "1023", "1048577", "not-an-integer"])
def test_json_rpc_body_limit_override_is_bounded(value):
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw["INTERLOCK_EMA_JSON_RPC_BODY_MAX_BYTES"] = value
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)


def test_json_rpc_body_limit_accepts_conservative_bounded_override():
    from core.ema_config import load_experimental_ema_settings

    raw = valid_raw_config()
    raw["INTERLOCK_EMA_JSON_RPC_BODY_MAX_BYTES"] = str(64 * 1024)
    settings = load_experimental_ema_settings(raw)
    assert settings is not None
    assert settings.json_rpc_body_max_bytes == 64 * 1024


@pytest.mark.parametrize(
    "field,value",
    [
        ("INTERLOCK_EMA_UNAUTHENTICATED_RATE_LIMIT", "0"),
        ("INTERLOCK_EMA_UNAUTHENTICATED_RATE_LIMIT", "1001"),
        ("INTERLOCK_EMA_AUTHENTICATED_RATE_LIMIT", "0"),
        ("INTERLOCK_EMA_AUTHENTICATED_RATE_LIMIT", "10001"),
        ("INTERLOCK_EMA_RATE_LIMIT_WINDOW_SECONDS", "0"),
        ("INTERLOCK_EMA_RATE_LIMIT_WINDOW_SECONDS", "3601"),
        ("INTERLOCK_EMA_RATE_LIMIT_MAX_KEYS", "15"),
        ("INTERLOCK_EMA_RATE_LIMIT_MAX_KEYS", "65537"),
    ],
)
def test_rate_limit_configuration_is_bounded(field, value):
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw[field] = value
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)


def test_optional_time_validation_controls_are_bounded_and_consistent():
    from core.ema_config import EMAConfigError, load_experimental_ema_settings

    raw = valid_raw_config()
    raw["INTERLOCK_EMA_MAX_TOKEN_AGE_SECONDS"] = "300"
    settings = load_experimental_ema_settings(raw)
    assert settings is not None
    assert settings.require_iat is True
    assert settings.max_token_age_seconds == 300

    raw["INTERLOCK_EMA_SESSION_LIFETIME_SECONDS"] = "0"
    with pytest.raises(EMAConfigError):
        load_experimental_ema_settings(raw)
