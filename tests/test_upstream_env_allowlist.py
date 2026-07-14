"""
Upstream MCP credential lookup is restricted to an explicit allowlist.

An MCP server may only reference env-var names listed in
MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS. Default deny: with no allowlist set,
authenticated upstream configuration is rejected. Interlock-internal
secrets (DATABASE_URL, ADMIN_TOKEN, ...) are never allowed, even when
allowlisted. Validation runs at registration and again before a call.

Run: python -m pytest tests/test_upstream_env_allowlist.py -q
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("MCP_REGISTRY_ALLOWED_HOSTS", "safe.example")
TEST_DB = tempfile.mktemp(suffix="_upstream_allowlist.db")
os.environ.setdefault("FIREWALL_DB_PATH", TEST_DB)

from core import db  # noqa: E402
from core import mcp_gateway  # noqa: E402
import proxy  # noqa: E402

ALLOWLIST_VAR = "MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS"

READ_TOOL = {
    "name": "read_file",
    "description": "Read a document.",
    "inputSchema": {
        "type": "object",
        "properties": {"doc_id": {"type": "string"}},
        "required": ["doc_id"],
    },
}

READ_TOOL_METADATA = {
    "effects": ["read"],
    "side_effect": "read_only",
    "data_classes": ["user_content"],
    "externality": "internal",
    "verification_level": "interlock_meta",
    "confidence": 0.95,
    "warnings": [],
}


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch):
    prior_db_path = db.DB_PATH
    db.DB_PATH = TEST_DB
    db.init_db()
    proxy._key_record_cache.clear()
    monkeypatch.delenv(ALLOWLIST_VAR, raising=False)
    yield
    db.DB_PATH = prior_db_path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(TEST_DB + suffix)
        except OSError:
            pass


@pytest.fixture()
def client():
    return TestClient(proxy.app)


def bearer_config(token_env):
    return {
        "url": "http://safe.example/mcp",
        "description": "Upstream allowlist test server",
        "allowed_tools": ["read_file"],
        "blocked_tools": [],
        "rate_limit": 10,
        "auth_type": "bearer",
        "auth_token_env": token_env,
    }


def test_default_deny_without_allowlist():
    result = mcp_gateway.register_mcp_server(
        "_allowlist_default_deny", bearer_config("SOME_UPSTREAM_TOKEN")
    )
    assert result["ok"] is False
    assert result["error"] == "invalid_upstream_auth_config"
    assert ALLOWLIST_VAR in result["message"]
    assert db.lookup_mcp_server("_allowlist_default_deny") is None


def test_http_registration_rejects_unallowlisted_env_var(client):
    admin_key = db.generate_key("developer", label="allowlist-admin", scopes=["admin"])[
        "raw_key"
    ]
    response = client.post(
        "/mcp/servers",
        headers={"x-api-key": admin_key},
        json={
            "server_id": "_allowlist_http_deny",
            "url": "http://safe.example/mcp",
            "allowed_tools": ["read_file"],
            "auth_type": "bearer",
            "auth_token_env": "SOME_UPSTREAM_TOKEN",
        },
    )
    assert response.status_code == 400, response.text
    assert db.lookup_mcp_server("_allowlist_http_deny") is None


def test_allowlisted_env_var_is_accepted(monkeypatch):
    monkeypatch.setenv(ALLOWLIST_VAR, "MCP_UPSTREAM_TOKEN_A, MCP_UPSTREAM_TOKEN_B")
    result = mcp_gateway.register_mcp_server(
        "_allowlist_accepted", bearer_config("MCP_UPSTREAM_TOKEN_A")
    )
    try:
        assert result["ok"] is True, result
    finally:
        db.unregister_mcp_server("_allowlist_accepted")


@pytest.mark.parametrize("forbidden", ["DATABASE_URL", "ADMIN_TOKEN"])
def test_internal_secrets_rejected_even_when_allowlisted(monkeypatch, forbidden):
    monkeypatch.setenv(ALLOWLIST_VAR, forbidden)
    result = mcp_gateway.register_mcp_server(
        f"_allowlist_forbidden_{forbidden.lower()}", bearer_config(forbidden)
    )
    assert result["ok"] is False
    assert result["error"] == "invalid_upstream_auth_config"
    assert db.lookup_mcp_server(f"_allowlist_forbidden_{forbidden.lower()}") is None


def test_call_time_revalidation_fails_closed_without_leaking_secret(
    client, monkeypatch
):
    """A server registered while its env var was allowlisted must fail
    closed at call time once the allowlist no longer permits it — with no
    upstream request and no secret material in the response."""
    server_id = "_allowlist_call_revalidation"
    secret_value = "sk-upstream-secret-value-do-not-leak"
    monkeypatch.setenv(ALLOWLIST_VAR, "MCP_UPSTREAM_TOKEN_A")
    monkeypatch.setenv("MCP_UPSTREAM_TOKEN_A", secret_value)

    result = mcp_gateway.register_mcp_server(
        server_id, bearer_config("MCP_UPSTREAM_TOKEN_A")
    )
    assert result["ok"] is True, result
    db.verify_mcp_server(server_id)
    db.upsert_mcp_tool_metadata(server_id, READ_TOOL, READ_TOOL_METADATA)

    call_key = db.generate_key(
        "developer", label="allowlist-caller", scopes=["mcp.call"]
    )["raw_key"]

    monkeypatch.setenv(ALLOWLIST_VAR, "")  # allowlist emptied after registration

    try:
        with patch("core.mcp_gateway.httpx.AsyncClient") as upstream:
            response = client.post(
                "/mcp/call",
                headers={"x-api-key": call_key},
                json={
                    "server_id": server_id,
                    "tool_name": "read_file",
                    "arguments": {"doc_id": "d-1"},
                },
            )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["ok"] is False
        assert payload["error"] == "upstream_auth_unavailable"
        upstream.assert_not_called()
        assert secret_value not in response.text
    finally:
        db.unregister_mcp_server(server_id)


def test_rejection_message_names_var_without_leaking_value(monkeypatch):
    monkeypatch.setenv("SOME_UPSTREAM_TOKEN", "secret-token-value")
    result = mcp_gateway.register_mcp_server(
        "_allowlist_no_leak", bearer_config("SOME_UPSTREAM_TOKEN")
    )
    assert result["ok"] is False
    assert "SOME_UPSTREAM_TOKEN" in result["message"]
    assert "secret-token-value" not in result["message"]
