"""
Reviewer/principal identity is derived from the authenticated API key.

Request-body `reviewer` (and chain `role`) are caller-controlled strings and
must never become the recorded identity in hash-chained audit events.

Run: python -m pytest tests/test_reviewer_identity.py -q
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("MCP_REGISTRY_ALLOWED_HOSTS", "safe.example")
TEST_DB = tempfile.mktemp(suffix="_reviewer_identity.db")
os.environ.setdefault("FIREWALL_DB_PATH", TEST_DB)

from core import db  # noqa: E402
import proxy  # noqa: E402

ATTACKER_REVIEWER = "attacker-chosen-reviewer"

READ_TOOL = {
    "name": "read_document",
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
def isolated_db():
    prior_db_path = db.DB_PATH
    db.DB_PATH = TEST_DB
    db.init_db()
    proxy._key_record_cache.clear()
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


@pytest.fixture()
def admin_identity():
    issued = db.generate_key("developer", label="security-reviewer", scopes=["admin"])
    return issued["raw_key"], issued["key_prefix"]


def seed_server(server_id, **extra_config):
    config = {
        "url": "http://safe.example/mcp",
        "description": "Reviewer identity test server",
        "allowed_tools": ["read_document"],
        "blocked_tools": [],
        "rate_limit": 10,
    }
    config.update(extra_config)
    db.register_mcp_server(server_id, config)
    db.upsert_mcp_tool_metadata(server_id, READ_TOOL, READ_TOOL_METADATA)
    return server_id


def latest_audit_row(matched_rule):
    for row in db.list_mcp_audit_logs(50):
        if row.get("matched_rule") == matched_rule:
            return row
    return None


def assert_derived_identity(row, key_prefix):
    assert row is not None
    assert f"key:{key_prefix}" in (row.get("role") or ""), row
    assert row.get("principal_id") == key_prefix, row
    assert ATTACKER_REVIEWER not in (row.get("role") or ""), row


def test_approve_ignores_caller_supplied_reviewer(client, admin_identity):
    raw_key, key_prefix = admin_identity
    server_id = seed_server("_identity_approve")
    try:
        response = client.post(
            f"/mcp/tools/{server_id}/read_document/approve",
            headers={"x-api-key": raw_key},
            json={"reviewer": ATTACKER_REVIEWER, "reason": "baseline ok"},
        )
        assert response.status_code == 200, response.text
        assert_derived_identity(latest_audit_row("tool_baseline_approved"), key_prefix)
    finally:
        db.unregister_mcp_server(server_id)


def test_quarantine_ignores_caller_supplied_reviewer(client, admin_identity):
    raw_key, key_prefix = admin_identity
    server_id = seed_server("_identity_quarantine")
    try:
        response = client.post(
            f"/mcp/tools/{server_id}/read_document/quarantine",
            headers={"x-api-key": raw_key},
            json={"reviewer": ATTACKER_REVIEWER, "reason": "hold for review"},
        )
        assert response.status_code == 200, response.text
        assert_derived_identity(latest_audit_row("operator_quarantine"), key_prefix)
    finally:
        db.unregister_mcp_server(server_id)


def test_server_verification_records_authenticated_identity(client, admin_identity):
    """The verification audit event must record the authenticated key, not
    the hardcoded 'operator' role."""
    raw_key, key_prefix = admin_identity
    server_id = seed_server("_identity_verify")
    try:
        response = client.post(
            f"/mcp/servers/{server_id}/verify",
            headers={"x-api-key": raw_key},
        )
        assert response.status_code == 200, response.text
        row = latest_audit_row("manual_server_verification")
        assert row is not None
        assert row.get("role") != "operator", row
        assert f"key:{key_prefix}" in (row.get("role") or ""), row
        assert row.get("principal_id") == key_prefix, row
    finally:
        db.unregister_mcp_server(server_id)


def test_probe_audit_records_authenticated_identity(client):
    issued = db.generate_key("developer", label="probe-runner", scopes=["mcp.probe"])
    raw_key, key_prefix = issued["raw_key"], issued["key_prefix"]
    server_id = seed_server(
        "_identity_probe",
        environment="non_production",
        probes_enabled=True,
    )
    db.verify_mcp_server(server_id)

    resp = MagicMock()
    resp.status_code = 403
    resp.headers = {}
    resp.json.return_value = {"error": {"message": "Forbidden"}}
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=resp)

    try:
        with patch(
            "core.effective_permission.httpx.AsyncClient",
            return_value=mock_client,
        ):
            response = client.post(
                f"/mcp/servers/{server_id}/probes/run",
                headers={"x-api-key": raw_key},
                json={
                    "tool_name": "read_document",
                    "arguments": {"doc_id": "d-1"},
                    "expected_outcome": "denied",
                    "expected_status_code": 403,
                    "non_production": True,
                    "safety_note": "Identity test probe.",
                },
            )
        assert response.status_code == 200, response.text
        row = latest_audit_row("effective_permission_probe")
        assert row is not None
        assert row.get("principal_id") == key_prefix, row
        assert f"key:{key_prefix}" in (row.get("role") or ""), row
    finally:
        db.unregister_mcp_server(server_id)


def test_chain_analysis_audit_ignores_caller_role(client):
    issued = db.generate_key("developer", label="chain-runner", scopes=["mcp.call"])
    raw_key, key_prefix = issued["raw_key"], issued["key_prefix"]

    response = client.post(
        "/mcp/chains/analyze",
        headers={"x-api-key": raw_key},
        json={
            "steps": [{"tool_name": "read_document", "arguments": {}}],
            "role": ATTACKER_REVIEWER,
            "safety_note": "Identity test chain.",
        },
    )
    assert response.status_code == 200, response.text
    row = latest_audit_row("chain_drift")
    assert row is not None
    assert ATTACKER_REVIEWER not in (row.get("role") or ""), row
    assert f"key:{key_prefix}" in (row.get("role") or ""), row
    assert row.get("principal_id") == key_prefix, row
