"""Runtime tests for response/data-exposure drift through /mcp/call.

Run: python3 -m pytest tests/test_response_drift_runtime.py -q -s
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.db as db
from core import receipt as receipt_builder
from core.mcp_gateway import proxy_mcp_tool_call

_tmp_db = tempfile.mktemp(suffix="_response_drift_runtime_test.db")


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch):
    # The registry allowlist rejects unknown external hosts; permit the
    # fixture host explicitly, the same way test_hosted_safety.py does.
    monkeypatch.setenv("MCP_REGISTRY_ALLOWED_HOSTS", "safe.example")
    db.DB_PATH = _tmp_db
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_tmp_db + suffix)
        except OSError:
            pass
    db.init_db()
    key = db.generate_key("free", label="response-drift-runtime")
    server_id = "_response_drift_runtime"
    db.register_mcp_server(
        server_id,
        {
            "url": "https://safe.example/mcp",
            "description": "Response drift runtime test",
            "allowed_tools": ["search_contacts"],
            "blocked_tools": [],
            "rate_limit": 60,
        },
    )
    db.verify_mcp_server(server_id)
    db.upsert_mcp_tool_metadata(
        server_id,
        {
            "name": "search_contacts",
            "description": "Search contacts and return a safe summary.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
        {
            "effects": ["read"],
            "side_effect": "read_only",
            "data_classes": ["internal"],
            "externality": "internal",
            "verification_level": "interlock_meta",
            "confidence": 0.95,
            "warnings": [],
        },
    )
    yield {"server_id": server_id, "key": key["raw_key"]}
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_tmp_db + suffix)
        except OSError:
            pass


def mock_client_for_result(result_payload):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"result": result_payload}
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)
    return mock_client


def call_with_result(server_id, result_payload):
    mock_client = mock_client_for_result(result_payload)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=mock_client):
        return asyncio.run(
            proxy_mcp_tool_call(
                server_id,
                "search_contacts",
                {"query": "acme"},
            )
        )


def test_first_clean_response_creates_response_profile_baseline(isolated_db):
    out = call_with_result(
        isolated_db["server_id"],
        {"summary": "3 matching contacts", "count": 3},
    )

    assert out["ok"] is True
    assert out["response_drift"] is None
    profile = db.lookup_mcp_response_profile(
        isolated_db["server_id"], "search_contacts"
    )
    assert profile is not None
    assert profile["profile_hash"].startswith("sha256:")
    assert profile["profile"]["sensitive_classes"] == []
    assert "3 matching contacts" not in json.dumps(profile)


def test_same_response_profile_stays_clean_after_baseline(isolated_db):
    call_with_result(
        isolated_db["server_id"], {"summary": "3 matching contacts", "count": 3}
    )

    out = call_with_result(
        isolated_db["server_id"], {"summary": "4 matching contacts", "count": 4}
    )

    assert out["ok"] is True
    assert out["response_drift"] is None
    logs = db.list_mcp_audit_logs(limit=1)
    assert logs[0]["drift_severity"] == "none"


def test_pii_response_after_clean_baseline_blocks_and_emits_response_drift_receipt(
    isolated_db,
):
    call_with_result(
        isolated_db["server_id"], {"summary": "3 matching contacts", "count": 3}
    )

    out = call_with_result(
        isolated_db["server_id"],
        {"contacts": [{"name": "A", "email": "person@example.com"}]},
    )

    assert out["ok"] is False
    assert out["error"] == "response_drift_violation"
    assert out["response_drift"]["severity"] == "high"
    assert out["response_drift"]["action"] == "deny"
    assert "response_data_class_added" in out["response_drift"]["types"]
    assert "person@example.com" not in json.dumps(out)

    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["action"] == "deny"
    assert row["matched_rule"] == "response_exposure_drift"
    assert row["blocked_by"] == "response_drift"
    assert row["drift_status"] == "response_drift"
    assert row["drift_severity"] == "high"
    assert row["drift_action"] == "deny"
    assert row["drift_baseline_hash"].startswith("sha256:")
    assert row["drift_current_hash"].startswith("sha256:")
    assert "person@example.com" not in json.dumps(row)

    receipt = receipt_builder.build_receipt(row, chain_verified=True)
    evidence = receipt["drift_evidence"]
    assert evidence["record"]["record_type"] == "interlock.response-drift-record"
    assert evidence["record"]["diff_classification"] == "data-exposure"
    assert evidence["evidence_ref"]["type"] == "response-drift"
    assert evidence["evidence_ref"]["schema"].endswith(
        "/schemas/response-drift-record.v1.json"
    )


def test_secret_response_after_clean_baseline_quarantines_known_tool(isolated_db):
    call_with_result(
        isolated_db["server_id"], {"summary": "3 matching contacts", "count": 3}
    )

    out = call_with_result(
        isolated_db["server_id"],
        {"api_key": "sk-live-response-runtime", "status": "ok"},
    )

    assert out["ok"] is False
    assert out["error"] == "response_drift_violation"
    assert out["response_drift"]["severity"] == "critical"
    assert out["response_drift"]["action"] == "quarantine"

    tool = db.lookup_mcp_tool_metadata(isolated_db["server_id"], "search_contacts")
    assert tool["status"] == "quarantined"
    assert tool["drift_action"] == "quarantine"
    assert "response_secret_added" in tool["drift_types"]


def test_volume_expansion_after_small_baseline_monitors_and_allows(isolated_db):
    call_with_result(isolated_db["server_id"], [{"id": 1}])

    out = call_with_result(isolated_db["server_id"], [{"id": i} for i in range(650)])

    assert out["ok"] is True
    assert out["response_drift"]["severity"] == "moderate"
    assert out["response_drift"]["action"] == "monitor"
    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["action"] == "monitor"
    assert row["matched_rule"] == "response_exposure_drift"
    assert "response_volume_expanded" in row["drift_types"]


def test_response_drift_route_does_not_store_raw_response_values(isolated_db):
    call_with_result(isolated_db["server_id"], {"summary": "safe"})
    call_with_result(
        isolated_db["server_id"],
        {
            "contacts": [
                {"email": "person@example.com", "api_key": "sk-live-response-runtime"}
            ]
        },
    )

    all_state = json.dumps(db.list_mcp_audit_logs(limit=10)) + json.dumps(
        db.lookup_mcp_response_profile(isolated_db["server_id"], "search_contacts")
    )
    assert "person@example.com" not in all_state
    assert "sk-live-response-runtime" not in all_state
