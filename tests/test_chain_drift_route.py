"""Route tests for pre-execution MCP chain drift analysis.

Run: python3 -m pytest tests/test_chain_drift_route.py -q -s
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.db as db
import proxy
from core import receipt as receipt_builder

_tmp_db = tempfile.mktemp(suffix="_chain_drift_route_test.db")


@pytest.fixture(autouse=True)
def isolated_db():
    db.DB_PATH = _tmp_db
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_tmp_db + suffix)
        except OSError:
            pass
    db.init_db()
    yield
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_tmp_db + suffix)
        except OSError:
            pass


def _request(**overrides):
    payload = {
        "chain_id": "chain-hidden-exfil",
        "steps": [
            {
                "server_id": "email",
                "tool_name": "read_email",
                "arguments": {"query": "secret-query"},
                "effects": ["read"],
                "data_classes": ["email", "pii"],
                "externality": "internal",
            },
            {
                "server_id": "slack",
                "tool_name": "post_message",
                "arguments": {"channel": "secret-channel"},
                "effects": ["sent"],
                "data_classes": [],
                "externality": "external",
            },
        ],
        "safety_note": "Pre-execution chain analysis only; no provider calls.",
    }
    payload.update(overrides)
    return proxy.MCPChainAnalyzeRequest(**payload)


def test_chain_analyze_rejects_blank_safety_note():
    request = _request(safety_note="   ")
    with patch("proxy.verify_key", return_value=({"rate_per_min": 60}, "test-key")):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(proxy.mcp_analyze_chain(request, x_api_key="test-key"))
    assert exc.value.status_code == 400


def test_chain_analyze_denies_sensitive_read_to_external_send_and_emits_receipt():
    with patch("proxy.verify_key", return_value=({"rate_per_min": 60}, "test-key")):
        out = asyncio.run(proxy.mcp_analyze_chain(_request(), x_api_key="test-key"))

    assert out["ok"] is True
    assert out["evaluation"]["drift_detected"] is True
    assert out["evaluation"]["severity"] == "critical"
    assert out["evaluation"]["action"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in out["evaluation"]["types"]
    assert out["evidence"]["audit_id"] > 0
    assert out["evidence"]["chain_profile_hash"].startswith("sha256:")

    row = db.list_mcp_audit_logs(limit=1)[0]
    encoded = json.dumps(row, sort_keys=True)
    assert row["action"] == "deny"
    assert row["matched_rule"] == "chain_drift"
    assert row["blocked_by"] == "chain_drift"
    assert row["argument_keys"] == []
    assert row["drift_status"] == "chain_drift"
    assert row["drift_severity"] == "critical"
    assert "secret-query" not in encoded
    assert "secret-channel" not in encoded

    receipt = receipt_builder.build_receipt(row, chain_verified=True)
    assert (
        receipt["drift_evidence"]["record"]["record_type"]
        == "interlock.chain-drift-record"
    )
    assert receipt["drift_evidence"]["evidence_ref"]["type"] == "chain-drift"
    assert "secret-query" not in json.dumps(receipt)


def test_chain_analyze_allows_read_only_chain():
    request = _request(
        chain_id="chain-read-only",
        steps=[
            {
                "server_id": "docs",
                "tool_name": "search_docs",
                "arguments": {"q": "secret-query"},
                "effects": ["read"],
                "data_classes": ["docs"],
                "externality": "internal",
            },
            {
                "server_id": "docs",
                "tool_name": "summarize_docs",
                "arguments": {"id": "secret-doc"},
                "effects": ["read"],
                "data_classes": ["docs"],
                "externality": "internal",
            },
        ],
    )
    with patch("proxy.verify_key", return_value=({"rate_per_min": 60}, "test-key")):
        out = asyncio.run(proxy.mcp_analyze_chain(request, x_api_key="test-key"))

    assert out["ok"] is True
    assert out["evaluation"]["drift_detected"] is False
    assert out["evaluation"]["action"] == "allow"
    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["action"] == "allow"
    assert row["argument_keys"] == []
