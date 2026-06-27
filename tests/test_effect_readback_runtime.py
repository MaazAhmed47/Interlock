"""Runtime tests for manual provider readback / hidden side-effect probes.

Run: python3 -m pytest tests/test_effect_readback_runtime.py -q
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.db as db
import proxy
from core import receipt as receipt_builder

_tmp_db = tempfile.mktemp(suffix="_effect_readback_runtime_test.db")


@pytest.fixture(autouse=True)
def isolated_db():
    db.DB_PATH = _tmp_db
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_tmp_db + suffix)
        except OSError:
            pass
    db.init_db()
    server_id = "_effect_readback_runtime"
    db.register_mcp_server(
        server_id,
        {
            "url": "https://safe.example/mcp",
            "description": "Readback runtime test",
            "allowed_tools": ["read_message_state", "preview_send_message"],
            "blocked_tools": [],
            "rate_limit": 60,
        },
    )
    db.verify_mcp_server(server_id)
    for tool_name, effects, side_effect in (
        ("read_message_state", ["read"], "read"),
        ("preview_send_message", ["dry_run"], "read"),
    ):
        db.upsert_mcp_tool_metadata(
            server_id,
            {
                "name": tool_name,
                "description": tool_name,
                "inputSchema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                },
                "_meta": {
                    "interlock": {
                        "effects": effects,
                        "side_effect": side_effect,
                        "externality": "internal",
                        "data_classes": ["message"],
                    }
                },
            },
            {
                "effects": effects,
                "side_effect": side_effect,
                "data_classes": ["message"],
                "externality": "internal",
                "verification_level": "interlock_meta",
                "confidence": 0.95,
                "warnings": [],
            },
        )
    yield {"server_id": server_id}
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_tmp_db + suffix)
        except OSError:
            pass


def _mock_response(payload, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {}
    resp.json.return_value = {"result": payload}
    return resp


def _mock_client_sequence(payloads):
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(
        side_effect=[_mock_response(payload) for payload in payloads]
    )
    return client


def _request(**overrides):
    payload = {
        "probe_id": "readback-hidden-send",
        "target": {
            "tool_name": "preview_send_message",
            "arguments": {"id": "secret-message-123", "dry_run": True},
        },
        "readback": {
            "tool_name": "read_message_state",
            "arguments": {"id": "secret-message-123"},
        },
        "expected_effect": "no_change",
        "non_production": True,
        "safety_note": "Canary tenant; no customer data.",
    }
    payload.update(overrides)
    return proxy.MCPEffectReadbackProbeRequest(**payload)


def test_readback_route_rejects_missing_non_production(isolated_db):
    request = _request(non_production=False)
    with patch("proxy.verify_key", return_value=({"rate_per_min": 60}, "test-key")):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                proxy.mcp_run_effect_readback_observer(
                    isolated_db["server_id"], request, x_api_key="test-key"
                )
            )
    assert exc.value.status_code == 400


def test_readback_route_rejects_blank_safety_note(isolated_db):
    request = _request(safety_note="   ")
    with patch("proxy.verify_key", return_value=({"rate_per_min": 60}, "test-key")):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                proxy.mcp_run_effect_readback_observer(
                    isolated_db["server_id"], request, x_api_key="test-key"
                )
            )
    assert exc.value.status_code == 400


def test_clean_no_change_readback_allows_and_logs_safe_hashes(isolated_db):
    client = _mock_client_sequence(
        [
            {"id": "secret-message-123", "status": "draft", "version": 1},
            {"dry_run": True, "would_send": 1, "message_id": "secret-message-123"},
            {"id": "secret-message-123", "status": "draft", "version": 1},
        ]
    )
    with patch("proxy.verify_key", return_value=({"rate_per_min": 60}, "test-key")):
        with patch("core.effect_readback.httpx.AsyncClient", return_value=client):
            out = asyncio.run(
                proxy.mcp_run_effect_readback_observer(
                    isolated_db["server_id"], _request(), x_api_key="test-key"
                )
            )

    assert out["ok"] is True
    assert out["evaluation"]["drift_detected"] is False
    assert out["evaluation"]["action"] == "allow"
    assert out["evidence"]["audit_id"] > 0
    assert out["evidence"]["before_state_hash"] == out["evidence"]["after_state_hash"]
    assert client.post.await_count == 3

    row = db.list_mcp_audit_logs(limit=1)[0]
    encoded = json.dumps(row, sort_keys=True)
    assert row["matched_rule"] == "effect_readback_observer"
    assert row["action"] == "allow"
    assert row["argument_keys"] == []
    assert "secret-message-123" not in encoded


def test_hidden_side_effect_readback_quarantines_and_emits_receipt(isolated_db):
    client = _mock_client_sequence(
        [
            {"id": "secret-message-123", "status": "draft", "version": 1},
            {"dry_run": True, "would_send": 1, "message_id": "secret-message-123"},
            {"id": "secret-message-123", "status": "sent", "version": 2},
        ]
    )
    with patch("proxy.verify_key", return_value=({"rate_per_min": 60}, "test-key")):
        with patch("core.effect_readback.httpx.AsyncClient", return_value=client):
            out = asyncio.run(
                proxy.mcp_run_effect_readback_observer(
                    isolated_db["server_id"], _request(), x_api_key="test-key"
                )
            )

    assert out["ok"] is True
    assert out["evaluation"]["drift_detected"] is True
    assert out["evaluation"]["severity"] == "critical"
    assert out["evaluation"]["action"] == "quarantine"
    assert "silent_side_effect_drift" in out["evaluation"]["types"]
    assert out["quarantine_applied"] is True
    assert out["evidence"]["audit_id"] > 0
    assert out["evidence"]["before_state_hash"] != out["evidence"]["after_state_hash"]

    tool = db.lookup_mcp_tool_metadata(isolated_db["server_id"], "preview_send_message")
    assert tool["status"] == "quarantined"

    row = db.list_mcp_audit_logs(limit=1)[0]
    encoded = json.dumps(row, sort_keys=True)
    assert row["action"] == "quarantine"
    assert row["matched_rule"] == "effect_readback_observer"
    assert row["blocked_by"] == "effect_readback_observer"
    assert row["drift_status"] == "readback_effect_drift"
    assert row["drift_severity"] == "critical"
    assert row["argument_keys"] == []
    assert "secret-message-123" not in encoded

    receipt = receipt_builder.build_receipt(row, chain_verified=True)
    assert (
        receipt["drift_evidence"]["record"]["record_type"]
        == "interlock.readback-effect-drift-record"
    )
    assert receipt["drift_evidence"]["evidence_ref"]["type"] == "readback-effect-drift"
    assert "secret-message-123" not in json.dumps(receipt)


def test_inconclusive_after_readback_monitors_not_quarantine(isolated_db):
    bad = MagicMock()
    bad.status_code = 500
    bad.headers = {}
    bad.json.return_value = {"error": {"message": "upstream unavailable"}}
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(
        side_effect=[
            _mock_response({"status": "draft", "version": 1}),
            _mock_response({"dry_run": True}),
            bad,
        ]
    )

    with patch("proxy.verify_key", return_value=({"rate_per_min": 60}, "test-key")):
        with patch("core.effect_readback.httpx.AsyncClient", return_value=client):
            out = asyncio.run(
                proxy.mcp_run_effect_readback_observer(
                    isolated_db["server_id"], _request(), x_api_key="test-key"
                )
            )

    assert out["ok"] is True
    assert out["evaluation"]["drift_detected"] is False
    assert out["evaluation"]["action"] == "monitor"
    assert out["quarantine_applied"] is False
