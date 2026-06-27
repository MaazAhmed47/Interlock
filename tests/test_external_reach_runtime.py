"""Runtime tests for destination-aware external reach drift through /mcp/call.

Run: python3 -m pytest tests/test_external_reach_runtime.py -q -s
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

_tmp_db = tempfile.mktemp(suffix="_external_reach_runtime_test.db")


@pytest.fixture(autouse=True)
def isolated_db():
    db.DB_PATH = _tmp_db
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_tmp_db + suffix)
        except OSError:
            pass
    db.init_db()
    server_id = "_external_reach_runtime"
    db.register_mcp_server(
        server_id,
        {
            "url": "https://safe.example/mcp",
            "description": "External reach runtime test",
            "allowed_tools": ["publish_report"],
            "blocked_tools": [],
            "rate_limit": 60,
        },
    )
    db.verify_mcp_server(server_id)
    db.upsert_mcp_tool_metadata(
        server_id,
        {
            "name": "publish_report",
            "description": "Publish a report to an approved destination.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "report_id": {"type": "string"},
                    "webhook_url": {"type": "string"},
                },
                "required": ["report_id", "webhook_url"],
            },
            "_meta": {
                "interlock": {
                    "effects": ["export"],
                    "side_effect": "mutating",
                    "externality": "external",
                    "data_classes": ["internal"],
                }
            },
        },
        {
            "effects": ["export"],
            "side_effect": "mutating",
            "data_classes": ["internal"],
            "externality": "external",
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


def mock_client():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"result": {"ok": True}}
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(return_value=mock_resp)
    return client


def call_tool(server_id, arguments, client=None):
    client = client or mock_client()
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        out = asyncio.run(proxy_mcp_tool_call(server_id, "publish_report", arguments))
    return out, client


def test_first_external_destination_call_creates_baseline_and_calls_upstream(
    isolated_db,
):
    out, client = call_tool(
        isolated_db["server_id"],
        {"report_id": "r1", "webhook_url": "https://hooks.slack.com/services/T/B/one"},
    )

    assert out["ok"] is True
    assert out["external_reach_drift"] is None
    client.post.assert_called_once()
    profile = db.lookup_mcp_external_reach_profile(
        isolated_db["server_id"], "publish_report"
    )
    assert profile is not None
    assert "url_host:hooks.slack.com" in profile["profile"]["external_destinations"]
    assert "services/T/B/one" not in json.dumps(profile)


def test_same_approved_host_passes_without_drift(isolated_db):
    call_tool(
        isolated_db["server_id"],
        {"report_id": "r1", "webhook_url": "https://hooks.slack.com/services/T/B/one"},
    )

    out, client = call_tool(
        isolated_db["server_id"],
        {"report_id": "r2", "webhook_url": "https://hooks.slack.com/services/T/B/two"},
    )

    assert out["ok"] is True
    assert out["external_reach_drift"] is None
    client.post.assert_called_once()


def test_new_external_host_denies_before_upstream_and_emits_receipt(isolated_db):
    call_tool(
        isolated_db["server_id"],
        {"report_id": "r1", "webhook_url": "https://hooks.slack.com/services/T/B/one"},
    )
    client = mock_client()

    out, client = call_tool(
        isolated_db["server_id"],
        {"report_id": "r2", "webhook_url": "https://evil.example/collect"},
        client,
    )

    assert out["ok"] is False
    assert out["error"] == "external_reach_drift_violation"
    assert out["external_reach_drift"]["severity"] == "high"
    assert out["external_reach_drift"]["action"] == "deny"
    assert "external_destination_added" in out["external_reach_drift"]["types"]
    client.post.assert_not_called()

    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["action"] == "deny"
    assert row["matched_rule"] == "external_reach_drift"
    assert row["blocked_by"] == "external_reach_drift"
    assert row["drift_status"] == "external_reach_drift"
    assert row["drift_severity"] == "high"
    assert row["drift_baseline_hash"].startswith("sha256:")
    assert row["drift_current_hash"].startswith("sha256:")
    assert "collect" not in json.dumps(row)

    receipt = receipt_builder.build_receipt(row, chain_verified=True)
    evidence = receipt["drift_evidence"]
    assert evidence["record"]["record_type"] == "interlock.external-reach-drift-record"
    assert evidence["record"]["diff_classification"] == "external-reach"
    assert evidence["evidence_ref"]["type"] == "external-reach-drift"


def test_new_external_host_with_secret_indicator_quarantines_tool(isolated_db):
    call_tool(
        isolated_db["server_id"],
        {"report_id": "r1", "webhook_url": "https://hooks.slack.com/services/T/B/one"},
    )
    client = mock_client()

    out, client = call_tool(
        isolated_db["server_id"],
        {
            "report_id": "r2",
            "webhook_url": "https://evil.example/collect",
            "include_secrets": True,
        },
        client,
    )

    assert out["ok"] is False
    assert out["external_reach_drift"]["severity"] == "critical"
    assert out["external_reach_drift"]["action"] == "quarantine"
    client.post.assert_not_called()
    tool = db.lookup_mcp_tool_metadata(isolated_db["server_id"], "publish_report")
    assert tool["status"] == "quarantined"
    assert "external_secret_destination_added" in tool["drift_types"]


def test_internal_destination_change_does_not_block(isolated_db):
    out, first_client = call_tool(
        isolated_db["server_id"],
        {"report_id": "r1", "webhook_url": "http://api.internal/hook"},
    )
    assert out["ok"] is True
    first_client.post.assert_called_once()

    out, second_client = call_tool(
        isolated_db["server_id"],
        {"report_id": "r2", "webhook_url": "http://worker.internal/hook"},
    )
    assert out["ok"] is True
    assert out["external_reach_drift"] is None
    second_client.post.assert_called_once()


def test_external_reach_drift_storage_excludes_raw_urls_emails_and_channels(
    isolated_db,
):
    call_tool(
        isolated_db["server_id"],
        {
            "report_id": "r1",
            "webhook_url": "https://hooks.slack.com/services/T/B/one",
            "slack_channel": "#customer-escalations",
            "recipient_email": "alice@company.example",
        },
    )
    call_tool(
        isolated_db["server_id"],
        {
            "report_id": "r2",
            "webhook_url": "https://evil.example/collect/secret",
            "slack_channel": "#board-room",
            "recipient_email": "mallory@outside.example",
        },
    )

    state = json.dumps(db.list_mcp_audit_logs(limit=10)) + json.dumps(
        db.lookup_mcp_external_reach_profile(isolated_db["server_id"], "publish_report")
    )
    assert "services/T/B/one" not in state
    assert "collect/secret" not in state
    assert "alice@" not in state
    assert "mallory@" not in state
    assert "customer-escalations" not in state
    assert "board-room" not in state
