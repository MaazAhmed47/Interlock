"""
Tests for MCP drift review API endpoints.
Run: python tests/test_mcp_review_api.py
"""
import os
import sys
import tempfile
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_tmp_db = tempfile.mktemp(suffix="_mcp_review_api_test.db")
os.environ["FIREWALL_DB_PATH"] = _tmp_db

from core import db
import proxy

TEST_KEY = "lf-free-demo-key-123"


def cleanup():
    for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


def seed_drifted_tool():
    db.register_mcp_server("_review_server", {
        "url": "http://localhost:9995/mcp",
        "description": "Review API test server",
        "allowed_tools": ["read_profile"],
        "blocked_tools": [],
        "rate_limit": 10,
    })
    db.verify_mcp_server("_review_server")
    db.upsert_mcp_tool_metadata("_review_server", {
        "name": "read_profile",
        "description": "Read a profile.",
        "inputSchema": {"type": "object", "properties": {"profile_id": {"type": "string"}}},
    }, {
        "effects": ["read"],
        "side_effect": "read_only",
        "data_classes": ["user_content"],
        "externality": "internal",
        "verification_level": "interlock_meta",
        "confidence": 0.95,
        "warnings": [],
    })
    db.upsert_mcp_tool_metadata("_review_server", {
        "name": "read_profile",
        "description": "Read a profile with optional format.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile_id": {"type": "string"},
                "format": {"type": "string"},
            },
        },
    }, {
        "effects": ["read"],
        "side_effect": "read_only",
        "data_classes": ["user_content"],
        "externality": "internal",
        "verification_level": "interlock_meta",
        "confidence": 0.95,
        "warnings": [],
    })


try:
    db.init_db()
    db.seed_legacy_keys()
    db.seed_mcp_servers()
    seed_drifted_tool()

    print("Test 1: GET /mcp/tools/drifted lists review-needed tools ...")
    data = asyncio.run(proxy.mcp_drifted_tools(x_api_key=TEST_KEY))
    assert len(data["tools"]) == 1
    assert data["tools"][0]["server_id"] == "_review_server"
    assert data["tools"][0]["tool_name"] == "read_profile"
    assert data["tools"][0]["drift_action"] == "monitor"
    print("  OK")

    print("Test 2: approve endpoint resets drift baseline ...")
    data = asyncio.run(proxy.mcp_approve_tool_baseline(
        "_review_server",
        "read_profile",
        request=proxy.MCPToolReviewRequest(
            reviewer="maaz",
            reason="Expected optional format field.",
        ),
        x_api_key=TEST_KEY,
    ))
    assert data["ok"] is True
    assert data["tool"]["status"] == "active"
    assert data["tool"]["drift_action"] == "allow"

    data = asyncio.run(proxy.mcp_drifted_tools(server_id="_review_server", x_api_key=TEST_KEY))
    assert data["tools"] == []
    print("  OK")

    print("Test 3: quarantine endpoint marks the tool quarantined ...")
    data = asyncio.run(proxy.mcp_quarantine_tool(
        "_review_server",
        "read_profile",
        request=proxy.MCPToolReviewRequest(
            reviewer="maaz",
            reason="Hold until owner confirms behavior.",
        ),
        x_api_key=TEST_KEY,
    ))
    assert data["ok"] is True
    assert data["tool"]["status"] == "quarantined"
    assert data["tool"]["drift_action"] == "quarantine"
    assert "operator_quarantine" in data["tool"]["drift_types"]
    print("  OK")

    print("Test 4: approve missing tool returns 404 ...")
    try:
        asyncio.run(proxy.mcp_approve_tool_baseline(
            "_review_server",
            "missing_tool",
            request=proxy.MCPToolReviewRequest(reviewer="maaz"),
            x_api_key=TEST_KEY,
        ))
        raise AssertionError("missing tool approval should raise 404")
    except proxy.HTTPException as exc:
        assert exc.status_code == 404
    print("  OK")

    print("Test 5: audit endpoint returns a graceful fallback if listing fails ...")
    original_list = proxy.mcp_routes.db.list_mcp_audit_logs
    original_log_exception = proxy.logger.exception

    def broken_list(_limit):
        raise RuntimeError("audit store unavailable")

    proxy.mcp_routes.db.list_mcp_audit_logs = broken_list
    proxy.logger.exception = lambda *args, **kwargs: None
    try:
        data = asyncio.run(proxy.mcp_audit(limit=10, x_api_key=TEST_KEY))
        assert data["events"] == []
        assert data["warning"] == "audit_unavailable"
    finally:
        proxy.mcp_routes.db.list_mcp_audit_logs = original_list
        proxy.logger.exception = original_log_exception
    print("  OK")

    print("\nAll MCP review API tests passed. (5/5)")
finally:
    cleanup()
