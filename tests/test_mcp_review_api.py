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

TEST_KEY = None  # minted below via db.generate_key after init_db


def cleanup():
    for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


def seed_drifted_tool():
    db.register_mcp_server("clean-proof-docs", {
        "url": "http://localhost:9995/mcp",
        "description": "Review API test server",
        "allowed_tools": ["read_profile"],
        "blocked_tools": [],
        "rate_limit": 10,
    })
    db.verify_mcp_server("clean-proof-docs")
    db.upsert_mcp_tool_metadata("clean-proof-docs", {
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
    db.upsert_mcp_tool_metadata("clean-proof-docs", {
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


def seed_hidden_fixture_with_broken_drift():
    db.register_mcp_server("m14", {
        "url": "http://localhost:8787/mcp",
        "description": "Drift matrix fixture",
        "allowed_tools": ["payments"],
        "blocked_tools": [],
        "rate_limit": 10,
    })
    db.verify_mcp_server("m14")
    db.upsert_mcp_tool_metadata("m14", {
        "name": "payments",
        "description": "Read payment status.",
        "inputSchema": {"type": "object", "properties": {"payment_id": {"type": "string"}}},
    }, {
        "effects": ["read"],
        "side_effect": "read_only",
        "data_classes": ["financial"],
        "externality": "internal",
        "verification_level": "interlock_meta",
        "confidence": 0.95,
        "warnings": [],
    })
    with db.get_conn() as conn:
        conn.execute(
            """
            UPDATE mcp_tool_metadata
               SET status='changed',
                   drift_severity='critical',
                   drift_action='allow',
                   drift_types='[\"side_effect_escalated\"]'
             WHERE server_id='m14' AND tool_name='payments'
            """
        )


try:
    db.init_db()
    TEST_KEY = db.generate_key("free", label="test-mcp-review")["raw_key"]
    db.seed_mcp_servers()
    seed_drifted_tool()
    seed_hidden_fixture_with_broken_drift()

    print("Test 1: GET /mcp/tools includes server-policy fallback inventory ...")
    inventory = asyncio.run(proxy.mcp_tools(x_api_key=TEST_KEY))
    assert any(t["server_id"] == "trusted-filesystem" and t["tool_name"] == "read_file" for t in inventory["tools"])
    assert any(t["server_id"] == "trusted-search" and t["tool_name"] == "search" for t in inventory["tools"])
    print("  OK")

    print("Test 2: GET /mcp/tools/drifted canonicalizes action mismatches and hides fixtures in buyer view ...")
    data = asyncio.run(proxy.mcp_drifted_tools(x_api_key=TEST_KEY))
    assert len(data["tools"]) == 2
    visible = asyncio.run(proxy.mcp_drifted_tools(demo_visible_only=True, x_api_key=TEST_KEY))
    assert len(visible["tools"]) == 1
    assert visible["tools"][0]["server_id"] == "clean-proof-docs"
    assert visible["tools"][0]["tool_name"] == "read_profile"
    assert visible["tools"][0]["drift_action"] == "monitor"

    fixture = next(tool for tool in data["tools"] if tool["server_id"] == "m14")
    assert fixture["drift_action"] == "quarantine"
    assert fixture["status"] == "quarantined"
    assert fixture["server_demo_visible"] is False
    print("  OK")

    print("Test 3: approve endpoint resets drift baseline ...")
    data = asyncio.run(proxy.mcp_approve_tool_baseline(
        "clean-proof-docs",
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

    data = asyncio.run(proxy.mcp_drifted_tools(server_id="clean-proof-docs", x_api_key=TEST_KEY))
    assert data["tools"] == []
    print("  OK")

    print("Test 4: quarantine endpoint marks the tool quarantined ...")
    data = asyncio.run(proxy.mcp_quarantine_tool(
        "clean-proof-docs",
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

    print("Test 5: approve missing tool returns 404 ...")
    try:
        asyncio.run(proxy.mcp_approve_tool_baseline(
            "clean-proof-docs",
            "missing_tool",
            request=proxy.MCPToolReviewRequest(reviewer="maaz"),
            x_api_key=TEST_KEY,
        ))
        raise AssertionError("missing tool approval should raise 404")
    except proxy.HTTPException as exc:
        assert exc.status_code == 404
    print("  OK")

    print("Test 6: audit endpoint returns a graceful fallback if listing fails ...")
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

    print("\nAll MCP review API tests passed. (6/6)")
finally:
    cleanup()
