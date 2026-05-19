"""
Tests for persistent MCP tool metadata registry and audit log.
Run: python test_mcp_registry_audit.py
"""
import os
import sys
import tempfile

sys.path.insert(0, ".")

_tmp_db = tempfile.mktemp(suffix="_mcp_registry_test.db")
import core.db as db
db.DB_PATH = _tmp_db
db.init_db()
db.seed_mcp_servers()


def cleanup():
    for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


try:
    print("Test 1: tool metadata is saved and can be looked up ...")
    tool = {
        "name": "share_file",
        "description": "Share a file with an external recipient.",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_id": {"type": "string"},
                "recipient_email": {"type": "string"},
            },
        },
    }
    metadata = {
        "effects": ["share"],
        "side_effect": "mutating",
        "data_classes": ["user_content", "pii"],
        "externality": "external",
        "verification_level": "mcp_annotations",
        "confidence": 0.75,
        "warnings": ["Official MCP annotations are treated as hints, not security contracts."],
    }
    saved = db.upsert_mcp_tool_metadata("trusted-filesystem", tool, metadata)
    assert saved["server_id"] == "trusted-filesystem"
    assert saved["tool_name"] == "share_file"
    assert saved["status"] == "active"
    assert saved["changed"] is False

    loaded = db.lookup_mcp_tool_metadata("trusted-filesystem", "share_file")
    assert loaded["normalized_metadata"]["effects"] == ["share"]
    assert loaded["raw_annotations"]["openWorldHint"] is True
    assert loaded["status"] == "active"
    print("  OK")

    print("Test 2: schema drift is detected for same server/tool ...")
    changed_tool = {
        "name": "share_file",
        "description": "Share a file with an external recipient.",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_id": {"type": "string"},
                "recipient_email": {"type": "string"},
                "permission": {"type": "string"},
            },
        },
    }
    changed = db.upsert_mcp_tool_metadata("trusted-filesystem", changed_tool, metadata)
    assert changed["changed"] is True
    assert changed["status"] == "changed"
    assert changed["drift_severity"] == "moderate"
    assert changed["drift_action"] == "monitor"
    assert "schema_field_added" in changed["drift_types"]
    assert changed["previous_schema_hash"] != changed["tool_schema_hash"]

    loaded = db.lookup_mcp_tool_metadata("trusted-filesystem", "share_file")
    assert loaded["status"] == "changed"
    assert loaded["drift_severity"] == "moderate"
    assert loaded["drift_action"] == "monitor"
    assert "schema_field_added" in loaded["drift_types"]
    assert loaded["last_changed"] is not None
    print("  OK")

    print("Test 3: critical drift quarantines the tool ...")
    critical_tool = {
        "name": "share_file",
        "description": "Share a file with an external recipient and execute a callback.",
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_id": {"type": "string"},
                "recipient_email": {"type": "string"},
                "command": {"type": "string"},
            },
            "required": ["file_id", "command"],
        },
    }
    critical_metadata = {
        "effects": ["share", "execute"],
        "side_effect": "destructive",
        "data_classes": ["user_content", "pii"],
        "externality": "external",
        "verification_level": "mcp_annotations",
        "confidence": 0.75,
        "warnings": [],
    }
    critical = db.upsert_mcp_tool_metadata("trusted-filesystem", critical_tool, critical_metadata)
    assert critical["changed"] is True
    assert critical["status"] == "quarantined"
    assert critical["drift_severity"] == "critical"
    assert critical["drift_action"] == "quarantine"
    assert "effect_escalated" in critical["drift_types"]

    loaded = db.lookup_mcp_tool_metadata("trusted-filesystem", "share_file")
    assert loaded["status"] == "quarantined"
    assert loaded["drift_severity"] == "critical"
    assert loaded["drift_action"] == "quarantine"
    assert loaded["previous_metadata"]["effects"] == ["share"]
    assert "execute" in loaded["normalized_metadata"]["effects"]
    print("  OK")

    print("Test 4: metadata lookup returns None for unknown tool ...")
    assert db.lookup_mcp_tool_metadata("trusted-filesystem", "missing_tool") is None
    print("  OK")

    print("Test 5: MCP audit events are written and listed ...")
    event = {
        "server_id": "trusted-filesystem",
        "tool_name": "share_file",
        "role": "finance_agent",
        "action": "deny",
        "matched_rule": "finance_external_transfer",
        "reason": "finance_agent cannot perform external share/export/message actions by default.",
        "effects": ["share"],
        "side_effect": "mutating",
        "data_classes": ["financial"],
        "externality": "external",
        "verification_level": "interlock_meta",
        "confidence": 0.95,
        "warnings": ["review external transfer"],
        "argument_keys": ["file_id", "recipient_email"],
        "blocked_by": "metadata_policy",
        "drift_severity": "high",
        "drift_action": "deny",
        "drift_types": ["required_field_added"],
    }
    audit = db.log_mcp_audit_event(event)
    assert audit["id"] > 0
    assert audit["action"] == "deny"

    logs = db.list_mcp_audit_logs(limit=5)
    assert len(logs) == 1
    assert logs[0]["matched_rule"] == "finance_external_transfer"
    assert logs[0]["effects"] == ["share"]
    assert logs[0]["warnings"] == ["review external transfer"]
    assert logs[0]["argument_keys"] == ["file_id", "recipient_email"]
    assert logs[0]["drift_severity"] == "high"
    assert logs[0]["drift_action"] == "deny"
    assert logs[0]["drift_types"] == ["required_field_added"]
    print("  OK")

    print("Test 6: drifted tool listing only returns changed or quarantined tools ...")
    drifted = db.list_drifted_mcp_tools()
    assert len(drifted) == 1
    assert drifted[0]["server_id"] == "trusted-filesystem"
    assert drifted[0]["tool_name"] == "share_file"
    assert drifted[0]["status"] == "quarantined"
    assert drifted[0]["drift_action"] == "quarantine"
    assert db.list_drifted_mcp_tools(server_id="missing-server") == []
    print("  OK")

    print("Test 7: approving a drifted tool resets current state as the new baseline ...")
    approved = db.approve_mcp_tool_baseline(
        "trusted-filesystem",
        "share_file",
        reviewer="maaz",
        reason="Reviewed updated sharing tool.",
    )
    assert approved["ok"] is True
    assert approved["status"] == "active"
    assert approved["drift_severity"] == "none"
    assert approved["drift_action"] == "allow"
    assert approved["drift_types"] == []

    loaded = db.lookup_mcp_tool_metadata("trusted-filesystem", "share_file")
    assert loaded["status"] == "active"
    assert loaded["drift_severity"] == "none"
    assert loaded["previous_metadata"] == {}

    logs = db.list_mcp_audit_logs(limit=1)
    assert logs[0]["action"] == "approve"
    assert logs[0]["matched_rule"] == "tool_baseline_approved"
    assert logs[0]["role"] == "maaz"
    print("  OK")

    print("Test 8: operator quarantine keeps or marks a tool quarantined ...")
    quarantined = db.quarantine_mcp_tool(
        "trusted-filesystem",
        "share_file",
        reviewer="maaz",
        reason="Hold until owner confirms the execute path.",
    )
    assert quarantined["ok"] is True
    assert quarantined["status"] == "quarantined"
    assert quarantined["drift_severity"] == "critical"
    assert quarantined["drift_action"] == "quarantine"
    assert "operator_quarantine" in quarantined["drift_types"]

    loaded = db.lookup_mcp_tool_metadata("trusted-filesystem", "share_file")
    assert loaded["status"] == "quarantined"
    assert loaded["drift_action"] == "quarantine"

    logs = db.list_mcp_audit_logs(limit=1)
    assert logs[0]["action"] == "quarantine"
    assert logs[0]["matched_rule"] == "operator_quarantine"
    assert logs[0]["blocked_by"] == "operator_review"
    assert logs[0]["drift_action"] == "quarantine"
    print("  OK")

    print("Test 9: approving or quarantining a missing tool returns not_found ...")
    missing_approve = db.approve_mcp_tool_baseline("trusted-filesystem", "missing_tool")
    missing_quarantine = db.quarantine_mcp_tool("trusted-filesystem", "missing_tool")
    assert missing_approve == {"ok": False, "error": "not_found"}
    assert missing_quarantine == {"ok": False, "error": "not_found"}
    print("  OK")

    print("\nAll MCP registry/audit tests passed. (9/9)")
finally:
    cleanup()
