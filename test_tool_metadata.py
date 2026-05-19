"""
Tests for core/tool_metadata.py.
Run: python test_tool_metadata.py
"""
import sys
sys.path.insert(0, ".")

from core.tool_metadata import normalize_tool_metadata


def names(values):
    return set(values)


print("Test 1: official MCP annotations normalize into read-only metadata ...")
metadata = normalize_tool_metadata({
    "name": "list_files",
    "description": "List files in a workspace.",
    "annotations": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
})
assert metadata["side_effect"] == "read_only"
assert metadata["externality"] == "internal"
assert metadata["verification_level"] == "mcp_annotations"
assert metadata["source"] == "mcp_annotations"
assert "read" in metadata["effects"]
assert metadata["confidence"] >= 0.7
print("  OK")

print("Test 2: Interlock _meta overrides weaker annotations ...")
metadata = normalize_tool_metadata({
    "name": "share_file",
    "description": "Share a file with a recipient.",
    "annotations": {"readOnlyHint": True, "openWorldHint": False},
    "_meta": {
        "interlock": {
            "effects": ["share"],
            "side_effect": "mutating",
            "externality": "external",
            "data_classes": ["user_content", "pii"],
            "identity_mode": "authenticated_user",
            "required_scopes": ["files.read", "sharing.write"],
        }
    },
    "inputSchema": {
        "type": "object",
        "properties": {
            "file_id": {"type": "string"},
            "recipient_email": {"type": "string"},
        },
    },
})
assert metadata["verification_level"] == "interlock_meta"
assert metadata["source"] == "interlock_meta"
assert metadata["side_effect"] == "mutating"
assert metadata["externality"] == "external"
assert names(metadata["effects"]) == {"share"}
assert names(metadata["data_classes"]) >= {"user_content", "pii"}
assert metadata["identity_mode"] == "authenticated_user"
assert metadata["required_scopes"] == ["files.read", "sharing.write"]
assert metadata["confidence"] >= 0.9
assert any("conflicts" in warning for warning in metadata["warnings"])
print("  OK")

print("Test 3: generic _meta.security is accepted ...")
metadata = normalize_tool_metadata({
    "name": "export_ledger",
    "description": "Export ledger rows.",
    "_meta": {
        "security": {
            "effects": ["export"],
            "side_effect": "mutating",
            "externality": "external",
            "data_classes": ["financial", "internal"],
            "identity_mode": "service_account",
        }
    },
    "inputSchema": {"type": "object", "properties": {"account_id": {"type": "string"}}},
})
assert metadata["verification_level"] == "security_meta"
assert metadata["source"] == "security_meta"
assert metadata["effects"] == ["export"]
assert metadata["side_effect"] == "mutating"
assert metadata["externality"] == "external"
assert names(metadata["data_classes"]) == {"financial", "internal"}
assert metadata["identity_mode"] == "service_account"
print("  OK")

print("Test 4: missing metadata falls back to read-only inference ...")
metadata = normalize_tool_metadata({
    "name": "read_customer_record",
    "description": "Read customer profile data.",
    "inputSchema": {
        "type": "object",
        "properties": {"customer_id": {"type": "string"}},
    },
})
assert metadata["verification_level"] == "heuristic"
assert metadata["source"] == "heuristic"
assert metadata["side_effect"] == "read_only"
assert "read" in metadata["effects"]
assert "user_content" in metadata["data_classes"]
assert any("inferred" in warning.lower() for warning in metadata["warnings"])
print("  OK")

print("Test 5: destructive tools infer destructive side effects ...")
metadata = normalize_tool_metadata({
    "name": "delete_user",
    "description": "Delete a user account.",
    "inputSchema": {
        "type": "object",
        "properties": {"user_id": {"type": "string"}},
    },
})
assert metadata["side_effect"] == "destructive"
assert "delete" in metadata["effects"]
assert any("destructive" in warning.lower() for warning in metadata["warnings"])
print("  OK")

print("Test 6: sensitive argument names infer data classes ...")
metadata = normalize_tool_metadata({
    "name": "send_patient_summary",
    "description": "Send a patient summary to an external recipient.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "patient_email": {"type": "string"},
            "ssn": {"type": "string"},
            "api_key": {"type": "string"},
            "diagnosis": {"type": "string"},
        },
    },
})
assert names(metadata["effects"]) >= {"message"}
assert metadata["externality"] == "external"
assert names(metadata["data_classes"]) >= {"pii", "phi", "secrets"}
assert any("sensitive" in warning.lower() for warning in metadata["warnings"])
print("  OK")

print("Test 7: open-world annotations are represented as external ...")
metadata = normalize_tool_metadata({
    "name": "web_search",
    "description": "Search the web.",
    "annotations": {
        "readOnlyHint": True,
        "openWorldHint": True,
    },
    "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
})
assert metadata["side_effect"] == "read_only"
assert metadata["externality"] == "external"
assert "read" in metadata["effects"]
print("  OK")

print("\nAll tool metadata tests passed. (7/7)")
