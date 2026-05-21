"""
Tests for MCP tool drift severity classification.
Run: python tests/test_mcp_drift.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mcp_drift import classify_tool_drift


BASE_TOOL = {
    "name": "read_file",
    "description": "Read a file from the workspace.",
    "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}

BASE_METADATA = {
    "effects": ["read"],
    "side_effect": "read_only",
    "data_classes": ["user_content"],
    "externality": "internal",
    "identity_mode": "authenticated_user",
    "required_scopes": ["files.read"],
    "verification_level": "mcp_annotations",
    "confidence": 0.75,
    "warnings": [],
}


def classify(new_tool, new_metadata):
    return classify_tool_drift(BASE_TOOL, new_tool, BASE_METADATA, new_metadata)


print("Test 1: unchanged tool has no drift ...")
drift = classify(BASE_TOOL, BASE_METADATA)
assert drift["severity"] == "none"
assert drift["action"] == "allow"
assert drift["reasons"] == []
print("  OK")

print("Test 2: description-only change is minor and monitored ...")
new_tool = dict(BASE_TOOL)
new_tool["description"] = "Read a file from a workspace path."
drift = classify(new_tool, BASE_METADATA)
assert drift["severity"] == "minor"
assert drift["action"] == "monitor"
assert "description_changed" in drift["types"]
print("  OK")

print("Test 3: optional schema field addition is moderate and monitored ...")
new_tool = {
    **BASE_TOOL,
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "format": {"type": "string"},
        },
        "required": ["path"],
    },
}
drift = classify(new_tool, BASE_METADATA)
assert drift["severity"] == "moderate"
assert drift["action"] == "monitor"
assert "schema_field_added" in drift["types"]
print("  OK")

print("Test 4: required field addition is high risk ...")
new_tool = {
    **BASE_TOOL,
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "approval_id": {"type": "string"},
        },
        "required": ["path", "approval_id"],
    },
}
drift = classify(new_tool, BASE_METADATA)
assert drift["severity"] == "high"
assert drift["action"] == "deny"
assert "required_field_added" in drift["types"]
print("  OK")

print("Test 5: sensitive field addition is high risk ...")
new_tool = {
    **BASE_TOOL,
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "api_key": {"type": "string"},
        },
        "required": ["path"],
    },
}
new_metadata = {**BASE_METADATA, "data_classes": ["user_content", "secrets"]}
drift = classify(new_tool, new_metadata)
assert drift["severity"] == "high"
assert drift["action"] == "deny"
assert "sensitive_field_added" in drift["types"]
print("  OK")

print("Test 6: read-only to mutating is high risk ...")
new_metadata = {
    **BASE_METADATA,
    "effects": ["read", "update"],
    "side_effect": "mutating",
}
drift = classify(BASE_TOOL, new_metadata)
assert drift["severity"] == "high"
assert drift["action"] == "deny"
assert "side_effect_escalated" in drift["types"]
print("  OK")

print("Test 7: mutating to destructive is critical ...")
old_metadata = {
    **BASE_METADATA,
    "effects": ["update"],
    "side_effect": "mutating",
}
new_metadata = {
    **BASE_METADATA,
    "effects": ["delete"],
    "side_effect": "destructive",
}
drift = classify_tool_drift(BASE_TOOL, BASE_TOOL, old_metadata, new_metadata)
assert drift["severity"] == "critical"
assert drift["action"] == "quarantine"
assert "side_effect_escalated" in drift["types"]
print("  OK")

print("Test 8: internal to external is high risk ...")
new_metadata = {
    **BASE_METADATA,
    "externality": "external",
}
drift = classify(BASE_TOOL, new_metadata)
assert drift["severity"] == "high"
assert drift["action"] == "deny"
assert "externality_escalated" in drift["types"]
print("  OK")

print("Test 9: new execute/delete/share/export effect is critical ...")
for effect in ("execute", "delete", "share", "export"):
    new_metadata = {
        **BASE_METADATA,
        "effects": ["read", effect],
        "side_effect": "mutating" if effect not in ("delete", "execute") else "destructive",
    }
    drift = classify(BASE_TOOL, new_metadata)
    assert drift["severity"] == "critical", effect
    assert drift["action"] == "quarantine", effect
    assert "effect_escalated" in drift["types"]
print("  OK")

print("Test 10: metadata source downgrade is high risk ...")
new_metadata = {
    **BASE_METADATA,
    "verification_level": "heuristic",
}
drift = classify(BASE_TOOL, new_metadata)
assert drift["severity"] == "high"
assert drift["action"] == "deny"
assert "metadata_downgraded" in drift["types"]
print("  OK")

print("Test 11: sensitive data class addition is high risk ...")
new_metadata = {
    **BASE_METADATA,
    "data_classes": ["user_content", "phi"],
}
drift = classify(BASE_TOOL, new_metadata)
assert drift["severity"] == "high"
assert drift["action"] == "deny"
assert "data_class_escalated" in drift["types"]
print("  OK")

print("Test 12: authenticated user to service account is high risk ...")
new_metadata = {
    **BASE_METADATA,
    "identity_mode": "service_account",
}
drift = classify(BASE_TOOL, new_metadata)
assert drift["severity"] == "high"
assert drift["action"] == "deny"
assert "identity_mode_escalated" in drift["types"]
print("  OK")

print("Test 13: required scope expansion to write is high risk ...")
new_metadata = {
    **BASE_METADATA,
    "required_scopes": ["files.read", "files.write"],
}
drift = classify(BASE_TOOL, new_metadata)
assert drift["severity"] == "high"
assert drift["action"] == "deny"
assert "scope_escalated" in drift["types"]
print("  OK")

print("\nAll MCP drift tests passed. (13/13)")
