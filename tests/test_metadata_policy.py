"""
Tests for core/metadata_policy.py.
Run: python tests/test_metadata_policy.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.metadata_policy import evaluate_metadata_policy


def decision_for(role, metadata, tool_name="test_tool", arguments=None):
    return evaluate_metadata_policy(
        server_id="test-server",
        tool_name=tool_name,
        arguments=arguments or {},
        role=role,
        tool_metadata=metadata,
    )


print("Test 1: readonly_agent is denied for destructive tools ...")
decision = decision_for("readonly_agent", {
    "effects": ["delete"],
    "side_effect": "destructive",
    "data_classes": ["user_content"],
    "externality": "internal",
    "verification_level": "heuristic",
    "confidence": 0.55,
    "warnings": ["Tool appears destructive based on name."],
})
assert decision["action"] == "deny"
assert decision["matched_rule"] == "readonly_agent_read_only"
assert "destructive" in decision["reason"].lower()
assert decision["audit_context"]["decision"] == "deny"
print("  OK")

print("Test 2: finance_agent is denied for external share/export ...")
decision = decision_for("finance_agent", {
    "effects": ["export"],
    "side_effect": "mutating",
    "data_classes": ["financial"],
    "externality": "external",
    "verification_level": "interlock_meta",
    "confidence": 0.95,
    "warnings": [],
})
assert decision["action"] == "deny"
assert decision["matched_rule"] == "finance_external_transfer"
assert "external" in decision["reason"].lower()
print("  OK")

print("Test 3: execute tools are denied unless devops_agent or admin_agent ...")
decision = decision_for("support_agent", {
    "effects": ["execute"],
    "side_effect": "mutating",
    "data_classes": [],
    "externality": "internal",
    "verification_level": "security_meta",
    "confidence": 0.85,
    "warnings": [],
})
assert decision["action"] == "deny"
assert decision["matched_rule"] == "execute_requires_privileged_role"

devops_decision = decision_for("devops_agent", {
    "effects": ["execute"],
    "side_effect": "mutating",
    "data_classes": [],
    "externality": "internal",
    "verification_level": "security_meta",
    "confidence": 0.85,
    "warnings": [],
})
assert devops_decision["action"] == "allow"
print("  OK")

print("Test 4: external secrets are denied for non-admin roles ...")
decision = decision_for("devops_agent", {
    "effects": ["message"],
    "side_effect": "mutating",
    "data_classes": ["secrets"],
    "externality": "external",
    "verification_level": "heuristic",
    "confidence": 0.55,
    "warnings": ["Sensitive data classes inferred."],
})
assert decision["action"] == "deny"
assert decision["matched_rule"] == "no_external_secrets"
print("  OK")

print("Test 5: low-confidence heuristic metadata is monitored ...")
decision = decision_for("support_agent", {
    "effects": ["read"],
    "side_effect": "read_only",
    "data_classes": ["user_content"],
    "externality": "internal",
    "verification_level": "heuristic",
    "confidence": 0.55,
    "warnings": ["Metadata missing; inferred from tool name."],
})
assert decision["action"] == "monitor"
assert decision["matched_rule"] == "low_confidence_heuristic"
assert decision["audit_context"]["verification_level"] == "heuristic"
print("  OK")

print("Test 6: read_only mismatch warnings are monitored ...")
decision = decision_for("support_agent", {
    "effects": ["read"],
    "side_effect": "read_only",
    "data_classes": [],
    "externality": "internal",
    "verification_level": "mcp_annotations",
    "confidence": 0.75,
    "warnings": ["Tool is marked read_only but name, description, or schema suggests side effects."],
})
assert decision["action"] == "monitor"
assert decision["matched_rule"] == "metadata_mismatch"
print("  OK")

print("Test 7: clean read-only tool is allowed ...")
decision = decision_for("support_agent", {
    "effects": ["read"],
    "side_effect": "read_only",
    "data_classes": ["user_content"],
    "externality": "internal",
    "verification_level": "interlock_meta",
    "confidence": 0.95,
    "warnings": [],
})
assert decision["action"] == "allow"
assert decision["matched_rule"] == "default_allow"
assert decision["audit_context"]["effects"] == ["read"]
print("  OK")

print("\nAll metadata policy tests passed. (7/7)")
