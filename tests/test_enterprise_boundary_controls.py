"""Enterprise boundary controls for Interlock's hard drift limits.

Run: python3 -m pytest tests/test_enterprise_boundary_controls.py -q -s
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.chain_drift import analyze_observed_audit_chain
from core.enterprise_assurance import (
    assess_compliance_posture,
    assess_production_proof_request,
)
from core.provider_scope import compare_provider_scope_attestation
from core.remediation import plan_remediation


def test_observed_chain_analysis_catches_risky_sequence_but_names_visibility_limit():
    rows = [
        {
            "id": 1,
            "server_id": "crm",
            "tool_name": "read_customers",
            "effects": ["read"],
            "data_classes": ["customer", "pii"],
            "externality": "internal",
            "argument_hash": "sha256:" + "1" * 64,
        },
        {
            "id": 2,
            "server_id": "slack",
            "tool_name": "post_to_slack",
            "effects": ["sent"],
            "data_classes": [],
            "externality": "external",
            "argument_hash": "sha256:" + "2" * 64,
        },
    ]

    result = analyze_observed_audit_chain(rows, chain_id="session-42")

    assert result["ok"] is True
    assert result["visibility"] == "observed_post_execution"
    assert result["pre_execution_prevention_available"] is False
    assert result["evaluation"]["severity"] == "critical"
    assert result["evaluation"]["action"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in result["evaluation"]["types"]
    assert "cannot_detect_unobserved_chain" in result["limits"]
    assert "post_to_slack" in result["chain"]["tool_names"]
    assert "secret" not in json.dumps(result).lower()


def test_provider_scope_attestation_detects_available_oauth_scope_expansion():
    result = compare_provider_scope_attestation(
        provider="genesys",
        subject="readonly-client",
        baseline_scopes=["conversations.read", "users.read"],
        current_scopes=["conversations.read", "users.read", "users.write", "admin"],
        introspection_available=True,
    )

    assert result["drift_detected"] is True
    assert result["diff_classification"] == "auth-scope"
    assert result["severity"] == "critical"
    assert result["decision"] == "quarantine"
    assert "provider_scope_expanded" in result["finding_types"]
    assert "provider_scope_admin_added" in result["finding_types"]
    assert result["baseline_scope_hash"].startswith("sha256:")
    assert result["current_scope_hash"].startswith("sha256:")
    assert "users.write" not in json.dumps(result)


def test_provider_scope_attestation_is_honest_when_introspection_is_unavailable():
    result = compare_provider_scope_attestation(
        provider="genesys",
        subject="readonly-client",
        baseline_scopes=["conversations.read"],
        current_scopes=[],
        introspection_available=False,
    )

    assert result["drift_detected"] is False
    assert result["severity"] == "none"
    assert result["decision"] == "monitor"
    assert "provider_scope_introspection_unavailable" in result["finding_types"]
    assert "behavioral probes" in " ".join(result["limits"]).lower()


def test_remediation_plan_never_claims_magic_rollback_after_hidden_side_effect():
    plan = plan_remediation(
        {
            "environment": "sandbox",
            "side_effect_executed": True,
            "effect_type": "external_send",
            "rollback_capabilities": ["delete_message"],
            "readback_available": True,
        }
    )

    assert plan["status"] == "rollback_available"
    assert plan["claims"]["side_effect_already_happened"] is True
    assert plan["claims"]["automatic_rollback_completed"] is False
    assert plan["actions"][:2] == ["quarantine_tool", "preserve_receipt"]
    assert "run_provider_rollback" in plan["actions"]
    assert "verify_provider_readback" in plan["actions"]
    assert (
        "rollback is a provider-specific follow-up" in " ".join(plan["limits"]).lower()
    )


def test_remediation_without_provider_rollback_is_containment_only():
    plan = plan_remediation(
        {
            "environment": "production",
            "side_effect_executed": True,
            "effect_type": "delete",
            "rollback_capabilities": [],
            "readback_available": False,
        }
    )

    assert plan["status"] == "containment_only"
    assert "quarantine_tool" in plan["actions"]
    assert "rotate_or_revoke_credentials" in plan["actions"]
    assert "manual_incident_review" in plan["actions"]
    assert plan["claims"]["automatic_rollback_completed"] is False


def test_production_proof_request_requires_explicit_enterprise_controls():
    not_ready = assess_production_proof_request(
        {
            "environment": "production",
            "written_approval": False,
            "non_customer_canary": False,
            "rollback_plan": False,
            "maintenance_window": False,
        }
    )
    assert not_ready["ready"] is False
    assert "written_approval" in not_ready["missing_controls"]
    assert "non_customer_canary" in not_ready["missing_controls"]
    assert "production proof is never implied" in " ".join(not_ready["limits"]).lower()

    ready = assess_production_proof_request(
        {
            "environment": "production",
            "written_approval": True,
            "non_customer_canary": True,
            "rollback_plan": True,
            "maintenance_window": True,
            "readback_plan": True,
        }
    )
    assert ready["ready"] is True
    assert ready["mode"] == "controlled_production_canary"


def test_compliance_posture_is_technical_evidence_not_certification():
    posture = assess_compliance_posture(
        requested_frameworks=["SOC2", "ISO27001", "OWASP MCP Top 10"],
        has_external_audit=False,
    )

    assert posture["certified"] is False
    assert posture["posture"] == "technical_evidence_only"
    assert "Security Receipts" in posture["evidence_artifacts"]
    assert "external auditor attestation" in posture["missing_for_certification"]
    assert "certification" in " ".join(posture["limits"]).lower()
