"""Terraform provider proof pack for Interlock.

This is a local mock/sandbox proof pack. It does not call Terraform CLI, cloud
providers, Terraform Cloud, or real MCP servers. It exercises Interlock's real
classifier/evidence paths with Terraform-shaped scenarios.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List

from core import db
from core import receipt as receipt_builder
from core.chain_drift import build_chain_profile, classify_chain_drift
from core.effect_drift import (
    build_effect_profile,
    classify_effect_drift,
    effect_profile_hash,
)
from core.effect_readback import (
    build_readback_state_profile,
    classify_readback_effect_drift,
)

PROVIDER = "terraform"
MODE = "local_mock_sandbox"


def run_terraform_proof_pack() -> Dict[str, Any]:
    """Run Terraform-shaped drift scenarios and return evidence-safe results."""
    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_terraform_proof_pack.db")
    db.DB_PATH = tmp_db
    try:
        db.init_db()
        scenarios = [
            _clean_plan_false_positive_control(),
            _plan_to_apply_effect_drift(),
            _plan_to_scheduled_destroy_temporal_drift(),
            _hidden_apply_provider_readback_drift(),
            _plan_apply_destroy_chain_drift(),
        ]
        return {
            "provider": PROVIDER,
            "mode": MODE,
            "summary": {
                "scenario_count": len(scenarios),
                "all_passed": all(bool(s.get("ok")) for s in scenarios),
            },
            "scenarios": scenarios,
            "limitations": [
                "Local mock/sandbox proof pack; no real Terraform CLI, Terraform Cloud, cloud provider, or production MCP server was contacted.",
                "No cloud credentials are required or loaded.",
                "Provider readback is simulated with evidence-safe before/after state hashes; a real provider pack should replace this with a safe sandbox state read tool.",
            ],
        }
    finally:
        db.DB_PATH = old_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass


def _clean_plan_false_positive_control() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"plan": True, "dry_run": True, "would_change": 2}}
    )
    current = build_effect_profile(
        {"result": {"plan": True, "dry_run": True, "would_change": 7}}
    )
    decision = classify_effect_drift(baseline, current)
    return _scenario(
        name="clean_plan_false_positive_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _plan_to_apply_effect_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"plan": True, "dry_run": True, "would_change": 2}}
    )
    current = build_effect_profile(
        {"result": {"applied": True, "updated": 2, "resource_id": "prod-vpc-secret"}}
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        name="plan_to_apply_effect_drift",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="plan_to_apply_effect_drift",
        expected_ok=(
            decision["severity"] == "high"
            and decision["action"] == "quarantine"
            and "effect_mutation_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _plan_to_scheduled_destroy_temporal_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"plan": True, "dry_run": True, "would_change": 2}}
    )
    current = build_effect_profile(
        {
            "result": {
                "scheduled_for": "2026-07-02T08:30:00Z",
                "delete_at": "2026-07-02T08:30:00Z",
                "destroy_at": "2026-07-02T08:30:00Z",
                "resource_id": "prod-vpc-secret",
            }
        }
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        name="plan_to_scheduled_destroy_temporal_drift",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="plan_to_scheduled_destroy_temporal_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "effect_temporal_destructive_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _hidden_apply_provider_readback_drift() -> Dict[str, Any]:
    before = build_readback_state_profile(
        {"workspace": "secret-workspace", "resource_count": 0, "state_version": 1}
    )
    after = build_readback_state_profile(
        {
            "workspace": "secret-workspace",
            "resource_count": 1,
            "state_version": 2,
            "state_id": "tfstate-secret",
        }
    )
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"dry_run": True, "plan": True},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name="hidden_apply_provider_readback_drift",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name="hidden_apply_provider_readback_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _plan_apply_destroy_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "terraform",
            "tool_name": "terraform_plan",
            "arguments": {"workspace": "secret-workspace"},
            "effects": ["plan"],
            "data_classes": ["infra"],
            "externality": "internal",
        },
        {
            "server_id": "terraform",
            "tool_name": "terraform_apply",
            "arguments": {"plan_id": "tfstate-secret"},
            "effects": ["applied", "deployed"],
            "data_classes": ["infra"],
            "externality": "external",
        },
        {
            "server_id": "terraform",
            "tool_name": "terraform_destroy",
            "arguments": {"target": "prod-vpc-secret"},
            "effects": ["deleted", "destroyed"],
            "data_classes": ["infra"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(steps, chain_id="terraform-plan-apply-destroy")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="plan_apply_destroy_chain_drift",
        decision=decision,
        profile=profile,
    )
    return _scenario(
        name="plan_apply_destroy_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_preview_to_deploy" in decision["types"]
            and "chain_preview_to_destructive" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _scenario(
    *,
    name: str,
    expected_ok: bool,
    decision: Dict[str, Any],
    receipt: Dict[str, Any] | None,
) -> Dict[str, Any]:
    out = {
        "name": name,
        "ok": bool(expected_ok),
        "drift_detected": bool(decision.get("drift_detected")),
        "severity": decision.get("severity") or "none",
        "decision": decision.get("action") or "allow",
        "finding_types": list(decision.get("types") or []),
        "reason": decision.get("reason") or _first(decision.get("reasons") or []),
    }
    if receipt is not None:
        out["receipt"] = receipt
    return out


def _effect_receipt(
    *, name: str, decision: Dict[str, Any], baseline_hash: str, current_hash: str
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "terraform-proof-pack",
            "tool_name": "terraform_plan",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_drift",
            "reason": _first(decision.get("reasons") or []),
            "effects": [],
            "side_effect": "terraform",
            "data_classes": ["infra"],
            "externality": "external",
            "verification_level": "provider_proof_pack_mock",
            "confidence": 0.95,
            "warnings": ["terraform_provider_proof_pack", "local_mock_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_drift" if decision["action"] == "quarantine" else "",
            "argument_hash": "sha256:" + "1" * 64,
            "drift_status": "effect_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_baseline_hash": baseline_hash,
            "drift_current_hash": current_hash,
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


def _readback_receipt(
    *, name: str, decision: Dict[str, Any], before_hash: str, after_hash: str
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "terraform-proof-pack",
            "tool_name": "terraform_plan",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "provider_proof_pack_mock_readback",
            "confidence": 0.95,
            "warnings": ["terraform_provider_proof_pack", "local_mock_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": "sha256:" + "2" * 64,
            "expected_outcome": "no_change",
            "observed_outcome": "state_changed",
            "drift_status": "readback_effect_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_baseline_hash": before_hash,
            "drift_current_hash": after_hash,
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


def _chain_receipt(
    *, name: str, decision: Dict[str, Any], profile: Dict[str, Any]
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "multi-step-chain",
            "tool_name": "terraform-plan-apply-destroy",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "chain_drift",
            "reason": decision["reason"],
            "effects": profile["effect_classes"],
            "side_effect": "chain",
            "data_classes": profile["data_classes"],
            "externality": "external",
            "verification_level": "provider_proof_pack_mock_chain",
            "confidence": 0.95,
            "warnings": ["terraform_provider_proof_pack", "local_mock_sandbox"],
            "argument_keys": [],
            "blocked_by": "chain_drift",
            "probe_id": name,
            "argument_hash": profile["argument_hash"],
            "expected_outcome": "chain_allowed",
            "observed_outcome": "chain_denied",
            "drift_status": "chain_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_current_hash": profile["profile_hash"],
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


def _first(values: List[str]) -> str:
    return values[0] if values else ""


def print_report(report: Dict[str, Any]) -> None:
    print(f"Terraform proof pack ({report['mode']})")
    for scenario in report["scenarios"]:
        status = "PASS" if scenario["ok"] else "FAIL"
        findings = ",".join(scenario.get("finding_types") or []) or "none"
        print(
            f"{status} {scenario['name']} severity={scenario['severity']} "
            f"decision={scenario['decision']} findings={findings}"
        )
    print("Limitations:")
    for item in report["limitations"]:
        print(f"- {item}")


if __name__ == "__main__":  # pragma: no cover
    print_report(run_terraform_proof_pack())
