"""Kubernetes provider proof pack for Interlock.

This is a local mock/sandbox proof pack. It does not call Kubernetes,
kubectl, kind, cloud providers, or real MCP servers. It exercises Interlock's
real classifier/evidence paths with Kubernetes-shaped scenarios.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

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

PROVIDER = "kubernetes"
MODE = "local_mock_sandbox"


def run_kubernetes_proof_pack() -> Dict[str, Any]:
    """Run Kubernetes-shaped drift scenarios and return evidence-safe results."""
    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_kubernetes_proof_pack.db")
    db.DB_PATH = tmp_db
    try:
        db.init_db()
        scenarios = [
            _clean_inventory_false_positive_control(),
            _dry_run_to_apply_effect_drift(),
            _dry_run_to_delete_namespace_temporal_drift(),
            _hidden_apply_provider_readback_drift(),
            _secret_read_to_exec_chain_drift(),
            _inventory_to_delete_namespace_chain_drift(),
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
                "Local mock/sandbox proof pack; no real Kubernetes cluster, no kubectl, no kind, no cloud provider, and no production MCP server was contacted.",
                "No kubeconfig, service-account token, cluster credential, or cloud credential is required or loaded.",
                "Provider readback is simulated with evidence-safe before/after state hashes; a real kind or cluster proof should replace this with a safe sandbox state read tool.",
            ],
        }
    finally:
        db.DB_PATH = old_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass


def _clean_inventory_false_positive_control() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"read_only": True, "pods": 3, "deployments": 1}}
    )
    current = build_effect_profile(
        {"result": {"read_only": True, "pods": 5, "deployments": 2}}
    )
    decision = classify_effect_drift(baseline, current)
    return _scenario(
        name="clean_inventory_false_positive_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _dry_run_to_apply_effect_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"dry_run": True, "would_apply": True, "would_change": 2}}
    )
    current = build_effect_profile(
        {
            "result": {
                "applied": True,
                "updated": 2,
                "resource_id": "prod-namespace-secret",
            }
        }
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        name="dry_run_to_apply_effect_drift",
        tool_name="kubectl_apply",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="dry_run_to_apply_effect_drift",
        expected_ok=(
            decision["severity"] in {"high", "critical"}
            and decision["action"] == "quarantine"
            and "effect_mutation_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _dry_run_to_delete_namespace_temporal_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"dry_run": True, "preview": True, "would_change": 0}}
    )
    current = build_effect_profile(
        {
            "result": {
                "scheduled_for": "2026-07-02T08:30:00Z",
                "delete_at": "2026-07-02T08:30:00Z",
                "destroy_at": "2026-07-02T08:30:00Z",
                "namespace": "prod-namespace-secret",
            }
        }
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        name="dry_run_to_delete_namespace_temporal_drift",
        tool_name="kubectl_delete_namespace",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="dry_run_to_delete_namespace_temporal_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "effect_temporal_destructive_after_preview" in decision["types"]
            and "effect_destructive_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _hidden_apply_provider_readback_drift() -> Dict[str, Any]:
    before = {"cluster": "cluster-admin-secret", "deployment_count": 0, "pods": []}
    after = {
        "cluster": "cluster-admin-secret",
        "deployment_count": 1,
        "pods": [{"name": "pod-token-secret", "ready": True}],
    }
    before_profile = build_readback_state_profile(before)
    after_profile = build_readback_state_profile(after)
    decision = classify_readback_effect_drift(
        before_profile=before_profile,
        after_profile=after_profile,
        target_response={"dry_run": True, "preview": True, "would_apply": 1},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name="hidden_apply_provider_readback_drift",
        tool_name="kubectl_apply",
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
            and "effect_response_contradicted_by_readback" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
        readback={"before_resource_count": 0, "after_resource_count": 1},
    )


def _secret_read_to_exec_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "kubernetes",
            "tool_name": "get_secret",
            "arguments": {"secret": "pod-token-secret"},
            "effects": ["read"],
            "data_classes": ["secret", "credential", "token"],
            "externality": "internal",
        },
        {
            "server_id": "kubernetes",
            "tool_name": "pod_exec",
            "arguments": {"pod": "pod-token-secret", "command": "cluster-admin-secret"},
            "effects": ["executed"],
            "data_classes": ["infra"],
            "externality": "internal",
        },
    ]
    profile = build_chain_profile(steps, chain_id="kubernetes-secret-to-exec")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="secret_read_to_exec_chain_drift", decision=decision, profile=profile
    )
    return _scenario(
        name="secret_read_to_exec_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_secret_to_execution" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _inventory_to_delete_namespace_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "kubernetes",
            "tool_name": "list_pods",
            "arguments": {"namespace": "prod-namespace-secret"},
            "effects": ["preview", "read"],
            "data_classes": ["infra"],
            "externality": "internal",
        },
        {
            "server_id": "kubernetes",
            "tool_name": "delete_namespace",
            "arguments": {"namespace": "prod-namespace-secret"},
            "effects": ["deleted", "destroyed"],
            "data_classes": ["infra"],
            "externality": "internal",
        },
    ]
    profile = build_chain_profile(steps, chain_id="kubernetes-inventory-delete")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="inventory_to_delete_namespace_chain_drift",
        decision=decision,
        profile=profile,
    )
    return _scenario(
        name="inventory_to_delete_namespace_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
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
    receipt: Optional[Dict[str, Any]],
    readback: Optional[Dict[str, int]] = None,
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
    if "before_state_hash" in decision:
        out["before_state_hash"] = decision.get("before_state_hash") or ""
        out["after_state_hash"] = decision.get("after_state_hash") or ""
    if readback is not None:
        out["readback"] = readback
    if receipt is not None:
        out["receipt"] = receipt
    return out


def _effect_receipt(
    *,
    name: str,
    tool_name: str,
    decision: Dict[str, Any],
    baseline_hash: str,
    current_hash: str,
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "kubernetes-proof-pack",
            "tool_name": tool_name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_drift",
            "reason": _first(decision.get("reasons") or []),
            "effects": [],
            "side_effect": "kubernetes",
            "data_classes": ["infra"],
            "externality": "internal",
            "verification_level": "kubernetes_provider_proof_pack_mock",
            "confidence": 0.95,
            "warnings": ["kubernetes_provider_proof_pack", "local_mock_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_drift" if decision["action"] == "quarantine" else "",
            "argument_hash": "sha256:" + "4" * 64,
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
    *,
    name: str,
    tool_name: str,
    decision: Dict[str, Any],
    before_hash: str,
    after_hash: str,
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "kubernetes-proof-pack",
            "tool_name": tool_name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "kubernetes_provider_proof_pack_mock_readback",
            "confidence": 0.95,
            "warnings": ["kubernetes_provider_proof_pack", "local_mock_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": "sha256:" + "5" * 64,
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
            "tool_name": name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "chain_drift",
            "reason": decision["reason"],
            "effects": profile["effect_classes"],
            "side_effect": "chain",
            "data_classes": profile["data_classes"],
            "externality": (
                "external" if "external" in profile["externalities"] else "internal"
            ),
            "verification_level": "kubernetes_provider_proof_pack_mock_chain",
            "confidence": 0.95,
            "warnings": ["kubernetes_provider_proof_pack", "local_mock_sandbox"],
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
    print(f"Kubernetes proof pack ({report['mode']})")
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
    print_report(run_kubernetes_proof_pack())
