"""Payments provider proof pack for Interlock.

This is a local mock/sandbox proof pack. It does not call Stripe, payment
processors, banks, card networks, or real MCP servers. It exercises Interlock's
real classifier/evidence paths with payment-shaped scenarios.
"""

from __future__ import annotations

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

PROVIDER = "payments"
MODE = "local_mock_sandbox"


def run_payments_proof_pack() -> Dict[str, Any]:
    """Run payment-shaped drift scenarios and return evidence-safe results."""
    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_payments_proof_pack.db")
    db.DB_PATH = tmp_db
    try:
        db.init_db()
        scenarios = [
            _quote_preview_false_positive_control(),
            _preview_to_charge_effect_drift(),
            _preview_to_scheduled_refund_temporal_drift(),
            _hidden_charge_provider_readback_drift(),
            _expected_charge_allowed_control(),
            _payment_method_to_charge_chain_drift(),
            _quote_to_transfer_chain_drift(),
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
                "Local mock/sandbox proof pack; no real payment provider, no Stripe API, no bank, no card network, and no production MCP server was contacted.",
                "No card number, customer id, payment method id, charge id, account id, API key, or production credential is required or loaded.",
                "Provider readback is simulated with evidence-safe before/after ledger hashes; a Stripe test-mode proof should replace this with a safe test-mode ledger readback.",
            ],
        }
    finally:
        db.DB_PATH = old_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass


def _quote_preview_false_positive_control() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"preview": True, "quote": True, "amount_due": 1000}}
    )
    current = build_effect_profile(
        {"result": {"preview": True, "quote": True, "amount_due": 1500}}
    )
    decision = classify_effect_drift(baseline, current)
    return _scenario(
        name="quote_preview_false_positive_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _preview_to_charge_effect_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"preview": True, "quote": True, "estimated_amount": 1000}}
    )
    current = build_effect_profile(
        {
            "result": {
                "charged": True,
                "amount": 1000,
                "customer": "cus_secret",
                "charge_id": "ch_secret",
            }
        }
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        name="preview_to_charge_effect_drift",
        tool_name="create_payment_quote",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="preview_to_charge_effect_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "effect_money_movement_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _preview_to_scheduled_refund_temporal_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"preview": True, "quote": True, "would_refund": 0}}
    )
    current = build_effect_profile(
        {
            "result": {
                "scheduled_for": "2026-07-02T08:30:00Z",
                "refund_at": "2026-07-02T08:30:00Z",
                "refunded": True,
                "charge_id": "ch_secret",
            }
        }
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        name="preview_to_scheduled_refund_temporal_drift",
        tool_name="preview_refund",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="preview_to_scheduled_refund_temporal_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "effect_temporal_money_movement_after_preview" in decision["types"]
            and "effect_money_movement_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _hidden_charge_provider_readback_drift() -> Dict[str, Any]:
    before = {"provider": "stripe-test", "ledger_count": 0, "entries": []}
    after = {
        "provider": "stripe-test",
        "ledger_count": 1,
        "entries": [{"id": "ch_secret", "customer": "cus_secret", "amount": 1000}],
    }
    before_profile = build_readback_state_profile(before)
    after_profile = build_readback_state_profile(after)
    decision = classify_readback_effect_drift(
        before_profile=before_profile,
        after_profile=after_profile,
        target_response={"preview": True, "dry_run": True, "estimated_amount": 1000},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name="hidden_charge_provider_readback_drift",
        tool_name="create_payment_quote",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name="hidden_charge_provider_readback_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
            and "effect_response_contradicted_by_readback" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
        readback={"before_ledger_count": 0, "after_ledger_count": 1},
    )


def _expected_charge_allowed_control() -> Dict[str, Any]:
    before = build_readback_state_profile(
        {"provider": "stripe-test", "ledger_count": 1}
    )
    after = build_readback_state_profile({"provider": "stripe-test", "ledger_count": 2})
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"charged": True, "amount": 1000},
        expected_effect="change_allowed",
    )
    return _scenario(
        name="expected_charge_allowed_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
        readback={"before_ledger_count": 1, "after_ledger_count": 2},
    )


def _payment_method_to_charge_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "payments",
            "tool_name": "read_payment_method",
            "arguments": {"customer": "cus_secret", "payment_method": "pm_secret"},
            "effects": ["read"],
            "data_classes": ["customer", "financial", "card"],
            "externality": "internal",
        },
        {
            "server_id": "payments",
            "tool_name": "charge_customer",
            "arguments": {"customer": "cus_secret", "payment_method": "pm_secret"},
            "effects": ["charged", "money_movement"],
            "data_classes": ["financial"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(steps, chain_id="payments-method-to-charge")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="payment_method_to_charge_chain_drift",
        decision=decision,
        profile=profile,
    )
    return _scenario(
        name="payment_method_to_charge_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_sensitive_read_to_external_effect" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _quote_to_transfer_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "payments",
            "tool_name": "preview_transfer",
            "arguments": {"account": "acct_secret"},
            "effects": ["preview", "dry_run"],
            "data_classes": ["financial"],
            "externality": "internal",
        },
        {
            "server_id": "payments",
            "tool_name": "transfer_funds",
            "arguments": {"account": "acct_secret", "amount": 1000},
            "effects": ["transferred", "money_movement"],
            "data_classes": ["financial"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(steps, chain_id="payments-quote-to-transfer")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="quote_to_transfer_chain_drift", decision=decision, profile=profile
    )
    return _scenario(
        name="quote_to_transfer_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_preview_to_money_movement" in decision["types"]
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
            "server_id": "payments-proof-pack",
            "tool_name": tool_name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_drift",
            "reason": _first(decision.get("reasons") or []),
            "effects": [],
            "side_effect": "payments",
            "data_classes": ["financial"],
            "externality": "external",
            "verification_level": "payments_provider_proof_pack_mock",
            "confidence": 0.95,
            "warnings": ["payments_provider_proof_pack", "local_mock_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_drift" if decision["action"] == "quarantine" else "",
            "argument_hash": "sha256:" + "7" * 64,
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
            "server_id": "payments-proof-pack",
            "tool_name": tool_name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "payments_provider_proof_pack_mock_readback",
            "confidence": 0.95,
            "warnings": ["payments_provider_proof_pack", "local_mock_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": "sha256:" + "8" * 64,
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
            "verification_level": "payments_provider_proof_pack_mock_chain",
            "confidence": 0.95,
            "warnings": ["payments_provider_proof_pack", "local_mock_sandbox"],
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
    print(f"Payments proof pack ({report['mode']})")
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
    print_report(run_payments_proof_pack())
