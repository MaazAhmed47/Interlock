"""Email/messaging provider proof pack for Interlock.

This is a local mock/sandbox proof pack. It does not call Gmail, iCloud,
Fastmail, SMTP providers, Slack, or real MCP servers. It exercises
Interlock's real classifier/evidence paths with email/messaging-shaped
scenarios.
"""

from __future__ import annotations

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
from core.external_reach import (
    build_external_reach_profile,
    classify_external_reach_drift,
    external_reach_profile_hash,
)

PROVIDER = "email_messaging"
MODE = "local_mock_sandbox"


def run_email_proof_pack() -> Dict[str, Any]:
    """Run email/messaging-shaped drift scenarios with evidence-safe output."""
    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_email_proof_pack.db")
    db.DB_PATH = tmp_db
    try:
        db.init_db()
        scenarios = [
            _clean_draft_false_positive_control(),
            _draft_to_sent_effect_drift(),
            _draft_to_scheduled_send_temporal_drift(),
            _recipient_domain_external_reach_drift(),
            _hidden_send_provider_readback_drift(),
            _read_inbox_to_slack_chain_drift(),
        ]
        return {
            "provider": PROVIDER,
            "mode": MODE,
            "summary": {
                "scenario_count": len(scenarios),
                "all_passed": all(bool(scenario.get("ok")) for scenario in scenarios),
            },
            "scenarios": scenarios,
            "limitations": [
                "Local mock/sandbox proof pack; no real Gmail, iCloud, Fastmail, SMTP provider, Slack workspace, or production MCP server was contacted.",
                "No Gmail, no iCloud, no Fastmail, no SMTP credentials, OAuth tokens, mailbox contents, message bodies, or real recipient addresses are required or loaded.",
                "Provider readback is simulated with evidence-safe before/after state hashes; a real provider pack should replace this with a safe sandbox mailbox/readback tool.",
            ],
        }
    finally:
        db.DB_PATH = old_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass


def _clean_draft_false_positive_control() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"preview": True, "dry_run": True, "would_send": 1}}
    )
    current = build_effect_profile(
        {"result": {"preview": True, "dry_run": True, "would_send": 3}}
    )
    decision = classify_effect_drift(baseline, current)
    return _scenario(
        name="clean_draft_false_positive_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _draft_to_sent_effect_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"preview": True, "dry_run": True, "would_send": 1}}
    )
    current = build_effect_profile(
        {"result": {"sent": True, "emailed": True, "message_id": "message-secret"}}
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        name="draft_to_sent_effect_drift",
        tool_name="email_draft",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="draft_to_sent_effect_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "effect_external_send_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _draft_to_scheduled_send_temporal_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"preview": True, "dry_run": True, "would_send": 1}}
    )
    current = build_effect_profile(
        {
            "result": {
                "scheduled_for": "2026-07-03T09:00:00Z",
                "send_at": "2026-07-03T09:00:00Z",
                "message_id": "message-secret",
            }
        }
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        name="draft_to_scheduled_send_temporal_drift",
        tool_name="email_draft",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="draft_to_scheduled_send_temporal_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "effect_temporal_external_after_preview" in decision["types"]
            and "effect_external_send_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _recipient_domain_external_reach_drift() -> Dict[str, Any]:
    baseline = build_external_reach_profile(
        {
            "recipient": "person@example.com",
            "pii_payload": True,
            "body": "body-secret",
        }
    )
    current = build_external_reach_profile(
        {
            "recipient": "vip@example.net",
            "pii_payload": True,
            "body": "body-secret",
        }
    )
    decision = classify_external_reach_drift(baseline, current)
    receipt = _external_reach_receipt(
        name="recipient_domain_external_reach_drift",
        decision=decision,
        baseline_hash=external_reach_profile_hash(baseline),
        current_hash=external_reach_profile_hash(current),
    )
    return _scenario(
        name="recipient_domain_external_reach_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "external_secret_destination_added" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _hidden_send_provider_readback_drift() -> Dict[str, Any]:
    before = build_readback_state_profile(
        {"mailbox": "sandbox", "sent_count": 0, "last_message_hash": None}
    )
    after = build_readback_state_profile(
        {
            "mailbox": "sandbox",
            "sent_count": 1,
            "last_message_hash": "message-secret",
        }
    )
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"preview": True, "dry_run": True, "would_send": 1},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name="hidden_send_provider_readback_drift",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name="hidden_send_provider_readback_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
            and "effect_response_contradicted_by_readback" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _read_inbox_to_slack_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "email",
            "tool_name": "read_inbox",
            "arguments": {"mailbox": "sandbox", "query": "from:customer"},
            "effects": ["read"],
            "data_classes": ["email", "customer", "pii"],
            "externality": "internal",
        },
        {
            "server_id": "messaging",
            "tool_name": "post_to_slack",
            "arguments": {"channel": "secret-channel", "text": "body-secret"},
            "effects": ["sent"],
            "data_classes": ["email", "customer", "pii"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(steps, chain_id="email-read-to-external-message")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="read_inbox_to_slack_chain_drift",
        decision=decision,
        profile=profile,
    )
    return _scenario(
        name="read_inbox_to_slack_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_sensitive_read_to_external_effect" in decision["types"]
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
    *,
    name: str,
    tool_name: str,
    decision: Dict[str, Any],
    baseline_hash: str,
    current_hash: str,
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "email-proof-pack",
            "tool_name": tool_name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_drift",
            "reason": _first(decision.get("reasons") or []),
            "effects": ["email"],
            "side_effect": "email",
            "data_classes": ["email", "customer", "pii"],
            "externality": "external",
            "verification_level": "provider_proof_pack_mock",
            "confidence": 0.95,
            "warnings": ["email_provider_proof_pack", "local_mock_sandbox", name],
            "argument_keys": [],
            "blocked_by": "effect_drift" if decision["action"] == "quarantine" else "",
            "argument_hash": "sha256:" + "3" * 64,
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


def _external_reach_receipt(
    *, name: str, decision: Dict[str, Any], baseline_hash: str, current_hash: str
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "email-proof-pack",
            "tool_name": "email_send",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "external_reach_drift",
            "reason": _first(decision.get("reasons") or []),
            "effects": ["sent"],
            "side_effect": "email",
            "data_classes": ["email", "customer", "pii"],
            "externality": "external",
            "verification_level": "provider_proof_pack_mock_external_reach",
            "confidence": 0.95,
            "warnings": ["email_provider_proof_pack", "local_mock_sandbox", name],
            "argument_keys": [],
            "blocked_by": "external_reach_drift",
            "argument_hash": "sha256:" + "4" * 64,
            "drift_status": "external_reach_drift",
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
            "server_id": "email-proof-pack",
            "tool_name": "email_draft",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "provider_proof_pack_mock_readback",
            "confidence": 0.95,
            "warnings": ["email_provider_proof_pack", "local_mock_sandbox", name],
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
            "tool_name": "email-read-to-external-message",
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
            "warnings": ["email_provider_proof_pack", "local_mock_sandbox", name],
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
    print(f"Email/messaging proof pack ({report['mode']})")
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
    print_report(run_email_proof_pack())
