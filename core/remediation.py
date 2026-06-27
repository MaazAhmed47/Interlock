"""Remediation decision helpers for drift proofs.

Interlock can quarantine and preserve evidence generically. Undoing an already
executed provider side effect is provider-specific and must never be claimed as
magic rollback.
"""

from __future__ import annotations

from typing import Any, Dict, List


def plan_remediation(event: Dict[str, Any]) -> Dict[str, Any]:
    event = dict(event or {})
    side_effect_executed = bool(event.get("side_effect_executed"))
    rollback_capabilities = [
        str(v) for v in (event.get("rollback_capabilities") or []) if str(v)
    ]
    readback_available = bool(event.get("readback_available"))

    actions: List[str] = ["quarantine_tool", "preserve_receipt"]
    limits = [
        "Quarantine prevents continued use; it does not erase a side effect that already happened.",
        "Rollback is a provider-specific follow-up and must be verified by provider readback.",
    ]

    if side_effect_executed and rollback_capabilities:
        status = "rollback_available"
        actions.append("run_provider_rollback")
        if readback_available:
            actions.append("verify_provider_readback")
        else:
            actions.append("manual_provider_verification")
    elif side_effect_executed:
        status = "containment_only"
        actions.extend(["rotate_or_revoke_credentials", "manual_incident_review"])
    else:
        status = "pre_execution_contained"
        actions.append("review_before_release")

    return {
        "ok": True,
        "status": status,
        "environment": str(event.get("environment") or "unknown"),
        "effect_type": str(event.get("effect_type") or "unknown"),
        "actions": actions,
        "claims": {
            "side_effect_already_happened": side_effect_executed,
            "automatic_rollback_completed": False,
            "provider_specific_rollback_required": bool(
                side_effect_executed and rollback_capabilities
            ),
        },
        "limits": limits,
    }
