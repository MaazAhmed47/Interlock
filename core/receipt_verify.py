"""
Receipt context-binding verification and the four-claim evidence view.

Two security jobs, both answered from the hash-chained ``mcp_audit_log`` —
never from UI copy:

1. Replay / freshness invariant (``verify_receipt_against_context``): a
   Security Receipt is bound to the exact runtime context it was issued for.
   A forwarded or replayed receipt MUST fail verification if any of target
   (server_id/tool_name), argument hash, call id, or surface hash differ from
   what the audit row recorded. The binding fields are committed into the
   row's v2 chain hash (core/db.py), so they cannot be rewritten after the
   fact without breaking chain verification. Rows written before binding
   existed fail CLOSED — they never verify as bound.

2. Claim 4 (``execution_after_detection``): "did any boundary-crossing call
   execute after drift detection?" is a real query over subsequent audit rows
   for the same server/tool, split into forwarded calls vs blocked attempts.
   Scope is honest: only gateway-mediated calls are visible; calls made
   around Interlock cannot be counted.

Pure functions over rows + core.db lookups. No FastAPI.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core import db
from core import drift_evidence
from core import receipt as receipt_mod

# Context fields a verifier must present. Missing any of them is a failure
# (context_incomplete), not a pass — partial context is how replays hide.
REQUIRED_CONTEXT_FIELDS = (
    "server_id",
    "tool_name",
    "argument_hash",
    "call_id",
    "surface_hash",
)

# How presented context fields map onto audit-row columns.
_CONTEXT_TO_ROW = {
    "server_id": "server_id",
    "tool_name": "tool_name",
    "argument_hash": "argument_hash",
    "call_id": "call_id",
    "surface_hash": "drift_current_hash",
}

# Optional extra binding: verifiers may also pin the approved baseline hash.
_OPTIONAL_CONTEXT_TO_ROW = {"approved_surface_hash": "drift_baseline_hash"}

_EXECUTED_ACTIONS = {"allow", "monitor"}
_EVENT_RULES = {"drift_detected", "effective_permission_probe"}


def _resolve_row(
    presented_context: Dict[str, Any],
    presented_receipt: Optional[Dict[str, Any]],
    audit_id: Optional[int],
) -> Optional[Dict[str, Any]]:
    """Locate the audit row the receipt claims to describe."""
    if audit_id is not None:
        return db.get_mcp_audit_log(int(audit_id))
    if presented_receipt:
        receipt_audit_id = presented_receipt.get("audit_id")
        if receipt_audit_id is not None:
            return db.get_mcp_audit_log(int(receipt_audit_id))
        binding = presented_receipt.get("binding") or {}
        if binding.get("call_id"):
            return db.get_mcp_audit_log_by_call_id(str(binding["call_id"]))
    call_id = str((presented_context or {}).get("call_id") or "")
    if call_id:
        return db.get_mcp_audit_log_by_call_id(call_id)
    return None


def _check_receipt_matches_row(
    presented_receipt: Dict[str, Any], row: Dict[str, Any]
) -> List[Dict[str, str]]:
    """Compare a presented receipt's tamper-evident fields to the stored row."""
    mismatches: List[Dict[str, str]] = []

    def compare(field: str, presented: Any, recorded: Any) -> None:
        if str(presented or "") != str(recorded or ""):
            mismatches.append(
                {
                    "field": field,
                    "presented": str(presented or ""),
                    "recorded": str(recorded or ""),
                }
            )

    compare(
        "integrity_hash",
        presented_receipt.get("integrity_hash"),
        row.get("integrity_hash"),
    )
    compare("prev_hash", presented_receipt.get("prev_hash"), row.get("prev_hash"))
    if presented_receipt.get("audit_id") is not None:
        compare("audit_id", presented_receipt.get("audit_id"), row.get("id"))

    recorded_binding = receipt_mod.derive_binding(row)
    presented_binding = presented_receipt.get("binding") or {}
    for field, recorded_value in recorded_binding.items():
        compare(
            f"receipt_binding.{field}", presented_binding.get(field), recorded_value
        )
    if row.get("hash_v") == 4:
        compare("receipt_version", presented_receipt.get("version"), "4")
        recorded_mcp = receipt_mod.derive_mcp_authority_context(row)
        presented_mcp = presented_receipt.get("mcp") or {}
        for field, recorded_value in recorded_mcp.items():
            compare(
                f"receipt_mcp.{field}",
                presented_mcp.get(field),
                recorded_value,
            )
        recorded_authority = receipt_mod.derive_authority_evidence(row)
        presented_authority = presented_receipt.get("authority") or {}
        for field, recorded_value in recorded_authority.items():
            compare(
                f"receipt_authority.{field}",
                presented_authority.get(field),
                recorded_value,
            )
    return mismatches


def _check_evidence_digest(
    presented_receipt: Dict[str, Any], row: Dict[str, Any]
) -> Optional[bool]:
    """
    Recompute the drift-evidence digest of a presented receipt and require it
    to equal both its own claimed digest and the digest independently derived
    from the stored row. Returns None when the receipt carries no evidence.
    """
    evidence = presented_receipt.get("drift_evidence")
    if not evidence:
        return None
    record = evidence.get("record")
    claimed = str((evidence.get("evidence_ref") or {}).get("digest") or "")
    if not isinstance(record, dict) or not claimed:
        return False
    try:
        recomputed = drift_evidence.compute_digest(record)
    except drift_evidence.CanonicalizationError:
        return False
    if recomputed != claimed:
        return False

    stored_evidence = receipt_mod.derive_drift_evidence(row)
    if not stored_evidence:
        return False
    stored_digest = str((stored_evidence.get("evidence_ref") or {}).get("digest") or "")
    return recomputed == stored_digest


def verify_receipt_against_context(
    presented_context: Dict[str, Any],
    presented_receipt: Optional[Dict[str, Any]] = None,
    audit_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Verify a receipt against the context it is being presented FOR.

    Hard invariant: verification fails if the presented target, argument
    hash, call id, or surface hash differ from the audit row's recorded
    binding — or if the row's chain hash, the receipt's tamper-evident
    fields, or the drift-evidence digest do not verify.
    """
    presented_context = dict(presented_context or {})
    checks: Dict[str, Any] = {
        "record_found": False,
        "chain": False,
        "receipt_match": None,
        "evidence_digest": None,
        "binding": False,
    }
    result: Dict[str, Any] = {
        "verified": False,
        "audit_id": None,
        "checks": checks,
        "mismatches": [],
        "reason": "",
    }

    missing = [f for f in REQUIRED_CONTEXT_FIELDS if f not in presented_context]
    if missing:
        result["reason"] = "context_incomplete"
        result["missing_context_fields"] = missing
        return result

    row = _resolve_row(presented_context, presented_receipt, audit_id)
    if not row:
        result["reason"] = "record_not_found"
        return result
    checks["record_found"] = True
    result["audit_id"] = row.get("id")

    if int(row.get("hash_v") or 1) < 2 or not (row.get("call_id") or ""):
        result["reason"] = "row_predates_binding_fields"
        return result

    chain = db.verify_mcp_audit_record(int(row["id"]))
    checks["chain"] = bool(chain.get("chain_verified"))
    result["chain_detail"] = chain

    mismatches: List[Dict[str, str]] = []
    if presented_receipt is not None:
        receipt_mismatches = _check_receipt_matches_row(presented_receipt, row)
        checks["receipt_match"] = not receipt_mismatches
        mismatches.extend(receipt_mismatches)
        checks["evidence_digest"] = _check_evidence_digest(presented_receipt, row)

    binding_ok = True
    comparisons = dict(_CONTEXT_TO_ROW)
    for optional_field, row_col in _OPTIONAL_CONTEXT_TO_ROW.items():
        if optional_field in presented_context:
            comparisons[optional_field] = row_col
    for field, row_col in comparisons.items():
        presented = str(presented_context.get(field) or "")
        recorded = str(row.get(row_col) or "")
        if presented != recorded:
            binding_ok = False
            mismatches.append(
                {"field": field, "presented": presented, "recorded": recorded}
            )
    checks["binding"] = binding_ok

    result["mismatches"] = mismatches
    hard_checks_ok = (
        checks["record_found"]
        and checks["chain"]
        and checks["binding"]
        and checks["receipt_match"] in (None, True)
        and checks["evidence_digest"] in (None, True)
    )
    result["verified"] = bool(hard_checks_ok and not mismatches)
    result["reason"] = (
        "verified"
        if result["verified"]
        else (
            "context_binding_mismatch"
            if mismatches
            else "chain_verification_failed" if not checks["chain"] else "failed"
        )
    )
    return result


def _compact_row(row: Dict[str, Any], kind: str) -> Dict[str, Any]:
    return {
        "audit_id": row.get("id"),
        "ts": row.get("ts") or "",
        "action": row.get("action") or "",
        "role": row.get("role") or "",
        "matched_rule": row.get("matched_rule") or "",
        "blocked_by": row.get("blocked_by") or "",
        "call_id": row.get("call_id") or "",
        "kind": kind,
    }


def execution_after_detection(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Claim 4: whether any boundary-crossing call executed after this event.

    Splits every subsequent audit row for the same server/tool into:
      - executed_calls: the gateway forwarded a tool call upstream
        (action allow/monitor with no block)
      - blocked_attempts: call attempts stopped by enforcement (blocked_by set)
      - events: detection/probe rows that are not tool-call attempts

    The truthful "quarantine happened first" statement is executed_count == 0
    with blocked_attempts >= 0 — derived here, not asserted by the UI.
    """
    server_id = row.get("server_id") or ""
    tool_name = row.get("tool_name") or ""
    detection_ts = row.get("ts") or ""
    subsequent = db.list_mcp_audit_after(
        server_id, tool_name, detection_ts, exclude_id=row.get("id")
    )

    executed: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    events: List[Dict[str, Any]] = []
    for candidate in subsequent:
        rule = str(candidate.get("matched_rule") or "")
        blocked_by = str(candidate.get("blocked_by") or "")
        action = str(candidate.get("action") or "").lower()
        if rule in _EVENT_RULES:
            events.append(_compact_row(candidate, "event"))
        elif blocked_by:
            blocked.append(_compact_row(candidate, "blocked_attempt"))
        elif action in _EXECUTED_ACTIONS:
            executed.append(_compact_row(candidate, "executed_call"))
        else:
            events.append(_compact_row(candidate, "event"))

    return {
        "detection_audit_id": row.get("id"),
        "detection_ts": detection_ts,
        "boundary_crossing_executed": bool(executed),
        "executed_count": len(executed),
        "executed_calls": executed,
        "blocked_attempts": len(blocked),
        "blocked_examples": blocked[:5],
        "event_count": len(events),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "basis": (
            f"Audit-log query: all mcp_audit_log rows for "
            f"{server_id}/{tool_name} after detection event "
            f"#{row.get('id')}. Gateway-mediated calls only — calls made "
            "outside Interlock are not visible to this query."
        ),
    }


def _inspect_path(surface_hash: str) -> Optional[str]:
    """Inspect path only when the canonical bytes are actually retained."""
    if not surface_hash:
        return None
    if db.get_tool_surface_snapshot(surface_hash) is None:
        return None
    return f"/audit/evidence/surface/{surface_hash}"


def build_claims(row: Dict[str, Any], receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Assemble the four-claim evidence view for one audit event."""
    approved_hash = str(row.get("drift_baseline_hash") or "")
    observed_hash = str(row.get("drift_current_hash") or "")
    is_probe = bool(row.get("probe_id")) or (
        str(row.get("matched_rule") or "") == "effective_permission_probe"
    )

    claim_1: Dict[str, Any] = {
        "approved_surface_hash": approved_hash,
        "inspect_path": _inspect_path(approved_hash),
        "basis": (
            "Approved baseline surface hash recorded on the audit row and "
            "committed into its chain hash."
        ),
    }
    if is_probe:
        claim_1["expected_outcome"] = row.get("expected_outcome") or ""
        claim_1["expected_status_code"] = row.get("expected_status_code")

    schema_unchanged: Optional[bool] = None
    if approved_hash and observed_hash:
        schema_unchanged = approved_hash == observed_hash
    claim_2: Dict[str, Any] = {
        "observed_surface_hash": observed_hash,
        "inspect_path": _inspect_path(observed_hash),
        "schema_unchanged": schema_unchanged,
        "changes": list(row.get("drift_reasons") or []),
        "basis": (
            "Observed surface hash and recorded drift reasons from the same "
            "audit row; canonical surface bytes are retained for hash "
            "recomputation where an inspect_path is present."
        ),
    }
    if is_probe:
        claim_2["observed_outcome"] = row.get("observed_outcome") or ""
        claim_2["observed_status_code"] = row.get("observed_status_code")

    claim_3 = {
        "decision": receipt.get("decision") or "",
        "rule_fired": receipt.get("rule_fired") or "",
        "reason": row.get("reason") or "",
        "drift_severity": row.get("drift_severity") or "none",
        "drift_types": list(row.get("drift_types") or []),
        "basis": "Verbatim decision fields from the hash-chained audit row.",
    }

    return {
        "audit_id": row.get("id"),
        "receipt_id": receipt.get("receipt_id") or "",
        "claim_1_approved": claim_1,
        "claim_2_observed": claim_2,
        "claim_3_decision": claim_3,
        "claim_4_execution_after_detection": execution_after_detection(row),
    }
