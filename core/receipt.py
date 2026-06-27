"""
Security Receipt builder.

Transforms a single ``mcp_audit_log`` row — already a link in the tamper-evident
hash chain — into a clean, shareable receipt: the tangible evidence a pilot
lead can show a manager or CISO. Pure functions, no FastAPI, so the mapping is
testable in isolation and reused by both the single-receipt and batch-export
endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from core import chain_drift as chain_drift_mod
from core import drift_evidence as drift_evidence_mod
from core import effect_drift as effect_drift_mod
from core import effect_readback as effect_readback_mod
from core import external_reach as external_reach_mod
from core import response_drift as response_drift_mod

# Decisions a receipt can present. Any block variant the audit log records
# collapses to "deny".
_DECISIONS = {"allow", "deny", "monitor", "quarantine"}

# data_class -> human redaction phrase. Unknown classes fall back to
# "<class> redacted".
_REDACTION_PHRASES = {
    "email": "email redacted",
    "phone": "phone number redacted",
    "phone_number": "phone number redacted",
    "ssn": "SSN redacted",
    "credit_card": "card number redacted",
    "card": "card number redacted",
    "card_number": "card number redacted",
    "api_key": "API key redacted",
    "secret": "secret redacted",
    "password": "password redacted",
    "ip_address": "IP address redacted",
    "address": "address redacted",
    "name": "name redacted",
}

# substring (lowercase) -> detection label, scanned across the event's reason,
# matched rule, blocked_by, and warnings.
_DETECTION_KEYWORDS = [
    ("prompt injection", "prompt_injection"),
    ("prompt_injection", "prompt_injection"),
    ("jailbreak", "prompt_injection"),
    ("ignore previous", "prompt_injection"),
    ("sql injection", "sql_injection"),
    ("sql_injection", "sql_injection"),
    ("sqli", "sql_injection"),
    ("code injection", "code_injection"),
    ("code_injection", "code_injection"),
    ("command injection", "shell_injection"),
    ("shell injection", "shell_injection"),
    ("path traversal", "path_traversal"),
    ("path_traversal", "path_traversal"),
    ("ssrf", "ssrf"),
    ("server-side request", "ssrf"),
]

# blocked_by -> detection label
_BLOCKED_BY_DETECTIONS = {
    "rbac": "rbac_violation",
    "response_pii": "pii",
    "response_injection": "response_injection",
    "untrusted_mcp_server": "untrusted_server",
    "unverified_mcp_server": "unverified_server",
    "tool_blocked": "tool_blocked",
    "tool_not_allowed": "tool_not_allowed",
    "tool_quarantined": "tool_quarantined",
}

_DRIFT_SEVERITY_RISK = {
    "critical": 25,
    "high": 18,
    "medium": 12,
    "minor": 6,
    "low": 6,
    "none": 0,
    "": 0,
}

_DECISION_BASE_RISK = {
    "quarantine": 80,
    "deny": 65,
    "monitor": 35,
    "allow": 0,
}

# Format registry — JSON today; CSV/PDF slot in here later without touching the
# route or the builder.
SUPPORTED_FORMATS = ("json",)


def normalize_decision(action: str, blocked_by: str = "") -> str:
    action = (action or "").lower().strip()
    if action in _DECISIONS:
        return action
    if action in ("block", "blocked") or blocked_by:
        return "deny"
    return action or "allow"


def _as_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if value in (None, ""):
        return []
    return [str(value)]


def derive_redactions(data_classes: List[str]) -> List[str]:
    out: List[str] = []
    for dc in data_classes:
        key = str(dc).lower().strip()
        phrase = _REDACTION_PHRASES.get(key, f"{dc} redacted")
        if phrase not in out:
            out.append(phrase)
    return out


def _drift_detected(row: Dict[str, Any]) -> bool:
    status = str(row.get("drift_status") or "").lower()
    severity = str(row.get("drift_severity") or "none").lower()
    if status in ("", "active", "none", "ok"):
        return severity not in ("", "none")
    return True


def derive_detections(row: Dict[str, Any]) -> List[str]:
    detections: List[str] = []

    def add(label: str) -> None:
        if label and label not in detections:
            detections.append(label)

    haystack = " ".join(
        [
            str(row.get("reason") or ""),
            str(row.get("matched_rule") or ""),
            str(row.get("blocked_by") or ""),
            " ".join(_as_list(row.get("warnings"))),
        ]
    ).lower()
    for needle, label in _DETECTION_KEYWORDS:
        if needle in haystack:
            add(label)

    add(_BLOCKED_BY_DETECTIONS.get(str(row.get("blocked_by") or "").lower(), ""))

    if _as_list(row.get("data_classes")):
        add("pii")

    if _drift_detected(row):
        drift_types = [
            str(kind).strip()
            for kind in _as_list(row.get("drift_types"))
            if str(kind).strip()
        ]
        if drift_types:
            for kind in drift_types:
                add(kind)
        elif str(row.get("matched_rule") or "") == "effective_permission_probe":
            add("effective_permission_drift")
        else:
            add("tool_definition_drift")

    return detections


def derive_drift(row: Dict[str, Any]) -> Dict[str, Any]:
    detected = _drift_detected(row)
    changes = _as_list(row.get("drift_reasons")) or _as_list(row.get("drift_types"))
    return {
        "detected": detected,
        "severity": str(row.get("drift_severity") or "none") if detected else "none",
        "changes": changes if detected else [],
    }


def derive_risk_score(row: Dict[str, Any], detections: List[str]) -> int:
    decision = normalize_decision(row.get("action", ""), row.get("blocked_by", ""))
    score = _DECISION_BASE_RISK.get(decision, 30)
    score += _DRIFT_SEVERITY_RISK.get(
        str(row.get("drift_severity") or "none").lower(), 0
    )
    score += min(20, 5 * len(detections))
    return max(0, min(100, score))


def _format_utc(ts: str) -> str:
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return ts


def receipt_id(row: Dict[str, Any]) -> str:
    integrity = str(row.get("integrity_hash") or "")
    suffix = integrity[:12] if integrity else "unverified"
    return f"rcpt-{row.get('id')}-{suffix}"


def derive_drift_evidence(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Build the content-addressed drift evidence block for a receipt, or None
    when the row has no emittable drift evidence (no drift, or a row written
    before the surface-hash columns existed).

    ``record`` is the exact object the digest commits to; ``evidence_ref`` is
    the trust-annotations-shaped reference an external consumer verifies by
    recomputation (see core/drift_evidence.py).
    """
    ref = f"audit://interlock/{row.get('id')}" if row.get("id") is not None else None
    chain_record = chain_drift_mod.build_chain_drift_record_from_audit_row(row)
    if chain_record is not None:
        return {
            "record": chain_record,
            "evidence_ref": chain_drift_mod.build_chain_drift_evidence_ref(
                chain_record, ref=ref
            ),
        }

    readback_record = (
        effect_readback_mod.build_readback_effect_drift_record_from_audit_row(row)
    )
    if readback_record is not None:
        return {
            "record": readback_record,
            "evidence_ref": effect_readback_mod.build_readback_effect_drift_evidence_ref(
                readback_record, ref=ref
            ),
        }

    probe_record = drift_evidence_mod.build_effective_permission_record_from_audit_row(
        row
    )
    if probe_record is not None:
        return {
            "record": probe_record,
            "evidence_ref": drift_evidence_mod.build_effective_permission_evidence_ref(
                probe_record, ref=ref
            ),
        }

    external_record = (
        external_reach_mod.build_external_reach_drift_record_from_audit_row(row)
    )
    if external_record is not None:
        return {
            "record": external_record,
            "evidence_ref": external_reach_mod.build_external_reach_drift_evidence_ref(
                external_record, ref=ref
            ),
        }

    effect_record = effect_drift_mod.build_effect_drift_record_from_audit_row(row)
    if effect_record is not None:
        return {
            "record": effect_record,
            "evidence_ref": effect_drift_mod.build_effect_drift_evidence_ref(
                effect_record, ref=ref
            ),
        }

    response_record = response_drift_mod.build_response_drift_record_from_audit_row(row)
    if response_record is not None:
        return {
            "record": response_record,
            "evidence_ref": response_drift_mod.build_response_drift_evidence_ref(
                response_record, ref=ref
            ),
        }

    record = drift_evidence_mod.build_drift_record_from_audit_row(row)
    if record is None:
        return None
    return {
        "record": record,
        "evidence_ref": drift_evidence_mod.build_evidence_ref(record, ref=ref),
    }


def build_receipt(row: Dict[str, Any], chain_verified: bool = False) -> Dict[str, Any]:
    """Map a single mcp_audit_log row to a Security Receipt."""
    ts = row.get("ts") or ""
    decision = normalize_decision(row.get("action", ""), row.get("blocked_by", ""))
    detections = derive_detections(row)
    redactions = derive_redactions(_as_list(row.get("data_classes")))
    rule_fired = row.get("matched_rule") or row.get("blocked_by") or "none"
    return {
        "receipt_id": receipt_id(row),
        "audit_id": row.get("id"),
        "timestamp": _format_utc(ts),
        "timestamp_iso": ts,
        "agent_role": row.get("role") or "",
        "server_id": row.get("server_id") or "",
        "tool_name": row.get("tool_name") or "",
        "decision": decision,
        "risk_score": derive_risk_score(row, detections),
        "rule_fired": rule_fired,
        "reason": row.get("reason") or "",
        "detections": detections,
        "redactions": redactions,
        "drift": derive_drift(row),
        "drift_evidence": derive_drift_evidence(row),
        "integrity_hash": row.get("integrity_hash") or "",
        "prev_hash": row.get("prev_hash") or "",
        "chain_verified": bool(chain_verified),
    }


def build_batch(
    rows: List[Dict[str, Any]],
    per_record_verifier: Optional[Callable[[Any], bool]] = None,
    chain_verified: bool = False,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a downloadable batch of receipts for a time range.

    per_record_verifier: optional callable(audit_id) -> bool used to stamp each
    receipt's own chain_verified flag. chain_verified is the batch-level
    integrity proof for the whole chain.
    """
    receipts = []
    for row in rows:
        verified = chain_verified
        if per_record_verifier is not None:
            verified = bool(per_record_verifier(row.get("id")))
        receipts.append(build_receipt(row, chain_verified=verified))

    return {
        "artifact": "interlock_security_receipts",
        "version": "1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "from": from_ts,
        "to": to_ts,
        "count": len(receipts),
        "chain_verified": bool(chain_verified),
        "receipts": receipts,
    }
