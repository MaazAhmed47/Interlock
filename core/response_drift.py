"""Response/data-exposure drift profiling and classification.

This module answers a different question than the response scanner:

- response_scanner: did this one response contain injection, PII, secrets, or
  excessive volume?
- response_drift: did the approved response exposure profile materially expand
  compared with the baseline?

Profiles are intentionally evidence-safe. They contain hashes, counts, field
names, and category labels, but never raw response values.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Set

from core.drift_evidence import canonical_json_bytes
from core.response_scanner import scan_pii_and_volume

SCHEMA_ID = "interlock.response-drift-record"
SCHEMA_VERSION = "1"
SCHEMA_URL = "https://getinterlock.dev/schemas/response-drift-record.v1.json"
CANONICALIZATION = "json/jcs-rfc8785"
EVIDENCE_TYPE = "response-drift"
DIGEST_ALG = "sha256"

SEVERITY_ORDER = {
    "none": 0,
    "minor": 1,
    "moderate": 2,
    "high": 3,
    "critical": 4,
}

ACTION_BY_SEVERITY = {
    "none": "allow",
    "minor": "monitor",
    "moderate": "monitor",
    "high": "deny",
    "critical": "quarantine",
}

_SECRET_CLASSES = {
    "secrets.password",
    "secrets.api_key",
    "secrets.bearer_token",
    "secrets.private_key",
}

_LABEL_TO_CLASS = {
    "REDACTED-EMAIL": "pii.email",
    "REDACTED-PHONE": "pii.phone",
    "REDACTED-SSN": "pii.ssn",
    "REDACTED-CREDIT-CARD": "financial.card",
    "REDACTED-PASSWORD": "secrets.password",
    "REDACTED-API-KEY": "secrets.api_key",
    "REDACTED-BEARER-TOKEN": "secrets.bearer_token",
    "REDACTED-PRIVATE-KEY": "secrets.private_key",
}

_FIELD_TO_CLASS = {
    "email": "pii.email",
    "phone": "pii.phone",
    "ssn": "pii.ssn",
    "social_security": "pii.ssn",
    "credit_card": "financial.card",
    "card_number": "financial.card",
    "password": "secrets.password",
    "api_key": "secrets.api_key",
    "apikey": "secrets.api_key",
    "token": "secrets.bearer_token",
    "bearer_token": "secrets.bearer_token",
    "private_key": "secrets.private_key",
}

_PLACEHOLDER_EMAILS = {
    "user@example.com",
    "test@example.com",
    "example@example.com",
    "admin@example.com",
    "alice@example.com",
    "bob@example.com",
}


def _digest_text(text: str) -> str:
    return f"{DIGEST_ALG}:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _digest_value(value: Any) -> str:
    return f"{DIGEST_ALG}:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def _safe_json_loads(text: str) -> tuple[Any, str]:
    try:
        return json.loads(text), "json"
    except (TypeError, ValueError):
        return text, "text"


def _walk_json(value: Any, *, depth: int = 0) -> Dict[str, Any]:
    field_names: Set[str] = set()
    max_depth = depth
    scalar_count = 0
    object_count = 0
    array_count = 0
    max_array_items = 0

    def walk(item: Any, current_depth: int) -> None:
        nonlocal max_depth, scalar_count, object_count, array_count, max_array_items
        max_depth = max(max_depth, current_depth)
        if isinstance(item, dict):
            object_count += 1
            for key, child in item.items():
                field_names.add(str(key).lower())
                walk(child, current_depth + 1)
        elif isinstance(item, list):
            array_count += 1
            max_array_items = max(max_array_items, len(item))
            for child in item:
                walk(child, current_depth + 1)
        else:
            scalar_count += 1

    walk(value, depth)
    return {
        "field_names": sorted(field_names),
        "max_depth": max_depth,
        "scalar_count": scalar_count,
        "object_count": object_count,
        "array_count": array_count,
        "max_array_items": max_array_items,
    }


def _strip_placeholder_emails(text: str) -> str:
    stripped = text
    for email in _PLACEHOLDER_EMAILS:
        stripped = stripped.replace(email, "[EXAMPLE-EMAIL]")
    return stripped


def _classes_from_fields(field_names: Iterable[str]) -> Set[str]:
    classes: Set[str] = set()
    for field in field_names:
        normalized = str(field).lower().replace("-", "_")
        if normalized in _FIELD_TO_CLASS:
            classes.add(_FIELD_TO_CLASS[normalized])
            continue
        for token, klass in _FIELD_TO_CLASS.items():
            if token in normalized:
                classes.add(klass)
    return classes


def _shape_fingerprint(profile: Dict[str, Any]) -> Dict[str, Any]:
    """Return the stable profile material used for drift comparison.

    Excludes raw content digest and exact byte count so ordinary value churn
    does not create drift. Keeps counts, field names, parser class, and exposure
    labels because those describe the response capability envelope.
    """
    return {
        "profile_version": profile.get("profile_version"),
        "parse_status": profile.get("parse_status"),
        "field_names": list(profile.get("field_names") or []),
        "sensitive_classes": list(profile.get("sensitive_classes") or []),
        "redaction_labels": list(profile.get("redaction_labels") or []),
        "array_count": int(profile.get("array_count") or 0),
        "max_array_items": int(profile.get("max_array_items") or 0),
        "object_count": int(profile.get("object_count") or 0),
        "scalar_count": int(profile.get("scalar_count") or 0),
        "max_depth": int(profile.get("max_depth") or 0),
        "volume_anomaly": bool(profile.get("volume_anomaly") or False),
    }


def build_response_exposure_profile(
    response_text: str, *, max_bytes: int = 50_000, max_items: int = 500
) -> Dict[str, Any]:
    """Build an evidence-safe exposure profile for a tool response.

    The profile contains category labels, counts, field names, and hashes only.
    It never stores raw response text or raw values.
    """
    text = str(response_text or "")
    parsed, parse_status = _safe_json_loads(text)
    structure = _walk_json(parsed)

    scan_text = _strip_placeholder_emails(text)
    scan = scan_pii_and_volume(scan_text, max_bytes=max_bytes, max_items=max_items)
    redaction_labels = sorted(set(scan.redactions or []))
    sensitive_classes = {
        _LABEL_TO_CLASS[label] for label in redaction_labels if label in _LABEL_TO_CLASS
    }
    sensitive_classes.update(_classes_from_fields(structure["field_names"]))

    matched = set(scan.matched_patterns or [])
    profile = {
        "profile_version": "1",
        "content_digest": _digest_text(text),
        "parse_status": parse_status,
        "byte_count": len(text.encode("utf-8")),
        "field_names": structure["field_names"],
        "sensitive_classes": sorted(sensitive_classes),
        "redaction_labels": redaction_labels,
        "array_count": structure["array_count"],
        "max_array_items": structure["max_array_items"],
        "object_count": structure["object_count"],
        "scalar_count": structure["scalar_count"],
        "max_depth": structure["max_depth"],
        "volume_anomaly": "volume_anomaly" in matched,
    }
    profile["profile_hash"] = response_profile_hash(profile)
    return profile


def response_profile_hash(profile: Dict[str, Any]) -> str:
    """Hash the material response-exposure profile, excluding raw-value digest."""
    return _digest_value(_shape_fingerprint(profile or {}))


def _max_severity(values: Iterable[str]) -> str:
    out = "none"
    for value in values:
        if SEVERITY_ORDER[value] > SEVERITY_ORDER[out]:
            out = value
    return out


def _finding(kind: str, severity: str, reason: str) -> Dict[str, str]:
    return {"type": kind, "severity": severity, "reason": reason}


def classify_response_exposure_drift(
    baseline_profile: Optional[Dict[str, Any]],
    current_profile: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Classify response/data-exposure expansion between two safe profiles."""
    baseline_profile = baseline_profile or {}
    current_profile = current_profile or {}
    findings: List[Dict[str, str]] = []

    baseline_classes = set(baseline_profile.get("sensitive_classes") or [])
    current_classes = set(current_profile.get("sensitive_classes") or [])
    added_classes = sorted(current_classes - baseline_classes)
    added_secrets = [klass for klass in added_classes if klass in _SECRET_CLASSES]
    added_non_secret = [
        klass for klass in added_classes if klass not in _SECRET_CLASSES
    ]

    if added_secrets:
        findings.append(
            _finding(
                "response_secret_added",
                "critical",
                f"Response exposure added secret classes: {added_secrets}.",
            )
        )
    if added_non_secret:
        findings.append(
            _finding(
                "response_data_class_added",
                "high",
                f"Response exposure added data classes: {added_non_secret}.",
            )
        )

    baseline_items = int(baseline_profile.get("max_array_items") or 0)
    current_items = int(current_profile.get("max_array_items") or 0)
    baseline_bytes = int(baseline_profile.get("byte_count") or 0)
    current_bytes = int(current_profile.get("byte_count") or 0)
    current_volume = bool(current_profile.get("volume_anomaly") or False)

    item_expanded = baseline_items <= 50 and current_items > 500
    byte_expanded = baseline_bytes <= 50_000 and current_bytes > 50_000
    if current_volume and (item_expanded or byte_expanded):
        reasons = []
        if item_expanded:
            reasons.append(
                f"max array items expanded from {baseline_items} to {current_items}"
            )
        if byte_expanded:
            reasons.append(
                f"response bytes expanded from {baseline_bytes} to {current_bytes}"
            )
        findings.append(
            _finding(
                "response_volume_expanded",
                "moderate",
                "Response volume expanded materially: " + "; ".join(reasons) + ".",
            )
        )

    severity = _max_severity(f["severity"] for f in findings)
    return {
        "drift_detected": severity != "none",
        "severity": severity,
        "action": ACTION_BY_SEVERITY[severity],
        "types": _ordered_unique(f["type"] for f in findings),
        "reasons": [f["reason"] for f in findings],
        "findings": findings,
        "baseline_profile_hash": response_profile_hash(baseline_profile),
        "current_profile_hash": response_profile_hash(current_profile),
    }


def _ordered_unique(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_response_drift_record(
    *,
    server_id: str,
    tool_name: str,
    baseline_profile_hash: str,
    current_profile_hash: str,
    finding_types: List[str],
    severity: str,
    decision: str,
) -> Dict[str, Any]:
    """Build a small recomputable response-drift evidence record."""
    finding_types = [str(value) for value in (finding_types or []) if str(value)]
    return {
        "record_type": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "server_id": str(server_id or ""),
        "tool_name": str(tool_name or ""),
        "baseline_profile_hash": str(baseline_profile_hash or ""),
        "current_profile_hash": str(current_profile_hash or ""),
        "diff_classification": "data-exposure",
        "finding_types": finding_types,
        "severity": str(severity or "none"),
        "decision": str(decision or "allow"),
    }


def compute_response_drift_digest(record: Dict[str, Any]) -> str:
    return _digest_value(record or {})


def build_response_drift_record_from_audit_row(
    row: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Build response-drift evidence from an MCP audit row when present."""
    finding_types = row.get("drift_types") or []
    if isinstance(finding_types, str):
        try:
            finding_types = json.loads(finding_types)
        except (json.JSONDecodeError, TypeError):
            finding_types = []
    finding_types = [str(value) for value in (finding_types or []) if str(value)]
    if not any(value.startswith("response_") for value in finding_types):
        return None

    severity = str(row.get("drift_severity") or "none").lower()
    if severity in ("", "none"):
        return None
    baseline_hash = str(row.get("drift_baseline_hash") or "")
    current_hash = str(row.get("drift_current_hash") or "")
    if not baseline_hash or not current_hash:
        return None

    return build_response_drift_record(
        server_id=row.get("server_id") or "",
        tool_name=row.get("tool_name") or "",
        baseline_profile_hash=baseline_hash,
        current_profile_hash=current_hash,
        finding_types=finding_types,
        severity=severity,
        decision=row.get("drift_action") or row.get("action") or "allow",
    )


def build_response_drift_evidence_ref(
    record: Dict[str, Any], ref: Optional[str] = None
) -> Dict[str, Any]:
    evidence_ref = {
        "type": EVIDENCE_TYPE,
        "digest": compute_response_drift_digest(record),
        "canonicalization": CANONICALIZATION,
        "schema": SCHEMA_URL,
    }
    if ref:
        evidence_ref["ref"] = ref
    return evidence_ref
