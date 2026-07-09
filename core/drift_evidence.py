"""
Content-addressed drift evidence records.

Builds the "drift" evidence record referenced by a Security Receipt's
``evidence_ref`` (targeting the MCP ``evidenceRef`` shape in the
io.modelcontextprotocol/trust-annotations draft, 2026-06-10 — field names
beyond type/digest/canonicalization/schema/ref are NOT asserted here).

The core guarantee is client-recomputability: an independent party holding the
drift record can re-derive its digest from the canonical record bytes without
trusting Interlock. To keep that claim honest:

  - The record schema is restricted to strings and lists of strings. For that
    value domain, ``canonical_json_bytes`` is byte-identical to RFC 8785 (JCS),
    so the declared canonicalization is "json/jcs-rfc8785".
  - The digest is sha256 over those bytes, emitted as "sha256:<hex>".
  - Tool *surface* hashes (the inner approved/current hashes) are computed over
    a canonical projection of the tool definition. Tool schemas are arbitrary
    JSON, so floats may appear; integral floats are serialized as integers
    (matching ECMAScript/JCS), non-integral floats use Python ``repr`` which
    matches JCS shortest-form for the normal range but is not guaranteed for
    extreme magnitudes — see ``canonical_json_bytes``.

Pure functions, stdlib only, no FastAPI — same style as ``core/receipt.py``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional

SCHEMA_ID = "interlock.drift-record"
SCHEMA_VERSION = "1"
# trust-annotations (io.modelcontextprotocol, draft 2026-06-10): "schema" is a
# URL string identifying the record schema, not an {id, version} object.
SCHEMA_URL = "https://getinterlock.dev/schemas/drift-record.v1.json"
CANONICALIZATION = "json/jcs-rfc8785"
DIGEST_ALG = "sha256"
EVIDENCE_TYPE = "drift"
EFFECTIVE_PERMISSION_SCHEMA_ID = "interlock.effective-permission-drift-record"
EFFECTIVE_PERMISSION_SCHEMA_VERSION = "1"
EFFECTIVE_PERMISSION_SCHEMA_URL = (
    "https://getinterlock.dev/schemas/effective-permission-drift-record.v1.json"
)
EFFECTIVE_PERMISSION_EVIDENCE_TYPE = "effective-permission-drift"

# Classification buckets for the standardized diff_classification field, in
# precedence order (most dangerous first). When a drift event carries several
# finding types, diff_classification is the highest-precedence bucket among
# them; the full finding-type list is carried inside the digested record.
CLASSIFICATION_PRECEDENCE = (
    "external-reach",
    "auth-scope",
    "data-exposure",
    "capability",
    "schema",
)

# core/mcp_drift.py finding type -> classification bucket. Unknown finding
# types map to "capability" (a tool whose behavior changed in a way we cannot
# bucket more precisely).
_TYPE_TO_CLASSIFICATION = {
    "description_changed": "schema",
    "schema_field_added": "schema",
    "schema_field_removed": "schema",
    "required_field_added": "schema",
    "param_type_changed": "schema",
    "effect_escalated": "capability",
    "side_effect_escalated": "capability",
    "tool_added": "capability",
    "tool_removed": "capability",
    "metadata_downgraded": "capability",
    "sensitive_field_added": "data-exposure",
    "data_class_escalated": "data-exposure",
    "description_exfiltration": "data-exposure",
    "scope_escalated": "auth-scope",
    "identity_mode_escalated": "auth-scope",
    "effective_permission_expansion": "auth-scope",
    "behavioral_scope_drift": "auth-scope",
    "effective_permission_contraction": "auth-scope",
    "permission_regression": "auth-scope",
    "externality_escalated": "external-reach",
}
_DEFAULT_CLASSIFICATION = "capability"

_RECORD_FIELDS = (
    "record_type",
    "schema_version",
    "server_id",
    "tool_name",
    "approved_surface_hash",
    "current_surface_hash",
    "diff_classification",
    "finding_types",
    "severity",
    "decision",
)

_EFFECTIVE_PERMISSION_RECORD_FIELDS = (
    "record_type",
    "schema_version",
    "probe_id",
    "server_id",
    "tool_name",
    "argument_hash",
    "expected_outcome",
    "expected_status_code",
    "observed_outcome",
    "observed_status_code",
    "observed_error_class",
    "finding_type",
    "diff_classification",
    "finding_types",
    "severity",
    "decision",
    "created_at",
)


class CanonicalizationError(ValueError):
    """Value cannot be canonicalized under the declared scheme."""


def _canonical_value(value: Any) -> Any:
    """Validate and normalize a value for canonical serialization."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        # JCS/ECMAScript serializes 1.0 as "1"; Python json.dumps emits "1.0".
        # Normalize integral floats to int. Non-integral floats fall through to
        # repr-based serialization (see module docstring caveat).
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalizationError("NaN/Infinity are not valid JSON")
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"Non-string object key: {key!r}")
            out[key] = _canonical_value(item)
        return out
    raise CanonicalizationError(f"Unsupported type for canonicalization: {type(value)}")


def canonical_json_bytes(value: Any) -> bytes:
    """
    Deterministic canonical serialization: UTF-8 bytes of JSON with
    lexicographically sorted keys, no insignificant whitespace, and literal
    (non-escaped) non-ASCII characters.

    For values containing only strings, integers, booleans, null, and
    containers thereof — which includes every drift record this module
    emits — the output is byte-identical to RFC 8785 (JCS). Keys sort by
    Unicode code point, which matches JCS UTF-16 ordering for all BMP keys.
    """
    normalized = _canonical_value(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(data: bytes) -> str:
    return f"{DIGEST_ALG}:{hashlib.sha256(data).hexdigest()}"


def arguments_hash(arguments: Optional[Dict[str, Any]]) -> str:
    """
    Content address of a tool call's arguments: sha256 over their canonical
    JSON bytes. Only the hash is ever persisted — raw argument values stay out
    of the audit log. This is the ``argument_hash`` receipts bind to.
    """
    return _digest_bytes(canonical_json_bytes(arguments or {}))


def compute_digest(record: Dict[str, Any]) -> str:
    """Digest of a drift record: sha256 over its canonical bytes."""
    return _digest_bytes(canonical_json_bytes(record))


def canonical_surface_json(tool_def: Dict[str, Any]) -> str:
    """Canonical JSON (as text) of the hashed tool-surface projection."""
    tool_def = tool_def or {}
    surface = {
        "name": str(tool_def.get("name") or ""),
        "description": str(tool_def.get("description") or ""),
        "inputSchema": tool_def.get("inputSchema")
        or tool_def.get("input_schema")
        or {},
    }
    return canonical_json_bytes(surface).decode("utf-8")


def tool_surface_hash(tool_def: Dict[str, Any]) -> str:
    """
    Content address of one tool's approved/current surface: sha256 over the
    canonical JSON of {name, description, inputSchema}.

    Note: deliberately a NEW composite hash — the stored ``tool_schema_hash``
    covers only the input schema and would not change on description drift.
    """
    return _digest_bytes(canonical_surface_json(tool_def).encode("utf-8"))


def classify_finding_types(finding_types: Iterable[str]) -> str:
    """Map drift finding types to the single highest-precedence classification."""
    buckets = {
        _TYPE_TO_CLASSIFICATION.get(str(t), _DEFAULT_CLASSIFICATION)
        for t in finding_types
        if str(t)
    }
    for bucket in CLASSIFICATION_PRECEDENCE:
        if bucket in buckets:
            return bucket
    return _DEFAULT_CLASSIFICATION


def build_drift_record(
    server_id: str,
    tool_name: str,
    approved_surface_hash: str,
    current_surface_hash: str,
    finding_types: List[str],
    severity: str,
    decision: str,
) -> Dict[str, Any]:
    """
    Build the canonical drift record the evidence digest commits to.

    Every field is a string (or list of strings), which is what keeps the
    JCS canonicalization claim exact. Severity uses the classifier vocabulary
    (none/minor/moderate/high/critical); decision is the gateway drift action
    (allow/monitor/deny/quarantine).
    """
    finding_types = [str(t) for t in (finding_types or []) if str(t)]
    return {
        "record_type": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "server_id": str(server_id or ""),
        "tool_name": str(tool_name or ""),
        "approved_surface_hash": str(approved_surface_hash or ""),
        "current_surface_hash": str(current_surface_hash or ""),
        "diff_classification": classify_finding_types(finding_types),
        "finding_types": finding_types,
        "severity": str(severity or "none"),
        "decision": str(decision or "allow"),
    }


def build_drift_record_from_audit_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Build a drift record from an ``mcp_audit_log`` row, or None when the row
    carries no emittable drift evidence (no drift, or a historical row written
    before the surface-hash columns existed).
    """
    severity = str(row.get("drift_severity") or "none").lower()
    if severity in ("", "none"):
        return None
    baseline_hash = str(row.get("drift_baseline_hash") or "")
    current_hash = str(row.get("drift_current_hash") or "")
    if not baseline_hash or not current_hash:
        return None
    finding_types = row.get("drift_types") or []
    if isinstance(finding_types, str):
        try:
            finding_types = json.loads(finding_types)
        except (json.JSONDecodeError, TypeError):
            finding_types = []
    return build_drift_record(
        server_id=row.get("server_id") or "",
        tool_name=row.get("tool_name") or "",
        approved_surface_hash=baseline_hash,
        current_surface_hash=current_hash,
        finding_types=list(finding_types),
        severity=severity,
        decision=row.get("drift_action") or "allow",
    )


def build_evidence_ref(
    record: Dict[str, Any], ref: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build the evidenceRef envelope for a drift record.

    Shape follows the io.modelcontextprotocol/trust-annotations draft
    (2026-06-10): type, digest, and canonicalization are required; schema is a
    URL string identifying the record schema; ref is an optional audit:// URI
    locating the record in Interlock's receipt stream.
    """
    evidence_ref = {
        "type": EVIDENCE_TYPE,
        "digest": compute_digest(record),
        "canonicalization": CANONICALIZATION,
        "schema": SCHEMA_URL,
    }
    if ref:
        evidence_ref["ref"] = ref
    return evidence_ref


def build_effective_permission_record(
    probe_id: str,
    server_id: str,
    tool_name: str,
    argument_hash: str,
    expected_outcome: str,
    expected_status_code: Any,
    observed_outcome: str,
    observed_status_code: Any,
    observed_error_class: str,
    finding_types: List[str],
    severity: str,
    decision: str,
    created_at: str = "",
) -> Dict[str, Any]:
    """Build canonical behavioral scope-drift evidence."""
    finding_types = [str(t) for t in (finding_types or []) if str(t)]
    finding_type = finding_types[0] if finding_types else ""
    return {
        "record_type": EFFECTIVE_PERMISSION_SCHEMA_ID,
        "schema_version": EFFECTIVE_PERMISSION_SCHEMA_VERSION,
        "probe_id": str(probe_id or ""),
        "server_id": str(server_id or ""),
        "tool_name": str(tool_name or ""),
        "argument_hash": str(argument_hash or ""),
        "expected_outcome": str(expected_outcome or ""),
        "expected_status_code": (
            "" if expected_status_code is None else str(expected_status_code)
        ),
        "observed_outcome": str(observed_outcome or ""),
        "observed_status_code": (
            "" if observed_status_code is None else str(observed_status_code)
        ),
        "observed_error_class": str(observed_error_class or ""),
        "finding_type": finding_type,
        "diff_classification": classify_finding_types(finding_types),
        "finding_types": finding_types,
        "severity": str(severity or "none"),
        "decision": str(decision or "allow"),
        "created_at": str(created_at or ""),
    }


def build_effective_permission_record_from_audit_row(
    row: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Build probe evidence from an audit row when it carries probe data."""
    if not row.get("probe_id"):
        return None
    severity = str(row.get("drift_severity") or "none").lower()
    if severity in ("", "none"):
        return None
    finding_types = row.get("drift_types") or []
    if isinstance(finding_types, str):
        try:
            finding_types = json.loads(finding_types)
        except (json.JSONDecodeError, TypeError):
            finding_types = []
    return build_effective_permission_record(
        probe_id=row.get("probe_id") or "",
        server_id=row.get("server_id") or "",
        tool_name=row.get("tool_name") or "",
        argument_hash=row.get("argument_hash") or "",
        expected_outcome=row.get("expected_outcome") or "",
        expected_status_code=row.get("expected_status_code"),
        observed_outcome=row.get("observed_outcome") or "",
        observed_status_code=row.get("observed_status_code"),
        observed_error_class=row.get("observed_error_class") or "",
        finding_types=list(finding_types),
        severity=severity,
        decision=row.get("drift_action") or row.get("action") or "allow",
        created_at=row.get("ts") or "",
    )


def build_effective_permission_evidence_ref(
    record: Dict[str, Any], ref: Optional[str] = None
) -> Dict[str, Any]:
    evidence_ref = {
        "type": EFFECTIVE_PERMISSION_EVIDENCE_TYPE,
        "digest": compute_digest(record),
        "canonicalization": CANONICALIZATION,
        "schema": EFFECTIVE_PERMISSION_SCHEMA_URL,
    }
    if ref:
        evidence_ref["ref"] = ref
    return evidence_ref


def verify_effective_permission_record(
    record: Dict[str, Any], claimed_digest: str
) -> Dict[str, Any]:
    """Verify a canonical effective-permission drift evidence record."""
    if not isinstance(record, dict):
        return {
            "verified": False,
            "computed_digest": "",
            "reason": "record_not_an_object",
        }
    missing = [f for f in _EFFECTIVE_PERMISSION_RECORD_FIELDS if f not in record]
    if missing:
        return {
            "verified": False,
            "computed_digest": "",
            "reason": f"missing_fields:{','.join(missing)}",
        }
    try:
        computed = compute_digest(record)
    except CanonicalizationError as exc:
        return {"verified": False, "computed_digest": "", "reason": str(exc)}
    verified = computed == str(claimed_digest or "")
    return {
        "verified": verified,
        "computed_digest": computed,
        "reason": "verified" if verified else "digest_mismatch",
    }


def verify_drift_record(record: Dict[str, Any], claimed_digest: str) -> Dict[str, Any]:
    """
    Independently recompute a drift record's digest and compare to the claim.

    Returns {"verified": bool, "computed_digest": str, "reason": str}. Performs
    structural checks first so a malformed record fails loudly rather than
    silently hashing garbage.
    """
    if not isinstance(record, dict):
        return {
            "verified": False,
            "computed_digest": "",
            "reason": "record_not_an_object",
        }
    missing = [f for f in _RECORD_FIELDS if f not in record]
    if missing:
        return {
            "verified": False,
            "computed_digest": "",
            "reason": f"missing_fields:{','.join(missing)}",
        }
    try:
        computed = compute_digest(record)
    except CanonicalizationError as exc:
        return {"verified": False, "computed_digest": "", "reason": str(exc)}
    verified = computed == str(claimed_digest or "")
    return {
        "verified": verified,
        "computed_digest": computed,
        "reason": "verified" if verified else "digest_mismatch",
    }
