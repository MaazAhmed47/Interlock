"""
Classify security-relevant drift in discovered MCP tool definitions.

The registry stores hashes, but hashes only answer "changed or not". This module
answers what changed, how risky it is, and what the gateway should do.
"""

import difflib
from typing import Any, Dict, Iterable, List, Set

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

SENSITIVE_FIELD_TOKENS = {
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "credential",
    "private_key",
    "ssn",
    "social_security",
    "diagnosis",
    "patient",
    "medical",
    "phi",
    "email",
    "phone",
    "bank",
    "account",
}
SENSITIVE_DATA_CLASSES = {"pii", "phi", "financial", "legal", "secrets"}
HIGH_RISK_SCOPE_TOKENS = {
    "write",
    "delete",
    "share",
    "export",
    "admin",
    "execute",
    "send",
    "message",
    "create",
    "update",
    "modify",
}
CRITICAL_EFFECTS = {"execute", "delete", "share", "export"}
SIDE_EFFECT_RANK = {"unknown": 0, "read_only": 1, "mutating": 2, "destructive": 3}
EXTERNALITY_RANK = {"unknown": 0, "internal": 1, "external": 2}
IDENTITY_RANK = {
    "unknown": 0,
    "authenticated_user": 1,
    "delegated_agent": 2,
    "service_account": 3,
}
VERIFICATION_RANK = {
    "unknown": 0,
    "heuristic": 1,
    "mcp_annotations": 2,
    "security_meta": 3,
    "interlock_meta": 4,
}


def classify_tool_drift(
    previous_tool: dict,
    current_tool: dict,
    previous_metadata: dict,
    current_metadata: dict,
) -> Dict[str, Any]:
    """Classify drift between prior and current MCP tool definitions."""
    previous_tool = previous_tool or {}
    current_tool = current_tool or {}
    previous_metadata = previous_metadata or {}
    current_metadata = current_metadata or {}

    findings: List[Dict[str, Any]] = []

    prev_description = str(previous_tool.get("description") or "")
    curr_description = str(current_tool.get("description") or "")
    if prev_description != curr_description:
        ratio = difflib.SequenceMatcher(
            None, prev_description, curr_description
        ).ratio()
        if (1.0 - ratio) > 0.30:
            findings.append(
                _finding(
                    "description_changed",
                    "moderate",
                    f"Tool description changed significantly ({round((1.0 - ratio) * 100)}% different).",
                )
            )
        else:
            findings.append(
                _finding("description_changed", "minor", "Tool description changed.")
            )

    prev_fields = _schema_fields(previous_tool)
    curr_fields = _schema_fields(current_tool)
    added_fields = sorted(curr_fields - prev_fields)
    removed_fields = sorted(prev_fields - curr_fields)

    if added_fields:
        findings.append(
            _finding(
                "schema_field_added",
                "moderate",
                f"Schema fields added: {added_fields}.",
            )
        )
    if removed_fields:
        findings.append(
            _finding(
                "schema_field_removed",
                "moderate",
                f"Schema fields removed: {removed_fields}.",
            )
        )

    prev_required = _schema_required(previous_tool)
    curr_required = _schema_required(current_tool)
    added_required = sorted(curr_required - prev_required)
    if added_required:
        findings.append(
            _finding(
                "required_field_added",
                "high",
                f"Required schema fields added: {added_required}.",
            )
        )

    prev_types = _schema_field_types(previous_tool)
    curr_types = _schema_field_types(current_tool)
    type_changed = sorted(
        field
        for field in (prev_types.keys() & curr_types.keys())
        if prev_types[field] != curr_types[field]
    )
    if type_changed:
        findings.append(
            _finding(
                "param_type_changed",
                "moderate",
                f"Parameter type changed for fields: {type_changed}.",
            )
        )

    sensitive_added = [field for field in added_fields if _is_sensitive_field(field)]
    if sensitive_added:
        findings.append(
            _finding(
                "sensitive_field_added",
                "high",
                f"Sensitive schema fields added: {sensitive_added}.",
            )
        )

    prev_effects = set(previous_metadata.get("effects") or [])
    curr_effects = set(current_metadata.get("effects") or [])
    added_effects = sorted(curr_effects - prev_effects)
    critical_added_effects = [
        effect for effect in added_effects if effect in CRITICAL_EFFECTS
    ]
    if critical_added_effects:
        findings.append(
            _finding(
                "effect_escalated",
                "critical",
                f"High-risk effects added: {critical_added_effects}.",
            )
        )
    elif added_effects:
        findings.append(
            _finding(
                "effect_escalated",
                "high",
                f"Tool effects expanded: {added_effects}.",
            )
        )

    prev_data_classes = set(previous_metadata.get("data_classes") or [])
    curr_data_classes = set(current_metadata.get("data_classes") or [])
    added_data_classes = sorted(curr_data_classes - prev_data_classes)
    sensitive_data_added = [
        value for value in added_data_classes if value in SENSITIVE_DATA_CLASSES
    ]
    if sensitive_data_added:
        findings.append(
            _finding(
                "data_class_escalated",
                "high",
                f"Sensitive data classes added: {sensitive_data_added}.",
            )
        )
    elif added_data_classes:
        findings.append(
            _finding(
                "data_class_escalated",
                "moderate",
                f"Data classes added: {added_data_classes}.",
            )
        )

    prev_side = previous_metadata.get("side_effect") or "unknown"
    curr_side = current_metadata.get("side_effect") or "unknown"
    if SIDE_EFFECT_RANK.get(curr_side, 0) > SIDE_EFFECT_RANK.get(prev_side, 0):
        severity = "critical" if curr_side == "destructive" else "high"
        findings.append(
            _finding(
                "side_effect_escalated",
                severity,
                f"Side effect escalated from {prev_side} to {curr_side}.",
            )
        )

    prev_externality = previous_metadata.get("externality") or "unknown"
    curr_externality = current_metadata.get("externality") or "unknown"
    if EXTERNALITY_RANK.get(curr_externality, 0) > EXTERNALITY_RANK.get(
        prev_externality, 0
    ):
        findings.append(
            _finding(
                "externality_escalated",
                "high",
                f"Externality escalated from {prev_externality} to {curr_externality}.",
            )
        )

    prev_identity = previous_metadata.get("identity_mode") or "unknown"
    curr_identity = current_metadata.get("identity_mode") or "unknown"
    if IDENTITY_RANK.get(curr_identity, 0) > IDENTITY_RANK.get(prev_identity, 0):
        severity = (
            "high"
            if curr_identity in {"delegated_agent", "service_account"}
            else "moderate"
        )
        findings.append(
            _finding(
                "identity_mode_escalated",
                severity,
                f"Identity mode escalated from {prev_identity} to {curr_identity}.",
            )
        )

    prev_scopes = _normalized_set(previous_metadata.get("required_scopes") or [])
    curr_scopes = _normalized_set(current_metadata.get("required_scopes") or [])
    added_scopes = sorted(curr_scopes - prev_scopes)
    if added_scopes:
        severity = (
            "high"
            if any(_is_high_risk_scope(scope) for scope in added_scopes)
            else "moderate"
        )
        findings.append(
            _finding(
                "scope_escalated",
                severity,
                f"Required scopes added: {added_scopes}.",
            )
        )

    prev_verification = previous_metadata.get("verification_level") or "unknown"
    curr_verification = current_metadata.get("verification_level") or "unknown"
    if VERIFICATION_RANK.get(curr_verification, 0) < VERIFICATION_RANK.get(
        prev_verification, 0
    ):
        findings.append(
            _finding(
                "metadata_downgraded",
                "high",
                f"Metadata verification downgraded from {prev_verification} to {curr_verification}.",
            )
        )

    severity = _max_severity(f["severity"] for f in findings)
    return {
        "severity": severity,
        "action": ACTION_BY_SEVERITY[severity],
        "types": _ordered_unique(f["type"] for f in findings),
        "reasons": [f["reason"] for f in findings],
        "findings": findings,
    }


def classify_server_drift(
    server_id: str,
    prev_tool_names: Set[str],
    curr_tool_names: Set[str],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for tool in sorted(prev_tool_names - curr_tool_names):
        findings.append(
            {
                "type": "tool_removed",
                "severity": "critical",
                "tool_name": tool,
                "reason": (
                    f"Tool '{tool}' was removed from server '{server_id}'. "
                    "Could indicate supply chain compromise."
                ),
            }
        )
    for tool in sorted(curr_tool_names - prev_tool_names):
        findings.append(
            {
                "type": "tool_added",
                "severity": "high",
                "tool_name": tool,
                "reason": (
                    f"New tool '{tool}' appeared on server '{server_id}'. "
                    "Verify against registry."
                ),
            }
        )
    return findings


def _schema(tool: dict) -> dict:
    schema = tool.get("inputSchema", {}) or tool.get("input_schema", {}) or {}
    return schema if isinstance(schema, dict) else {}


def _schema_fields(tool: dict) -> Set[str]:
    return _schema_field_names(_schema(tool))


def _schema_required(tool: dict) -> Set[str]:
    required = _schema(tool).get("required", [])
    if not isinstance(required, list):
        return set()
    return {str(value).lower() for value in required}


def _schema_field_types(tool: dict) -> Dict[str, str]:
    schema = _schema(tool)
    properties = schema.get("properties") or {}
    if not isinstance(properties, dict):
        return {}
    return {
        str(name).lower(): str(prop.get("type", ""))
        for name, prop in properties.items()
        if isinstance(prop, dict) and prop.get("type")
    }


def _schema_field_names(schema: Any) -> Set[str]:
    names: Set[str] = set()
    if not isinstance(schema, dict):
        return names
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            names.add(str(name).lower())
            names.update(_schema_field_names(child))
    for key in ("items", "oneOf", "anyOf", "allOf"):
        child = schema.get(key)
        if isinstance(child, dict):
            names.update(_schema_field_names(child))
        elif isinstance(child, list):
            for item in child:
                names.update(_schema_field_names(item))
    return names


def _is_sensitive_field(field: str) -> bool:
    normalized = field.lower().replace("-", "_")
    return any(token in normalized for token in SENSITIVE_FIELD_TOKENS)


def _is_high_risk_scope(scope: str) -> bool:
    normalized = scope.lower().replace("-", "_")
    return any(token in normalized for token in HIGH_RISK_SCOPE_TOKENS)


def _normalized_set(values: Any) -> Set[str]:
    if not isinstance(values, list):
        return set()
    return {
        str(value).strip().lower().replace("-", "_")
        for value in values
        if str(value).strip()
    }


def _finding(kind: str, severity: str, reason: str) -> Dict[str, str]:
    return {"type": kind, "severity": severity, "reason": reason}


def _max_severity(severities: Iterable[str]) -> str:
    max_seen = "none"
    for severity in severities:
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[max_seen]:
            max_seen = severity
    return max_seen


def _ordered_unique(values: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
