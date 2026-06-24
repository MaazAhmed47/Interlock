"""
Classify security-relevant drift in discovered MCP tool definitions.

The registry stores hashes, but hashes only answer "changed or not". This module
answers what changed, how risky it is, and what the gateway should do.
"""

import difflib
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from core.tool_inspector import DANGEROUS_FILES
from core.tool_metadata import normalize_tool_metadata

# ── Description-exfiltration detection (added-text conjunction) ────────────────
# A description rug-pull adds an instruction that (S) touches a sensitive
# resource AND ships it to an (external) destination via an (egress) action.
# Detection is strictly conjunctive and runs only on the ADDED text, so a benign
# reword (no added signal) and a benign doc-link (external dest but no egress
# verb and no sensitive path) both stay minor.

# (S) sensitive-resource paths — reuse the vetted, path-anchored set from the
# tool-call inspector rather than re-deriving fragile patterns here.
SENSITIVE_PATH_PATTERNS = list(DANGEROUS_FILES)

# Credential / key / secret material: presence in an exfil conjunction is
# critical (quarantine) rather than high (deny).
CRITICAL_RESOURCE_PATTERNS = [
    r"~/\.?ssh/",
    r"\.ssh/",
    r"id_(rsa|dsa|ecdsa|ed25519)\b",
    r"~/\.aws/",
    r"\.aws/credentials",
    r"private[-_]key",
    r"\.pem\b",
    r"\.key\b",
    r"\.p12\b",
    r"\.pfx\b",
    r"credentials\.json",
    r"\.env\b",
    r"/etc/shadow",
    r"\.htpasswd",
    r"api[-_]key",
    r"\bsecret\b",
    r"\bpassword\b",
]

# (egress) word-boundary action tokens — never substring matches, so "url"
# inside "curl" cannot trigger anything (the externality accident we found).
EGRESS_VERB_PATTERNS = [
    r"\bcurl\b",
    r"\bwget\b",
    r"\bscp\b",
    r"\bsftp\b",
    r"\bnc\b",
    r"\bncat\b",
    r"\bnetcat\b",
    r"\bfetch\b",
    r"\bpost\b",
    r"\bput\b",
    r"\bupload\b",
    r"\bforward\b",
    r"\bexfiltrate\b",
    r"\bexfil\b",
    r"\btransmit\b",
    r"\bsend\b",
    r"\bbeacon\b",
    r"\bpost-data\b",
    r"\binvoke-webrequest\b",
    r"\biwr\b",
]

DELIVERY_CONTEXT_PATTERNS = [
    r"\bpayload\b",
    r"\brequest body\b",
    r"\bcopy\b",
    r"\bdiagnostics?\b",
    r"\bbackup\b",
    r"\barchive\b",
]

# Hosts that are NOT an external destination (loopback, RFC-1918, link-local,
# cloud metadata, *.local / *.internal).
_INTERNAL_HOST_PATTERNS = [
    r"^localhost$",
    r"^127\.\d+\.\d+\.\d+$",
    r"^10\.\d+\.\d+\.\d+$",
    r"^192\.168\.\d+\.\d+$",
    r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$",
    r"^169\.254\.\d+\.\d+$",
    r"^0\.0\.0\.0$",
    r".*\.local$",
    r".*\.internal$",
    r"^metadata\.",
    r"^host\.docker\.internal$",
    r"^kubernetes\.default(\.svc)?$",
]

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
        # A description text change carries no capability/schema signal on its
        # own — it is minor by default (logged, not escalated), so meaning-
        # preserving rewords stop being false positives. Danger lives in the
        # CONTENT of what was added, handled by the exfiltration check below.
        findings.append(
            _finding("description_changed", "minor", "Tool description changed.")
        )
        exfil = _detect_description_exfiltration(prev_description, curr_description)
        if exfil is not None:
            findings.append(exfil)

    prev_fields = _schema_fields(previous_tool)
    curr_fields = _schema_fields(current_tool)
    added_fields = sorted(curr_fields - prev_fields)
    removed_fields = sorted(prev_fields - curr_fields)

    # A same-type, same-required add+remove pair is ONE rename, not a field
    # addition + removal (+ a synthesized required-field change). Without this, a
    # benign rename of a required field is wrongly denied.
    renames = _detect_renames(previous_tool, current_tool, added_fields, removed_fields)
    renamed_old = {old for old, _ in renames}
    renamed_new = {new for _, new in renames}
    effective_added = [f for f in added_fields if f not in renamed_new]
    effective_removed = [f for f in removed_fields if f not in renamed_old]

    for old, new in renames:
        findings.append(
            _finding("field_renamed", "moderate", f"Field renamed: {old} -> {new}.")
        )
    if effective_added:
        # A new field appearing is minor by itself: a new OPTIONAL field is a
        # backward-compatible addition. A new REQUIRED field is escalated by the
        # independent required_field_added finding (high), and a sensitive name
        # by sensitive_field_added (high) — so this floor never masks them.
        findings.append(
            _finding(
                "schema_field_added",
                "minor",
                f"Schema fields added: {effective_added}.",
            )
        )
    if effective_removed:
        findings.append(
            _finding(
                "schema_field_removed",
                "moderate",
                f"Schema fields removed: {effective_removed}.",
            )
        )

    prev_required = _schema_required(previous_tool)
    curr_required = _schema_required(current_tool)
    added_required = sorted((curr_required - prev_required) - renamed_new)
    removed_required = sorted((prev_required - curr_required) - renamed_old)
    if added_required:
        findings.append(
            _finding(
                "required_field_added",
                "high",
                f"Required schema fields added: {added_required}.",
            )
        )
    if removed_required:
        findings.append(
            _finding(
                "required_field_removed",
                "high",
                f"Required schema fields removed: {removed_required}. "
                "A safety/approval gate may have been dropped.",
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

    # Constraint relaxation on a field whose name and type did not change:
    # enum/const widening, looser numeric/length bounds, dropped pattern, or
    # opened additionalProperties. Tightening emits nothing.
    findings.extend(_constraint_widenings(previous_tool, current_tool))

    sensitive_added = [field for field in added_fields if _is_sensitive_field(field)]
    if sensitive_added:
        findings.append(
            _finding(
                "sensitive_field_added",
                "high",
                f"Sensitive schema fields added: {sensitive_added}.",
            )
        )

    # Fields whose current value is only heuristically inferred (no declared
    # source). Low-confidence inference must not, on its own, drive a deny.
    curr_inferred = set(current_metadata.get("inferred") or [])

    prev_effects = set(previous_metadata.get("effects") or [])
    curr_effects = set(current_metadata.get("effects") or [])
    added_effects = sorted(curr_effects - prev_effects)
    critical_added_effects = [
        effect for effect in added_effects if effect in CRITICAL_EFFECTS
    ]
    if critical_added_effects:
        severity = "moderate" if "effects" in curr_inferred else "critical"
        findings.append(
            _finding(
                "effect_escalated",
                severity,
                f"High-risk effects added: {critical_added_effects}.",
            )
        )
    elif added_effects:
        severity = "moderate" if "effects" in curr_inferred else "high"
        findings.append(
            _finding(
                "effect_escalated",
                severity,
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
        severity = "moderate" if "data_classes" in curr_inferred else "high"
        findings.append(
            _finding(
                "data_class_escalated",
                severity,
                f"Sensitive data classes added: {sensitive_data_added}.",
            )
        )
    elif added_data_classes and "data_classes" not in curr_inferred:
        # Only DECLARED non-sensitive data-class additions are a real signal.
        # A merely INFERRED non-sensitive delta (e.g. a meaning-preserving
        # description reword that the heuristic reads differently) carries no
        # capability signal and must not, on its own, drive an escalation —
        # same principle as the effects branch above.
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
        if "side_effect" in curr_inferred:
            severity = "moderate"
        else:
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
        severity = "moderate" if "externality" in curr_inferred else "high"
        findings.append(
            _finding(
                "externality_escalated",
                severity,
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


def _added_tool_destructive_reason(tool_def: Optional[dict]) -> Optional[str]:
    """Return a reason string when a newly-added tool carries destructive or
    exfiltration capability, else None. The caller establishes *newness* against
    the baseline; this judges only the capability of the new definition.

    Signals (any one is sufficient):
      - the tool self-declares ``destructiveHint`` true;
      - the heuristic metadata verdict resolves ``side_effect`` to ``destructive``
        from the name/description verbs — this corroborates (or stands in for) the
        annotation, so a server cannot evade purely by omitting ``destructiveHint``;
      - the description conjunctively instructs exfiltration of a sensitive
        resource to an external destination.

    Official MCP annotations are hints, not contracts, which is why the heuristic
    verdict is treated as an equal, independent signal here.
    """
    if not isinstance(tool_def, dict):
        return None
    annotations = tool_def.get("annotations") or {}
    if annotations.get("destructiveHint") is True:
        return "self-declares destructiveHint=true"

    metadata = normalize_tool_metadata(tool_def)
    if metadata.get("side_effect") == "destructive":
        return "its name/description resolve to a destructive side effect"

    exfil = _detect_description_exfiltration("", str(tool_def.get("description") or ""))
    if exfil is not None:
        return exfil["reason"]
    return None


def classify_server_drift(
    server_id: str,
    prev_tool_names: Set[str],
    curr_tool_names: Set[str],
    curr_tool_defs: Optional[Dict[str, dict]] = None,
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
    curr_tool_defs = curr_tool_defs or {}
    for tool in sorted(curr_tool_names - prev_tool_names):
        # A new capability appearing on a previously-baselined server is the
        # rug-pull case the drift engine exists to catch. Default to "high"
        # (verify against registry); escalate to "critical" when the newcomer can
        # destroy or exfiltrate, so it is quarantined before any agent can use it.
        destructive_reason = _added_tool_destructive_reason(curr_tool_defs.get(tool))
        if destructive_reason:
            findings.append(
                {
                    "type": "tool_added",
                    "severity": "critical",
                    "tool_name": tool,
                    "reason": (
                        f"New tool '{tool}' appeared on server '{server_id}' and "
                        f"{destructive_reason}. Quarantined pending operator review."
                    ),
                }
            )
        else:
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
    """Return the input schema for backward-compatible callers."""
    schema = _schema_from_keys(tool, ("inputSchema", "input_schema"))
    return schema if isinstance(schema, dict) else {}


def _schema_from_keys(tool: dict, keys: Iterable[str]) -> dict:
    if not isinstance(tool, dict):
        return {}
    for key in keys:
        schema = tool.get(key)
        if isinstance(schema, dict):
            return schema
    return {}


def _schema_sections(tool: dict) -> Dict[str, dict]:
    sections = {"input": _schema(tool)}
    output = _schema_from_keys(tool, ("outputSchema", "output_schema"))
    if output:
        sections["output"] = output
    return sections


def _schema_fields(tool: dict) -> Set[str]:
    names: Set[str] = set()
    for label, schema in _schema_sections(tool).items():
        names.update(_schema_field_names(schema, label))
    return names


def _schema_required(tool: dict) -> Set[str]:
    required: Set[str] = set()
    for label, schema in _schema_sections(tool).items():
        required.update(_schema_required_names(schema, label))
    return required


def _schema_field_types(tool: dict) -> Dict[str, str]:
    types: Dict[str, str] = {}
    for label, schema in _schema_sections(tool).items():
        types.update(_schema_field_types_from_schema(schema, label))
    return types


def _join_schema_path(prefix: str, name: str) -> str:
    return f"{prefix}.{name}" if prefix else name


def _schema_field_names(schema: Any, prefix: str = "") -> Set[str]:
    names: Set[str] = set()
    if not isinstance(schema, dict):
        return names
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            path = _join_schema_path(prefix, str(name).lower())
            names.add(path)
            names.update(_schema_field_names(child, path))
    for key in ("items", "oneOf", "anyOf", "allOf"):
        child = schema.get(key)
        if isinstance(child, dict):
            names.update(_schema_field_names(child, prefix))
        elif isinstance(child, list):
            for item in child:
                names.update(_schema_field_names(item, prefix))
    return names


def _schema_required_names(schema: Any, prefix: str = "") -> Set[str]:
    names: Set[str] = set()
    if not isinstance(schema, dict):
        return names

    raw_required = schema.get("required", [])
    required = (
        {str(value).lower() for value in raw_required}
        if isinstance(raw_required, list)
        else set()
    )
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            normalized = str(name).lower()
            path = _join_schema_path(prefix, normalized)
            if normalized in required:
                names.add(path)
            names.update(_schema_required_names(child, path))

    for key in ("items", "oneOf", "anyOf", "allOf"):
        child = schema.get(key)
        if isinstance(child, dict):
            names.update(_schema_required_names(child, prefix))
        elif isinstance(child, list):
            for item in child:
                names.update(_schema_required_names(item, prefix))
    return names


def _schema_field_types_from_schema(schema: Any, prefix: str = "") -> Dict[str, str]:
    types: Dict[str, str] = {}
    if not isinstance(schema, dict):
        return types

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            path = _join_schema_path(prefix, str(name).lower())
            if isinstance(child, dict):
                if child.get("type"):
                    types[path] = str(child.get("type"))
                types.update(_schema_field_types_from_schema(child, path))

    for key in ("items", "oneOf", "anyOf", "allOf"):
        child = schema.get(key)
        if isinstance(child, dict):
            types.update(_schema_field_types_from_schema(child, prefix))
        elif isinstance(child, list):
            for item in child:
                types.update(_schema_field_types_from_schema(item, prefix))
    return types


def _schema_properties(schema: Any, prefix: str = "") -> Dict[str, dict]:
    props: Dict[str, dict] = {}
    if not isinstance(schema, dict):
        return props

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            path = _join_schema_path(prefix, str(name).lower())
            if isinstance(child, dict):
                props[path] = child
                props.update(_schema_properties(child, path))

    for key in ("items", "oneOf", "anyOf", "allOf"):
        child = schema.get(key)
        if isinstance(child, dict):
            props.update(_schema_properties(child, prefix))
        elif isinstance(child, list):
            for item in child:
                props.update(_schema_properties(item, prefix))
    return props


def _detect_renames(
    previous_tool: dict,
    current_tool: dict,
    added_fields: List[str],
    removed_fields: List[str],
) -> List[tuple]:
    """Pair a removed and an added top-level field with identical type and
    required-status as a single rename. Conservative: only same-signature pairs
    match, so a rename collapses to one change rather than add+remove+required
    churn. Sensitive-field detection stays on the full added set, so a rename
    *to* a sensitive name is still flagged elsewhere."""
    prev_types = _schema_field_types(previous_tool)
    curr_types = _schema_field_types(current_tool)
    prev_required = _schema_required(previous_tool)
    curr_required = _schema_required(current_tool)
    renames: List[tuple] = []
    used: Set[str] = set()
    for old in removed_fields:
        if old not in prev_types:
            continue
        old_sig = (prev_types[old], old in prev_required)
        for new in added_fields:
            if new in used or new not in curr_types:
                continue
            if (curr_types[new], new in curr_required) == old_sig:
                renames.append((old, new))
                used.add(new)
                break
    return renames


def _num(value: Any):
    if isinstance(value, bool):
        return None
    return value if isinstance(value, (int, float)) else None


def _allowed_values(prop: dict):
    """Return the closed value set of a property (enum, or single-value const),
    or None when the property is unconstrained."""
    enum = prop.get("enum")
    if isinstance(enum, list):
        return [str(v) for v in enum]
    if "const" in prop:
        return [str(prop["const"])]
    return None


def _constraint_widenings(
    previous_tool: dict, current_tool: dict
) -> List[Dict[str, str]]:
    """Detect constraint RELAXATION on shared top-level properties: enum/const
    widening (high — expands the allowed operations), and looser numeric/length
    bounds, dropped pattern, or opened additionalProperties (moderate)."""
    prev_sections = _schema_sections(previous_tool)
    curr_sections = _schema_sections(current_tool)
    prev_props: Dict[str, dict] = {}
    curr_props: Dict[str, dict] = {}
    for label, schema in prev_sections.items():
        prev_props.update(_schema_properties(schema, label))
    for label, schema in curr_sections.items():
        curr_props.update(_schema_properties(schema, label))
    findings: List[Dict[str, str]] = []

    if isinstance(prev_props, dict) and isinstance(curr_props, dict):
        for name in sorted(set(prev_props) & set(curr_props)):
            prev_p = prev_props.get(name)
            curr_p = curr_props.get(name)
            if not isinstance(prev_p, dict) or not isinstance(curr_p, dict):
                continue
            high: List[str] = []
            moderate: List[str] = []

            prev_allowed = _allowed_values(prev_p)
            curr_allowed = _allowed_values(curr_p)
            if prev_allowed is not None:
                if curr_allowed is None:
                    high.append(f"'{name}' enum/const constraint removed")
                elif set(curr_allowed) > set(prev_allowed):
                    added = sorted(set(curr_allowed) - set(prev_allowed))
                    high.append(f"'{name}' enum widened to include {added}")

            prev_max = _num(prev_p.get("maximum"))
            if prev_max is not None:
                if "maximum" not in curr_p:
                    moderate.append(f"'{name}' maximum bound removed")
                elif (
                    _num(curr_p.get("maximum")) is not None
                    and _num(curr_p["maximum"]) > prev_max
                ):
                    moderate.append(f"'{name}' maximum bound raised")

            prev_min = _num(prev_p.get("minimum"))
            if prev_min is not None:
                if "minimum" not in curr_p:
                    moderate.append(f"'{name}' minimum bound removed")
                elif (
                    _num(curr_p.get("minimum")) is not None
                    and _num(curr_p["minimum"]) < prev_min
                ):
                    moderate.append(f"'{name}' minimum bound lowered")

            prev_ml = _num(prev_p.get("maxLength"))
            if prev_ml is not None:
                if "maxLength" not in curr_p:
                    moderate.append(f"'{name}' maxLength removed")
                elif (
                    _num(curr_p.get("maxLength")) is not None
                    and _num(curr_p["maxLength"]) > prev_ml
                ):
                    moderate.append(f"'{name}' maxLength raised")

            if prev_p.get("pattern") and curr_p.get("pattern") != prev_p.get("pattern"):
                moderate.append(f"'{name}' pattern relaxed or removed")

            if (
                prev_p.get("additionalProperties") is False
                and curr_p.get("additionalProperties") is not False
            ):
                moderate.append(f"'{name}' additionalProperties opened")

            if high:
                findings.append(
                    _finding("constraint_relaxed", "high", "; ".join(high) + ".")
                )
            elif moderate:
                findings.append(
                    _finding(
                        "constraint_relaxed", "moderate", "; ".join(moderate) + "."
                    )
                )

    for label in sorted(set(prev_sections) & set(curr_sections)):
        prev_schema = prev_sections[label]
        curr_schema = curr_sections[label]
        if (
            prev_schema.get("additionalProperties") is False
            and curr_schema.get("additionalProperties") is not False
        ):
            findings.append(
                _finding(
                    "constraint_relaxed",
                    "moderate",
                    f"{label} schema additionalProperties opened to accept arbitrary fields.",
                )
            )
    return findings


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


def _added_description_text(prev_desc: str, curr_desc: str) -> str:
    """Return only the text present in curr but not in prev (the inserted /
    replaced segments). A reword reshuffles already-approved tokens and adds
    little; an injection appends new instructions."""
    matcher = difflib.SequenceMatcher(None, prev_desc, curr_desc)
    parts: List[str] = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            parts.append(curr_desc[j1:j2])
    return " ".join(parts)


def _search_any(text: str, patterns: Iterable[str]):
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


def _is_internal_host(host: str) -> bool:
    host = host.split(":")[0].strip().lower()
    return any(re.match(p, host) for p in _INTERNAL_HOST_PATTERNS)


def _external_destination(text: str) -> Optional[str]:
    """Return an external network destination found in text, or None. A URL to
    an internal/loopback/metadata host does not count; neither does a bare word.
    Used only inside the conjunction, so a lone doc-link never escalates."""
    for m in re.finditer(r"https?://([^\s/\"'>)]+)", text, re.IGNORECASE):
        if not _is_internal_host(m.group(1)):
            return m.group(0)
    for m in re.finditer(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", text, re.IGNORECASE):
        return m.group(0)
    return None


def _detect_description_exfiltration(
    prev_desc: str, curr_desc: str
) -> Optional[Dict[str, str]]:
    """Escalate a description change ONLY when its added text conjunctively
    instructs (S) accessing a sensitive resource, via an (egress) action, to an
    (external) destination. Each signal alone is insufficient — that keeps
    rewords and doc-links minor."""
    added = _added_description_text(prev_desc, curr_desc)
    if not added:
        return None
    sensitive = _search_any(added, SENSITIVE_PATH_PATTERNS)
    if not sensitive:
        return None
    egress = _search_any(added, EGRESS_VERB_PATTERNS)
    if not egress:
        egress = _search_any(added, DELIVERY_CONTEXT_PATTERNS)
    if not egress:
        return None
    destination = _external_destination(added)
    if not destination:
        return None
    is_critical = _search_any(added, CRITICAL_RESOURCE_PATTERNS) is not None
    severity = "critical" if is_critical else "high"
    return _finding(
        "description_exfiltration",
        severity,
        (
            "Description now instructs accessing a sensitive resource "
            f"('{sensitive}') and sending it to an external destination "
            f"('{destination}'). This was not in the approved description."
        ),
    )


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
