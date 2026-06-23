

"""
Normalize MCP tool metadata into Interlock's internal policy vocabulary.

Official MCP annotations are useful hints, but they are not security contracts.
This module preserves that distinction by recording source, verification level,
confidence, and warnings whenever metadata is inferred or inconsistent.
"""
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

VALID_EFFECTS = {
    "read",
    "create",
    "update",
    "delete",
    "share",
    "export",
    "message",
    "execute",
}
VALID_SIDE_EFFECTS = {"read_only", "mutating", "destructive", "unknown"}
VALID_DATA_CLASSES = {
    "pii",
    "phi",
    "financial",
    "legal",
    "secrets",
    "user_content",
    "internal",
}
VALID_EXTERNALITY = {"internal", "external", "unknown"}
VALID_IDENTITY_MODES = {
    "authenticated_user",
    "service_account",
    "delegated_agent",
    "unknown",
}

SOURCE_INTERLOCK = "interlock_meta"
SOURCE_SECURITY = "security_meta"
SOURCE_MCP = "mcp_annotations"
SOURCE_HEURISTIC = "heuristic"
SOURCE_UNKNOWN = "unknown"


@dataclass
class ToolMetadata:
    effects: List[str] = field(default_factory=list)
    side_effect: str = "unknown"
    data_classes: List[str] = field(default_factory=list)
    externality: str = "unknown"
    identity_mode: str = "unknown"
    required_scopes: List[str] = field(default_factory=list)
    source: str = SOURCE_UNKNOWN
    verification_level: str = SOURCE_UNKNOWN
    confidence: float = 0.0
    warnings: List[str] = field(default_factory=list)
    # Fields whose final value came only from heuristic inference (no declared
    # source). Consumers use this to avoid letting low-confidence inference, on
    # its own, drive a hard decision such as deny.
    inferred: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["effects"] = _ordered_unique(data["effects"])
        data["data_classes"] = _ordered_unique(data["data_classes"])
        data["required_scopes"] = _ordered_unique(data["required_scopes"])
        data["warnings"] = _ordered_unique(data["warnings"])
        data["inferred"] = _ordered_unique(data["inferred"])
        return data


def normalize_tool_metadata(tool: dict) -> Dict[str, Any]:
    """Return normalized, explainable metadata for an MCP tool definition."""
    tool = tool or {}
    heuristic = _infer_from_tool_shape(tool)
    annotations = _parse_mcp_annotations(tool.get("annotations") or {})
    security_meta = _parse_meta_block(tool, "security")
    interlock_meta = _parse_meta_block(tool, "interlock")

    sources = [
        (SOURCE_INTERLOCK, interlock_meta, 0.95),
        (SOURCE_SECURITY, security_meta, 0.85),
        (SOURCE_MCP, annotations, 0.75),
        (SOURCE_HEURISTIC, heuristic, 0.55),
    ]

    strongest_source = SOURCE_UNKNOWN
    for source, partial, _confidence in sources:
        if _has_signal(partial):
            strongest_source = source
            break

    output = ToolMetadata(
        source=strongest_source,
        verification_level=strongest_source,
        confidence=_confidence_for_source(strongest_source),
    )

    for _source, partial, _confidence in sources:
        _merge_missing(output, partial)

    warnings: List[str] = []
    for _source, partial, _confidence in sources:
        warnings.extend(partial.get("warnings", []))

    if strongest_source == SOURCE_HEURISTIC:
        warnings.append(
            "Metadata missing; inferred from tool name, description, and schema."
        )
    elif strongest_source == SOURCE_UNKNOWN:
        warnings.append("No tool metadata or reliable inference was available.")
    elif _has_signal(heuristic):
        warnings.append(
            "Some missing metadata fields were inferred from tool name, description, and schema."
        )

    warnings.extend(
        _detect_conflicts(
            tool, output, heuristic, annotations, security_meta, interlock_meta
        )
    )
    output.warnings = _ordered_unique(warnings)

    if not output.effects:
        output.effects = ["read"] if output.side_effect == "read_only" else []
    if not output.data_classes:
        output.data_classes = []
    if output.side_effect == "unknown":
        output.side_effect = _side_effect_from_effects(output.effects)

    # Per-field provenance: mark fields that no declared source (interlock /
    # security / MCP annotations) supplied, so a value present only because the
    # heuristic inferred it is flagged as low-confidence.
    declared_partials = [interlock_meta, security_meta, annotations]
    for f in (
        "effects",
        "data_classes",
        "externality",
        "side_effect",
        "identity_mode",
        "required_scopes",
    ):
        value = getattr(output, f)
        if value in (None, [], "", "unknown"):
            continue
        declared = any(
            partial.get(f) not in (None, [], "", "unknown")
            for partial in declared_partials
        )
        if not declared:
            output.inferred.append(f)

    return output.to_dict()


def _parse_mcp_annotations(annotations: dict) -> Dict[str, Any]:
    if not isinstance(annotations, dict) or not annotations:
        return {}

    partial: Dict[str, Any] = {"warnings": []}
    read_only = annotations.get("readOnlyHint")
    destructive = annotations.get("destructiveHint")
    open_world = annotations.get("openWorldHint")

    if read_only is True:
        partial["side_effect"] = "read_only"
        partial["effects"] = ["read"]
    elif read_only is False and destructive is True:
        partial["side_effect"] = "destructive"
    elif read_only is False and destructive is False:
        partial["side_effect"] = "mutating"
    elif destructive is True:
        partial["side_effect"] = "destructive"
    elif destructive is False:
        partial["side_effect"] = "mutating"

    if open_world is True:
        partial["externality"] = "external"
    elif open_world is False:
        partial["externality"] = "internal"

    partial["mcp_hints"] = {
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": annotations.get("idempotentHint"),
        "openWorldHint": open_world,
    }
    partial["warnings"].append(
        "Official MCP annotations are treated as hints, not security contracts."
    )
    return partial


def _parse_meta_block(tool: dict, namespace: str) -> Dict[str, Any]:
    meta = tool.get("_meta") or {}
    if not isinstance(meta, dict):
        return {}

    nested = meta.get(namespace)
    if not isinstance(nested, dict):
        nested = {}

    block = dict(nested)
    dotted_prefix = f"{namespace}."
    for key, value in meta.items():
        if isinstance(key, str) and key.startswith(dotted_prefix):
            block[key[len(dotted_prefix) :]] = value

    if namespace == "interlock":
        for key, value in meta.items():
            if isinstance(key, str) and key.endswith(".requiredScopes"):
                block.setdefault("requiredScopes", value)

    if not block:
        return {}

    partial = {
        "effects": _clean_list(_first_present(block, "effects"), VALID_EFFECTS),
        "side_effect": _clean_value(
            _first_present(block, "side_effect", "sideEffect"), VALID_SIDE_EFFECTS
        ),
        "data_classes": _clean_list(
            _first_present(block, "data_classes", "dataClasses"),
            VALID_DATA_CLASSES,
        ),
        "externality": _clean_value(
            _first_present(block, "externality"), VALID_EXTERNALITY
        ),
        "identity_mode": _clean_value(
            _first_present(block, "identity_mode", "identityMode"),
            VALID_IDENTITY_MODES,
        ),
        "required_scopes": _clean_string_list(
            _first_present(block, "required_scopes", "requiredScopes", "scopes")
        ),
        "warnings": [],
    }
    return {k: v for k, v in partial.items() if v not in (None, [], "")}


def _infer_from_tool_shape(tool: dict) -> Dict[str, Any]:
    name = str(tool.get("name") or "").lower()
    description = str(tool.get("description") or "").lower()
    schema = tool.get("inputSchema", {}) or tool.get("input_schema", {}) or {}
    field_names = _schema_field_names(schema)
    haystack = " ".join([name, description, " ".join(sorted(field_names))])
    effects: List[str] = []
    if _contains_any(
        haystack, ["read", "list", "get", "fetch", "search", "query", "lookup"]
    ):
        effects.append("read")
    if _contains_any(haystack, ["create", "add", "new", "upload", "write_file"]):
        effects.append("create")
    if _contains_any(haystack, ["update", "modify", "patch", "edit", "write"]):
        effects.append("update")
    if _contains_any(
        haystack, ["delete", "drop", "wipe", "truncate", "remove", "destroy"]
    ):
        effects.append("delete")
    if _contains_any(haystack, ["share", "invite", "permission", "grant", "recipient"]):
        effects.append("share")
    if _contains_any(haystack, ["export", "download", "extract", "dump"]):
        effects.append("export")
    if _contains_any(haystack, ["send", "email", "message", "notify", "sms"]):
        effects.append("message")
    if _contains_any(
        haystack,
        ["execute", "run", "bash", "shell", "command", "script", "deploy", "restart"],
    ):
        effects.append("execute")

    data_classes: List[str] = []
    if _contains_any(
        haystack, ["email", "phone", "ssn", "social_security", "address", "dob"]
    ):
        data_classes.append("pii")
    if _contains_any(
        haystack, ["patient", "diagnosis", "medical", "clinical", "health", "phi"]
    ):
        data_classes.append("phi")
    if _contains_any(
        haystack,
        ["account", "ledger", "transaction", "invoice", "payment", "bank", "financial"],
    ):
        data_classes.append("financial")
    if _contains_any(
        haystack, ["contract", "matter", "claim", "patent", "legal", "privileged"]
    ):
        data_classes.append("legal")
    if _contains_any(
        haystack,
        [
            "api_key",
            "apikey",
            "token",
            "secret",
            "password",
            "credential",
            "private_key",
        ],
    ):
        data_classes.append("secrets")
    if _contains_any(
        haystack,
        ["customer", "user", "file", "document", "record", "profile", "content"],
    ):
        data_classes.append("user_content")
    if _contains_any(haystack, ["internal", "employee", "workspace", "tenant"]):
        data_classes.append("internal")

    externality = "unknown"
    if _contains_any(
        haystack,
        [
            "external",
            "public",
            "internet",
            "web",
            "url",
            "webhook",
            "recipient",
            "email",
            "share",
        ],
    ):
        externality = "external"
    elif _contains_any(haystack, ["internal", "workspace", "local", "tenant"]):
        externality = "internal"

    side_effect = _side_effect_from_effects(effects)
    warnings = []
    if effects or data_classes or externality != "unknown":
        warnings.append(
            "Metadata fields inferred from tool name, description, and schema."
        )
    if side_effect == "destructive":
        warnings.append(
            "Tool appears destructive based on name, description, or schema."
        )
    if data_classes:
        warnings.append(
            "Sensitive data classes inferred from argument names or description."
        )

    return {
        "effects": _ordered_unique(effects),
        "side_effect": side_effect,
        "data_classes": _ordered_unique(data_classes),
        "externality": externality,
        "warnings": warnings,
    }


def _detect_conflicts(
    tool: dict,
    output: ToolMetadata,
    heuristic: dict,
    annotations: dict,
    security_meta: dict,
    interlock_meta: dict,
) -> List[str]:
    warnings: List[str] = []
    sources = [
        (SOURCE_INTERLOCK, interlock_meta),
        (SOURCE_SECURITY, security_meta),
        (SOURCE_MCP, annotations),
    ]

    for source, partial in sources:
        side_effect = partial.get("side_effect")
        if side_effect and heuristic.get("side_effect") not in (
            None,
            "unknown",
            side_effect,
        ):
            warnings.append(
                f"{source} side_effect '{side_effect}' conflicts with heuristic '{heuristic.get('side_effect')}'."
            )
        externality = partial.get("externality")
        if externality and heuristic.get("externality") not in (
            None,
            "unknown",
            externality,
        ):
            warnings.append(
                f"{source} externality '{externality}' conflicts with heuristic '{heuristic.get('externality')}'."
            )

    if interlock_meta and annotations:
        if interlock_meta.get("side_effect") and annotations.get("side_effect"):
            if interlock_meta["side_effect"] != annotations["side_effect"]:
                warnings.append(
                    "Interlock metadata conflicts with official MCP annotations for side_effect."
                )
        if interlock_meta.get("externality") and annotations.get("externality"):
            if interlock_meta["externality"] != annotations["externality"]:
                warnings.append(
                    "Interlock metadata conflicts with official MCP annotations for externality."
                )

    schema = tool.get("inputSchema", {}) or tool.get("input_schema", {}) or {}
    field_names = _schema_field_names(schema)
    if output.externality == "internal" and any(
        "recipient" in f or "email" in f or "url" in f for f in field_names
    ):
        warnings.append(
            "Tool is marked internal but schema includes external recipient, email, or URL fields."
        )
    if output.side_effect == "read_only" and heuristic.get("side_effect") in {
        "mutating",
        "destructive",
    }:
        warnings.append(
            "Tool is marked read_only but name, description, or schema suggests side effects."
        )

    return warnings


def _merge_missing(target: ToolMetadata, partial: Dict[str, Any]) -> None:
    if not partial:
        return
    if not target.effects and partial.get("effects"):
        target.effects = _clean_list(partial["effects"], VALID_EFFECTS)
    if target.side_effect == "unknown" and partial.get("side_effect"):
        target.side_effect = (
            _clean_value(partial["side_effect"], VALID_SIDE_EFFECTS) or "unknown"
        )
    if not target.data_classes and partial.get("data_classes"):
        target.data_classes = _clean_list(partial["data_classes"], VALID_DATA_CLASSES)
    if target.externality == "unknown" and partial.get("externality"):
        target.externality = (
            _clean_value(partial["externality"], VALID_EXTERNALITY) or "unknown"
        )
    if target.identity_mode == "unknown" and partial.get("identity_mode"):
        target.identity_mode = (
            _clean_value(partial["identity_mode"], VALID_IDENTITY_MODES) or "unknown"
        )
    if not target.required_scopes and partial.get("required_scopes"):
        target.required_scopes = _clean_string_list(partial["required_scopes"])


def _has_signal(partial: Dict[str, Any]) -> bool:
    if not partial:
        return False
    return any(
        partial.get(key) not in (None, [], "", "unknown")
        for key in (
            "effects",
            "side_effect",
            "data_classes",
            "externality",
            "identity_mode",
            "required_scopes",
        )
    )


def _confidence_for_source(source: str) -> float:
    return {
        SOURCE_INTERLOCK: 0.95,
        SOURCE_SECURITY: 0.85,
        SOURCE_MCP: 0.75,
        SOURCE_HEURISTIC: 0.55,
    }.get(source, 0.0)


def _side_effect_from_effects(effects: Iterable[str]) -> str:
    effect_set = set(effects or [])
    if "delete" in effect_set:
        return "destructive"
    if effect_set and effect_set <= {"read"}:
        return "read_only"
    if effect_set:
        return "mutating"
    return "unknown"


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


def _contains_any(text: str, terms: Iterable[str]) -> bool:
    return any(re.search(rf"\b{re.escape(term)}\b", text) for term in terms)


def _first_present(block: dict, *keys: str) -> Any:
    for key in keys:
        if key in block:
            return block[key]
    return None


def _clean_value(value: Any, allowed: Set[str]) -> Optional[str]:
    if value is None:
        return None
    clean = str(value).strip().lower().replace("-", "_")
    return clean if clean in allowed else None


def _clean_list(value: Any, allowed: Set[str]) -> List[str]:
    return [v for v in _clean_string_list(value) if v in allowed]


def _clean_string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = [value]
    return _ordered_unique(
        str(v).strip().lower().replace("-", "_") for v in raw if str(v).strip()
    )


def _ordered_unique(values: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
