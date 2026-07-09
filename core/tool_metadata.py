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

READ_ACTIONS = {"read", "list", "get", "fetch", "search", "query", "lookup", "show"}
CREATE_ACTIONS = {"create", "add", "new", "upload"}
UPDATE_ACTIONS = {"update", "modify", "patch", "edit", "write", "set"}
DELETE_ACTIONS = {"delete", "drop", "wipe", "truncate", "remove", "destroy"}
SHARE_ACTIONS = {"share", "invite", "permission", "grant"}
EXPORT_ACTIONS = {"export", "download", "extract", "dump"}
MESSAGE_ACTIONS = {"send", "email", "message", "notify", "sms"}
EXECUTE_ACTIONS = {
    "execute",
    "run",
    "bash",
    "shell",
    "command",
    "script",
    "deploy",
    "restart",
}

ACTION_TO_EFFECT = {
    **{term: "read" for term in READ_ACTIONS},
    **{term: "create" for term in CREATE_ACTIONS},
    **{term: "update" for term in UPDATE_ACTIONS},
    **{term: "delete" for term in DELETE_ACTIONS},
    **{term: "share" for term in SHARE_ACTIONS},
    **{term: "export" for term in EXPORT_ACTIONS},
    **{term: "message" for term in MESSAGE_ACTIONS},
    **{term: "execute" for term in EXECUTE_ACTIONS},
}

ACTION_ALIASES = {
    "reads": "read",
    "lists": "list",
    "gets": "get",
    "fetches": "fetch",
    "searches": "search",
    "queries": "query",
    "looks": "lookup",
    "shows": "show",
    "creates": "create",
    "adds": "add",
    "uploads": "upload",
    "updates": "update",
    "modifies": "modify",
    "patches": "patch",
    "edits": "edit",
    "writes": "write",
    "sets": "set",
    "deletes": "delete",
    "drops": "drop",
    "wipes": "wipe",
    "truncates": "truncate",
    "removes": "remove",
    "destroys": "destroy",
    "shares": "share",
    "invites": "invite",
    "grants": "grant",
    "exports": "export",
    "downloads": "download",
    "extracts": "extract",
    "dumps": "dump",
    "sends": "send",
    "emails": "email",
    "messages": "message",
    "notifies": "notify",
    "executes": "execute",
    "runs": "run",
    "deploys": "deploy",
    "restarts": "restart",
}

MUTATING_STATUS_ACTIONS = CREATE_ACTIONS | UPDATE_ACTIONS | {"write"}
NON_MUTATING_CONTEXT_TERMS = {
    "policy",
    "policies",
    "status",
    "state",
    "enabled",
    "whether",
    "setting",
    "settings",
}


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
    elif destructive is True:
        partial["side_effect"] = "destructive"

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
    if partial["effects"] and partial["side_effect"] in (None, "", "unknown"):
        partial["side_effect"] = _side_effect_from_effects(partial["effects"])
    return {k: v for k, v in partial.items() if v not in (None, [], "")}


def _infer_from_tool_shape(tool: dict) -> Dict[str, Any]:
    raw_name = str(tool.get("name") or "")
    name = raw_name.lower()
    description = str(tool.get("description") or "").lower()
    schema = tool.get("inputSchema", {}) or tool.get("input_schema", {}) or {}
    field_names = _schema_field_names(schema)
    raw_haystack = " ".join([name, description, " ".join(sorted(field_names))])
    haystack = " ".join([raw_haystack, raw_haystack.replace("_", " ")])
    effects: List[str] = []
    if _is_non_mutating_context(raw_name, description):
        effects.append("read")
    else:
        effects.extend(_effects_from_tool_name(raw_name))
        effects.extend(_effects_from_description(description))

    data_classes: List[str] = []
    if _contains_any(
        haystack, ["email", "phone", "ssn", "social_security", "address", "dob"]
    ):
        data_classes.append("pii")
    if _contains_any(
        haystack, ["patient", "diagnosis", "medical", "clinical", "health", "phi"]
    ):
        data_classes.append("phi")
    if _has_financial_context(haystack):
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
            "credential",
            "private_key",
        ],
    ) or _has_credential_secret_context(haystack):
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


def _name_tokens(name: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name or ""))
    return [token for token in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if token]


def _normalize_action(token: str) -> Optional[str]:
    token = ACTION_ALIASES.get(token, token)
    return token if token in ACTION_TO_EFFECT else None


def _effect_for_action(action: str) -> Optional[str]:
    return ACTION_TO_EFFECT.get(action)


def _effects_from_tool_name(name: str) -> List[str]:
    tokens = _name_tokens(name)
    if not tokens:
        return []

    effects: List[str] = []
    first = _normalize_action(tokens[0])
    if first:
        effect = _effect_for_action(first)
        if effect:
            effects.append(effect)

    if len(tokens) >= 2 and tokens[0] == "write" and tokens[1] == "file":
        effects.append("create")
    return _ordered_unique(effects)


def _effects_from_description(description: str) -> List[str]:
    text = str(description or "").strip().lower()
    if not text:
        return []

    effects: List[str] = []
    m = re.match(r"^(?:this tool\s+)?([a-z]+)\b", text)
    if m:
        action = _normalize_action(m.group(1))
        effect = _effect_for_action(action) if action else None
        if effect:
            effects.append(effect)

    for pattern in (
        r"\b(?:can|may|will|must|able to)\s+([a-z]+)\b",
        r"\band\s+([a-z]+)\b",
    ):
        for match in re.finditer(pattern, text):
            action = _normalize_action(match.group(1))
            effect = _effect_for_action(action) if action else None
            if effect:
                effects.append(effect)
    return _ordered_unique(effects)


def _is_non_mutating_context(name: str, description: str) -> bool:
    tokens = _name_tokens(name)
    text = f"{name} {description}".lower().replace("_", " ")
    description_text = str(description or "").lower()

    if re.search(r"\bread[-\s]?only\b", text):
        return True

    if tokens and tokens[-1] in NON_MUTATING_CONTEXT_TERMS:
        first = _normalize_action(tokens[0])
        return first not in MUTATING_STATUS_ACTIONS

    if (
        tokens
        and tokens[0] in READ_ACTIONS
        and any(token in NON_MUTATING_CONTEXT_TERMS for token in tokens[1:])
    ):
        return True

    if re.match(
        r"^\s*(show|shows|return|returns|read|reads|list|lists|get|gets)\b",
        description_text,
    ):
        return any(term in text for term in NON_MUTATING_CONTEXT_TERMS)

    return False


def _has_financial_context(text: str) -> bool:
    if _contains_any(
        text, ["ledger", "transaction", "invoice", "payment", "bank", "financial"]
    ):
        return True
    return bool(
        re.search(
            r"\baccount\b.{0,30}\b(billing|invoice|payment|bank|ledger|transaction|financial)\b",
            text,
        )
        or re.search(
            r"\b(billing|invoice|payment|bank|ledger|transaction|financial)\b.{0,30}\baccount\b",
            text,
        )
    )


def _has_credential_secret_context(text: str) -> bool:
    return bool(
        re.search(
            r"\b(?:secret|secrets)[\s_-]*(?:key|token|password|credential)\b",
            text,
        )
        or re.search(
            r"\b(?:key|token|password|credential)[\s_-]*(?:secret|secrets)\b",
            text,
        )
        or re.search(
            r"\b(?:api|access|auth|bearer|refresh|session|secret|private)[\s_-]*(?:token|password)\b",
            text,
        )
        or re.search(
            r"\b(?:token|password)[\s_-]*(?:key|secret|credential|hash|value)\b",
            text,
        )
    )


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
    if effect_set & {"delete", "execute"}:
        return "destructive"
    if effect_set == {"share"}:
        return "mutating"
    if effect_set and effect_set <= {"read", "export", "share"}:
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
