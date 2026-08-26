"""Bounded, raw-preserving inspection of model-facing MCP definition text.

The inspector never rewrites a tool definition. It extracts only explicitly
model-facing text locations into a bounded inspection projection and emits
safe metadata: categories, bounded JSON paths, code-point classes, and hashes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import unicodedata
from typing import Any, Iterable

from core.mcp_drift import _detect_description_exfiltration

MAX_TRAVERSAL_DEPTH = 24
MAX_VISITED_NODES = 2_048
MAX_TEXT_FIELDS = 256
MAX_TEXT_LENGTH = 4_096
MAX_INSPECTED_CHARACTERS = 65_536

_TEXT_KEYS = {"title", "description", "$comment"}
_STRING_VALUE_KEYS = {"default"}
_STRING_LIST_KEYS = {"examples"}
_MODEL_FACING_EXTENSION_KEYS = {
    "x-description",
    "x-display-name",
    "x-help",
    "x-instructions",
    "x-model-description",
    "x-summary",
    "x-title",
}
_SCHEMA_MAP_KEYS = {
    "$defs",
    "definitions",
    "dependentSchemas",
    "patternProperties",
    "properties",
}
_SCHEMA_SINGLE_KEYS = {
    "additionalProperties",
    "contains",
    "else",
    "if",
    "items",
    "not",
    "propertyNames",
    "then",
    "unevaluatedProperties",
}
_SCHEMA_LIST_KEYS = {"allOf", "anyOf", "oneOf", "prefixItems"}
_META_CONTAINER_KEYS = {"_meta", "annotations"}

_MODEL_DIRECTED_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous\s+)?(?:instructions|prompts)\b",
        r"\bforget\s+(?:everything|all|your\s+instructions)\b",
        r"\breveal\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)\b",
        r"\b(?:show|print|return)\s+(?:your|the)\s+system\s+prompt\b",
        r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|admin|root)\b",
    )
)
_LEGACY_TOP_LEVEL_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"unrestricted",
        r"no.{0,10}sandbox",
        r"bypass.{0,10}(security|safety|restriction)",
        r"execute.{0,30}(arbitrary|user|untrusted)",
        r"full.{0,10}(system|admin|root).{0,10}access",
        r"download.{0,30}execute",
        r"reverse.{0,5}shell",
    )
)
_HTML_COMMENT_RE = re.compile(r"<!--(?P<body>.*?)-->", re.DOTALL)
_MARKDOWN_COMMENT_RES = (
    re.compile(r"\[(?:comment|//)\]\s*:\s*<>\s*\((?P<body>.*?)\)", re.DOTALL),
    re.compile(r"\[(?:comment|//)\]\s*:\s*#\s*\((?P<body>.*?)\)", re.DOTALL),
)

_BIDI_FORMATTING_CODE_POINTS = {
    0x202A: "embedding",
    0x202B: "embedding",
    0x202C: "pop_directional_formatting",
    0x202D: "override",
    0x202E: "override",
    0x2066: "isolate",
    0x2067: "isolate",
    0x2068: "isolate",
    0x2069: "pop_directional_isolate",
}
_CONCEALMENT_CODE_POINTS = {
    0x200B: "zero_width_space",
    0x2060: "word_joiner",
    0xFEFF: "zero_width_no_break_space",
}


@dataclass(frozen=True)
class _TextField:
    path: str
    text: str
    control_only: bool = False


@dataclass(frozen=True)
class DefinitionTextFinding:
    category: str
    path: str
    severity: str
    text_sha256: str
    code_point_categories: tuple[str, ...] = ()
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "category": self.category,
            "path": self.path,
            "severity": self.severity,
            "disposition": "quarantine",
            "text_sha256": self.text_sha256,
            "truncated": self.truncated,
        }
        if self.code_point_categories:
            value["code_point_categories"] = list(self.code_point_categories)
        return value


@dataclass(frozen=True)
class DefinitionInspection:
    findings: tuple[DefinitionTextFinding, ...]
    inspected_fields: int
    inspected_characters: int
    limit_exceeded: bool

    @property
    def requires_review(self) -> bool:
        return bool(self.findings)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "disposition": "quarantine" if self.requires_review else "allow",
            "findings": [finding.to_dict() for finding in self.findings],
            "inspected_fields": self.inspected_fields,
            "inspected_characters": self.inspected_characters,
            "limit_exceeded": self.limit_exceeded,
            "limits": {
                "max_depth": MAX_TRAVERSAL_DEPTH,
                "max_nodes": MAX_VISITED_NODES,
                "max_text_fields": MAX_TEXT_FIELDS,
                "max_text_length": MAX_TEXT_LENGTH,
                "max_characters": MAX_INSPECTED_CHARACTERS,
            },
        }


def _digest(text: str) -> str:
    return (
        "sha256:" + hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    )


def _safe_pointer_token(value: Any) -> str:
    text = str(value)
    if len(text) <= 64 and re.fullmatch(r"[A-Za-z0-9_.$-]+", text):
        return text.replace("~", "~0").replace("/", "~1")
    return (
        "@key-"
        + hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]
    )


def _path(parent: str, token: Any) -> str:
    return f"{parent}/{_safe_pointer_token(token)}"


def _has_model_directed_instruction(text: str) -> bool:
    return any(pattern.search(text) for pattern in _MODEL_DIRECTED_PATTERNS)


def _comment_bodies(text: str) -> Iterable[str]:
    for match in _HTML_COMMENT_RE.finditer(text):
        yield match.group("body")
    for pattern in _MARKDOWN_COMMENT_RES:
        for match in pattern.finditer(text):
            yield match.group("body")


def _contains_sensitive_egress(text: str) -> bool:
    return _detect_description_exfiltration("", text) is not None


def _extract_text_fields(tool: Any) -> tuple[list[_TextField], bool, int]:
    fields: list[_TextField] = []
    visited: set[int] = set()
    nodes = 0
    limit_exceeded = False

    def add(path: str, value: Any, *, control_only: bool = False) -> None:
        nonlocal limit_exceeded
        if not isinstance(value, str):
            return
        if len(fields) >= MAX_TEXT_FIELDS:
            limit_exceeded = True
            return
        fields.append(_TextField(path=path, text=value, control_only=control_only))

    if not isinstance(tool, dict):
        return fields, False, nodes
    add("/name", tool.get("name"), control_only=True)
    for key in ("title", "description"):
        add(_path("", key), tool.get(key))

    stack: list[tuple[Any, str, int, str]] = []
    for key in ("inputSchema", "outputSchema", "input_schema", "output_schema"):
        value = tool.get(key)
        if isinstance(value, dict):
            stack.append((value, _path("", key), 1, "schema"))
    for key in _META_CONTAINER_KEYS:
        value = tool.get(key)
        if isinstance(value, dict):
            stack.append((value, _path("", key), 1, "metadata"))

    while stack:
        node, node_path, depth, mode = stack.pop()
        if depth > MAX_TRAVERSAL_DEPTH:
            limit_exceeded = True
            continue
        if not isinstance(node, (dict, list)):
            continue
        identity = id(node)
        if identity in visited:
            continue
        visited.add(identity)
        nodes += 1
        if nodes > MAX_VISITED_NODES:
            limit_exceeded = True
            break

        if isinstance(node, list):
            for index in reversed(range(len(node))):
                child = node[index]
                if isinstance(child, (dict, list)):
                    stack.append((child, _path(node_path, index), depth + 1, mode))
            continue

        text_keys = _TEXT_KEYS | _MODEL_FACING_EXTENSION_KEYS
        if mode == "metadata":
            text_keys = text_keys | {"help", "instructions", "summary"}
        for key in sorted(text_keys):
            add(_path(node_path, key), node.get(key))
        for key in _STRING_VALUE_KEYS:
            add(_path(node_path, key), node.get(key))
        for key in _STRING_LIST_KEYS:
            values = node.get(key)
            if isinstance(values, list):
                for index, value in enumerate(values):
                    add(_path(_path(node_path, key), index), value)

        if mode == "metadata":
            for key, child in reversed(list(node.items())):
                if isinstance(child, (dict, list)):
                    stack.append((child, _path(node_path, key), depth + 1, mode))
            continue

        for key in sorted(_SCHEMA_MAP_KEYS, reverse=True):
            mapping = node.get(key)
            if isinstance(mapping, dict):
                for child_key, child in reversed(list(mapping.items())):
                    if isinstance(child, dict):
                        stack.append(
                            (
                                child,
                                _path(_path(node_path, key), child_key),
                                depth + 1,
                                "schema",
                            )
                        )
        for key in sorted(_SCHEMA_SINGLE_KEYS, reverse=True):
            child = node.get(key)
            if isinstance(child, dict):
                stack.append((child, _path(node_path, key), depth + 1, "schema"))
        for key in sorted(_SCHEMA_LIST_KEYS, reverse=True):
            children = node.get(key)
            if isinstance(children, list):
                for index in reversed(range(len(children))):
                    child = children[index]
                    if isinstance(child, dict):
                        stack.append(
                            (
                                child,
                                _path(_path(node_path, key), index),
                                depth + 1,
                                "schema",
                            )
                        )

    return fields, limit_exceeded, nodes


def inspect_tool_definition_text(tool: Any) -> DefinitionInspection:
    fields, traversal_limited, _ = _extract_text_fields(tool)
    findings: list[DefinitionTextFinding] = []
    seen: set[tuple[str, str]] = set()
    inspected_characters = 0
    inspected_fields = 0
    limit_exceeded = traversal_limited

    def add_finding(
        category: str,
        field: _TextField,
        inspected: str,
        *,
        code_points: Iterable[str] = (),
        truncated: bool = False,
    ) -> None:
        key = (category, field.path)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            DefinitionTextFinding(
                category=category,
                path=field.path,
                severity="critical",
                text_sha256=_digest(inspected),
                code_point_categories=tuple(sorted(set(code_points))),
                truncated=truncated,
            )
        )

    for field in fields:
        if inspected_characters >= MAX_INSPECTED_CHARACTERS:
            limit_exceeded = True
            break
        remaining = MAX_INSPECTED_CHARACTERS - inspected_characters
        allowed = min(MAX_TEXT_LENGTH, remaining)
        inspected = field.text[:allowed]
        truncated = len(field.text) > allowed
        if truncated:
            limit_exceeded = True
        inspected_characters += len(inspected)
        inspected_fields += 1

        bidi_categories = [
            f"bidi_{_BIDI_FORMATTING_CODE_POINTS[ord(character)]}"
            for character in inspected
            if ord(character) in _BIDI_FORMATTING_CODE_POINTS
        ]
        if bidi_categories:
            add_finding(
                "bidi_formatting_control",
                field,
                inspected,
                code_points=bidi_categories,
                truncated=truncated,
            )

        concealment_categories = [
            _CONCEALMENT_CODE_POINTS[ord(character)]
            for character in inspected
            if ord(character) in _CONCEALMENT_CODE_POINTS
        ]
        deconcealed = "".join(
            character
            for character in inspected
            if ord(character) not in _CONCEALMENT_CODE_POINTS
        )
        if concealment_categories and (
            _has_model_directed_instruction(deconcealed)
            or _contains_sensitive_egress(deconcealed)
        ):
            add_finding(
                "zero_width_concealment",
                field,
                inspected,
                code_points=concealment_categories,
                truncated=truncated,
            )

        normalized = unicodedata.normalize("NFKC", deconcealed)
        if normalized != deconcealed and _has_model_directed_instruction(normalized):
            add_finding(
                "normalization_divergence", field, inspected, truncated=truncated
            )

        if field.control_only:
            if concealment_categories:
                add_finding(
                    "zero_width_name_control",
                    field,
                    inspected,
                    code_points=concealment_categories,
                    truncated=truncated,
                )
            continue

        detection_view = normalized
        if _has_model_directed_instruction(detection_view):
            add_finding(
                "model_directed_instruction", field, inspected, truncated=truncated
            )
        if field.path == "/description" and any(
            pattern.search(detection_view) for pattern in _LEGACY_TOP_LEVEL_PATTERNS
        ):
            add_finding(
                "legacy_description_risk", field, inspected, truncated=truncated
            )
        if _contains_sensitive_egress(detection_view):
            add_finding(
                "sensitive_resource_egress", field, inspected, truncated=truncated
            )
        if any(
            _has_model_directed_instruction(body) or _contains_sensitive_egress(body)
            for body in _comment_bodies(detection_view)
        ):
            add_finding(
                "instruction_bearing_comment", field, inspected, truncated=truncated
            )

    if limit_exceeded:
        limit_field = _TextField(path="/@inspection-limit", text="bounded-limit")
        add_finding(
            "inspection_limit_exceeded",
            limit_field,
            "bounded-limit",
            truncated=True,
        )

    return DefinitionInspection(
        findings=tuple(findings),
        inspected_fields=inspected_fields,
        inspected_characters=inspected_characters,
        limit_exceeded=limit_exceeded,
    )
