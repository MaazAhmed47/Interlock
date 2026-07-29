"""Bounded MCP 2026-07-28 protocol validation helpers.

The helpers in this module do not log or persist request or response content.
They return only the validated values needed by the live gateway or raise a
reason-only exception suitable for fail-closed handling.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_SCHEMA_NODES = 10_000
MAX_VALUE_NODES = 20_000
MAX_NESTING_DEPTH = 64
MAX_SSE_BYTES = 2 * 1024 * 1024

_DRAFT_2020_12_URIS = {
    "https://json-schema.org/draft/2020-12/schema",
    "https://json-schema.org/draft/2020-12/schema#",
}
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_INTEGER_HEADER = re.compile(r"^-?[0-9]+$")
_META_LABEL = re.compile(r"^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_META_NAME = re.compile(r"^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])?$")
_LOG_LEVELS = {
    "debug",
    "info",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
}


class MCP2026ProtocolError(ValueError):
    """A protocol value failed validation without retaining its contents."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ParameterHeaderBinding:
    """One statically reachable primitive parameter-to-header binding."""

    path: tuple[str, ...]
    suffix: str
    primitive_type: str

    @property
    def header_name(self) -> str:
        return f"Mcp-Param-{self.suffix}"


def validate_json_value(value: Any) -> None:
    """Reject values that cannot appear in standards-conforming JSON."""
    for current, _depth in _walk_bounded(value, max_nodes=MAX_VALUE_NODES):
        if isinstance(current, float) and not math.isfinite(current):
            raise MCP2026ProtocolError("invalid_json_number")
        if isinstance(current, dict) and any(
            not isinstance(key, str) for key in current
        ):
            raise MCP2026ProtocolError("invalid_json_object")
        if not isinstance(current, (dict, list, str, int, float, bool, type(None))):
            raise MCP2026ProtocolError("invalid_json_value")


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def parse_json_bytes(raw: bytes) -> Any:
    """Decode strict UTF-8 JSON and reject non-standard numeric constants."""
    failed = False
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        failed = True
        value = None
    if failed:
        raise MCP2026ProtocolError("invalid_json")
    validate_json_value(value)
    return value


def validate_meta_object(meta: Any) -> None:
    """Validate `_meta` key syntax while leaving extension values opaque."""
    if not isinstance(meta, dict):
        raise MCP2026ProtocolError("invalid_meta_object")
    for key in meta:
        if not isinstance(key, str):
            raise MCP2026ProtocolError("invalid_meta_key")
        if "/" in key:
            prefix, name = key.split("/", 1)
            labels = prefix.split(".")
            if not labels or any(not _META_LABEL.fullmatch(label) for label in labels):
                raise MCP2026ProtocolError("invalid_meta_key")
        else:
            name = key
        if not _META_NAME.fullmatch(name):
            raise MCP2026ProtocolError("invalid_meta_key")


def _validate_client_capabilities(capabilities: Any) -> None:
    if not isinstance(capabilities, dict):
        raise MCP2026ProtocolError("invalid_client_capabilities")
    for field in ("experimental", "roots"):
        if field in capabilities and not isinstance(capabilities[field], dict):
            raise MCP2026ProtocolError("invalid_client_capabilities")
    for field, children in (
        ("sampling", ("context", "tools")),
        ("elicitation", ("form", "url")),
    ):
        if field not in capabilities:
            continue
        value = capabilities[field]
        if not isinstance(value, dict) or any(
            child in value and not isinstance(value[child], dict) for child in children
        ):
            raise MCP2026ProtocolError("invalid_client_capabilities")
    extensions = capabilities.get("extensions")
    if extensions is not None:
        if not isinstance(extensions, dict):
            raise MCP2026ProtocolError("invalid_client_capabilities")
        for key, value in extensions.items():
            if "/" not in key or not isinstance(value, dict):
                raise MCP2026ProtocolError("invalid_client_capabilities")
            validate_meta_object({key: None})


def validate_request_meta(meta: Any) -> None:
    """Validate the required and known optional per-request metadata fields."""
    validate_meta_object(meta)
    version = meta.get("io.modelcontextprotocol/protocolVersion")
    capabilities = meta.get("io.modelcontextprotocol/clientCapabilities")
    if not isinstance(version, str) or not version:
        raise MCP2026ProtocolError("invalid_request_meta")
    _validate_client_capabilities(capabilities)
    client_info = meta.get("io.modelcontextprotocol/clientInfo")
    if "io.modelcontextprotocol/clientInfo" in meta and (
        not isinstance(client_info, dict)
        or not isinstance(client_info.get("name"), str)
        or not client_info["name"]
        or not isinstance(client_info.get("version"), str)
        or not client_info["version"]
    ):
        raise MCP2026ProtocolError("invalid_client_info")
    progress_token = meta.get("progressToken")
    if "progressToken" in meta and (
        isinstance(progress_token, bool)
        or not isinstance(progress_token, (str, int, float))
    ):
        raise MCP2026ProtocolError("invalid_progress_token")
    log_level = meta.get("io.modelcontextprotocol/logLevel")
    if "io.modelcontextprotocol/logLevel" in meta and log_level not in _LOG_LEVELS:
        raise MCP2026ProtocolError("invalid_log_level")


def _walk_bounded(value: Any, *, max_nodes: int) -> Iterable[tuple[Any, int]]:
    pending: list[tuple[Any, int]] = [(value, 0)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if count > max_nodes or depth > MAX_NESTING_DEPTH:
            raise MCP2026ProtocolError("protocol_value_too_complex")
        yield current, depth
        if isinstance(current, dict):
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current)


def validate_json_schema(schema: Any, *, require_object_root: bool = False) -> None:
    """Validate the supported MCP JSON Schema dialect without fetching refs."""
    if not isinstance(schema, dict):
        raise MCP2026ProtocolError("invalid_json_schema")
    for current, _depth in _walk_bounded(schema, max_nodes=MAX_SCHEMA_NODES):
        if isinstance(current, dict):
            for keyword in ("$ref", "$dynamicRef", "$recursiveRef"):
                if keyword not in current:
                    continue
                reference = current[keyword]
                if not isinstance(reference, str) or not reference.startswith("#"):
                    raise MCP2026ProtocolError("external_schema_reference_unsupported")

    dialect = schema.get("$schema")
    if dialect is not None and dialect not in _DRAFT_2020_12_URIS:
        raise MCP2026ProtocolError("unsupported_json_schema_dialect")
    invalid_schema = False
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError:
        invalid_schema = True
    if invalid_schema:
        raise MCP2026ProtocolError("invalid_json_schema")
    if require_object_root and schema.get("type") != "object":
        raise MCP2026ProtocolError("tool_input_schema_must_be_object")


def validate_schema_instance(schema: Any, instance: Any) -> None:
    """Validate one bounded value against a previously untrusted schema."""
    validate_json_schema(schema)
    for _current, _depth in _walk_bounded(instance, max_nodes=MAX_VALUE_NODES):
        pass
    failure_reason = None
    try:
        Draft202012Validator(schema).validate(instance)
    except ValidationError:
        failure_reason = "schema_validation_failed"
    except Exception:
        # Local references can still be unresolved. Never permit the resolver
        # to turn that into an outbound retrieval or an uncaught gateway error.
        failure_reason = "schema_resolution_failed"
    if failure_reason is not None:
        raise MCP2026ProtocolError(failure_reason)


def _all_parameter_annotations(value: Any) -> int:
    count = 0
    for current, _depth in _walk_bounded(value, max_nodes=MAX_SCHEMA_NODES):
        if isinstance(current, dict) and "x-mcp-header" in current:
            count += 1
    return count


def parameter_header_bindings(schema: Any) -> tuple[ParameterHeaderBinding, ...]:
    """Return validated, deterministic bindings for all valid annotations."""
    validate_json_schema(schema, require_object_root=True)
    bindings: list[ParameterHeaderBinding] = []

    def visit_object(current: Mapping[str, Any], path: tuple[str, ...]) -> None:
        properties = current.get("properties", {})
        if not isinstance(properties, dict):
            return
        for property_name in sorted(properties):
            property_schema = properties[property_name]
            if not isinstance(property_name, str) or not isinstance(
                property_schema, dict
            ):
                continue
            property_path = (*path, property_name)
            if "x-mcp-header" in property_schema:
                suffix = property_schema["x-mcp-header"]
                primitive_type = property_schema.get("type")
                if (
                    not isinstance(suffix, str)
                    or not suffix
                    or not _HEADER_TOKEN.fullmatch(suffix)
                    or primitive_type not in {"string", "integer", "boolean"}
                ):
                    raise MCP2026ProtocolError("invalid_parameter_header_annotation")
                bindings.append(
                    ParameterHeaderBinding(property_path, suffix, primitive_type)
                )
            if property_schema.get("type") == "object":
                visit_object(property_schema, property_path)

    visit_object(schema, ())
    if len(bindings) != _all_parameter_annotations(schema):
        raise MCP2026ProtocolError("invalid_parameter_header_reachability")
    lowered = [binding.suffix.lower() for binding in bindings]
    if len(lowered) != len(set(lowered)):
        raise MCP2026ProtocolError("duplicate_parameter_header_annotation")
    return tuple(bindings)


def uses_parameter_headers(schema: Any) -> bool:
    """Return whether a schema contains the annotation without validating it."""
    try:
        return _all_parameter_annotations(schema) > 0
    except MCP2026ProtocolError:
        return True


def _value_at_path(arguments: Mapping[str, Any], path: Sequence[str]) -> Any:
    current: Any = arguments
    for component in path:
        if not isinstance(current, dict) or component not in current:
            return None
        current = current[component]
    return current


def _primitive_text(value: Any, primitive_type: str) -> str | None:
    if value is None:
        return None
    if primitive_type == "string" and isinstance(value, str):
        return value
    if primitive_type == "boolean" and isinstance(value, bool):
        return "true" if value else "false"
    if (
        primitive_type == "integer"
        and isinstance(value, int)
        and not isinstance(value, bool)
        and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER
    ):
        return str(value)
    raise MCP2026ProtocolError("invalid_parameter_header_value")


def encode_header_value(value: str) -> str:
    """Encode a name or primitive value using the MCP Base64 sentinel."""
    sentinel = value.startswith("=?base64?") and value.endswith("?=")
    plain_ascii = all(
        character == "\t" or 0x20 <= ord(character) <= 0x7E for character in value
    )
    if plain_ascii and value == value.strip() and not sentinel:
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def decode_header_value(value: str) -> str:
    """Decode and validate an MCP header value."""
    if not (value.startswith("=?base64?") and value.endswith("?=")):
        if value != value.strip() or any(
            character != "\t" and not 0x20 <= ord(character) <= 0x7E
            for character in value
        ):
            raise MCP2026ProtocolError("invalid_header_value")
        return value
    encoded = value[len("=?base64?") : -len("?=")]
    failed = False
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        failed = True
        decoded = ""
    if failed:
        raise MCP2026ProtocolError("invalid_header_value")
    return decoded


def build_parameter_headers(
    schema: Any, arguments: Mapping[str, Any]
) -> dict[str, str]:
    """Build only declared transport headers from validated argument values."""
    headers: dict[str, str] = {}
    for binding in parameter_header_bindings(schema):
        text = _primitive_text(
            _value_at_path(arguments, binding.path), binding.primitive_type
        )
        if text is not None:
            headers[binding.header_name] = encode_header_value(text)
    return headers


def validate_parameter_headers(
    schema: Any,
    arguments: Mapping[str, Any],
    raw_headers: Sequence[tuple[bytes, bytes]],
) -> None:
    """Validate supplied Mcp-Param headers without retaining their values."""
    bindings = {
        binding.header_name.lower(): binding
        for binding in parameter_header_bindings(schema)
    }
    supplied: dict[str, str] = {}
    for raw_name, raw_value in raw_headers:
        failed_name = False
        try:
            name = raw_name.decode("ascii").lower()
        except UnicodeDecodeError:
            failed_name = True
            name = ""
        if failed_name:
            raise MCP2026ProtocolError("invalid_parameter_header_name")
        if not name.startswith("mcp-param-"):
            continue
        if name in supplied or name not in bindings:
            raise MCP2026ProtocolError("unexpected_parameter_header")
        supplied[name] = raw_value.decode("latin-1")

    for name, binding in bindings.items():
        expected = _primitive_text(
            _value_at_path(arguments, binding.path), binding.primitive_type
        )
        actual = supplied.pop(name, None)
        if expected is None:
            if actual is not None:
                raise MCP2026ProtocolError("parameter_header_mismatch")
            continue
        if actual is None:
            raise MCP2026ProtocolError("parameter_header_mismatch")
        decoded = decode_header_value(actual)
        if binding.primitive_type == "integer":
            if not _INTEGER_HEADER.fullmatch(decoded) or int(decoded) != int(expected):
                raise MCP2026ProtocolError("parameter_header_mismatch")
        elif decoded != expected:
            raise MCP2026ProtocolError("parameter_header_mismatch")


def parse_sse_jsonrpc_response(raw: bytes, request_id: str | int) -> dict[str, Any]:
    """Parse one bounded SSE exchange and return its sole matching response."""
    if len(raw) > MAX_SSE_BYTES:
        raise MCP2026ProtocolError("upstream_response_too_large")
    failed_decode = False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        failed_decode = True
        text = ""
    if failed_decode:
        raise MCP2026ProtocolError("upstream_invalid_sse")

    final: dict[str, Any] | None = None
    data_lines: list[str] = []

    def consume_event() -> None:
        nonlocal final, data_lines
        if not data_lines:
            return
        failed_event = False
        try:
            message = parse_json_bytes("\n".join(data_lines).encode("utf-8"))
        except MCP2026ProtocolError:
            failed_event = True
            message = None
        if failed_event:
            raise MCP2026ProtocolError("upstream_invalid_sse")
        data_lines = []
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise MCP2026ProtocolError("upstream_invalid_sse_message")
        if "method" in message:
            if "id" in message or not str(message.get("method", "")).startswith(
                "notifications/"
            ):
                raise MCP2026ProtocolError("upstream_server_request_unsupported")
            return
        if message.get("id") != request_id or final is not None:
            raise MCP2026ProtocolError("upstream_unrelated_sse_response")
        final = message

    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line:
            consume_event()
        elif line.startswith(":"):
            continue
        elif line == "data":
            data_lines.append("")
        elif line.startswith("data:"):
            value = line[5:]
            data_lines.append(value[1:] if value.startswith(" ") else value)
        elif ":" in line or line in {"event", "id", "retry"}:
            continue
        else:
            raise MCP2026ProtocolError("upstream_invalid_sse")
    consume_event()
    if final is None:
        raise MCP2026ProtocolError("upstream_missing_sse_response")
    return final


def validate_tool_schemas(tool: Any) -> None:
    """Validate the schema-bearing fields of one MCP tool definition."""
    if (
        not isinstance(tool, dict)
        or not isinstance(tool.get("name"), str)
        or not tool["name"]
        or (
            "description" in tool
            and tool["description"] is not None
            and not isinstance(tool["description"], str)
        )
    ):
        raise MCP2026ProtocolError("invalid_tool_definition")
    validate_json_schema(tool.get("inputSchema"), require_object_root=True)
    parameter_header_bindings(tool["inputSchema"])
    if "outputSchema" in tool:
        validate_json_schema(tool["outputSchema"])


def validate_call_tool_result(result: Any) -> None:
    """Validate the mandatory structural shape of a complete tool result."""
    if not isinstance(result, dict) or not isinstance(result.get("content"), list):
        raise MCP2026ProtocolError("invalid_tool_result")
    if "isError" in result and not isinstance(result["isError"], bool):
        raise MCP2026ProtocolError("invalid_tool_result")
    if "_meta" in result:
        validate_meta_object(result["_meta"])
    for block in result["content"]:
        if not isinstance(block, dict):
            raise MCP2026ProtocolError("invalid_tool_content")
        block_type = block.get("type")
        if block_type == "text":
            valid = isinstance(block.get("text"), str)
        elif block_type in {"image", "audio"}:
            valid = isinstance(block.get("data"), str) and isinstance(
                block.get("mimeType"), str
            )
        elif block_type == "resource_link":
            valid = isinstance(block.get("name"), str) and isinstance(
                block.get("uri"), str
            )
        elif block_type == "resource":
            resource = block.get("resource")
            if isinstance(resource, dict) and isinstance(resource.get("uri"), str):
                has_text = isinstance(resource.get("text"), str)
                has_blob = isinstance(resource.get("blob"), str)
                valid = has_text != has_blob
            else:
                valid = False
        else:
            valid = False
        if not valid:
            raise MCP2026ProtocolError("invalid_tool_content")
        if "_meta" in block:
            validate_meta_object(block["_meta"])
