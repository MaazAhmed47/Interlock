"""Focused mandatory MCP 2026-07-28 protocol helper tests."""

import json

import pytest

from core.mcp_2026_protocol import (
    MAX_SAFE_INTEGER,
    MCP2026ProtocolError,
    build_parameter_headers,
    parameter_header_bindings,
    parse_json_bytes,
    parse_sse_jsonrpc_response,
    validate_json_schema,
    validate_call_tool_result,
    validate_meta_object,
    validate_parameter_headers,
    validate_request_meta,
    validate_schema_instance,
)


def _schema(annotation: str = "Tenant") -> dict:
    return {
        "type": "object",
        "properties": {
            "tenant": {"type": "string", "x-mcp-header": annotation},
            "options": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean", "x-mcp-header": "Enabled"},
                    "limit": {"type": "integer", "x-mcp-header": "Limit"},
                },
            },
        },
    }


def test_json_schema_2020_12_default_and_explicit_dialect_are_validated():
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"count": {"type": "integer", "minimum": 1}},
        "required": ["count"],
    }
    validate_json_schema(schema, require_object_root=True)
    validate_schema_instance(schema, {"count": 1})

    with pytest.raises(MCP2026ProtocolError, match="schema_validation_failed"):
        validate_schema_instance(schema, {"count": 0})


@pytest.mark.parametrize(
    ("schema", "reason"),
    [
        ({"$schema": "https://json-schema.org/draft-07/schema#"}, "unsupported"),
        ({"type": "not-a-json-schema-type"}, "invalid_json_schema"),
        ({"type": "object", "$ref": "https://example.invalid/schema"}, "external"),
        ({"type": "string"}, "tool_input_schema_must_be_object"),
    ],
)
def test_invalid_dialects_schemas_external_refs_and_input_roots_fail_closed(
    schema, reason
):
    with pytest.raises(MCP2026ProtocolError, match=reason):
        validate_json_schema(schema, require_object_root=True)


def test_local_schema_references_validate_without_network_resolution():
    schema = {
        "type": "object",
        "$defs": {"identifier": {"type": "string", "minLength": 1}},
        "properties": {"id": {"$ref": "#/$defs/identifier"}},
        "required": ["id"],
    }
    validate_schema_instance(schema, {"id": "safe"})
    with pytest.raises(MCP2026ProtocolError, match="schema_validation_failed"):
        validate_schema_instance(schema, {"id": ""})


def test_meta_keys_follow_the_official_prefix_and_name_grammar():
    validate_meta_object(
        {
            "progressToken": 1,
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "com.example/private_value": "opaque",
        }
    )
    for key in ("bad prefix/value", "1invalid.prefix/name", "vendor/-bad", "a//b"):
        with pytest.raises(MCP2026ProtocolError, match="invalid_meta_key"):
            validate_meta_object({key: "opaque"})


def test_known_request_meta_fields_and_capability_shapes_are_validated():
    validate_request_meta(
        {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "elicitation": {"form": {}},
                "extensions": {"com.example/feature": {}},
            },
            "progressToken": 1,
            "io.modelcontextprotocol/logLevel": "warning",
        }
    )
    invalid_updates = (
        {"io.modelcontextprotocol/clientCapabilities": []},
        {"io.modelcontextprotocol/clientCapabilities": {"sampling": []}},
        {"io.modelcontextprotocol/clientCapabilities": {"sampling": None}},
        {"io.modelcontextprotocol/clientCapabilities": {"elicitation": None}},
        {"progressToken": True},
        {"io.modelcontextprotocol/logLevel": "verbose"},
    )
    for update in invalid_updates:
        meta = {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            **update,
        }
        with pytest.raises(MCP2026ProtocolError):
            validate_request_meta(meta)


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_non_finite_numbers_are_rejected_as_invalid_json(constant):
    with pytest.raises(MCP2026ProtocolError, match="invalid_json"):
        parse_json_bytes(b'{"jsonrpc":"2.0","id":1,"result":' + constant + b"}")


def test_sse_non_finite_numbers_are_rejected_as_invalid_json():
    raw = b'data: {"jsonrpc":"2.0","id":"request-1","result":NaN}\n\n'
    with pytest.raises(MCP2026ProtocolError, match="upstream_invalid_sse"):
        parse_sse_jsonrpc_response(raw, "request-1")


def test_valid_parameter_headers_are_nested_deterministic_and_encoded():
    schema = _schema()
    assert [binding.path for binding in parameter_header_bindings(schema)] == [
        ("options", "enabled"),
        ("options", "limit"),
        ("tenant",),
    ]
    assert build_parameter_headers(
        schema,
        {
            "tenant": "=?base64?literal?=",
            "options": {"enabled": True, "limit": 7},
        },
    ) == {
        "Mcp-Param-Enabled": "true",
        "Mcp-Param-Limit": "7",
        "Mcp-Param-Tenant": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
    }


@pytest.mark.parametrize(
    "schema",
    [
        _schema(""),
        _schema("bad header"),
        {
            "type": "object",
            "properties": {"value": {"type": "number", "x-mcp-header": "Value"}},
        },
        {
            "type": "object",
            "items": {"type": "string", "x-mcp-header": "Value"},
        },
        {
            "type": "object",
            "properties": {
                "one": {"type": "string", "x-mcp-header": "Tenant"},
                "two": {"type": "string", "x-mcp-header": "tenant"},
            },
        },
    ],
)
def test_invalid_parameter_header_definitions_are_rejected(schema):
    with pytest.raises(MCP2026ProtocolError):
        parameter_header_bindings(schema)


def test_parameter_values_are_primitive_safe_and_null_or_absent_are_omitted():
    schema = _schema()
    assert build_parameter_headers(schema, {"tenant": None}) == {}
    with pytest.raises(MCP2026ProtocolError, match="invalid_parameter_header_value"):
        build_parameter_headers(schema, {"options": {"limit": MAX_SAFE_INTEGER + 1}})
    with pytest.raises(MCP2026ProtocolError, match="invalid_parameter_header_value"):
        build_parameter_headers(schema, {"tenant": {"secret": "not-a-string"}})


def test_inbound_parameter_headers_match_body_without_retaining_values():
    schema = _schema()
    arguments = {"tenant": "north", "options": {"enabled": True, "limit": 7}}
    validate_parameter_headers(
        schema,
        arguments,
        [
            (b"mcp-param-tenant", b"north"),
            (b"MCP-PARAM-ENABLED", b"true"),
            (b"mcp-param-limit", b"007"),
        ],
    )

    hostile = [
        (b"mcp-param-tenant", b"private-secret"),
        (b"mcp-param-enabled", b"true"),
        (b"mcp-param-limit", b"7"),
    ]
    with pytest.raises(MCP2026ProtocolError) as captured:
        validate_parameter_headers(schema, arguments, hostile)
    assert "private-secret" not in str(captured.value)


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"mcp-param-tenant", b"north"), (b"mcp-param-tenant", b"north")],
        [(b"mcp-param-unknown", b"value")],
        [(b"mcp-param-tenant", b"north\r\ninjected")],
    ],
)
def test_missing_duplicate_unknown_and_injected_parameter_headers_fail(headers):
    with pytest.raises(MCP2026ProtocolError):
        validate_parameter_headers(_schema(), {"tenant": "north"}, headers)


def _event(message: dict) -> bytes:
    return f"data: {json.dumps(message)}\n\n".encode()


def test_sse_parser_ignores_comments_and_notifications_then_returns_final_response():
    raw = (
        b": keepalive\n\n"
        + _event(
            {
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progress": 1},
            }
        )
        + _event(
            {
                "jsonrpc": "2.0",
                "id": "request-1",
                "result": {"resultType": "complete"},
            }
        )
    )
    assert parse_sse_jsonrpc_response(raw, "request-1")["result"]["resultType"] == (
        "complete"
    )


@pytest.mark.parametrize(
    "raw",
    [
        _event({"jsonrpc": "2.0", "id": "server", "method": "roots/list"}),
        _event({"jsonrpc": "2.0", "id": "wrong", "result": {}}),
        b"data: not-json\n\n",
        b": comments only\n\n",
    ],
)
def test_sse_server_requests_unrelated_responses_and_malformed_streams_fail(raw):
    with pytest.raises(MCP2026ProtocolError):
        parse_sse_jsonrpc_response(raw, "request-1")


def test_complete_tool_result_content_blocks_are_structurally_validated():
    validate_call_tool_result(
        {
            "resultType": "complete",
            "content": [
                {"type": "text", "text": "safe"},
                {"type": "image", "data": "AA==", "mimeType": "image/png"},
                {
                    "type": "resource",
                    "resource": {"uri": "memory://result", "text": "safe"},
                },
            ],
            "isError": False,
        }
    )
    for result in (
        {"content": [{"type": "text", "text": 1}]},
        {"content": [{"type": "unknown", "value": "opaque"}]},
        {"content": [], "isError": "false"},
    ):
        with pytest.raises(MCP2026ProtocolError):
            validate_call_tool_result(result)
