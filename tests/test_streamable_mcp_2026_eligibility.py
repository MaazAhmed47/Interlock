from core import mcp_tool_eligibility


def test_valid_parameter_header_tool_requires_explicit_modern_upstream_profile(
    monkeypatch,
):
    raw = {
        "name": "read_document",
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "string", "x-mcp-header": "Tenant"}},
        },
    }
    record = {
        "status": "active",
        "raw_tool_definition": raw,
        "normalized_metadata": {},
        "tool_schema_hash": "sha256:test",
        "description_hash": "sha256:test",
    }
    monkeypatch.setattr(
        mcp_tool_eligibility.db,
        "lookup_mcp_server",
        lambda _: {
            "verified": True,
            "allowed_tools": ["read_document"],
            "upstream_protocol_profile": "2026-07-28",
        },
    )
    monkeypatch.setattr(
        mcp_tool_eligibility.db, "lookup_mcp_tool_metadata", lambda *_: record
    )
    monkeypatch.setattr(
        mcp_tool_eligibility.db, "canonicalize_mcp_tool_record", lambda value: value
    )

    result = mcp_tool_eligibility.evaluate_streamable_tool("server", "read_document")

    assert result.eligible is True
    assert result.reason == "eligible"

    monkeypatch.setattr(
        mcp_tool_eligibility.db,
        "lookup_mcp_server",
        lambda _: {
            "verified": True,
            "allowed_tools": ["read_document"],
            "upstream_protocol_profile": "legacy",
        },
    )
    legacy = mcp_tool_eligibility.evaluate_streamable_tool("server", "read_document")
    assert legacy.eligible is False
    assert legacy.reason == "unsupported_mcp_parameter_header"


def test_invalid_parameter_header_tool_is_not_advertised(monkeypatch):
    raw = {
        "name": "read_document",
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "string", "x-mcp-header": "bad header"}},
        },
    }
    record = {
        "status": "active",
        "raw_tool_definition": raw,
        "normalized_metadata": {},
        "tool_schema_hash": "sha256:test",
        "description_hash": "sha256:test",
    }
    monkeypatch.setattr(
        mcp_tool_eligibility.db,
        "lookup_mcp_server",
        lambda _: {
            "verified": True,
            "allowed_tools": ["read_document"],
            "upstream_protocol_profile": "2026-07-28",
        },
    )
    monkeypatch.setattr(
        mcp_tool_eligibility.db, "lookup_mcp_tool_metadata", lambda *_: record
    )
    monkeypatch.setattr(
        mcp_tool_eligibility.db, "canonicalize_mcp_tool_record", lambda value: value
    )

    result = mcp_tool_eligibility.evaluate_streamable_tool("server", "read_document")
    assert result.eligible is False
    assert result.reason == "invalid_mcp_tool_schema"
