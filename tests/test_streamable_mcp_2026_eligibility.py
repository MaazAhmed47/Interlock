from core import mcp_tool_eligibility


def test_parameter_header_tool_is_not_advertised_until_it_can_be_mirrored(
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
        lambda _: {"verified": True, "allowed_tools": ["read_document"]},
    )
    monkeypatch.setattr(
        mcp_tool_eligibility.db, "lookup_mcp_tool_metadata", lambda *_: record
    )
    monkeypatch.setattr(
        mcp_tool_eligibility.db, "canonicalize_mcp_tool_record", lambda value: value
    )

    result = mcp_tool_eligibility.evaluate_streamable_tool("server", "read_document")

    assert result.eligible is False
    assert result.reason == "unsupported_mcp_parameter_header"
