"""Work-budget and pre-parse body-limit regressions for definition inspection."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
import pytest
from starlette.requests import Request

from core import db
from core.http_body import MALFORMED, TOO_LARGE, declared_length_error
from core import mcp_definition_inspector as inspector


class CountingList(list):
    def __init__(self, values):
        super().__init__(values)
        self.reads = 0

    def __iter__(self):
        for value in super().__iter__():
            self.reads += 1
            yield value

    def __getitem__(self, index):
        self.reads += 1
        return super().__getitem__(index)


class CountingDict(dict):
    def __init__(self, values):
        super().__init__(values)
        self.reads = 0

    def items(self):
        for item in super().items():
            self.reads += 1
            yield item


def _metadata(result) -> dict:
    return result.to_metadata()


def test_wide_combinator_stops_enumeration_and_bounds_pending_work():
    work_limit = getattr(
        inspector, "MAX_ENUMERATED_CHILDREN", inspector.MAX_VISITED_NODES
    )
    pending_limit = getattr(inspector, "MAX_PENDING_ITEMS", inspector.MAX_VISITED_NODES)
    shared = {"description": "Ordinary documentation."}
    children = CountingList([shared] * (work_limit + 50))
    result = inspector.inspect_tool_definition_text(
        {"name": "wide", "inputSchema": {"allOf": children}}
    )
    metadata = _metadata(result)
    assert result.limit_exceeded is True
    assert children.reads <= work_limit + 1
    assert metadata["enumerated_children"] <= work_limit
    assert metadata["pending_peak"] <= pending_limit


def test_wide_mapping_stops_without_materializing_all_items():
    work_limit = getattr(
        inspector, "MAX_ENUMERATED_CHILDREN", inspector.MAX_VISITED_NODES
    )
    properties = CountingDict(
        (f"field_{index}", {"description": "Ordinary documentation."})
        for index in range(work_limit + 50)
    )
    result = inspector.inspect_tool_definition_text(
        {"name": "wide", "inputSchema": {"properties": properties}}
    )
    metadata = _metadata(result)
    assert result.limit_exceeded is True
    assert properties.reads <= work_limit + 1
    assert metadata["enumerated_children"] <= work_limit


def test_wide_mapping_counts_primitive_siblings_as_work():
    work_limit = inspector.MAX_ENUMERATED_CHILDREN
    properties = CountingDict(
        (f"field_{index}", "invalid-schema-child") for index in range(work_limit + 50)
    )
    result = inspector.inspect_tool_definition_text(
        {"name": "wide", "inputSchema": {"properties": properties}}
    )
    assert result.limit_exceeded is True
    assert properties.reads <= work_limit + 1
    assert result.enumerated_children <= work_limit


def test_examples_stop_immediately_after_field_budget():
    examples = CountingList(["ordinary"] * (inspector.MAX_TEXT_FIELDS + 50))
    result = inspector.inspect_tool_definition_text(
        {"name": "examples", "inputSchema": {"examples": examples}}
    )
    assert result.limit_exceeded is True
    assert examples.reads <= inspector.MAX_TEXT_FIELDS + 1
    assert result.inspected_fields <= inspector.MAX_TEXT_FIELDS


def test_wide_metadata_extensions_obey_child_and_pending_budgets():
    work_limit = getattr(
        inspector, "MAX_ENUMERATED_CHILDREN", inspector.MAX_VISITED_NODES
    )
    entries = CountingList([{"x-help": "Ordinary documentation."}] * (work_limit + 50))
    result = inspector.inspect_tool_definition_text(
        {"name": "metadata", "_meta": {"entries": entries}}
    )
    metadata = _metadata(result)
    assert result.limit_exceeded is True
    assert entries.reads <= work_limit + 1
    assert metadata["pending_peak"] <= getattr(
        inspector, "MAX_PENDING_ITEMS", inspector.MAX_VISITED_NODES
    )


def test_node_field_and_character_limits_are_auditable():
    deep = {"description": "ordinary"}
    for _ in range(inspector.MAX_TRAVERSAL_DEPTH + 2):
        deep = {"items": deep}
    depth_result = inspector.inspect_tool_definition_text(
        {"name": "deep", "inputSchema": deep}
    )
    assert depth_result.limit_exceeded is True

    long_text = "x" * (inspector.MAX_INSPECTED_CHARACTERS + 1)
    character_result = inspector.inspect_tool_definition_text(
        {"name": "long", "description": long_text}
    )
    assert character_result.limit_exceeded is True
    assert character_result.inspected_characters <= inspector.MAX_INSPECTED_CHARACTERS
    for result in (depth_result, character_result):
        findings = result.to_metadata()["findings"]
        assert any(item["category"] == "inspection_limit_exceeded" for item in findings)


def test_node_and_cumulative_character_budgets_fail_closed(monkeypatch):
    monkeypatch.setattr(inspector, "MAX_VISITED_NODES", 3)
    monkeypatch.setattr(inspector, "MAX_TRAVERSAL_DEPTH", 20)
    chain = {"description": "ordinary"}
    for _ in range(5):
        chain = {"items": chain}
    node_result = inspector.inspect_tool_definition_text(
        {"name": "nodes", "inputSchema": chain}
    )
    assert node_result.limit_exceeded is True
    assert node_result.visited_nodes == 3

    monkeypatch.setattr(inspector, "MAX_INSPECTED_CHARACTERS", 12)
    monkeypatch.setattr(inspector, "MAX_TEXT_LENGTH", 12)
    character_result = inspector.inspect_tool_definition_text(
        {
            "name": "chars",
            "description": "ordinary",
            "inputSchema": {"description": "documentation"},
        }
    )
    assert character_result.limit_exceeded is True
    assert character_result.inspected_characters == 12
    assert any(
        finding.category == "inspection_limit_exceeded"
        for finding in character_result.findings
    )


@pytest.fixture()
def validation_client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "validate-body.db"))
    db.init_db()
    key = db.generate_key(
        "free", label="definition-validator", scopes=["mcp.discover"]
    )["raw_key"]
    import proxy

    return TestClient(proxy.app), key


def _valid_body_bytes() -> bytes:
    return json.dumps(
        {
            "tool_definition": {
                "name": "bounded_tool",
                "description": "Ordinary documentation.",
                "inputSchema": {"type": "object", "properties": {}},
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")


def test_validation_body_normal_exact_boundary_and_plus_one(validation_client):
    from routes.mcp import MAX_MCP_VALIDATE_BODY_BYTES

    client, key = validation_client
    base = _valid_body_bytes()
    exact = base + b" " * (MAX_MCP_VALIDATE_BODY_BYTES - len(base))
    accepted = client.post(
        "/mcp/validate-tool",
        headers={"X-API-Key": key, "Content-Type": "application/json"},
        content=exact,
    )
    assert accepted.status_code == 200

    rejected = client.post(
        "/mcp/validate-tool",
        headers={"X-API-Key": key, "Content-Type": "application/json"},
        content=exact + b" ",
    )
    assert rejected.status_code == 413
    assert rejected.json() == {"detail": {"error": "request_body_too_large"}}


def test_validation_stream_cap_rejects_missing_or_lying_length(validation_client):
    from routes.mcp import MAX_MCP_VALIDATE_BODY_BYTES

    client, key = validation_client

    def oversized_chunks():
        yield b"{" + b"x" * (MAX_MCP_VALIDATE_BODY_BYTES // 2)
        yield b"x" * (MAX_MCP_VALIDATE_BODY_BYTES // 2 + 1)

    chunked = client.post(
        "/mcp/validate-tool",
        headers={
            "X-API-Key": key,
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
        },
        content=oversized_chunks(),
    )
    assert chunked.status_code == 413

    lying = client.post(
        "/mcp/validate-tool",
        headers={
            "X-API-Key": key,
            "Content-Type": "application/json",
            "Content-Length": "2",
        },
        content=b"{" + b"x" * MAX_MCP_VALIDATE_BODY_BYTES,
    )
    assert lying.status_code == 413


def test_validation_malformed_json_and_multibyte_byte_accounting(validation_client):
    from routes.mcp import MAX_MCP_VALIDATE_BODY_BYTES

    client, key = validation_client
    malformed = client.post(
        "/mcp/validate-tool",
        headers={"X-API-Key": key, "Content-Type": "application/json"},
        content=b"{",
    )
    assert malformed.status_code == 400
    assert malformed.json() == {"detail": {"error": "malformed_json"}}

    prefix = _valid_body_bytes()[:-1]
    unicode_suffix = ',"padding":"'.encode() + "界".encode() * 100 + b'"}'
    payload = prefix + unicode_suffix
    payload += b" " * (MAX_MCP_VALIDATE_BODY_BYTES + 1 - len(payload))
    assert len(payload) == MAX_MCP_VALIDATE_BODY_BYTES + 1
    response = client.post(
        "/mcp/validate-tool",
        headers={"X-API-Key": key, "Content-Type": "application/json"},
        content=payload,
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([(b"content-length", b"1"), (b"content-length", b"1")], MALFORMED),
        ([(b"content-length", b"-1")], MALFORMED),
        ([(b"content-length", b"invalid")], MALFORMED),
        ([(b"content-length", b"999999")], TOO_LARGE),
    ],
)
def test_validation_declared_length_rejects_ambiguous_values(headers, expected):
    request = Request({"type": "http", "headers": headers})
    assert declared_length_error(request, 1024) == expected


def test_oversized_validation_error_never_echoes_body(validation_client, caplog):
    from routes.mcp import MAX_MCP_VALIDATE_BODY_BYTES

    client, key = validation_client
    marker = "PRIVATE_" + "VALIDATION_" + "MARKER"
    body = ("{" + marker + ("x" * MAX_MCP_VALIDATE_BODY_BYTES)).encode()
    response = client.post(
        "/mcp/validate-tool",
        headers={"X-API-Key": key, "Content-Type": "application/json"},
        content=body,
    )
    serialized = response.text + repr(response.json()) + caplog.text
    assert response.status_code == 413
    assert marker not in serialized
