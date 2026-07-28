"""Explicit legacy and MCP 2026 upstream wire-profile tests."""

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core import db
from core.mcp_gateway import (
    _encode_mcp_header_value,
    _fetch_tool_list_payload,
    proxy_mcp_tool_call,
    register_mcp_server,
)
from core.tool_metadata import normalize_tool_metadata

SERVER_ID = "_test_upstream_profile_server"


def _tool(name: str = "read_document", *, parameter_header: bool = False) -> dict:
    property_schema = {"type": "string"}
    if parameter_header:
        property_schema["x-mcp-header"] = "Tenant"
    return {
        "name": name,
        "description": "Read one document.",
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": property_schema},
        },
    }


def _response(data: dict) -> MagicMock:
    response = MagicMock()
    response.content = b"json"
    response.status_code = 200
    response.json.return_value = data
    return response


@pytest.fixture(autouse=True)
def clean_server():
    db.init_db()
    db.unregister_mcp_server(SERVER_ID)
    yield
    db.unregister_mcp_server(SERVER_ID)


def _register(profile: str = "legacy", *, parameter_header: bool = False) -> None:
    assert db.register_mcp_server(
        SERVER_ID,
        {
            "url": "http://localhost:9799/mcp",
            "allowed_tools": ["read_document"],
            "upstream_protocol_profile": profile,
        },
    )
    db.verify_mcp_server(SERVER_ID)
    definition = _tool(parameter_header=parameter_header)
    db.upsert_mcp_tool_metadata(
        SERVER_ID, definition, normalize_tool_metadata(definition)
    )


def test_registration_defaults_to_legacy_and_rejects_unknown_profile():
    _register()
    assert db.lookup_mcp_server(SERVER_ID)["upstream_protocol_profile"] == "legacy"
    db.unregister_mcp_server(SERVER_ID)

    rejected = register_mcp_server(
        SERVER_ID,
        {
            "url": "http://localhost:9799/mcp",
            "upstream_protocol_profile": "auto",
        },
    )
    assert rejected["ok"] is False
    assert rejected["error"] == "registration_rejected"
    assert db.lookup_mcp_server(SERVER_ID) is None


def test_legacy_discovery_wire_shape_is_unchanged():
    _register()
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        request = kwargs["json"]
        return _response(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {"tools": [_tool()]},
            }
        )

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = post
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        result = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert result["ok"] is True
    assert len(calls) == 1
    assert calls[0]["json"]["method"] == "tools/list"
    assert calls[0]["json"]["params"] == {}
    assert "headers" not in calls[0]


def test_declared_2026_discovery_is_pinned_and_self_describing():
    _register("2026-07-28")
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        request = kwargs["json"]
        if request["method"] == "server/discover":
            result = {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
            }
        else:
            result = {"resultType": "complete", "tools": [_tool()]}
        return _response({"jsonrpc": "2.0", "id": request["id"], "result": result})

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = post
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is True
    assert [call["json"]["method"] for call in calls] == [
        "server/discover",
        "tools/list",
    ]
    for call in calls:
        method = call["json"]["method"]
        assert call["headers"]["MCP-Protocol-Version"] == "2026-07-28"
        assert call["headers"]["Mcp-Method"] == method
        meta = call["json"]["params"]["_meta"]
        assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        assert isinstance(meta["io.modelcontextprotocol/clientInfo"], dict)
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {}


@pytest.mark.parametrize(
    ("discover_result", "expected_error"),
    [
        (
            {
                "resultType": "complete",
                "supportedVersions": ["2025-11-25"],
                "capabilities": {"tools": {}},
            },
            "upstream_protocol_mismatch",
        ),
        (
            {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {},
            },
            "upstream_protocol_mismatch",
        ),
        (
            {
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
            },
            "unsupported_upstream_result_type",
        ),
    ],
)
def test_declared_2026_discovery_never_downgrades(discover_result, expected_error):
    _register("2026-07-28")
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        request = kwargs["json"]
        return _response(
            {"jsonrpc": "2.0", "id": request["id"], "result": discover_result}
        )

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = post
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == expected_error
    assert [call["json"]["method"] for call in calls] == ["server/discover"]


def test_paginated_tool_surface_is_rejected_without_partial_baseline():
    _register("2026-07-28")

    async def post(_url, **kwargs):
        request = kwargs["json"]
        if request["method"] == "server/discover":
            result = {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
            }
        else:
            result = {
                "resultType": "complete",
                "tools": [_tool()],
                "nextCursor": "page-2",
            }
        return _response({"jsonrpc": "2.0", "id": request["id"], "result": result})

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = post
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "unsupported_upstream_pagination"


def test_declared_2026_tool_call_sends_headers_and_meta():
    _register("2026-07-28")
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        request = kwargs["json"]
        return _response(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": "safe"}],
                    "isError": False,
                },
            }
        )

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = post
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            proxy_mcp_tool_call(
                SERVER_ID,
                "read_document",
                {"tenant": "internal"},
                role="admin_agent",
            )
        )

    assert outcome["ok"] is True
    call = calls[0]
    assert call["headers"]["MCP-Protocol-Version"] == "2026-07-28"
    assert call["headers"]["Mcp-Method"] == "tools/call"
    assert call["headers"]["Mcp-Name"] == "read_document"
    assert (
        call["json"]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"]
        == "2026-07-28"
    )


def test_declared_2026_tool_call_rejects_missing_result_type():
    _register("2026-07-28")

    async def post(_url, **kwargs):
        request = kwargs["json"]
        return _response(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {"content": [], "isError": False},
            }
        )

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = post
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            proxy_mcp_tool_call(SERVER_ID, "read_document", {}, role="admin_agent")
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "unsupported_upstream_result_type"


def test_x_mcp_header_tool_is_never_called():
    _register("2026-07-28", parameter_header=True)
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock()

    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            proxy_mcp_tool_call(
                SERVER_ID,
                "read_document",
                {"tenant": "internal"},
                role="admin_agent",
            )
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "unsupported_mcp_parameter_header"
    client.post.assert_not_awaited()


def test_header_values_are_encoded_and_auth_cannot_override_protocol_headers(
    monkeypatch,
):
    raw = "read\r\nInjected: yes"
    encoded = _encode_mcp_header_value(raw)
    assert "\r" not in encoded and "\n" not in encoded
    assert encoded == f"=?base64?{base64.b64encode(raw.encode()).decode()}?="

    monkeypatch.setenv("MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS", "SAFE_TOKEN")
    monkeypatch.setenv("SAFE_TOKEN", "secret")
    rejected = register_mcp_server(
        SERVER_ID,
        {
            "url": "http://localhost:9799/mcp",
            "auth_type": "x-api-key",
            "auth_header": "MCP-Protocol-Version",
            "auth_token_env": "SAFE_TOKEN",
            "upstream_protocol_profile": "2026-07-28",
        },
    )
    assert rejected["ok"] is False
    assert rejected["error"] == "invalid_upstream_auth_config"
