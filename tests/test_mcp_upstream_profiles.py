"""Explicit legacy and MCP 2026 upstream wire-profile tests."""

import asyncio
import base64
import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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
    response.content = json.dumps(data).encode("utf-8")
    response.status_code = 200
    response.headers = {"content-type": "application/json"}
    response.json.return_value = data

    async def aiter_bytes():
        yield response.content

    response.aiter_bytes = aiter_bytes
    return response


class _StreamContext:
    def __init__(self, post, url, kwargs):
        self.post = post
        self.url = url
        self.kwargs = kwargs

    async def __aenter__(self):
        return await self.post(self.url, **self.kwargs)

    async def __aexit__(self, *_args):
        return False


def _mock_client(post):
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = post
    client.stream = lambda _method, url, **kwargs: _StreamContext(post, url, kwargs)
    return client


@pytest.fixture(autouse=True)
def clean_server():
    db.init_db()
    db.unregister_mcp_server(SERVER_ID)
    yield
    db.unregister_mcp_server(SERVER_ID)


def _register(
    profile: str = "legacy",
    *,
    parameter_header: bool = False,
    output_schema: dict | None = None,
) -> None:
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
    if output_schema is not None:
        definition["outputSchema"] = output_schema
    db.upsert_mcp_tool_metadata(
        SERVER_ID, definition, normalize_tool_metadata(definition)
    )


@contextmanager
def _official_typescript_server(
    response_mode: str = "json",
) -> Iterator[tuple[str, list[dict]]]:
    node_root = os.environ.get("INTERLOCK_MCP_SDK_NODE_ROOT")
    if not node_root:
        pytest.skip(
            "set INTERLOCK_MCP_SDK_NODE_ROOT to an isolated npm root with "
            "@modelcontextprotocol/server==2.0.0"
        )
    script = Path(__file__).parent / "sdk_interop/typescript_strict_server.mjs"
    env = os.environ.copy()
    env["SDK_NODE_ROOT"] = node_root
    env["SDK_RESPONSE_MODE"] = response_mode
    process = subprocess.Popen(
        [os.environ.get("INTERLOCK_MCP_SDK_NODE") or "node", str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert process.stdout is not None
    port = process.stdout.readline().strip()
    if not port:
        stderr = process.stderr.read() if process.stderr is not None else ""
        process.kill()
        raise AssertionError(f"official TypeScript server did not start: {stderr}")
    captures: list[dict] = []
    try:
        yield f"http://127.0.0.1:{int(port)}/mcp", captures
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=10)
        captures.extend(
            json.loads(line) for line in stderr.splitlines() if line.startswith("{")
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

    client = _mock_client(post)
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
                "ttlMs": 0,
                "cacheScope": "private",
            }
        else:
            result = {
                "resultType": "complete",
                "tools": [_tool()],
                "ttlMs": 0,
                "cacheScope": "private",
            }
        return _response({"jsonrpc": "2.0", "id": request["id"], "result": result})

    client = _mock_client(post)
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


@pytest.mark.parametrize("response_mode", ["json", "sse"])
def test_explicit_2026_profile_interoperates_with_official_typescript_server(
    monkeypatch, response_mode
):
    monkeypatch.setenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", "true")
    with _official_typescript_server(response_mode) as (url, captures):
        assert db.register_mcp_server(
            SERVER_ID,
            {
                "url": url,
                "allowed_tools": ["read_document"],
                "upstream_protocol_profile": "2026-07-28",
            },
        )
        db.verify_mcp_server(SERVER_ID)
        discovered = asyncio.run(_fetch_tool_list_payload(url, 5, SERVER_ID))
        assert discovered["ok"] is True
        definition = discovered["tools"][0]
        db.upsert_mcp_tool_metadata(
            SERVER_ID, definition, normalize_tool_metadata(definition)
        )
        called = asyncio.run(
            proxy_mcp_tool_call(
                SERVER_ID,
                "read_document",
                {"document_id": "safe"},
                role="admin_agent",
            )
        )

    assert called["ok"] is True
    assert called["result"]["isError"] is False
    assert [capture["body"]["method"] for capture in captures] == [
        "server/discover",
        "tools/list",
        "tools/call",
    ]
    for capture, method in zip(
        captures, ("server/discover", "tools/list", "tools/call"), strict=True
    ):
        assert capture["headers"] == {
            "acceptsJsonAndSse": True,
            "contentTypeIsJson": True,
            "protocolMatchesMeta": True,
            "methodMatchesBody": True,
            "nameMatchesBody": True,
        }
        assert capture["body"] == {
            "jsonrpc": "2.0",
            "hasId": True,
            "idType": "string",
            "method": method,
            "meta": {
                "protocolVersion": "2026-07-28",
                "clientInfoIsObject": True,
                "clientCapabilitiesIsObject": True,
            },
        }
    retained = json.dumps(captures, sort_keys=True)
    assert "document_id" not in retained
    assert "safe" not in retained


@pytest.mark.parametrize(
    ("discover_result", "expected_error"),
    [
        (
            {
                "resultType": "complete",
                "supportedVersions": ["2025-11-25"],
                "capabilities": {"tools": {}},
                "ttlMs": 0,
                "cacheScope": "private",
            },
            "upstream_protocol_mismatch",
        ),
        (
            {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {},
                "ttlMs": 0,
                "cacheScope": "private",
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

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == expected_error
    assert [call["json"]["method"] for call in calls] == ["server/discover"]


@pytest.mark.parametrize(
    ("result_update", "expected_error"),
    [
        ({"ttlMs": None}, "upstream_invalid_cache_hint"),
        ({"ttlMs": -1}, "upstream_invalid_cache_hint"),
        ({"cacheScope": "shared"}, "upstream_invalid_cache_hint"),
        ({"_meta": []}, "upstream_invalid_metadata"),
        (
            {
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {"name": "strict-server"}
                }
            },
            "upstream_invalid_server_identity",
        ),
    ],
)
def test_declared_2026_rejects_invalid_required_result_metadata(
    result_update, expected_error
):
    _register("2026-07-28")
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        request = kwargs["json"]
        result = {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {}},
            "ttlMs": 0,
            "cacheScope": "private",
            **result_update,
        }
        return _response({"jsonrpc": "2.0", "id": request["id"], "result": result})

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == expected_error
    assert [call["json"]["method"] for call in calls] == ["server/discover"]


def test_declared_2026_rejects_missing_jsonrpc_without_downgrade():
    _register("2026-07-28")
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        request = kwargs["json"]
        return _response(
            {
                "id": request["id"],
                "result": {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                    "ttlMs": 0,
                    "cacheScope": "private",
                },
            }
        )

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "upstream_invalid_envelope"
    assert [call["json"]["method"] for call in calls] == ["server/discover"]


def test_declared_2026_accepts_bounded_sse_without_downgrade():
    _register("2026-07-28")
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        request = kwargs["json"]
        result = {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {}},
            "ttlMs": 0,
            "cacheScope": "private",
        }
        if request["method"] == "tools/list":
            result = {
                "resultType": "complete",
                "tools": [_tool()],
                "ttlMs": 0,
                "cacheScope": "private",
            }
        response = _response({})
        response.headers = {"content-type": "text/event-stream"}
        response.content = (
            "data: "
            + json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result})
            + "\n\n"
        ).encode()
        return response

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is True
    assert [call["json"]["method"] for call in calls] == [
        "server/discover",
        "tools/list",
    ]


@pytest.mark.parametrize("failure", ["http_rejection", "timeout"])
def test_declared_2026_transport_failure_never_retries_legacy(failure):
    _register("2026-07-28")
    calls = []

    async def post(url, **kwargs):
        calls.append(kwargs)
        if failure == "timeout":
            raise httpx.ReadTimeout("strict modern upstream timed out")
        request = httpx.Request("POST", url)
        return httpx.Response(
            404,
            request=request,
            json={
                "jsonrpc": "2.0",
                "id": kwargs["json"]["id"],
                "error": {"code": -32601, "message": "Method not found"},
            },
        )

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert [call["json"]["method"] for call in calls] == ["server/discover"]
    assert (
        calls[0]["json"]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"]
        == "2026-07-28"
    )


@pytest.mark.parametrize("cursor", ["page-2", "", None])
def test_paginated_tool_surface_is_rejected_without_partial_baseline(cursor):
    _register("2026-07-28")

    async def post(_url, **kwargs):
        request = kwargs["json"]
        if request["method"] == "server/discover":
            result = {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
                "ttlMs": 0,
                "cacheScope": "private",
            }
        else:
            result = {
                "resultType": "complete",
                "tools": [_tool()],
                "nextCursor": cursor,
                "ttlMs": 0,
                "cacheScope": "private",
            }
        return _response({"jsonrpc": "2.0", "id": request["id"], "result": result})

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "unsupported_upstream_pagination"


@pytest.mark.parametrize(
    "input_schema",
    [
        {"type": "string"},
        {
            "type": "object",
            "$ref": "https://schemas.example.invalid/private.json",
        },
        {
            "type": "object",
            "properties": {"tenant": {"type": "string", "x-mcp-header": "bad header"}},
        },
    ],
)
def test_declared_2026_excludes_invalid_tool_schemas_without_losing_valid_tools(
    input_schema,
):
    _register("2026-07-28")

    async def post(_url, **kwargs):
        request = kwargs["json"]
        if request["method"] == "server/discover":
            result = {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
                "ttlMs": 0,
                "cacheScope": "private",
            }
        else:
            result = {
                "resultType": "complete",
                "tools": [
                    {**_tool("invalid_document"), "inputSchema": input_schema},
                    _tool("read_document"),
                ],
                "ttlMs": 0,
                "cacheScope": "private",
            }
        return _response({"jsonrpc": "2.0", "id": request["id"], "result": result})

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is True
    assert [tool["name"] for tool in outcome["tools"]] == ["read_document"]
    assert "schemas.example.invalid" not in str(outcome)


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

    client = _mock_client(post)
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

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            proxy_mcp_tool_call(SERVER_ID, "read_document", {}, role="admin_agent")
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "unsupported_upstream_result_type"


def test_valid_x_mcp_header_tool_is_mirrored_from_arguments():
    _register("2026-07-28", parameter_header=True)
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

    client = _mock_client(post)

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
    assert len(calls) == 1
    assert calls[0]["headers"]["Mcp-Param-Tenant"] == "internal"
    assert "internal" not in str(outcome["audit"])


def test_declared_output_schema_is_validated_before_response_release():
    output_schema = {
        "type": "object",
        "properties": {"status": {"const": "approved"}},
        "required": ["status"],
    }
    _register("2026-07-28", output_schema=output_schema)

    async def post(_url, **kwargs):
        request = kwargs["json"]
        return _response(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": "not released"}],
                    "structuredContent": {"status": "denied"},
                    "isError": False,
                },
            }
        )

    client = _mock_client(post)
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
    assert outcome["error"] == "upstream_output_schema_mismatch"
    assert "not released" not in str(outcome)


def test_sse_server_request_is_rejected_without_retry_or_content_retention():
    _register("2026-07-28")
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        response = _response({})
        response.headers = {"content-type": "text/event-stream"}
        response.content = (
            'data: {"jsonrpc":"2.0","id":"server-id-secret",'
            '"method":"roots/list","params":{"secret":"never-retain"}}\n\n'
        ).encode()
        return response

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "upstream_server_request_unsupported"
    assert len(calls) == 1
    assert "server-id-secret" not in str(outcome)
    assert "never-retain" not in str(outcome)


def test_modern_sse_body_is_rejected_while_streaming_before_full_retention():
    _register("2026-07-28")
    yielded = []

    async def post(_url, **_kwargs):
        response = _response({})
        response.headers = {"content-type": "text/event-stream"}
        response.content = b""

        async def aiter_bytes():
            for chunk in (b"x" * (1024 * 1024),) * 3:
                yielded.append(len(chunk))
                yield chunk

        response.aiter_bytes = aiter_bytes
        return response

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "response_too_large"
    assert yielded == [1024 * 1024, 1024 * 1024, 1024 * 1024]


def test_modern_upstream_non_finite_json_is_rejected_without_retry():
    _register("2026-07-28")
    calls = []

    async def post(_url, **kwargs):
        calls.append(kwargs)
        response = _response({})
        response.content = b'{"jsonrpc":"2.0","id":"opaque","result":NaN}'
        return response

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "upstream_invalid_json"
    assert len(calls) == 1


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
