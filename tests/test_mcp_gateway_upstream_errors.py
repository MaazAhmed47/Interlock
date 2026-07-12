"""The MCP call path fails closed on invalid upstream HTTP/JSON-RPC responses."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from core import db
from core.mcp_gateway import proxy_mcp_tool_call

SERVER_ID = "_test_upstream_failure_server"


@pytest.fixture(autouse=True)
def trusted_server():
    db.init_db()
    db.unregister_mcp_server(SERVER_ID)
    db.register_mcp_server(
        SERVER_ID,
        {
            "url": "http://localhost:9799/mcp",
            "description": "upstream failure test",
            "allowed_tools": ["read_document"],
            "blocked_tools": [],
        },
    )
    db.verify_mcp_server(SERVER_ID)
    yield
    db.unregister_mcp_server(SERVER_ID)


def _response(*, data=None, content=b"json", json_error=None, status=200):
    response = MagicMock()
    response.content = content
    response.status_code = status
    response.json = MagicMock(
        side_effect=json_error,
        return_value=data,
    )
    if status >= 400:
        request = httpx.Request("POST", "http://localhost:9799/mcp")
        real_response = httpx.Response(status, json=data or {}, request=request)
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "upstream status failure", request=request, response=real_response
        )
    return response


@pytest.mark.parametrize(
    ("response", "post_error", "expected_error"),
    [
        (
            _response(json_error=json.JSONDecodeError("bad", "x", 0)),
            None,
            "upstream_invalid_json",
        ),
        (_response(data={"error": "failed"}, status=500), None, "upstream_http_error"),
        (
            _response(
                data={
                    "jsonrpc": "2.0",
                    "id": "x",
                    "error": {"code": -32000, "message": "denied"},
                }
            ),
            None,
            "upstream_jsonrpc_error",
        ),
        (None, httpx.ReadTimeout("slow upstream"), "mcp_server_timeout"),
        (_response(content=b"", data=None), None, "upstream_empty_response"),
        (
            _response(data={"jsonrpc": "2.0", "result": None}),
            None,
            "upstream_invalid_envelope",
        ),
    ],
)
def test_invalid_upstream_response_is_failed_and_audited(
    response, post_error, expected_error
):
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(side_effect=post_error, return_value=response)

    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            proxy_mcp_tool_call(
                SERVER_ID,
                "read_document",
                {"doc_id": "q3"},
                role="admin_agent",
                principal_id="lf_test_key",
            )
        )

    assert outcome["ok"] is False
    assert outcome["error"] == expected_error
    assert outcome["audit"]["audit_id"]
    row = db.get_mcp_audit_log(outcome["audit"]["audit_id"])
    assert row["action"] == "deny"
    assert row["matched_rule"] == "upstream_call_failed"
    assert row["observed_error_class"] == expected_error
    assert row["principal_id"] == "lf_test_key"


def test_each_jsonrpc_tool_call_uses_a_unique_request_id():
    ids = []

    async def post(_url, **kwargs):
        request_id = kwargs["json"]["id"]
        ids.append(request_id)
        return _response(data={"jsonrpc": "2.0", "id": request_id, "result": {}})

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = post

    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        for _ in range(2):
            outcome = asyncio.run(
                proxy_mcp_tool_call(SERVER_ID, "read_document", {}, role="admin_agent")
            )
            assert outcome["ok"] is True

    assert len(ids) == 2
    assert ids[0] != ids[1]
