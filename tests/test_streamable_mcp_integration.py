"""End-to-end proof for the JSON-response MCP Streamable HTTP transport."""

from __future__ import annotations

import asyncio
import importlib.metadata
import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import proxy
from core import db
from core.tool_metadata import normalize_tool_metadata

PROTOCOL_VERSION = "2025-11-25"
SERVER_ID = "_test_streamable_integration"
SECOND_SERVER_ID = "_test_streamable_other_server"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _serve(app: FastAPI) -> Iterator[str]:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="critical",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if not thread.is_alive() or time.monotonic() >= deadline:
            raise RuntimeError("test HTTP server did not start")
        time.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _tool(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"Read data with {name}.",
        "inputSchema": {
            "type": "object",
            "properties": {"document_id": {"type": "string"}},
        },
    }


def _initialize_message(request_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "integration-proof", "version": "1"},
        },
    }


def _transport_headers(key: str, **extra: str) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "X-API-Key": key,
    }
    headers.update(extra)
    return headers


def _open_session(url: str, key: str) -> str:
    initialized = httpx.post(
        url,
        headers=_transport_headers(key),
        json=_initialize_message(),
        timeout=5,
    )
    assert initialized.status_code == 200, initialized.text
    session_id = initialized.headers.get("MCP-Session-Id")
    assert session_id
    notification = httpx.post(
        url,
        headers=_transport_headers(
            key,
            **{
                "MCP-Protocol-Version": PROTOCOL_VERSION,
                "MCP-Session-Id": session_id,
            },
        ),
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        timeout=5,
    )
    assert notification.status_code == 202, notification.text
    return session_id


def _session_headers(key: str, session_id: str) -> dict[str, str]:
    return _transport_headers(
        key,
        **{
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "MCP-Session-Id": session_id,
        },
    )


def _call_message(name: str, arguments: dict[str, Any] | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


@pytest.fixture
def live_transport(tmp_path_factory):
    root = tmp_path_factory.mktemp("streamable-mcp")
    prior_db_path = db.DB_PATH
    db.DB_PATH = str(Path(root) / "streamable.db")
    db.init_db()
    proxy._key_record_cache.clear()

    upstream_calls: list[dict[str, Any]] = []
    upstream = FastAPI()

    @upstream.post("/mcp")
    async def upstream_call(request: Request):
        message = await request.json()
        upstream_calls.append(message)
        name = message.get("params", {}).get("name", "")
        document_id = message.get("params", {}).get("arguments", {}).get("document_id")
        text = (
            "contact person@example.com"
            if document_id == "pii-response"
            else f"safe result from {name}"
        )
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "content": [{"type": "text", "text": text}],
                    "isError": False,
                },
            }
        )

    with _serve(upstream) as upstream_url:
        db.register_mcp_server(
            SERVER_ID,
            {
                "url": f"{upstream_url}/mcp",
                "description": "Streamable integration fixture",
                "allowed_tools": [
                    "read_document",
                    "missing_metadata",
                    "blocked_tool",
                    "quarantined_tool",
                ],
                "blocked_tools": ["blocked_tool"],
                "environment": "non_production",
            },
        )
        db.verify_mcp_server(SERVER_ID)
        db.register_mcp_server(
            SECOND_SERVER_ID,
            {
                "url": f"{upstream_url}/mcp",
                "description": "Second Streamable integration fixture",
                "allowed_tools": ["read_document"],
                "blocked_tools": [],
                "environment": "non_production",
            },
        )
        db.verify_mcp_server(SECOND_SERVER_ID)
        for name in (
            "read_document",
            "blocked_tool",
            "quarantined_tool",
            "nonallowlisted_tool",
        ):
            definition = _tool(name)
            db.upsert_mcp_tool_metadata(
                SERVER_ID, definition, normalize_tool_metadata(definition)
            )
        second_definition = _tool("read_document")
        db.upsert_mcp_tool_metadata(
            SECOND_SERVER_ID,
            second_definition,
            normalize_tool_metadata(second_definition),
        )
        with db.get_conn() as conn:
            conn.execute(
                "UPDATE mcp_tool_metadata SET status = 'quarantined', "
                "drift_severity = 'critical', drift_action = 'quarantine' "
                "WHERE server_id = ? AND tool_name = 'quarantined_tool'",
                (SERVER_ID,),
            )

        key = db.generate_key(
            "free",
            label="streamable-integration",
            scopes=["mcp.call"],
            role="admin_agent",
        )["raw_key"]
        other_key = db.generate_key(
            "free",
            label="streamable-other-identity",
            scopes=["mcp.call"],
            role="admin_agent",
        )["raw_key"]
        readonly_key = db.generate_key(
            "free",
            label="streamable-readonly-identity",
            scopes=["mcp.call"],
            role="readonly_agent",
        )["raw_key"]

        with _serve(proxy.app) as interlock_url:
            yield {
                "url": f"{interlock_url}/mcp/stream/{SERVER_ID}",
                "base_url": interlock_url,
                "other_url": (f"{interlock_url}/mcp/stream/{SECOND_SERVER_ID}"),
                "key": key,
                "other_key": other_key,
                "readonly_key": readonly_key,
                "upstream_calls": upstream_calls,
            }

    db.unregister_mcp_server(SERVER_ID)
    db.unregister_mcp_server(SECOND_SERVER_ID)
    proxy._key_record_cache.clear()
    db.DB_PATH = prior_db_path


def test_official_sdk_initialize_list_and_allowed_call(live_transport):
    assert importlib.metadata.version("mcp") == "1.28.1"

    async def exercise():
        async with httpx.AsyncClient(
            headers={"X-API-Key": live_transport["key"]}
        ) as client:
            async with streamable_http_client(
                live_transport["url"], http_client=client, terminate_on_close=False
            ) as (read_stream, write_stream, get_session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await session.initialize()
                    listed = await session.list_tools()
                    called = await session.call_tool(
                        "read_document", {"document_id": "safe-document"}
                    )
                    return initialized, listed, called, get_session_id()

    before = len(live_transport["upstream_calls"])
    initialized, listed, called, session_id = asyncio.run(exercise())

    assert initialized.protocolVersion == PROTOCOL_VERSION
    assert session_id
    assert [tool.name for tool in listed.tools] == ["read_document"]
    assert called.isError is False
    assert called.content[0].text == "safe result from read_document"
    assert len(live_transport["upstream_calls"]) == before + 1


def test_pre_initialize_call_and_notification_do_not_reach_upstream(live_transport):
    before = len(live_transport["upstream_calls"])
    with httpx.Client(timeout=5) as client:
        call = client.post(
            live_transport["url"],
            headers=_transport_headers(
                live_transport["key"],
                **{"MCP-Protocol-Version": PROTOCOL_VERSION},
            ),
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_document", "arguments": {}},
            },
        )
        notification = client.post(
            live_transport["url"],
            headers=_transport_headers(
                live_transport["key"],
                **{"MCP-Protocol-Version": PROTOCOL_VERSION},
            ),
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

    assert call.status_code >= 400
    assert notification.status_code >= 400
    assert len(live_transport["upstream_calls"]) == before


def test_session_is_not_active_until_initialized_notification(live_transport):
    initialized = httpx.post(
        live_transport["url"],
        headers=_transport_headers(live_transport["key"]),
        json=_initialize_message(),
        timeout=5,
    )
    session_id = initialized.headers["MCP-Session-Id"]
    before = len(live_transport["upstream_calls"])
    listed = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["key"], session_id),
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        timeout=5,
    )
    called = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["key"], session_id),
        json=_call_message("read_document"),
        timeout=5,
    )
    assert listed.status_code == 404
    assert called.status_code == 404
    assert len(live_transport["upstream_calls"]) == before


def test_allowlisted_tool_without_metadata_is_hidden_and_denied(live_transport):
    async def exercise():
        async with httpx.AsyncClient(
            headers={"X-API-Key": live_transport["key"]}
        ) as client:
            async with streamable_http_client(
                live_transport["url"], http_client=client, terminate_on_close=False
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    called = await session.call_tool("missing_metadata", {})
                    return listed, called

    before = len(live_transport["upstream_calls"])
    listed, called = asyncio.run(exercise())

    assert "missing_metadata" not in [tool.name for tool in listed.tools]
    assert called.isError is True
    assert len(live_transport["upstream_calls"]) == before


def test_hostile_origin_is_rejected_under_default_local_config(
    live_transport, monkeypatch
):
    monkeypatch.setenv("INTERLOCK_ENV", "local")
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    response = httpx.post(
        live_transport["url"],
        headers=_transport_headers(
            live_transport["key"], Origin="https://evil.example"
        ),
        json=_initialize_message(),
        timeout=5,
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "origin",
    [
        "not-an-origin",
        "null",
        "https://evil.example/path",
        "https://user@client.example",
        "https://client.example:bad",
        "https://client.example?query=1",
        "https://client.example#fragment",
    ],
)
def test_malformed_origins_are_rejected(live_transport, monkeypatch, origin):
    monkeypatch.setenv("INTERLOCK_ENV", "local")
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://client.example")
    response = httpx.post(
        live_transport["url"],
        headers=_transport_headers(live_transport["key"], Origin=origin),
        json=_initialize_message(),
        timeout=5,
    )
    assert response.status_code == 403


def test_explicit_exact_origin_is_accepted(live_transport, monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://client.example")
    response = httpx.post(
        live_transport["url"],
        headers=_transport_headers(
            live_transport["key"], Origin="https://client.example"
        ),
        json=_initialize_message(),
        timeout=5,
    )
    assert response.status_code == 200


def test_ineligible_tools_are_neither_listed_nor_executed(live_transport):
    async def exercise():
        async with httpx.AsyncClient(
            headers={"X-API-Key": live_transport["key"]}
        ) as client:
            async with streamable_http_client(
                live_transport["url"], http_client=client, terminate_on_close=False
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    denied = {}
                    for name in (
                        "missing_metadata",
                        "blocked_tool",
                        "quarantined_tool",
                        "unknown_tool",
                        "nonallowlisted_tool",
                    ):
                        denied[name] = await session.call_tool(name, {})
                    return listed, denied

    before = len(live_transport["upstream_calls"])
    listed, denied = asyncio.run(exercise())

    assert [tool.name for tool in listed.tools] == ["read_document"]
    assert all(result.isError is True for result in denied.values())
    assert len(live_transport["upstream_calls"]) == before


def test_rbac_denial_and_response_scanning_remain_in_gateway_path(live_transport):
    readonly_session = _open_session(
        live_transport["url"], live_transport["readonly_key"]
    )
    before = len(live_transport["upstream_calls"])
    denied = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["readonly_key"], readonly_session),
        json=_call_message("read_document"),
        timeout=5,
    )
    assert denied.status_code == 200
    assert denied.json()["result"]["isError"] is True
    assert len(live_transport["upstream_calls"]) == before

    admin_session = _open_session(live_transport["url"], live_transport["key"])
    scanned = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["key"], admin_session),
        json=_call_message("read_document", {"document_id": "pii-response"}),
        timeout=5,
    )
    assert scanned.status_code == 200
    result_text = scanned.json()["result"]["content"][0]["text"]
    assert "person@example.com" not in result_text
    assert "[REDACTED-EMAIL]" in result_text


def test_bad_missing_expired_and_identity_or_server_mismatched_sessions_fail_closed(
    live_transport, monkeypatch
):
    session_id = _open_session(live_transport["url"], live_transport["key"])
    message = {"jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {}}

    missing = httpx.post(
        live_transport["url"],
        headers=_transport_headers(
            live_transport["key"],
            **{"MCP-Protocol-Version": PROTOCOL_VERSION},
        ),
        json=message,
        timeout=5,
    )
    malformed = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["key"], "not-a-session"),
        json=message,
        timeout=5,
    )
    wrong_identity = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["other_key"], session_id),
        json=message,
        timeout=5,
    )
    wrong_server = httpx.post(
        live_transport["other_url"],
        headers=_session_headers(live_transport["key"], session_id),
        json=message,
        timeout=5,
    )

    monkeypatch.setenv("INTERLOCK_MCP_SESSION_TTL_SECONDS", "1")
    expiring = _open_session(live_transport["url"], live_transport["key"])
    time.sleep(1.05)
    expired = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["key"], expiring),
        json=message,
        timeout=5,
    )

    assert {
        response.status_code
        for response in (missing, malformed, wrong_identity, wrong_server, expired)
    } == {404}


def test_session_store_is_hard_bounded(live_transport, monkeypatch):
    monkeypatch.setenv("INTERLOCK_MCP_MAX_SESSIONS", "1")
    first = _open_session(live_transport["url"], live_transport["key"])
    second = _open_session(live_transport["url"], live_transport["key"])
    message = {"jsonrpc": "2.0", "id": 21, "method": "tools/list", "params": {}}
    evicted = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["key"], first),
        json=message,
        timeout=5,
    )
    current = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["key"], second),
        json=message,
        timeout=5,
    )
    assert evicted.status_code == 404
    assert current.status_code == 200


def test_duplicate_and_conflicting_authentication_fails_closed(live_transport):
    cases = [
        [
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
            ("X-API-Key", live_transport["key"]),
            ("X-API-Key", live_transport["key"]),
        ],
        [
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
            ("Authorization", f"Bearer {live_transport['key']}"),
            ("Authorization", f"Bearer {live_transport['key']}"),
        ],
        [
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
            ("X-API-Key", live_transport["key"]),
            ("Authorization", f"Bearer {live_transport['key']}"),
        ],
    ]
    for headers in cases:
        response = httpx.post(
            live_transport["url"],
            headers=headers,
            json=_initialize_message(),
            timeout=5,
        )
        assert response.status_code == 401
        assert live_transport["key"] not in response.text


def test_bearer_authentication_can_initialize(live_transport):
    headers = _transport_headers(live_transport["key"])
    headers.pop("X-API-Key")
    headers["Authorization"] = f"Bearer {live_transport['key']}"
    response = httpx.post(
        live_transport["url"],
        headers=headers,
        json=_initialize_message(),
        timeout=5,
    )
    assert response.status_code == 200
    assert response.headers.get("MCP-Session-Id")


def test_protocol_and_json_rpc_failures_are_safe(live_transport):
    session_id = _open_session(live_transport["url"], live_transport["key"])
    message = {"jsonrpc": "2.0", "id": 30, "method": "tools/list", "params": {}}
    missing_protocol = _session_headers(live_transport["key"], session_id)
    missing_protocol.pop("MCP-Protocol-Version")
    invalid_protocol = _session_headers(live_transport["key"], session_id)
    invalid_protocol["MCP-Protocol-Version"] = "2099-01-01"

    responses = [
        httpx.post(
            live_transport["url"], headers=missing_protocol, json=message, timeout=5
        ),
        httpx.post(
            live_transport["url"], headers=invalid_protocol, json=message, timeout=5
        ),
        httpx.post(
            live_transport["url"],
            headers=_session_headers(live_transport["key"], session_id),
            content=b'{"jsonrpc":',
            timeout=5,
        ),
        httpx.post(
            live_transport["url"],
            headers=_session_headers(live_transport["key"], session_id),
            json={"jsonrpc": "1.0", "id": 1, "method": "tools/list"},
            timeout=5,
        ),
    ]
    assert [response.status_code for response in responses] == [400, 400, 400, 400]


def test_declared_and_chunked_oversized_bodies_are_rejected(live_transport):
    parsed = urlsplit(live_transport["url"])
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        request = (
            f"POST {parsed.path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Accept: application/json, text/event-stream\r\n"
            "Content-Type: application/json\r\n"
            f"X-API-Key: {live_transport['key']}\r\n"
            "Content-Length: 262145\r\n"
            "Connection: close\r\n\r\n{}"
        ).encode("ascii")
        sock.sendall(request)
        declared_status = sock.recv(256).split(b"\r\n", 1)[0]

    async def send_chunked():
        async def chunks():
            yield b"x" * (128 * 1024)
            yield b"y" * (128 * 1024)
            yield b"z"

        async with httpx.AsyncClient(timeout=5) as client:
            return await client.post(
                live_transport["url"],
                headers=_transport_headers(live_transport["key"]),
                content=chunks(),
            )

    chunked = asyncio.run(send_chunked())
    assert b" 413 " in declared_status
    assert chunked.status_code == 413


def test_audits_and_logs_do_not_retain_credentials_arguments_or_response_bodies(
    live_transport, caplog
):
    argument_marker = "private-argument-marker"
    session_id = _open_session(live_transport["url"], live_transport["key"])
    response = httpx.post(
        live_transport["url"],
        headers=_session_headers(live_transport["key"], session_id),
        json=_call_message("read_document", {"document_id": argument_marker}),
        timeout=5,
    )
    assert response.status_code == 200
    audit_text = str(db.list_mcp_audit_logs(limit=20))
    assert live_transport["key"] not in audit_text
    assert "Authorization" not in audit_text
    assert argument_marker not in audit_text
    assert "safe result from read_document" not in audit_text
    assert any(row.get("argument_hash") for row in db.list_mcp_audit_logs(limit=20))
    assert live_transport["key"] not in caplog.text
    assert argument_marker not in caplog.text
    assert "safe result from read_document" not in caplog.text


def test_legacy_mcp_call_regression_still_uses_gateway(live_transport):
    before = len(live_transport["upstream_calls"])
    response = httpx.post(
        f"{live_transport['base_url']}/mcp/call",
        headers={"X-API-Key": live_transport["key"]},
        json={
            "server_id": SERVER_ID,
            "tool_name": "read_document",
            "arguments": {"document_id": "legacy-route"},
        },
        timeout=5,
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert len(live_transport["upstream_calls"]) == before + 1


def test_get_and_delete_remain_json_only_profile_405(live_transport):
    for method in (httpx.get, httpx.delete):
        response = method(live_transport["url"], timeout=5)
        assert response.status_code == 405
        assert response.headers["Allow"] == "POST"
