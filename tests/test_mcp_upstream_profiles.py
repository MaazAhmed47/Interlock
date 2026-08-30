"""Explicit legacy and MCP 2026 upstream wire-profile tests."""

import asyncio
import base64
import json
import logging
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from core import db, receipt
from core.mcp_gateway import (
    MCPUpstreamResponseError,
    _complete_upstream_result,
    _encode_mcp_header_value,
    _fetch_tool_list_payload,
    proxy_mcp_tool_call,
    register_mcp_server,
)
from core.tool_metadata import normalize_tool_metadata

SERVER_ID = "_test_upstream_profile_server"
UPSTREAM_SENTINELS = (
    "raw-upstream-secret-91",
    "ignore-previous-instructions-91",
)
UPSTREAM_LOG_SENTINELS = {
    "reason": UPSTREAM_SENTINELS[0],
    "location": "hostile-redirect-location-91",
    "body": "hostile-raw-body-91",
    "message": UPSTREAM_SENTINELS[1],
    "data": "hostile-nested-error-data-91",
}


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


def _hostile_http_response(status: int) -> httpx.Response:
    secret, injection = UPSTREAM_SENTINELS
    headers = {"content-type": "application/json"}
    if status == 302:
        headers["location"] = f"https://redirect.invalid/{secret}/{injection}"
    return httpx.Response(
        status,
        request=httpx.Request("POST", "http://localhost:9799/mcp"),
        headers=headers,
        content=json.dumps(
            {"error": {"message": secret, "data": {"nested": injection}}}
        ).encode(),
        extensions={"reason_phrase": f"Malicious {secret} {injection}".encode()},
    )


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
    url: str = "http://localhost:9799/mcp",
) -> None:
    assert db.register_mcp_server(
        SERVER_ID,
        {
            "url": url,
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


async def _serve_hostile_http_response(status: int, operation):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "hostile-response-id",
            "untrusted_body_marker": UPSTREAM_LOG_SENTINELS["body"],
            "error": {
                "code": -32091,
                "message": UPSTREAM_LOG_SENTINELS["message"],
                "data": {"nested": {"instruction": UPSTREAM_LOG_SENTINELS["data"]}},
            },
        }
    ).encode()

    async def handle(reader, writer):
        await reader.read(65536)
        reason = f"Malicious {UPSTREAM_LOG_SENTINELS['reason']}"
        location = f"https://redirect.invalid/{UPSTREAM_LOG_SENTINELS['location']}"
        writer.write(
            (
                f"HTTP/1.1 {status} {reason}\r\n"
                f"Location: {location}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        return await operation(f"http://127.0.0.1:{port}/mcp")
    finally:
        server.close()
        await server.wait_closed()


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


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("status", [500, 302])
def test_discovery_http_status_text_is_never_exposed(profile, status, caplog):
    _register(profile)
    response = _hostile_http_response(status)

    async def post(_url, **_kwargs):
        return response

    client = _mock_client(post)
    with patch(
        "core.mcp_gateway.httpx.AsyncClient", return_value=client
    ) as client_factory:
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome == {
        "ok": False,
        "error": "upstream_http_error",
        "message": f"MCP server returned HTTP {status}.",
        "server_url": "http://localhost:9799/mcp",
    }
    client_factory.assert_called_once_with(
        timeout=1,
        verify=True,
        proxy=None,
        follow_redirects=False,
        trust_env=False,
    )
    exposed = json.dumps(outcome, sort_keys=True) + caplog.text
    assert all(sentinel not in exposed for sentinel in UPSTREAM_SENTINELS)


def test_mcp_discover_route_does_not_expose_redirect_metadata(caplog):
    import proxy

    _register("legacy")
    response = _hostile_http_response(302)

    async def post(_url, **_kwargs):
        return response

    client = _mock_client(post)
    with (
        patch("routes.mcp.proxy.require_scope", return_value=None),
        patch(
            "routes.mcp.ensure_safe_outbound_url_async",
            new=AsyncMock(return_value="http://localhost:9799/mcp"),
        ),
        patch("core.mcp_gateway.httpx.AsyncClient", return_value=client),
    ):
        api_response = TestClient(proxy.app).post(
            "/mcp/discover",
            json={
                "server_url": "http://localhost:9799/mcp",
                "server_id": SERVER_ID,
            },
        )

    assert api_response.status_code == 200
    assert api_response.json() == {
        "ok": False,
        "error": "upstream_http_error",
        "message": "MCP server returned HTTP 302.",
        "server_url": "http://localhost:9799/mcp",
    }
    exposed = api_response.text + caplog.text
    assert all(sentinel not in exposed for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
def test_discovery_jsonrpc_message_and_data_are_never_exposed(profile, caplog):
    _register(profile)

    async def post(_url, **kwargs):
        request = kwargs["json"]
        return _response(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {
                    "code": -32091,
                    "message": UPSTREAM_SENTINELS[0],
                    "data": {"nested": {"instruction": UPSTREAM_SENTINELS[1]}},
                },
            }
        )

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == (
        "mcp_discovery_error" if profile == "legacy" else "upstream_jsonrpc_error"
    )
    assert outcome["message"] == "MCP server returned a JSON-RPC error."
    exposed = json.dumps(outcome, sort_keys=True) + caplog.text
    assert all(sentinel not in exposed for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
def test_discovery_unexpected_upstream_exception_text_is_generic(profile, caplog):
    _register(profile)

    async def post(_url, **_kwargs):
        raise RuntimeError(" :: ".join(UPSTREAM_SENTINELS))

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome == {
        "ok": False,
        "error": "mcp_discovery_error",
        "message": "MCP discovery failed.",
        "server_url": "http://localhost:9799/mcp",
    }
    exposed = json.dumps(outcome, sort_keys=True) + caplog.text
    assert all(sentinel not in exposed for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("status", [500, 302])
def test_tool_call_http_status_metadata_is_absent_from_all_evidence(
    profile, status, caplog
):
    _register(profile)
    response = _hostile_http_response(status)

    async def post(_url, **_kwargs):
        return response

    client = _mock_client(post)
    with patch(
        "core.mcp_gateway.httpx.AsyncClient", return_value=client
    ) as client_factory:
        outcome = asyncio.run(
            proxy_mcp_tool_call(
                SERVER_ID,
                "read_document",
                {},
                role="admin_agent",
                principal_id="profile-http-test-principal",
            )
        )

    client_factory.assert_called_once_with(
        timeout=30.0,
        verify=True,
        proxy=None,
        follow_redirects=False,
        trust_env=False,
    )
    assert outcome["ok"] is False
    assert outcome["error"] == "upstream_http_error"
    assert outcome["message"] == f"MCP server returned HTTP {status}."
    assert outcome["upstream_error"] == {"status_code": status}
    audit_id = outcome["audit"]["audit_id"]
    audit = db.get_mcp_audit_log(audit_id)
    verification = db.verify_mcp_audit_record(audit_id)
    security_receipt = receipt.build_receipt(
        audit, chain_verified=verification["chain_verified"]
    )
    assert audit["id"] == audit_id
    assert audit["call_id"] == outcome["audit"]["call_id"]
    assert audit["action"] == "deny"
    assert audit["observed_error_class"] == "upstream_http_error"
    assert security_receipt["audit_id"] == audit_id
    assert security_receipt["binding"]["call_id"] == audit["call_id"]
    assert security_receipt["chain_verified"] is True
    exposed = "\n".join(
        [
            json.dumps(outcome, sort_keys=True),
            json.dumps(audit, sort_keys=True, default=str),
            json.dumps(security_receipt, sort_keys=True, default=str),
            caplog.text,
        ]
    )
    assert all(sentinel not in exposed for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("status", [500, 302])
@pytest.mark.parametrize("gateway_path", ["discovery", "tools_call"])
def test_real_http_transport_logs_never_expose_upstream_text(
    profile, status, gateway_path, caplog
):
    caplog.set_level(logging.DEBUG)
    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING

    async def exercise():
        async def operation(server_url):
            _register(profile, url=server_url)
            with patch(
                "core.mcp_gateway.ensure_safe_outbound_url_async",
                new=AsyncMock(return_value=server_url),
            ):
                if gateway_path == "discovery":
                    return await _fetch_tool_list_payload(server_url, 1, SERVER_ID)
                return await proxy_mcp_tool_call(
                    SERVER_ID,
                    "read_document",
                    {},
                    role="admin_agent",
                    principal_id="real-http-log-test-principal",
                )

        return await _serve_hostile_http_response(status, operation)

    logging.getLogger("interlock.mcp_gateway").debug(
        "interlock-application-log-control"
    )
    outcome = asyncio.run(exercise())
    assert outcome["ok"] is False
    assert outcome["error"] == "upstream_http_error"
    assert outcome["message"] == f"MCP server returned HTTP {status}."
    if gateway_path == "tools_call":
        assert outcome["upstream_error"] == {"status_code": status}

    evidence = [json.dumps(outcome, sort_keys=True, default=str)]
    if gateway_path == "tools_call":
        audit_id = outcome["audit"]["audit_id"]
        audit = db.get_mcp_audit_log(audit_id)
        verification = db.verify_mcp_audit_record(audit_id)
        security_receipt = receipt.build_receipt(
            audit, chain_verified=verification["chain_verified"]
        )
        assert audit["call_id"] == outcome["audit"]["call_id"]
        assert security_receipt["binding"]["call_id"] == audit["call_id"]
        evidence.extend(
            [
                json.dumps(audit, sort_keys=True, default=str),
                json.dumps(security_receipt, sort_keys=True, default=str),
            ]
        )

    emitted_records = [
        f"{record.name}:{record.levelname}:{record.getMessage()}"
        for record in caplog.records
    ]
    assert any(
        "interlock-application-log-control" in record for record in emitted_records
    )
    exposed = "\n".join(evidence + emitted_records)
    assert all(
        sentinel not in exposed for sentinel in UPSTREAM_LOG_SENTINELS.values()
    ), emitted_records


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
def test_tool_call_unexpected_upstream_exception_is_generic_and_audited(
    profile, caplog
):
    _register(profile)

    async def post(_url, **_kwargs):
        raise RuntimeError(" :: ".join(UPSTREAM_SENTINELS))

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            proxy_mcp_tool_call(
                SERVER_ID,
                "read_document",
                {},
                role="admin_agent",
                principal_id="profile-exception-test-principal",
            )
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "mcp_server_error"
    assert outcome["message"] == "MCP server call failed."
    audit_id = outcome["audit"]["audit_id"]
    audit = db.get_mcp_audit_log(audit_id)
    assert audit["id"] == audit_id
    assert audit["observed_error_class"] == "mcp_server_error"
    exposed = "\n".join(
        [
            json.dumps(outcome, sort_keys=True),
            json.dumps(audit, sort_keys=True, default=str),
            caplog.text,
        ]
    )
    assert all(sentinel not in exposed for sentinel in UPSTREAM_SENTINELS)


MALFORMED_ERROR_ENVELOPES = [
    pytest.param("malformed", id="string-error"),
    pytest.param(None, id="null-error"),
    pytest.param({"code": -32000}, id="missing-message"),
    pytest.param({"code": -32000, "message": None}, id="non-string-message"),
    pytest.param({"code": "-32000", "message": "failed"}, id="string-code"),
    pytest.param({"code": -32000.5, "message": "failed"}, id="float-code"),
    pytest.param({"code": True, "message": "failed"}, id="boolean-code"),
]

ERROR_ENVELOPE_IDENTITY_CASES = [
    pytest.param("missing-jsonrpc", id="missing-jsonrpc"),
    pytest.param("wrong-jsonrpc", id="wrong-jsonrpc"),
    pytest.param("missing-id", id="missing-id"),
    pytest.param("mismatched-id", id="mismatched-id"),
]


def _error_envelope_with_identity_case(request_id: str, identity_case: str) -> dict:
    envelope = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32000, "message": UPSTREAM_SENTINELS[0]},
    }
    if identity_case == "missing-jsonrpc":
        envelope.pop("jsonrpc")
    elif identity_case == "wrong-jsonrpc":
        envelope["jsonrpc"] = "1.0"
    elif identity_case == "missing-id":
        envelope.pop("id")
    elif identity_case == "mismatched-id":
        envelope["id"] = f"wrong-{request_id}"
    return envelope


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("identity_case", ERROR_ENVELOPE_IDENTITY_CASES)
def test_jsonrpc_error_envelope_identity_is_strict_for_every_profile(
    profile, identity_case
):
    request_id = "generated-request-id"
    envelope = _error_envelope_with_identity_case(request_id, identity_case)

    with pytest.raises(MCPUpstreamResponseError) as raised:
        _complete_upstream_result(envelope, request_id, profile, "tools/call")

    assert raised.value.error == "upstream_invalid_envelope"
    assert (
        raised.value.message
        == "MCP server returned an invalid JSON-RPC response envelope."
    )
    assert all(
        sentinel not in str(raised.value) + repr(raised.value)
        for sentinel in UPSTREAM_SENTINELS
    )


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("identity_case", ERROR_ENVELOPE_IDENTITY_CASES)
def test_discovery_error_identity_matches_generated_request(profile, identity_case):
    _register(profile)

    async def post(_url, **kwargs):
        request_id = kwargs["json"]["id"]
        return _response(_error_envelope_with_identity_case(request_id, identity_case))

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == (
        "mcp_discovery_error" if profile == "legacy" else "upstream_invalid_envelope"
    )
    assert (
        outcome["message"]
        == "MCP server returned an invalid JSON-RPC response envelope."
    )
    assert all(sentinel not in json.dumps(outcome) for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("identity_case", ERROR_ENVELOPE_IDENTITY_CASES)
def test_tool_call_error_identity_matches_generated_request(profile, identity_case):
    _register(profile)

    async def post(_url, **kwargs):
        request_id = kwargs["json"]["id"]
        return _response(_error_envelope_with_identity_case(request_id, identity_case))

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            proxy_mcp_tool_call(
                SERVER_ID,
                "read_document",
                {},
                role="admin_agent",
                principal_id="profile-identity-test-principal",
            )
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "upstream_invalid_envelope"
    assert (
        outcome["message"]
        == "MCP server returned an invalid JSON-RPC response envelope."
    )
    audit_id = outcome["audit"]["audit_id"]
    audit = db.get_mcp_audit_log(audit_id)
    assert audit["id"] == audit_id
    assert audit["call_id"] == outcome["audit"]["call_id"]
    assert audit["action"] == "deny"
    assert audit["observed_error_class"] == "upstream_invalid_envelope"
    exposed = json.dumps(outcome, sort_keys=True) + json.dumps(
        audit, sort_keys=True, default=str
    )
    assert all(sentinel not in exposed for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("upstream_error", MALFORMED_ERROR_ENVELOPES)
@pytest.mark.parametrize(
    "with_result", [False, True], ids=["error-only", "result-and-error"]
)
def test_malformed_jsonrpc_error_envelopes_are_invalid_for_every_profile(
    profile, upstream_error, with_result
):
    envelope = {"jsonrpc": "2.0", "id": "request-id", "error": upstream_error}
    if with_result:
        envelope["result"] = {}

    with pytest.raises(MCPUpstreamResponseError) as raised:
        _complete_upstream_result(envelope, "request-id", profile, "tools/call")

    assert raised.value.error == "upstream_invalid_envelope"
    assert (
        raised.value.message
        == "MCP server returned an invalid JSON-RPC error envelope."
    )
    rendered = str(raised.value) + repr(raised.value)
    assert all(sentinel not in rendered for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
def test_result_and_well_formed_error_is_invalid_for_every_profile(profile):
    with pytest.raises(MCPUpstreamResponseError) as raised:
        _complete_upstream_result(
            {
                "jsonrpc": "2.0",
                "id": "request-id",
                "result": {},
                "error": {"code": -32000, "message": UPSTREAM_SENTINELS[0]},
            },
            "request-id",
            profile,
            "tools/call",
        )

    assert raised.value.error == "upstream_invalid_envelope"
    assert all(sentinel not in str(raised.value) for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("code", [-32091, 10**100])
def test_valid_integer_jsonrpc_codes_remain_safe_classification(profile, code):
    with pytest.raises(MCPUpstreamResponseError) as raised:
        _complete_upstream_result(
            {
                "jsonrpc": "2.0",
                "id": "request-id",
                "error": {
                    "code": code,
                    "message": UPSTREAM_SENTINELS[0],
                    "data": {"nested": UPSTREAM_SENTINELS[1]},
                },
            },
            "request-id",
            profile,
            "tools/call",
        )

    assert raised.value.error == "upstream_jsonrpc_error"
    assert raised.value.message == "MCP server returned a JSON-RPC error."
    assert raised.value.upstream_error == {"code": code}
    exposed = str(raised.value) + repr(raised.value)
    assert all(sentinel not in exposed for sentinel in UPSTREAM_SENTINELS)


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
def test_discovery_malformed_error_is_invalid_envelope_for_every_profile(profile):
    _register(profile)

    async def post(_url, **kwargs):
        request = kwargs["json"]
        return _response({"jsonrpc": "2.0", "id": request["id"], "error": None})

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            _fetch_tool_list_payload("http://localhost:9799/mcp", 1, SERVER_ID)
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "upstream_invalid_envelope"
    assert (
        outcome["message"] == "MCP server returned an invalid JSON-RPC error envelope."
    )


@pytest.mark.parametrize("profile", ["legacy", "2026-07-28"])
def test_tool_call_malformed_error_is_invalid_and_audit_linked(profile):
    _register(profile)

    async def post(_url, **kwargs):
        request = kwargs["json"]
        return _response({"jsonrpc": "2.0", "id": request["id"], "error": "malformed"})

    client = _mock_client(post)
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            proxy_mcp_tool_call(
                SERVER_ID,
                "read_document",
                {},
                role="admin_agent",
                principal_id="profile-test-principal",
            )
        )

    assert outcome["ok"] is False
    assert outcome["error"] == "upstream_invalid_envelope"
    audit_id = outcome["audit"]["audit_id"]
    audit = db.get_mcp_audit_log(audit_id)
    assert audit["id"] == audit_id
    assert audit["call_id"] == outcome["audit"]["call_id"]
    assert audit["action"] == "deny"
    assert audit["observed_error_class"] == "upstream_invalid_envelope"


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
