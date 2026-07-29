"""Wire-level contract tests for Interlock's MCP 2026 Streamable HTTP profile."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
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

import proxy
from core import db
from core.tool_metadata import normalize_tool_metadata
from routes.streamable_mcp import _json_result

PROTOCOL_VERSION = "2026-07-28"
SERVER_ID = "_test_streamable_integration"
SECOND_SERVER_ID = "_test_streamable_other_server"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _serve(app: Any) -> Iterator[str]:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical")
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


class _SanitizedWireCapture:
    """Capture only protocol fields needed for the SDK profile regression."""

    def __init__(self, app: Any, exchanges: list[dict[str, Any]]) -> None:
        self.app = app
        self.exchanges = exchanges

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_body = bytearray()
        response_body = bytearray()
        response_status = 0

        async def captured_receive():
            message = await receive()
            if message["type"] == "http.request":
                request_body.extend(message.get("body", b""))
            return message

        async def captured_send(message):
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = message["status"]
            elif message["type"] == "http.response.body":
                response_body.extend(message.get("body", b""))
            await send(message)

        await self.app(scope, captured_receive, captured_send)
        parsed_request = json.loads(request_body) if request_body else None
        if parsed_request and isinstance(parsed_request.get("method"), str):
            headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope["headers"]
                if key.decode("latin-1").lower()
                in {
                    "accept",
                    "content-type",
                    "mcp-method",
                    "mcp-protocol-version",
                    "user-agent",
                }
            }
            self.exchanges.append(
                {
                    "request": {"headers": headers, "body": parsed_request},
                    "response": {
                        "status": response_status,
                        "body": json.loads(response_body) if response_body else None,
                    },
                }
            )


class _TestCredentialInjector:
    """Inject the fixture credential for an auth-unaware conformance client."""

    def __init__(self, app: Any, key: str) -> None:
        self.app = app
        self.key = key.encode("ascii")

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        scoped = dict(scope)
        scoped["headers"] = [
            *(item for item in scope["headers"] if item[0].lower() != b"x-api-key"),
            (b"x-api-key", self.key),
        ]
        await self.app(scoped, receive, send)


def _tool(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"Read data with {name}.",
        "inputSchema": {
            "type": "object",
            "properties": {"document_id": {"type": "string"}},
        },
    }


def _params(**values: Any) -> dict[str, Any]:
    return {
        **values,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "interlock-2026-contract-test",
                "version": "1",
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    }


def _message(method: str, request_id: int, **params: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": _params(**params),
    }


def _headers(
    key: str, method: str, name: str | None = None, **extra: str
) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "X-API-Key": key,
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
    }
    if name is not None:
        headers["Mcp-Name"] = name
    headers.update(extra)
    return headers


def _post(
    transport: dict[str, Any], method: str, request_id: int, **params: Any
) -> httpx.Response:
    name = params.get("name") if method == "tools/call" else None
    return httpx.post(
        transport["url"],
        headers=_headers(transport["key"], method, name),
        json=_message(method, request_id, **params),
        timeout=5,
    )


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
        result = {
            "content": [{"type": "text", "text": text}],
            "isError": False,
        }
        if document_id == "spoof-identity":
            result.update(
                {
                    "resultType": "input_required",
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "untrusted-upstream",
                            "version": "leak",
                        }
                    },
                }
            )
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": result,
            }
        )

    with _serve(upstream) as upstream_url:
        for server_id, allowed in (
            (
                SERVER_ID,
                [
                    "read_document",
                    "missing_metadata",
                    "blocked_tool",
                    "quarantined_tool",
                ],
            ),
            (SECOND_SERVER_ID, ["read_document"]),
        ):
            db.register_mcp_server(
                server_id,
                {
                    "url": f"{upstream_url}/mcp",
                    "description": "Streamable integration fixture",
                    "allowed_tools": allowed,
                    "blocked_tools": ["blocked_tool"] if server_id == SERVER_ID else [],
                    "environment": "non_production",
                },
            )
            db.verify_mcp_server(server_id)
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
        definition = _tool("read_document")
        db.upsert_mcp_tool_metadata(
            SECOND_SERVER_ID, definition, normalize_tool_metadata(definition)
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
        readonly_key = db.generate_key(
            "free",
            label="streamable-readonly",
            scopes=["mcp.call"],
            role="readonly_agent",
        )["raw_key"]
        with _serve(proxy.app) as interlock_url:
            yield {
                "url": f"{interlock_url}/mcp/stream/{SERVER_ID}",
                "base_url": interlock_url,
                "key": key,
                "readonly_key": readonly_key,
                "upstream_calls": upstream_calls,
            }
    db.unregister_mcp_server(SERVER_ID)
    db.unregister_mcp_server(SECOND_SERVER_ID)
    proxy._key_record_cache.clear()
    db.DB_PATH = prior_db_path


def test_discover_list_and_allowed_call_are_stateless(live_transport):
    discovered = _post(live_transport, "server/discover", 1)
    listed_first = _post(live_transport, "tools/list", 2)
    listed_second = _post(live_transport, "tools/list", 3)
    called = _post(
        live_transport,
        "tools/call",
        4,
        name="read_document",
        arguments={"document_id": "safe"},
    )

    assert (
        discovered.status_code
        == listed_first.status_code
        == listed_second.status_code
        == 200
    )
    discover_result = discovered.json()["result"]
    assert discover_result["resultType"] == "complete"
    assert discover_result["supportedVersions"] == [PROTOCOL_VERSION]
    assert discover_result["ttlMs"] > 0
    assert discover_result["cacheScope"] == "private"
    assert "serverInfo" not in discover_result
    assert (
        discover_result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"]
        == "interlock-mcp-gateway"
    )
    list_result = listed_first.json()["result"]
    assert list_result["ttlMs"] > 0
    assert list_result["cacheScope"] == "private"
    assert list_result["tools"] == listed_second.json()["result"]["tools"]
    assert [tool["name"] for tool in list_result["tools"]] == ["read_document"]
    assert "MCP-Session-Id" not in discovered.headers
    assert called.json()["result"]["isError"] is False
    assert len(live_transport["upstream_calls"]) == 1


def _official_sdk_python_2() -> str:
    python = os.environ.get("INTERLOCK_MCP_SDK_PYTHON")
    if not python:
        pytest.skip(
            "set INTERLOCK_MCP_SDK_PYTHON to an isolated interpreter with mcp==2.0.0"
        )
    version_check = subprocess.run(
        [
            python,
            "-c",
            "import importlib.metadata as m; print(m.version('mcp'))",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert version_check.stdout.strip() == "2.0.0"
    return python


def _official_sdk_node_2() -> tuple[str, str]:
    node = os.environ.get("INTERLOCK_MCP_SDK_NODE") or "node"
    root = os.environ.get("INTERLOCK_MCP_SDK_NODE_ROOT")
    if not root:
        pytest.skip(
            "set INTERLOCK_MCP_SDK_NODE_ROOT to an isolated npm root with "
            "@modelcontextprotocol/client==2.0.0"
        )
    version_check = subprocess.run(
        [
            node,
            "-e",
            "const p=require(process.argv[1]); process.stdout.write(p.version)",
            str(Path(root) / "node_modules/@modelcontextprotocol/client/package.json"),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert version_check.stdout == "2.0.0"
    return node, root


def _run_sdk_probe(
    command: list[str], url: str, key: str, *, node_root: str | None = None
) -> dict[str, Any]:
    env = os.environ.copy()
    env["SDK_PROBE_URL"] = url
    env["SDK_PROBE_KEY"] = key
    if node_root is not None:
        env["SDK_NODE_ROOT"] = node_root
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        env=env,
        text=True,
        timeout=30,
    )
    return json.loads(completed.stdout)


def _assert_modern_sdk_exchange(
    exchange: dict[str, Any], method: str, client_name: str
) -> None:
    request = exchange["request"]
    assert request["headers"]["accept"] == "application/json, text/event-stream"
    assert request["headers"]["content-type"] == "application/json"
    assert request["headers"]["mcp-protocol-version"] == PROTOCOL_VERSION
    assert request["headers"]["mcp-method"] == method
    meta = request["body"]["params"]["_meta"]
    assert meta["io.modelcontextprotocol/protocolVersion"] == PROTOCOL_VERSION
    assert meta["io.modelcontextprotocol/clientInfo"]["name"] == client_name
    assert isinstance(meta["io.modelcontextprotocol/clientCapabilities"], dict)


def test_official_python_sdk_2_0_0_modern_discovery_and_operations(live_transport):
    python = _official_sdk_python_2()
    exchanges: list[dict[str, Any]] = []
    script = Path(__file__).parent / "sdk_interop/python_client_probe.py"

    with _serve(_SanitizedWireCapture(proxy.app, exchanges)) as base_url:
        outcome = _run_sdk_probe(
            [python, str(script), "auto"],
            f"{base_url}/mcp/stream/{SERVER_ID}",
            live_transport["key"],
        )

    assert outcome == {
        "call_is_error": False,
        "connected": True,
        "server_name": "interlock-mcp-gateway",
        "tool_names": ["read_document"],
    }
    assert [item["request"]["body"]["method"] for item in exchanges] == [
        "server/discover",
        "tools/list",
        "tools/call",
    ]
    for exchange, method in zip(
        exchanges, ("server/discover", "tools/list", "tools/call"), strict=True
    ):
        _assert_modern_sdk_exchange(exchange, method, "interlock-python-sdk-probe")


def test_official_python_sdk_2_0_0_explicit_pin_has_no_legacy_handshake(
    live_transport,
):
    python = _official_sdk_python_2()
    exchanges: list[dict[str, Any]] = []
    script = Path(__file__).parent / "sdk_interop/python_client_probe.py"

    with _serve(_SanitizedWireCapture(proxy.app, exchanges)) as base_url:
        outcome = _run_sdk_probe(
            [python, str(script), PROTOCOL_VERSION],
            f"{base_url}/mcp/stream/{SERVER_ID}",
            live_transport["key"],
        )

    assert outcome["connected"] is True
    assert [item["request"]["body"]["method"] for item in exchanges] == [
        "tools/list",
        "tools/call",
    ]
    assert all(item["request"]["body"]["method"] != "initialize" for item in exchanges)


def test_official_typescript_sdk_2_0_0_pinned_discovery_and_operations(
    live_transport,
):
    node, node_root = _official_sdk_node_2()
    exchanges: list[dict[str, Any]] = []
    script = Path(__file__).parent / "sdk_interop/typescript_client_probe.mjs"

    with _serve(_SanitizedWireCapture(proxy.app, exchanges)) as base_url:
        outcome = _run_sdk_probe(
            [node, str(script)],
            f"{base_url}/mcp/stream/{SERVER_ID}",
            live_transport["key"],
            node_root=node_root,
        )

    assert outcome == {
        "connected": True,
        "server_name": "interlock-mcp-gateway",
        "tool_names": ["read_document"],
        "call_is_error": False,
    }
    assert [item["request"]["body"]["method"] for item in exchanges] == [
        "server/discover",
        "tools/list",
        "tools/call",
    ]
    for exchange, method in zip(
        exchanges, ("server/discover", "tools/list", "tools/call"), strict=True
    ):
        _assert_modern_sdk_exchange(exchange, method, "interlock-typescript-sdk-probe")


def test_official_sdk_explicit_pins_do_not_fall_back_after_protocol_rejection():
    python = _official_sdk_python_2()
    node, node_root = _official_sdk_node_2()
    python_script = Path(__file__).parent / "sdk_interop/python_client_probe.py"
    typescript_script = (
        Path(__file__).parent / "sdk_interop/typescript_client_probe.mjs"
    )
    reject_app = FastAPI()

    @reject_app.post("/mcp")
    async def reject_modern(request: Request):
        message = await request.json()
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32601, "message": "Method not found"},
            },
            status_code=404,
        )

    python_exchanges: list[dict[str, Any]] = []
    with _serve(_SanitizedWireCapture(reject_app, python_exchanges)) as base_url:
        python_outcome = _run_sdk_probe(
            [python, str(python_script), PROTOCOL_VERSION],
            f"{base_url}/mcp",
            "not-a-real-secret",
        )

    typescript_exchanges: list[dict[str, Any]] = []
    with _serve(_SanitizedWireCapture(reject_app, typescript_exchanges)) as base_url:
        typescript_outcome = _run_sdk_probe(
            [node, str(typescript_script)],
            f"{base_url}/mcp",
            "not-a-real-secret",
            node_root=node_root,
        )

    assert python_outcome["connected"] is False
    assert typescript_outcome["connected"] is False
    assert [item["request"]["body"]["method"] for item in python_exchanges] == [
        "tools/list"
    ]
    assert [item["request"]["body"]["method"] for item in typescript_exchanges] == [
        "server/discover"
    ]


def test_official_alpha_conformance_scoped_stateless_evidence(live_transport, tmp_path):
    conformance_js = os.environ.get("INTERLOCK_MCP_CONFORMANCE_JS")
    if not conformance_js:
        pytest.skip(
            "set INTERLOCK_MCP_CONFORMANCE_JS to the isolated official "
            "0.2.0-alpha.10 CLI dist/index.js"
        )
    conformance_key = db.generate_key(
        "enterprise",
        label="mcp-conformance-alpha",
        scopes=["mcp.call"],
        role="admin_agent",
    )["raw_key"]
    with _serve(_TestCredentialInjector(proxy.app, conformance_key)) as base_url:
        completed = subprocess.run(
            [
                os.environ.get("INTERLOCK_MCP_SDK_NODE") or "node",
                conformance_js,
                "server",
                "--url",
                f"{base_url}/mcp/stream/{SERVER_ID}",
                "--scenario",
                "server-stateless",
                "--spec-version",
                PROTOCOL_VERSION,
                "--output-dir",
                str(tmp_path),
                "--verbose",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

    check_files = list(tmp_path.rglob("checks.json"))
    assert check_files, completed.stdout + completed.stderr
    checks = json.loads(check_files[0].read_text(encoding="utf-8"))
    by_id = {check["id"]: check for check in checks}
    expected_successes = {
        "sep-2575-request-meta-invalid-missing-meta",
        "sep-2575-request-meta-invalid-missing-protocol-version",
        "sep-2575-request-meta-invalid-missing-client-capabilities",
        "sep-2575-request-meta-client-info-optional",
        "sep-2575-server-implements-discover",
        "sep-2575-server-identifies-in-result-meta",
        "sep-2575-server-unsupported-version-error",
        "sep-2575-http-server-unsupported-version-400",
        "sep-2575-http-server-header-mismatch-400",
        "sep-2575-http-server-method-not-found-404-initialize",
        "sep-2575-http-server-method-not-found-404-ping",
        "sep-2575-http-server-method-not-found-404-logging-setlevel",
        "sep-2575-http-server-method-not-found-404",
    }
    assert expected_successes <= by_id.keys()
    assert {check_id: by_id[check_id]["status"] for check_id in expected_successes} == {
        check_id: "SUCCESS" for check_id in expected_successes
    }


def test_upstream_result_cannot_replace_gateway_identity_or_result_type():
    response = _json_result(
        1,
        {
            "resultType": "input_required",
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "untrusted-upstream",
                    "version": "leak",
                }
            },
            "content": [],
        },
    )
    payload = response.body.decode("utf-8")

    assert '"resultType":"complete"' in payload
    assert '"name":"interlock-mcp-gateway"' in payload
    assert "untrusted-upstream" not in payload


def test_live_upstream_result_cannot_replace_gateway_identity(live_transport):
    response = _post(
        live_transport,
        "tools/call",
        9,
        name="read_document",
        arguments={"document_id": "spoof-identity"},
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["resultType"] == "complete"
    assert result["_meta"] == {
        "io.modelcontextprotocol/serverInfo": {
            "name": "interlock-mcp-gateway",
            "version": "0.2.0-alpha.1",
        }
    }
    assert "untrusted-upstream" not in response.text


def test_removed_lifecycle_methods_do_not_activate_or_forward(live_transport):
    before = len(live_transport["upstream_calls"])
    for request_id, method in (
        (10, "initialize"),
        (11, "notifications/initialized"),
        (12, "ping"),
    ):
        response = _post(live_transport, method, request_id)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == -32601
    assert len(live_transport["upstream_calls"]) == before


@pytest.mark.parametrize(
    ("headers", "message", "code"),
    [
        ({"Mcp-Method": ""}, _message("tools/list", 20), -32020),
        ({"Mcp-Method": "tools/call"}, _message("tools/list", 21), -32020),
        (
            {"Mcp-Name": "wrong"},
            _message("tools/call", 22, name="read_document", arguments={}),
            -32020,
        ),
        ({"MCP-Protocol-Version": "2025-11-25"}, _message("tools/list", 23), -32020),
    ],
)
def test_standard_header_mismatches_fail_closed(live_transport, headers, message, code):
    method = message["method"]
    name = message["params"].get("name") if method == "tools/call" else None
    response = httpx.post(
        live_transport["url"],
        headers=_headers(live_transport["key"], method, name, **headers),
        json=message,
        timeout=5,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == code


def test_missing_or_conflicting_per_request_meta_is_rejected(live_transport):
    missing = _message("tools/list", 30)
    missing["params"].pop("_meta")
    conflicting = _message("tools/list", 31)
    conflicting["params"]["_meta"][
        "io.modelcontextprotocol/protocolVersion"
    ] = "2025-11-25"
    unsupported = _message("tools/list", 32)
    unsupported["params"]["_meta"][
        "io.modelcontextprotocol/protocolVersion"
    ] = "2025-11-25"
    for message, expected, version in (
        (missing, -32602, PROTOCOL_VERSION),
        (conflicting, -32020, PROTOCOL_VERSION),
        (unsupported, -32022, "2025-11-25"),
    ):
        response = httpx.post(
            live_transport["url"],
            headers=_headers(
                live_transport["key"],
                "tools/list",
                **{"MCP-Protocol-Version": version},
            ),
            json=message,
            timeout=5,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == expected


def test_optional_client_info_and_encoded_mcp_name_are_accepted(live_transport):
    message = _message(
        "tools/call", 32, name="read_document", arguments={"document_id": "safe"}
    )
    message["params"]["_meta"].pop("io.modelcontextprotocol/clientInfo")
    encoded_name = base64.b64encode(b"read_document").decode("ascii")
    response = httpx.post(
        live_transport["url"],
        headers=_headers(
            live_transport["key"],
            "tools/call",
            f"=?base64?{encoded_name}?=",
        ),
        json=message,
        timeout=5,
    )

    assert response.status_code == 200
    assert response.json()["result"]["isError"] is False


def test_ineligible_tools_stay_hidden_and_gateway_controls_remain(live_transport):
    listed = _post(live_transport, "tools/list", 40)
    before = len(live_transport["upstream_calls"])
    for index, name in enumerate(
        (
            "missing_metadata",
            "blocked_tool",
            "quarantined_tool",
            "unknown_tool",
            "nonallowlisted_tool",
        ),
        start=41,
    ):
        denied = _post(live_transport, "tools/call", index, name=name, arguments={})
        assert denied.status_code == 200
        assert denied.json()["error"] == {
            "code": -32602,
            "message": "Unknown or unavailable tool",
        }
    assert [tool["name"] for tool in listed.json()["result"]["tools"]] == [
        "read_document"
    ]
    assert len(live_transport["upstream_calls"]) == before


def test_rbac_and_response_scanning_remain_in_gateway_path(live_transport):
    readonly = httpx.post(
        live_transport["url"],
        headers=_headers(live_transport["readonly_key"], "tools/call", "read_document"),
        json=_message("tools/call", 50, name="read_document", arguments={}),
        timeout=5,
    )
    scanned = _post(
        live_transport,
        "tools/call",
        51,
        name="read_document",
        arguments={"document_id": "pii-response"},
    )
    assert readonly.json()["result"]["isError"] is True
    text = scanned.json()["result"]["content"][0]["text"]
    assert "person@example.com" not in text
    assert "[REDACTED-EMAIL]" in text


def test_auth_origin_body_and_audit_containment(live_transport, monkeypatch, caplog):
    hostile_origin = httpx.post(
        live_transport["url"],
        headers=_headers(
            live_transport["key"], "tools/list", Origin="https://evil.example"
        ),
        json=_message("tools/list", 60),
        timeout=5,
    )
    assert hostile_origin.status_code == 403
    argument_marker = "private-argument-marker"
    response = _post(
        live_transport,
        "tools/call",
        61,
        name="read_document",
        arguments={"document_id": argument_marker},
    )
    assert response.status_code == 200
    audit_text = str(db.list_mcp_audit_logs(limit=20))
    assert live_transport["key"] not in audit_text
    assert argument_marker not in audit_text
    assert "safe result from read_document" not in audit_text
    assert live_transport["key"] not in caplog.text
    assert argument_marker not in caplog.text

    parsed = urlsplit(live_transport["url"])
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        request = (
            f"POST {parsed.path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Accept: application/json, text/event-stream\r\n"
            "Content-Type: application/json\r\n"
            f"X-API-Key: {live_transport['key']}\r\n"
            "Content-Length: 262145\r\nConnection: close\r\n\r\n{}"
        ).encode("ascii")
        sock.sendall(request)
        assert b" 413 " in sock.recv(256).split(b"\r\n", 1)[0]


def test_legacy_route_and_non_post_profile_remain_explicit(live_transport):
    legacy = httpx.post(
        f"{live_transport['base_url']}/mcp/call",
        headers={"X-API-Key": live_transport["key"]},
        json={"server_id": SERVER_ID, "tool_name": "read_document", "arguments": {}},
        timeout=5,
    )
    assert legacy.status_code == 200
    assert legacy.json()["ok"] is True
    for method in (httpx.get, httpx.delete):
        response = method(live_transport["url"], timeout=5)
        assert response.status_code == 405
        assert response.headers["Allow"] == "POST"
