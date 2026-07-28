"""Stateless MCP 2026-07-28 Streamable HTTP endpoint.

Interlock exposes only its approved tool surface and gateway-mediated tool
calls. It does not advertise protocol features it cannot enforce.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

import proxy
from config import cors_allowed_origins
from core import db
from core.http_body import TOO_LARGE, read_bounded_body
from core.http_credentials import single_api_credential
from core.mcp_gateway import proxy_mcp_tool_call
from core.mcp_tool_eligibility import list_streamable_tools

router = APIRouter()

_JSON_RPC_VERSION = "2.0"
_PROTOCOL_VERSION = "2026-07-28"
_PATH = "/mcp/stream/{server_id}"
_MAX_BODY_BYTES = 256 * 1024
_LIST_TTL_MS = 5_000
_SERVER_INFO = {"name": "interlock-mcp-gateway", "version": "0.2.0-alpha.1"}
_SERVER_CAPABILITIES = {"tools": {"listChanged": False}}


def _result_meta() -> dict[str, Any]:
    return {"io.modelcontextprotocol/serverInfo": _SERVER_INFO}


def _json_result(request_id: Any, result: dict[str, Any]) -> JSONResponse:
    # The gateway is the server seen by the inbound client. Do not let an
    # upstream result replace its wire discriminator or identity stamp.
    payload = {**result, "resultType": "complete", "_meta": _result_meta()}
    return JSONResponse(
        {"jsonrpc": _JSON_RPC_VERSION, "id": request_id, "result": payload}
    )


def _json_error(
    request_id: Any,
    code: int,
    message: str,
    *,
    status_code: int = 200,
    data: Optional[dict[str, Any]] = None,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse(
        {"jsonrpc": _JSON_RPC_VERSION, "id": request_id, "error": error},
        status_code=status_code,
    )


def _origin_error(request: Request) -> Optional[Response]:
    """Reject every supplied Origin not present in the explicit allowlist."""
    origins = request.headers.getlist("origin")
    if not origins:
        return None
    if len(origins) != 1:
        return Response(status_code=403)
    origin = _normalize_origin(origins[0])
    allowed = {
        normalized
        for value in cors_allowed_origins()
        if value != "*" and (normalized := _normalize_origin(value)) is not None
    }
    if origin is None or origin not in allowed:
        return Response(status_code=403)
    return None


def _normalize_origin(value: str) -> Optional[str]:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    authority = f"{host}:{port}" if port is not None else host
    return f"{parsed.scheme.lower()}://{authority}"


def _credential(request: Request) -> Optional[str]:
    return single_api_credential(request)


def _transport_headers_error(request: Request) -> Optional[Response]:
    accept = {
        value.split(";", 1)[0].strip().lower()
        for value in (request.headers.get("accept") or "").split(",")
    }
    if "application/json" not in accept or "text/event-stream" not in accept:
        return Response(status_code=406)
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0]
    if content_type.strip().lower() != "application/json":
        return Response(status_code=415)
    return None


async def _read_bounded_body(
    request: Request,
) -> tuple[Optional[bytes], Optional[Response]]:
    body, error = await read_bounded_body(request, _MAX_BODY_BYTES)
    if error == TOO_LARGE:
        return None, Response(status_code=413)
    if error is not None:
        return None, Response(status_code=400)
    return body, None


def _request_meta(message: dict[str, Any]) -> Optional[dict[str, Any]]:
    params = message.get("params", {})
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    version = meta.get("io.modelcontextprotocol/protocolVersion")
    client_info = meta.get("io.modelcontextprotocol/clientInfo")
    capabilities = meta.get("io.modelcontextprotocol/clientCapabilities")
    if (
        not isinstance(version, str)
        or not version
        or not isinstance(capabilities, dict)
    ):
        return None
    if client_info is not None and (
        not isinstance(client_info, dict)
        or not isinstance(client_info.get("name"), str)
        or not client_info["name"]
        or not isinstance(client_info.get("version"), str)
        or not client_info["version"]
    ):
        return None
    return meta


def _decode_mcp_header_value(value: str) -> Optional[str]:
    if not (value.startswith("=?base64?") and value.endswith("?=")):
        if value != value.strip() or any(
            character != "\t" and not 0x20 <= ord(character) <= 0x7E
            for character in value
        ):
            return None
        return value
    encoded = value[len("=?base64?") : -len("?=")]
    try:
        return base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _header_error(
    request: Request, message: dict[str, Any], method: str
) -> Optional[JSONResponse]:
    request_id = message.get("id")
    version = request.headers.get("mcp-protocol-version")
    if version != _PROTOCOL_VERSION:
        return _json_error(
            request_id,
            -32022,
            "Unsupported protocol version",
            status_code=400,
            data={"supported": [_PROTOCOL_VERSION], "requested": version},
        )
    if request.headers.get("mcp-method") != method:
        return _json_error(request_id, -32020, "Header mismatch", status_code=400)
    params = message.get("params", {})
    if method == "tools/call":
        expected_name = params.get("name") if isinstance(params, dict) else None
        raw_name = request.headers.get("mcp-name")
        header_name = (
            _decode_mcp_header_value(raw_name) if raw_name is not None else None
        )
        if not isinstance(expected_name, str) or header_name != expected_name:
            return _json_error(request_id, -32020, "Header mismatch", status_code=400)
    elif request.headers.get("mcp-name") is not None:
        return _json_error(request_id, -32020, "Header mismatch", status_code=400)
    return None


def _unsupported_version_error(
    request_id: Any, meta: dict[str, Any]
) -> Optional[JSONResponse]:
    requested = meta["io.modelcontextprotocol/protocolVersion"]
    if requested != _PROTOCOL_VERSION:
        return _json_error(
            request_id,
            -32022,
            "Unsupported protocol version",
            status_code=400,
            data={"supported": [_PROTOCOL_VERSION], "requested": requested},
        )
    return None


@router.post(_PATH, include_in_schema=False)
async def streamable_http_post(server_id: str, request: Request):
    """Serve stateless MCP JSON-RPC over Streamable HTTP."""
    origin_error = _origin_error(request)
    if origin_error is not None:
        return origin_error
    transport_error = _transport_headers_error(request)
    if transport_error is not None:
        return transport_error

    credential = _credential(request)
    if credential is None:
        return Response(status_code=401)
    key_info, raw_key = proxy.require_scope(credential, "mcp.call")
    proxy.check_rate(raw_key, key_info["rate_per_min"])
    server = db.lookup_mcp_server(server_id)
    if not server or not server.get("verified"):
        return Response(status_code=404)

    body, body_error = await _read_bounded_body(request)
    if body_error is not None:
        return body_error
    try:
        message = json.loads(body or b"")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _json_error(None, -32700, "Parse error", status_code=400)
    if not isinstance(message, dict) or message.get("jsonrpc") != _JSON_RPC_VERSION:
        return _json_error(None, -32600, "Invalid Request", status_code=400)

    method = message.get("method")
    request_id = message.get("id")
    if (
        not isinstance(method, str)
        or not method
        or request_id is None
        or isinstance(request_id, bool)
        or not isinstance(request_id, (str, int))
    ):
        return _json_error(request_id, -32600, "Invalid Request", status_code=400)
    header_error = _header_error(request, message, method)
    if header_error is not None:
        return header_error
    meta = _request_meta(message)
    if meta is None:
        return _json_error(request_id, -32602, "Invalid params", status_code=400)
    version_error = _unsupported_version_error(request_id, meta)
    if version_error is not None:
        return version_error

    if method == "server/discover":
        return _json_result(
            request_id,
            {
                "supportedVersions": [_PROTOCOL_VERSION],
                "capabilities": _SERVER_CAPABILITIES,
                "instructions": "Interlock exposes approved tools and enforces its gateway trust boundary.",
                "ttlMs": _LIST_TTL_MS,
                "cacheScope": "private",
            },
        )
    if method == "tools/list":
        return _json_result(
            request_id,
            {
                "tools": list_streamable_tools(server_id),
                "ttlMs": _LIST_TTL_MS,
                "cacheScope": "private",
            },
        )
    if method == "tools/call":
        params = message.get("params")
        if not isinstance(params, dict):
            return _json_error(request_id, -32602, "Invalid params")
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or not isinstance(arguments, dict):
            return _json_error(request_id, -32602, "Invalid params")
        result = await proxy_mcp_tool_call(
            server_id=server_id,
            tool_name=tool_name,
            arguments=arguments,
            role=key_info.get("role") or "readonly_agent",
            principal_id=key_info.get("key_prefix") or str(key_info.get("id") or ""),
            api_key=raw_key,
            require_streamable_eligibility=True,
        )
        if result.get("ok") and isinstance(result.get("result"), dict):
            return _json_result(request_id, result["result"])
        return _json_result(
            request_id,
            {
                "content": [
                    {"type": "text", "text": "Interlock denied the tool call."}
                ],
                "isError": True,
            },
        )
    return _json_error(request_id, -32601, "Method not found", status_code=404)


@router.get(_PATH, include_in_schema=False)
@router.delete(_PATH, include_in_schema=False)
async def streamable_http_non_post(server_id: str, request: Request):
    """The 2026 profile has no GET lifecycle endpoint or session deletion."""
    origin_error = _origin_error(request)
    if origin_error is not None:
        return origin_error
    return Response(status_code=405, headers={"Allow": "POST"})
