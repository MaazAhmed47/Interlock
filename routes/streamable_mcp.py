"""JSON-response MCP Streamable HTTP endpoint backed by Interlock's gateway."""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

import proxy
from config import cors_allowed_origins
from core import db
from core.mcp_gateway import proxy_mcp_tool_call
from core.mcp_tool_eligibility import list_streamable_tools
from core.streamable_sessions import session_store

router = APIRouter()

_JSON_RPC_VERSION = "2.0"
_PROTOCOL_VERSION = "2025-11-25"
_PATH = "/mcp/stream/{server_id}"
_MAX_BODY_BYTES = 256 * 1024


def _json_result(request_id: Any, result: Any) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": _JSON_RPC_VERSION, "id": request_id, "result": result}
    )


def _json_error(
    request_id: Any, code: int, message: str, *, status_code: int = 200
) -> JSONResponse:
    return JSONResponse(
        {
            "jsonrpc": _JSON_RPC_VERSION,
            "id": request_id,
            "error": {"code": code, "message": message},
        },
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
    """Accept one API-key credential without accepting ambiguous headers."""
    api_keys = request.headers.getlist("x-api-key")
    authorizations = request.headers.getlist("authorization")
    if len(api_keys) > 1 or len(authorizations) > 1:
        return None
    if api_keys and authorizations:
        return None
    if api_keys:
        return api_keys[0]
    if authorizations:
        value = authorizations[0]
        if value.lower().startswith("bearer ") and value[7:].strip():
            return value[7:].strip()
    return None


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


def _protocol_header_error(request: Request) -> Optional[Response]:
    if request.headers.get("mcp-protocol-version") != _PROTOCOL_VERSION:
        return Response(status_code=400)
    return None


def _session_id(request: Request) -> Optional[str]:
    values = request.headers.getlist("mcp-session-id")
    if len(values) != 1:
        return None
    return values[0]


def _principal_binding(key_info: dict[str, Any]) -> Optional[str]:
    key_id = key_info.get("id")
    key_hash = key_info.get("key_hash")
    if key_id is None or not isinstance(key_hash, str) or not key_hash:
        return None
    return f"{key_id}:{key_hash}"


async def _read_bounded_body(
    request: Request,
) -> tuple[Optional[bytes], Optional[Response]]:
    """Bound both declared and chunked request bodies before JSON parsing."""
    content_lengths = [
        value
        for name, value in request.scope.get("headers", [])
        if name.lower() == b"content-length"
    ]
    if len(content_lengths) > 1:
        return None, Response(status_code=400)
    if content_lengths:
        try:
            raw_length = content_lengths[0].decode("ascii")
        except UnicodeDecodeError:
            return None, Response(status_code=400)
        if not raw_length.isdigit():
            return None, Response(status_code=400)
        normalized = raw_length.lstrip("0") or "0"
        maximum = str(_MAX_BODY_BYTES)
        if len(normalized) > len(maximum) or (
            len(normalized) == len(maximum) and normalized > maximum
        ):
            return None, Response(status_code=413)

    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > _MAX_BODY_BYTES - len(body):
            return None, Response(status_code=413)
        body.extend(chunk)
    return bytes(body), None


def _valid_initialize(message: dict[str, Any]) -> bool:
    params = message.get("params")
    return (
        "id" in message
        and message.get("id") is not None
        and isinstance(params, dict)
        and isinstance(params.get("protocolVersion"), str)
        and bool(params["protocolVersion"])
        and isinstance(params.get("capabilities"), dict)
        and isinstance(params.get("clientInfo"), dict)
        and isinstance(params["clientInfo"].get("name"), str)
        and bool(params["clientInfo"]["name"])
        and isinstance(params["clientInfo"].get("version"), str)
        and bool(params["clientInfo"]["version"])
    )


@router.post(_PATH, include_in_schema=False)
async def streamable_http_post(server_id: str, request: Request):
    """Serve MCP JSON-RPC over the standard Streamable HTTP request shape."""
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
    principal_binding = _principal_binding(key_info)
    if principal_binding is None:
        return Response(status_code=401)

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
    if not isinstance(method, str) or not method:
        return _json_error(request_id, -32600, "Invalid Request", status_code=400)

    if method == "initialize":
        if request.headers.getlist("mcp-session-id"):
            return Response(status_code=400)
        if not _valid_initialize(message):
            return _json_error(request_id, -32602, "Invalid params", status_code=400)
        session = session_store.create(principal_binding, server_id)
        response = _json_result(
            request_id,
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "interlock-mcp-gateway",
                    "version": "0.2.0-alpha.1",
                },
                "instructions": (
                    "Interlock proxies this server's registered tools through "
                    "its runtime trust controls."
                ),
            },
        )
        response.headers["MCP-Session-Id"] = session.session_id
        return response

    protocol_error = _protocol_header_error(request)
    if protocol_error is not None:
        return protocol_error

    session_id = _session_id(request)
    if session_id is None:
        return Response(status_code=404)

    if method == "notifications/initialized":
        if "id" in message:
            return _json_error(request_id, -32600, "Invalid Request", status_code=400)
        if not session_store.mark_initialized(session_id, principal_binding, server_id):
            return Response(status_code=404)
        return Response(status_code=202)

    if (
        session_store.authorize(
            session_id,
            principal_binding,
            server_id,
            require_initialized=True,
        )
        is None
    ):
        return Response(status_code=404)

    if "id" not in message:
        return Response(status_code=202)

    if method == "ping":
        if "id" not in message or request_id is None:
            return _json_error(None, -32600, "Invalid Request", status_code=400)
        return _json_result(request_id, {})

    if method == "tools/list":
        if "id" not in message or request_id is None:
            return _json_error(None, -32600, "Invalid Request", status_code=400)
        return _json_result(request_id, {"tools": list_streamable_tools(server_id)})

    if method == "tools/call":
        if "id" not in message or request_id is None:
            return _json_error(None, -32600, "Invalid Request", status_code=400)
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

    return _json_error(request_id, -32601, "Method not found")


@router.get(_PATH, include_in_schema=False)
@router.delete(_PATH, include_in_schema=False)
async def streamable_http_non_post(server_id: str, request: Request):
    """This JSON-only profile intentionally does not expose an SSE stream."""
    origin_error = _origin_error(request)
    if origin_error is not None:
        return origin_error
    return Response(status_code=405, headers={"Allow": "POST"})
