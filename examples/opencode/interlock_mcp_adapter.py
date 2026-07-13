#!/usr/bin/env python3
"""
Minimal MCP stdio adapter for using Interlock from OpenCode.

This adapter exposes Interlock's existing REST API as MCP tools. It is meant for
local demos and integration testing; Interlock remains the runtime gateway.
"""

import json
import os
import sys
import urllib.error
import urllib.request

SERVER_INFO = {"name": "interlock-opencode-adapter", "version": "0.1.0"}


def _api_base() -> str:
    return os.getenv("INTERLOCK_API_URL", "http://localhost:8001").rstrip("/")


def _api_key() -> str:
    return os.getenv("INTERLOCK_API_KEY", "")


def _admin_api_key() -> str:
    return os.getenv("INTERLOCK_ADMIN_API_KEY", "") or _api_key()


def _request(
    method: str, path: str, payload: dict | None = None, *, admin: bool = False
) -> dict:
    body = None
    headers = {"Accept": "application/json"}

    key = _admin_api_key() if admin else _api_key()
    if key:
        headers["x-api-key"] = key

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        f"{_api_base()}{path}",
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(raw)
        except json.JSONDecodeError:
            detail = raw
        return {"ok": False, "status": exc.code, "error": detail}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _text_result(value: dict, is_error: bool = False) -> dict:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(value, indent=2, sort_keys=True),
            }
        ],
        "isError": is_error,
    }


def _tools() -> list[dict]:
    return [
        {
            "name": "interlock_mcp_call",
            "description": (
                "Call a registered MCP server tool through Interlock's runtime "
                "gateway. Interlock enforces trust, tool allowlists, metadata "
                "policy, RBAC, drift, provenance, argument inspection, response "
                "scanning, and audit logging before returning the result."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server_id": {"type": "string"},
                    "tool_name": {"type": "string"},
                    "arguments": {"type": "object", "default": {}},
                },
                "required": ["server_id", "tool_name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "interlock_mcp_discover",
            "description": "Discover and validate tools from an MCP server through Interlock.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server_url": {"type": "string"},
                    "server_id": {
                        "type": "string",
                        "description": "Optional registered Interlock server id for persistence and drift checks.",
                    },
                },
                "required": ["server_url"],
                "additionalProperties": False,
            },
        },
        {
            "name": "interlock_validate_tool",
            "description": "Validate one MCP tool definition with Interlock's tool poisoning checks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_definition": {"type": "object"},
                },
                "required": ["tool_definition"],
                "additionalProperties": False,
            },
        },
        {
            "name": "interlock_mcp_audit",
            "description": "Read recent Interlock MCP audit decisions with the admin-scoped API key.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 25,
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "interlock_mcp_servers",
            "description": "List MCP servers registered in Interlock.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    ]


def _call_tool(name: str, args: dict) -> dict:
    args = args or {}

    if name == "interlock_mcp_call":
        payload = {
            "server_id": args["server_id"],
            "tool_name": args["tool_name"],
            "arguments": args.get("arguments") or {},
        }
        result = _request("POST", "/mcp/call", payload)
        return _text_result(result, is_error=result.get("ok") is False)

    if name == "interlock_mcp_discover":
        payload = {"server_url": args["server_url"], "server_id": args.get("server_id")}
        result = _request("POST", "/mcp/discover", payload)
        return _text_result(result, is_error=result.get("ok") is False)

    if name == "interlock_validate_tool":
        result = _request(
            "POST", "/mcp/validate-tool", {"tool_definition": args["tool_definition"]}
        )
        return _text_result(result, is_error=result.get("is_threat") is True)

    if name == "interlock_mcp_audit":
        limit = int(args.get("limit") or 25)
        result = _request("GET", f"/mcp/audit?limit={limit}", admin=True)
        return _text_result(result, is_error=result.get("ok") is False)

    if name == "interlock_mcp_servers":
        result = _request("GET", "/mcp/servers")
        return _text_result(result, is_error=result.get("ok") is False)

    return _text_result({"ok": False, "error": f"Unknown tool: {name}"}, is_error=True)


def _handle(message: dict) -> dict | None:
    msg_id = message.get("id")
    method = message.get("method")

    if msg_id is None:
        return None

    try:
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": _tools()}}

        if method == "tools/call":
            params = message.get("params") or {}
            result = _call_tool(params.get("name", ""), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32603, "message": str(exc)},
        }


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            print(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": str(exc)},
                    }
                ),
                flush=True,
            )
            continue

        response = _handle(message)
        if response is not None:
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
