#!/usr/bin/env python3
"""Legacy-lifecycle stdio MCP adapter for the LiveKit Agents proof.

LiveKit's real MCPToolset initializes this local process with the MCP SDK's
legacy session lifecycle. Inventory comes from Interlock's persisted tool
registry and every tool invocation is forwarded through Interlock `/mcp/call`.
This adapter does not add initialize/session behavior to Interlock itself.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any

import httpx
from mcp import types
from mcp.server import InitializationOptions, NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError

SERVER_NAME = "interlock-livekit-compatibility-adapter"
SERVER_VERSION = "1.0.0"
MAX_PUBLIC_ERROR_CHARS = 300
SAFE_HOLD_MESSAGE = (
    "Interlock held this tool call before upstream forwarding. "
    "Review the Interlock audit evidence before retrying."
)
SAFE_UPSTREAM_ERROR_MESSAGE = (
    "Interlock forwarded this tool call, but the upstream MCP server failed. "
    "Review the Interlock audit evidence before retrying."
)
SAFE_DENIAL_MESSAGE = (
    "Interlock denied this tool call. Review the Interlock audit evidence "
    "before retrying."
)
_UPSTREAM_ERROR_CODES = {
    "mcp_server_timeout",
    "unsupported_upstream_response_media_type",
    "upstream_empty_response",
    "upstream_http_error",
    "upstream_invalid_envelope",
    "upstream_invalid_json",
    "upstream_jsonrpc_error",
}


def _settings() -> tuple[str, str, str, set[str]]:
    base_url = os.getenv("INTERLOCK_API_URL", "http://127.0.0.1:8001").rstrip("/")
    api_key = os.getenv("INTERLOCK_API_KEY", "")
    server_id = os.getenv("INTERLOCK_SERVER_ID", "")
    allowed = {
        item.strip()
        for item in os.getenv("INTERLOCK_TOOL_NAMES", "read_customer").split(",")
        if item.strip()
    }
    return base_url, api_key, server_id, allowed


def _bounded_text(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:MAX_PUBLIC_ERROR_CHARS]


def safe_gateway_message(_tool_name: str, response: dict[str, Any]) -> str:
    """Map an allowlisted gateway code to fixed, non-reflected text."""
    error = response.get("error")
    if error == "tool_quarantined":
        return SAFE_HOLD_MESSAGE
    if error in _UPSTREAM_ERROR_CODES:
        return SAFE_UPSTREAM_ERROR_MESSAGE
    return SAFE_DENIAL_MESSAGE


def _is_eligible_inventory_row(row: dict[str, Any]) -> bool:
    """Fail closed unless Interlock's persisted state is active and allowed."""
    return (
        row.get("status") == "active"
        and row.get("drift_action") == "allow"
        and row.get("drift_severity") == "none"
    )


def _request_headers(api_key: str) -> dict[str, str]:
    if not api_key:
        raise RuntimeError("Interlock API key is missing.")
    return {"x-api-key": api_key, "accept": "application/json"}


def _safe_http_error(operation: str, response: httpx.Response) -> RuntimeError:
    return RuntimeError(
        f"Interlock {operation} failed with HTTP {response.status_code}."
    )


async def _list_interlock_tools() -> list[types.Tool]:
    base_url, api_key, server_id, allowed = _settings()
    if not server_id:
        raise RuntimeError("Interlock server id is missing.")
    try:
        async with httpx.AsyncClient(timeout=2.0, trust_env=False) as client:
            response = await client.get(
                f"{base_url}/mcp/tools",
                params={"server_id": server_id},
                headers=_request_headers(api_key),
            )
    except httpx.HTTPError as exc:
        raise RuntimeError("Interlock inventory is unavailable.") from exc
    if response.status_code != 200:
        raise _safe_http_error("inventory", response)

    payload = response.json()
    inventory = payload.get("tools") if isinstance(payload, dict) else None
    if not isinstance(inventory, list):
        raise RuntimeError("Interlock inventory returned an invalid response.")

    tools: list[types.Tool] = []
    for row in inventory:
        if not isinstance(row, dict):
            continue
        raw = row.get("raw_tool_definition")
        name = str(row.get("tool_name") or "")
        if (
            name not in allowed
            or not _is_eligible_inventory_row(row)
            or not isinstance(raw, dict)
        ):
            continue
        try:
            tools.append(types.Tool.model_validate(raw))
        except Exception as exc:
            raise RuntimeError(
                "Interlock inventory contains an invalid active tool definition."
            ) from exc
    return tools


async def _call_interlock_tool(
    tool_name: str, arguments: dict[str, Any]
) -> types.CallToolResult:
    base_url, api_key, server_id, allowed = _settings()
    if not server_id:
        raise RuntimeError("Interlock server id is missing.")
    if tool_name not in allowed:
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text", text="Interlock rejected an unknown proof tool."
                )
            ],
            isError=True,
        )
    try:
        async with httpx.AsyncClient(timeout=35.0, trust_env=False) as client:
            response = await client.post(
                f"{base_url}/mcp/call",
                headers={
                    **_request_headers(api_key),
                    "content-type": "application/json",
                },
                json={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "arguments": arguments,
                },
            )
    except httpx.HTTPError as exc:
        raise RuntimeError("Interlock gateway is unavailable.") from exc
    if response.status_code != 200:
        raise _safe_http_error("gateway", response)

    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Interlock gateway returned an invalid response.")
    if payload.get("ok") is not True:
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text", text=safe_gateway_message(tool_name, payload)
                )
            ],
            isError=True,
        )

    result = payload.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("Interlock gateway returned no tool result.")
    try:
        return types.CallToolResult.model_validate(result)
    except Exception as exc:
        raise RuntimeError(
            "Interlock gateway returned an invalid tool result."
        ) from exc


server: Server[object] = Server(SERVER_NAME, version=SERVER_VERSION)


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    try:
        return await _list_interlock_tools()
    except RuntimeError as exc:
        raise McpError(
            types.ErrorData(code=-32000, message=_bounded_text(exc))
        ) from None


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
    return await _call_interlock_tool(name, arguments)


async def run_adapter() -> None:
    delay = float(os.getenv("INTERLOCK_ADAPTER_STARTUP_DELAY_SECONDS", "0") or "0")
    if delay > 0:
        await asyncio.sleep(delay)
    capabilities = server.get_capabilities(
        notification_options=NotificationOptions(), experimental_capabilities={}
    )
    options = InitializationOptions(
        server_name=SERVER_NAME,
        server_version=SERVER_VERSION,
        capabilities=capabilities,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options)


def main() -> None:
    asyncio.run(run_adapter())


if __name__ == "__main__":
    main()
