"""Disposable official Python SDK probe for the scoped MCP 2026 profile."""

from __future__ import annotations

import asyncio
import json
import os
import sys

import httpx2
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import Implementation


async def _main() -> None:
    mode = sys.argv[1]
    use_parameter_header = len(sys.argv) > 2 and sys.argv[2] == "parameter-header"
    headers = {"X-API-Key": os.environ["SDK_PROBE_KEY"]}
    outcome: dict[str, object]
    async with httpx2.AsyncClient(headers=headers) as http_client:
        transport = streamable_http_client(
            os.environ["SDK_PROBE_URL"],
            http_client=http_client,
            terminate_on_close=False,
        )
        try:
            async with Client(
                transport,
                mode=mode,
                client_info=Implementation(
                    name="interlock-python-sdk-probe", version="2.0.0"
                ),
                cache=None,
            ) as client:
                listed = await client.list_tools()
                called = await client.call_tool(
                    "read_document",
                    {
                        "document_id": "safe",
                        **({"tenant": "internal"} if use_parameter_header else {}),
                    },
                )
                server_info = client.server_info
                outcome = {
                    "connected": True,
                    "server_name": server_info.name if server_info else None,
                    "tool_names": [tool.name for tool in listed.tools],
                    "call_is_error": called.is_error,
                }
        except BaseException as exc:
            outcome = {
                "connected": False,
                "error_type": type(exc).__name__,
            }
    print(json.dumps(outcome, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(_main())
