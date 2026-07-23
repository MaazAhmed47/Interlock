"""Authoritative trusted-tool eligibility for Streamable HTTP MCP."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from core import db


@dataclass(frozen=True)
class ToolEligibility:
    eligible: bool
    reason: str
    server: Optional[dict[str, Any]] = None
    stored_tool: Optional[dict[str, Any]] = None


def evaluate_streamable_tool(server_id: str, tool_name: str) -> ToolEligibility:
    """Require one verified, active, allowlisted stored tool baseline."""
    server = db.lookup_mcp_server(server_id)
    if not server:
        return ToolEligibility(False, "untrusted_mcp_server")
    if not server.get("verified"):
        return ToolEligibility(False, "unverified_mcp_server", server=server)

    allowed = set(server.get("allowed_tools") or [])
    blocked = set(server.get("blocked_tools") or [])
    if tool_name in blocked:
        return ToolEligibility(False, "tool_blocked", server=server)
    if tool_name not in allowed:
        return ToolEligibility(False, "tool_not_allowed", server=server)

    stored = db.lookup_mcp_tool_metadata(server_id, tool_name)
    if not stored:
        return ToolEligibility(False, "tool_metadata_missing", server=server)
    stored = db.canonicalize_mcp_tool_record(stored)
    if (
        stored.get("status") == "quarantined"
        or stored.get("drift_action") == "quarantine"
    ):
        return ToolEligibility(
            False, "tool_quarantined", server=server, stored_tool=stored
        )
    if stored.get("status") != "active":
        return ToolEligibility(
            False, "tool_not_active", server=server, stored_tool=stored
        )

    raw = stored.get("raw_tool_definition")
    normalized = stored.get("normalized_metadata")
    if (
        not isinstance(raw, dict)
        or raw.get("name") != tool_name
        or not isinstance(raw.get("inputSchema"), dict)
        or not isinstance(normalized, dict)
        or not stored.get("tool_schema_hash")
        or not stored.get("description_hash")
    ):
        return ToolEligibility(
            False, "tool_metadata_untrusted", server=server, stored_tool=stored
        )
    return ToolEligibility(True, "eligible", server=server, stored_tool=stored)


def list_streamable_tools(server_id: str) -> list[dict[str, Any]]:
    """List exactly the tool definitions accepted by the call boundary."""
    tools: list[dict[str, Any]] = []
    for record in db.list_mcp_tool_metadata(server_id):
        name = record.get("tool_name")
        if not isinstance(name, str):
            continue
        eligibility = evaluate_streamable_tool(server_id, name)
        if eligibility.eligible and eligibility.stored_tool is not None:
            tools.append(eligibility.stored_tool["raw_tool_definition"])
    return tools
