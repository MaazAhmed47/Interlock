import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException

import proxy
from core import db
from core.mcp_gateway import (
    discover_mcp_tools,
    list_mcp_servers,
    proxy_mcp_tool_call,
    register_mcp_server,
    validate_mcp_tool_definition,
)
from core.shadow_mode import calculate_risk_score
from models.schemas import (
    MCPDiscoverRequest,
    MCPRegisterRequest,
    MCPToolCallRequest,
    MCPToolReviewRequest,
    MCPToolValidateRequest,
)

router = APIRouter()


@router.get("/mcp/servers")
async def mcp_list_servers(x_api_key: Optional[str] = Header(None)):
    """List all registered MCP servers."""
    proxy.verify_key(x_api_key)
    return {"servers": list_mcp_servers()}


@router.post("/mcp/servers")
async def mcp_register(request: MCPRegisterRequest, x_api_key: Optional[str] = Header(None)):
    """Register a new MCP server (requires manual verification before use)."""
    proxy.verify_key(x_api_key)
    return register_mcp_server(request.server_id, request.dict())


@router.post("/mcp/discover")
async def mcp_discover(request: MCPDiscoverRequest, x_api_key: Optional[str] = Header(None)):
    """
    Discover tools from an MCP server.
    Every tool is validated for malicious patterns before being returned.
    """
    proxy.verify_key(x_api_key)
    return await discover_mcp_tools(request.server_url, server_id=request.server_id)


@router.get("/mcp/tools")
async def mcp_tools(server_id: Optional[str] = None, x_api_key: Optional[str] = Header(None)):
    """List persisted MCP tool metadata, optionally for one server."""
    proxy.verify_key(x_api_key)
    return {"tools": db.list_mcp_tool_metadata(server_id)}


@router.get("/mcp/tools/drifted")
async def mcp_drifted_tools(server_id: Optional[str] = None, x_api_key: Optional[str] = Header(None)):
    """List MCP tools that need operator review because they changed or are quarantined."""
    proxy.verify_key(x_api_key)
    return {"tools": db.list_drifted_mcp_tools(server_id)}


@router.post("/mcp/tools/{server_id}/{tool_name}/approve")
async def mcp_approve_tool_baseline(
    server_id: str,
    tool_name: str,
    request: MCPToolReviewRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Approve the current MCP tool definition as the new trusted baseline."""
    proxy.verify_key(x_api_key)
    result = db.approve_mcp_tool_baseline(
        server_id,
        tool_name,
        reviewer=request.reviewer or "operator",
        reason=request.reason or "",
    )
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="MCP tool metadata not found.")
    tool = dict(result)
    tool.pop("ok", None)
    return {"ok": True, "tool": tool}


@router.post("/mcp/tools/{server_id}/{tool_name}/quarantine")
async def mcp_quarantine_tool(
    server_id: str,
    tool_name: str,
    request: MCPToolReviewRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Keep or mark an MCP tool quarantined until an operator approves it."""
    proxy.verify_key(x_api_key)
    result = db.quarantine_mcp_tool(
        server_id,
        tool_name,
        reviewer=request.reviewer or "operator",
        reason=request.reason or "",
    )
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="MCP tool metadata not found.")
    tool = dict(result)
    tool.pop("ok", None)
    return {"ok": True, "tool": tool}


@router.get("/mcp/audit")
async def mcp_audit(limit: int = 100, x_api_key: Optional[str] = Header(None)):
    """List recent MCP audit decisions."""
    proxy.verify_key(x_api_key)
    try:
        return {"events": db.list_mcp_audit_logs(limit)}
    except Exception:
        proxy.logger.exception("Failed to list MCP audit logs")
        return {"events": [], "warning": "audit_unavailable"}


@router.post("/mcp/validate-tool")
async def mcp_validate(request: MCPToolValidateRequest, x_api_key: Optional[str] = Header(None)):
    """Validate a single MCP tool definition for security issues."""
    proxy.verify_key(x_api_key)
    start = time.time()
    result = validate_mcp_tool_definition(request.tool_definition)
    result.scan_time_ms = round((time.time() - start) * 1000, 2)
    result.risk_score = calculate_risk_score(result)
    return result


@router.post("/mcp/call")
async def mcp_call(request: MCPToolCallRequest, x_api_key: Optional[str] = Header(None)):
    """
    Proxy an MCP tool call through the gateway.
    Pipeline: trust check -> tool whitelist -> inspector -> RBAC -> forward -> response scan.
    """
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    return await proxy_mcp_tool_call(
        server_id=request.server_id,
        tool_name=request.tool_name,
        arguments=request.arguments,
        role=request.role,
        api_key=raw_key,
    )


@router.delete("/mcp/servers/{server_id}")
async def mcp_unregister(server_id: str, x_api_key: Optional[str] = Header(None)):
    """Remove an MCP server from the registry."""
    proxy.verify_key(x_api_key)
    removed = db.unregister_mcp_server(server_id)
    if removed:
        return {"ok": True, "removed": server_id}
    return {"ok": False, "error": "not_found"}
