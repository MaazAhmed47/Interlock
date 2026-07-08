import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException

import proxy
from core import db
from core.chain_drift import run_chain_analysis
from core.effective_permission import run_effective_permission_probe
from core.effect_readback import run_effect_readback_observer
from core.limits import clamp_limit
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url
from core.mcp_gateway import (
    discover_mcp_tools,
    list_mcp_servers,
    proxy_mcp_tool_call,
    register_mcp_server,
    validate_mcp_tool_definition,
)
from core.shadow_mode import calculate_risk_score
from models.schemas import (
    MCPEffectivePermissionProbeRequest,
    MCPEffectReadbackProbeRequest,
    MCPChainAnalyzeRequest,
    MCPDiscoverRequest,
    MCPRebaselineRequest,
    MCPRegisterRequest,
    MCPToolCallRequest,
    MCPToolReviewRequest,
    MCPToolValidateRequest,
)

router = APIRouter()

MAX_MCP_SERVER_LIMIT = 100
MAX_MCP_TOOL_LIMIT = 500
MAX_MCP_AUDIT_LIMIT = 500


def _tool_inventory_with_server_policy(
    server_id: Optional[str] = None,
    limit: int = MAX_MCP_TOOL_LIMIT,
    *,
    demo_visible_only: bool = False,
) -> list[dict]:
    tools = db.list_mcp_tool_metadata(
        server_id, limit=limit, demo_visible_only=demo_visible_only
    )
    seen = {(tool.get("server_id"), tool.get("tool_name")) for tool in tools}

    for server in list_mcp_servers(limit=limit, demo_visible_only=demo_visible_only):
        sid = server.get("server_id")
        if server_id and sid != server_id:
            continue

        description = server.get("description") or sid or "MCP server"
        for name in server.get("allowed_tools") or []:
            key = (sid, name)
            if key in seen:
                continue
            tools.append(
                {
                    "server_id": sid,
                    "tool_name": name,
                    "status": "allowed",
                    "description": f"Allowed by server policy: {description}",
                    "normalized_metadata": {
                        "effects": ["server_policy"],
                        "side_effect": "unknown",
                        "data_classes": [],
                    },
                    "server_registry_class": server.get("registry_class"),
                    "server_registry_note": server.get("registry_note"),
                    "server_demo_visible": server.get("demo_visible", True),
                }
            )
            seen.add(key)

        for name in server.get("blocked_tools") or []:
            key = (sid, name)
            if key in seen:
                continue
            tools.append(
                {
                    "server_id": sid,
                    "tool_name": name,
                    "status": "blocked",
                    "description": f"Blocked by server policy: {description}",
                    "normalized_metadata": {
                        "effects": ["blocked"],
                        "side_effect": "blocked",
                        "data_classes": [],
                    },
                    "server_registry_class": server.get("registry_class"),
                    "server_registry_note": server.get("registry_note"),
                    "server_demo_visible": server.get("demo_visible", True),
                }
            )
            seen.add(key)

    return tools[:limit]


@router.get("/mcp/servers")
async def mcp_list_servers(
    limit: int = 100,
    demo_visible_only: bool = False,
    x_api_key: Optional[str] = Header(None),
):
    """List all registered MCP servers."""
    proxy.verify_key(x_api_key)
    safe_limit = clamp_limit(limit, default=100, maximum=MAX_MCP_SERVER_LIMIT)
    return {"servers": list_mcp_servers(limit=safe_limit, demo_visible_only=demo_visible_only)}


@router.post("/mcp/servers")
async def mcp_register(
    request: MCPRegisterRequest, x_api_key: Optional[str] = Header(None)
):
    """Register a new MCP server (requires manual verification before use)."""
    proxy.verify_key(x_api_key)
    try:
        ensure_safe_outbound_url(request.url, context="MCP server")
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return register_mcp_server(request.server_id, request.dict())


@router.post("/mcp/servers/{server_id}/verify")
async def mcp_verify_server(server_id: str, x_api_key: Optional[str] = Header(None)):
    """Mark a registered MCP server verified after manual operator review."""
    proxy.verify_key(x_api_key)
    verified = db.verify_mcp_server(server_id)
    if not verified:
        raise HTTPException(status_code=404, detail="MCP server not found.")

    server = db.lookup_mcp_server(server_id) or {
        "server_id": server_id,
        "verified": True,
    }
    db.log_mcp_audit_event(
        {
            "server_id": server_id,
            "tool_name": "",
            "role": "operator",
            "action": "verify",
            "matched_rule": "manual_server_verification",
            "reason": "MCP server manually verified after operator review.",
            "effects": [],
            "side_effect": "unknown",
            "data_classes": [],
            "externality": "unknown",
            "verification_level": "manual",
            "confidence": 1.0,
            "warnings": [],
            "argument_keys": [],
            "blocked_by": "",
        }
    )
    return {"ok": True, "server_id": server_id, "verified": True, "server": server}


@router.post("/mcp/discover")
async def mcp_discover(
    request: MCPDiscoverRequest, x_api_key: Optional[str] = Header(None)
):
    """
    Discover tools from an MCP server.
    Every tool is validated for malicious patterns before being returned.
    """
    proxy.verify_key(x_api_key)
    try:
        ensure_safe_outbound_url(request.server_url, context="MCP discovery")
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return await discover_mcp_tools(request.server_url, server_id=request.server_id)


@router.post("/mcp/servers/{server_id}/rebaseline")
async def mcp_rebaseline_server(
    server_id: str,
    request: MCPRebaselineRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Reset a registered server's stored tool baseline and rediscover it."""
    proxy.verify_key(x_api_key)
    if not request.confirm_rebaseline:
        raise HTTPException(
            status_code=400,
            detail="MCP server rebaseline requires confirm_rebaseline=true.",
        )

    server = db.lookup_mcp_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="MCP server not found.")
    try:
        ensure_safe_outbound_url(server["url"], context="MCP discovery")
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    cleared = db.clear_mcp_tool_metadata(server_id)
    discovery = await discover_mcp_tools(server["url"], server_id=server_id)
    return {
        "ok": bool(discovery.get("ok")),
        "server_id": server_id,
        "cleared_tools": cleared,
        "discovery": discovery,
    }


@router.get("/mcp/tools")
async def mcp_tools(
    server_id: Optional[str] = None,
    limit: int = 100,
    demo_visible_only: bool = False,
    x_api_key: Optional[str] = Header(None),
):
    """List persisted MCP tool metadata, optionally for one server."""
    proxy.verify_key(x_api_key)
    safe_limit = clamp_limit(limit, default=100, maximum=MAX_MCP_TOOL_LIMIT)
    return {"tools": _tool_inventory_with_server_policy(server_id, safe_limit, demo_visible_only=demo_visible_only)}


@router.get("/mcp/tools/drifted")
async def mcp_drifted_tools(
    server_id: Optional[str] = None,
    limit: int = 100,
    demo_visible_only: bool = False,
    x_api_key: Optional[str] = Header(None),
):
    """List MCP tools that need operator review because they changed or are quarantined."""
    proxy.verify_key(x_api_key)
    safe_limit = clamp_limit(limit, default=100, maximum=MAX_MCP_TOOL_LIMIT)
    return {"tools": db.list_drifted_mcp_tools(server_id, limit=safe_limit, demo_visible_only=demo_visible_only)}


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


@router.post("/mcp/servers/{server_id}/probes/run")
async def mcp_run_effective_permission_probe(
    server_id: str,
    request: MCPEffectivePermissionProbeRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Run one manual non-production effective-permission probe."""
    proxy.verify_key(x_api_key)
    if not request.non_production:
        raise HTTPException(
            status_code=400,
            detail="Effective-permission probes require non_production=true.",
        )
    if not (request.safety_note or "").strip():
        raise HTTPException(
            status_code=400,
            detail="Effective-permission probes require a safety_note.",
        )
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    return await run_effective_permission_probe(server_id, payload)


@router.post("/mcp/servers/{server_id}/effects/readback/run")
async def mcp_run_effect_readback_observer(
    server_id: str,
    request: MCPEffectReadbackProbeRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Run one manual non-production provider-readback effect probe."""
    proxy.verify_key(x_api_key)
    if not request.non_production:
        raise HTTPException(
            status_code=400,
            detail="Readback effect probes require non_production=true.",
        )
    if not (request.safety_note or "").strip():
        raise HTTPException(
            status_code=400,
            detail="Readback effect probes require a safety_note.",
        )
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    return await run_effect_readback_observer(server_id, payload)


@router.post("/mcp/chains/analyze")
async def mcp_analyze_chain(
    request: MCPChainAnalyzeRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Analyze a planned multi-step MCP tool chain before execution."""
    proxy.verify_key(x_api_key)
    if not (request.safety_note or "").strip():
        raise HTTPException(
            status_code=400,
            detail="Chain analysis requires a safety_note.",
        )
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    return run_chain_analysis(payload)


@router.get("/mcp/audit")
async def mcp_audit(limit: int = 100, x_api_key: Optional[str] = Header(None)):
    """List recent MCP audit decisions."""
    proxy.verify_key(x_api_key)
    try:
        safe_limit = clamp_limit(limit, default=100, maximum=MAX_MCP_AUDIT_LIMIT)
        return {"events": db.list_mcp_audit_logs(safe_limit)}
    except Exception:
        proxy.logger.exception("Failed to list MCP audit logs")
        return {"events": [], "warning": "audit_unavailable"}


@router.post("/mcp/validate-tool")
async def mcp_validate(
    request: MCPToolValidateRequest, x_api_key: Optional[str] = Header(None)
):
    """Validate a single MCP tool definition for security issues."""
    proxy.verify_key(x_api_key)
    start = time.time()
    result = validate_mcp_tool_definition(request.tool_definition)
    result.scan_time_ms = round((time.time() - start) * 1000, 2)
    result.risk_score = calculate_risk_score(result)
    return result


@router.post("/mcp/call")
async def mcp_call(
    request: MCPToolCallRequest, x_api_key: Optional[str] = Header(None)
):
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
