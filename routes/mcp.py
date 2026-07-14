import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException

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
    MCPServerEnvironmentRequest,
    MCPToolCallRequest,
    MCPToolReviewRequest,
    MCPToolValidateRequest,
)

router = APIRouter()
control_plane_router = APIRouter(
    dependencies=[Depends(proxy.require_api_scope("admin"))]
)

MAX_MCP_SERVER_LIMIT = 100
MAX_MCP_TOOL_LIMIT = 500
MAX_MCP_AUDIT_LIMIT = 500


def _derived_identity(key_record: dict) -> dict:
    """
    Reviewer/principal identity derived from the authenticated key record.
    Request bodies never contribute to recorded identity — a caller-supplied
    `reviewer` or `role` string must not enter the hash-chained audit log.
    """
    key_prefix = key_record.get("key_prefix") or str(key_record.get("id") or "")
    label = (key_record.get("label") or "").strip()
    reviewer = f"{label} (key:{key_prefix})" if label else f"key:{key_prefix}"
    return {"reviewer": reviewer, "principal_id": key_prefix}


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
    proxy.require_scope(x_api_key, "mcp.read")
    safe_limit = clamp_limit(limit, default=100, maximum=MAX_MCP_SERVER_LIMIT)
    return {
        "servers": list_mcp_servers(
            limit=safe_limit, demo_visible_only=demo_visible_only
        )
    }


@control_plane_router.post("/mcp/servers")
async def mcp_register(
    request: MCPRegisterRequest, x_api_key: Optional[str] = Header(None)
):
    """Register a new MCP server (requires manual verification before use)."""
    proxy.require_scope(x_api_key, "admin")
    try:
        ensure_safe_outbound_url(request.url, context="MCP server")
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    result = register_mcp_server(request.server_id, payload)
    if result.get("error") in {
        "invalid_upstream_auth_config",
        "registration_rejected",
    }:
        raise HTTPException(
            status_code=400, detail=result.get("message") or result["error"]
        )
    return result


@control_plane_router.post("/mcp/servers/{server_id}/verify")
async def mcp_verify_server(server_id: str, x_api_key: Optional[str] = Header(None)):
    """Mark a registered MCP server verified after manual operator review."""
    key_info, _ = proxy.require_scope(x_api_key, "admin")
    identity = _derived_identity(key_info)
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
            "role": identity["reviewer"],
            "principal_id": identity["principal_id"],
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


@control_plane_router.post("/mcp/servers/{server_id}/environment")
async def mcp_set_server_environment(
    server_id: str,
    request: MCPServerEnvironmentRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Admin-only: persist a server's probe-authorization state.

    This is the ONLY path that can mark a server non-production and
    probe-enabled; the runtime probe gate reads this stored state instead
    of any request flag.
    """
    key_info, _ = proxy.require_scope(x_api_key, "admin")
    identity = _derived_identity(key_info)
    updated = db.set_mcp_server_environment(
        server_id, request.environment, request.probes_enabled
    )
    if not updated:
        raise HTTPException(status_code=404, detail="MCP server not found.")

    server = db.lookup_mcp_server(server_id)
    db.log_mcp_audit_event(
        {
            "server_id": server_id,
            "tool_name": "",
            "role": identity["reviewer"],
            "principal_id": identity["principal_id"],
            "action": "environment_update",
            "matched_rule": "server_environment_update",
            "reason": (
                f"MCP server environment set to {request.environment} with "
                f"probes_enabled={bool(request.probes_enabled)}."
            ),
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
    return {"ok": True, "server_id": server_id, "server": server}


@router.post("/mcp/discover")
async def mcp_discover(
    request: MCPDiscoverRequest, x_api_key: Optional[str] = Header(None)
):
    """
    Discover tools from an MCP server.
    Every tool is validated for malicious patterns before being returned.
    """
    proxy.require_scope(x_api_key, "mcp.discover")
    try:
        ensure_safe_outbound_url(request.server_url, context="MCP discovery")
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return await discover_mcp_tools(request.server_url, server_id=request.server_id)


@control_plane_router.post("/mcp/servers/{server_id}/rebaseline")
async def mcp_rebaseline_server(
    server_id: str,
    request: MCPRebaselineRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Reset a registered server's stored tool baseline and rediscover it."""
    proxy.require_scope(x_api_key, "admin")
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
    proxy.require_scope(x_api_key, "mcp.read")
    safe_limit = clamp_limit(limit, default=100, maximum=MAX_MCP_TOOL_LIMIT)
    return {
        "tools": _tool_inventory_with_server_policy(
            server_id, safe_limit, demo_visible_only=demo_visible_only
        )
    }


@router.get("/mcp/tools/drifted")
async def mcp_drifted_tools(
    server_id: Optional[str] = None,
    limit: int = 100,
    demo_visible_only: bool = False,
    x_api_key: Optional[str] = Header(None),
):
    """List MCP tools that need operator review because they changed or are quarantined."""
    proxy.require_scope(x_api_key, "mcp.read")
    safe_limit = clamp_limit(limit, default=100, maximum=MAX_MCP_TOOL_LIMIT)
    return {
        "tools": db.list_drifted_mcp_tools(
            server_id, limit=safe_limit, demo_visible_only=demo_visible_only
        )
    }


@control_plane_router.post("/mcp/tools/{server_id}/{tool_name}/approve")
async def mcp_approve_tool_baseline(
    server_id: str,
    tool_name: str,
    request: MCPToolReviewRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Approve the current MCP tool definition as the new trusted baseline.

    request.reviewer is retained for wire compatibility but deliberately
    ignored — the recorded reviewer is derived from the authenticated key.
    """
    key_info, _ = proxy.require_scope(x_api_key, "admin")
    identity = _derived_identity(key_info)
    result = db.approve_mcp_tool_baseline(
        server_id,
        tool_name,
        reviewer=identity["reviewer"],
        reason=request.reason or "",
        principal_id=identity["principal_id"],
    )
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="MCP tool metadata not found.")
    tool = dict(result)
    tool.pop("ok", None)
    return {"ok": True, "tool": tool}


@control_plane_router.post("/mcp/tools/{server_id}/{tool_name}/quarantine")
async def mcp_quarantine_tool(
    server_id: str,
    tool_name: str,
    request: MCPToolReviewRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Keep or mark an MCP tool quarantined until an operator approves it.

    request.reviewer is retained for wire compatibility but deliberately
    ignored — the recorded reviewer is derived from the authenticated key.
    """
    key_info, _ = proxy.require_scope(x_api_key, "admin")
    identity = _derived_identity(key_info)
    result = db.quarantine_mcp_tool(
        server_id,
        tool_name,
        reviewer=identity["reviewer"],
        reason=request.reason or "",
        principal_id=identity["principal_id"],
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
    """Run one manual effective-permission probe.

    Authorization is the mcp.probe scope PLUS the server's stored registry
    state (non-production and probe-enabled). The request body's
    non_production flag and safety_note are recorded as audit context only.
    """
    key_info, _ = proxy.require_scope(x_api_key, "mcp.probe")
    if not (request.safety_note or "").strip():
        raise HTTPException(
            status_code=400,
            detail="Effective-permission probes require a safety_note.",
        )
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    result = await run_effective_permission_probe(
        server_id, payload, principal=_derived_identity(key_info)
    )
    if result.get("error") == "probes_not_enabled":
        raise HTTPException(status_code=403, detail=result.get("message"))
    return result


@router.post("/mcp/servers/{server_id}/effects/readback/run")
async def mcp_run_effect_readback_observer(
    server_id: str,
    request: MCPEffectReadbackProbeRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Run one manual provider-readback effect probe.

    Same authorization model as effective-permission probes: mcp.probe
    scope PLUS stored non-production, probe-enabled registry state.
    """
    key_info, _ = proxy.require_scope(x_api_key, "mcp.probe")
    if not (request.safety_note or "").strip():
        raise HTTPException(
            status_code=400,
            detail="Readback effect probes require a safety_note.",
        )
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    result = await run_effect_readback_observer(
        server_id, payload, principal=_derived_identity(key_info)
    )
    if result.get("error") == "probes_not_enabled":
        raise HTTPException(status_code=403, detail=result.get("message"))
    return result


@router.post("/mcp/chains/analyze")
async def mcp_analyze_chain(
    request: MCPChainAnalyzeRequest,
    x_api_key: Optional[str] = Header(None),
):
    """Analyze a planned multi-step MCP tool chain before execution."""
    key_info, _ = proxy.require_scope(x_api_key, "mcp.call")
    if not (request.safety_note or "").strip():
        raise HTTPException(
            status_code=400,
            detail="Chain analysis requires a safety_note.",
        )
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    return run_chain_analysis(payload, principal=_derived_identity(key_info))


@control_plane_router.get("/mcp/audit")
async def mcp_audit(limit: int = 100, x_api_key: Optional[str] = Header(None)):
    """List recent MCP audit decisions."""
    proxy.require_scope(x_api_key, "admin")
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
    proxy.require_scope(x_api_key, "mcp.discover")
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
    key_info, raw_key = proxy.require_scope(x_api_key, "mcp.call")
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    return await proxy_mcp_tool_call(
        server_id=request.server_id,
        tool_name=request.tool_name,
        arguments=request.arguments,
        # request.role is retained for wire compatibility but deliberately
        # ignored. Authorization is bound to the authenticated key record.
        role=key_info.get("role") or "readonly_agent",
        principal_id=key_info.get("key_prefix") or str(key_info.get("id") or ""),
        api_key=raw_key,
    )


@control_plane_router.delete("/mcp/servers/{server_id}")
async def mcp_unregister(server_id: str, x_api_key: Optional[str] = Header(None)):
    """Remove an MCP server from the registry."""
    proxy.require_scope(x_api_key, "admin")
    removed = db.unregister_mcp_server(server_id)
    if removed:
        return {"ok": True, "removed": server_id}
    return {"ok": False, "error": "not_found"}
