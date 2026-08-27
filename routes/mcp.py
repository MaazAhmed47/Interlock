import json
import re
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

import proxy
from config import (
    boundary_review_idempotency_ttl_seconds,
    ci_boundary_review_max_request_bytes,
)
from core import db
from core.http_body import MALFORMED, TOO_LARGE, discard_bounded_body, read_bounded_body
from core.http_cache_headers import NO_STORE_HEADERS as _NO_STORE_HEADERS
from core.chain_drift import run_chain_analysis
from core.ci_boundary_review import run_boundary_review
from core.effective_permission import run_effective_permission_probe
from core.effect_readback import run_effect_readback_observer
from core.http_credentials import single_api_credential
from core.limits import clamp_limit
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url_async
from core.mcp_gateway import (
    discover_mcp_tools,
    fetch_candidate_tool_surface,
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
    MCPToolApprovalRequest,
    MCPToolApprovalResponse,
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
MAX_MCP_VALIDATE_BODY_BYTES = 256 * 1024


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
        canonical_url = await ensure_safe_outbound_url_async(
            request.url, context="MCP server"
        )
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    payload = request.model_dump() if hasattr(request, "model_dump") else request.dict()
    payload["url"] = canonical_url
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
        server_url = await ensure_safe_outbound_url_async(
            request.server_url, context="MCP discovery"
        )
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return await discover_mcp_tools(server_url, server_id=request.server_id)


def _candidate_summary(candidate: Optional[dict]) -> Optional[dict]:
    if not candidate:
        return None
    return {
        "candidate_surface_hash": candidate.get("candidate_surface_hash"),
        "tool_count": candidate.get("tool_count"),
        "created_at": candidate.get("created_at"),
        "created_by": candidate.get("created_by"),
    }


@control_plane_router.get("/mcp/servers/{server_id}/rebaseline")
async def mcp_rebaseline_status(
    server_id: str,
    x_api_key: Optional[str] = Header(None),
):
    """The reviewer's view: active baseline hash, staged candidate, history."""
    proxy.require_scope(x_api_key, "admin")
    snapshot = db.get_rebaseline_review_snapshot(server_id)
    if not snapshot.get("ok"):
        raise HTTPException(status_code=404, detail="MCP server not found.")
    return {
        "ok": True,
        "server_id": server_id,
        "active": snapshot["active"],
        "candidate": _candidate_summary(snapshot["candidate"]),
        "versions": snapshot["versions"],
    }


@control_plane_router.post("/mcp/servers/{server_id}/rebaseline/discover")
async def mcp_rebaseline_discover(
    server_id: str,
    x_api_key: Optional[str] = Header(None),
):
    """
    Stage a rebaseline CANDIDATE: fetch and validate the server's complete
    tool surface, then store it for review. Never mutates the active
    baseline — on timeout, malformed response, or validation failure the
    active baseline AND any previously staged candidate stay unchanged.
    """
    key_info, _ = proxy.require_scope(x_api_key, "admin")
    identity = _derived_identity(key_info)
    server = db.lookup_mcp_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="MCP server not found.")
    try:
        server_url = await ensure_safe_outbound_url_async(
            server["url"], context="MCP discovery"
        )
    except OutboundUrlRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    result = await fetch_candidate_tool_surface(server_url, server_id=server_id)
    if not result.get("ok"):
        snapshot = db.get_rebaseline_review_snapshot(server_id)
        if not snapshot.get("ok"):
            raise HTTPException(status_code=404, detail="MCP server not found.")
        return {
            "ok": False,
            "server_id": server_id,
            "error": result.get("error"),
            "message": result.get("message", ""),
            "blocked": result.get("blocked", []),
            "active_surface_hash": snapshot["active"]["surface_hash"],
            "candidate": _candidate_summary(snapshot["candidate"]),
        }

    candidate = db.save_rebaseline_candidate(
        server_id, result["validated_tools"], identity["reviewer"]
    )
    if candidate.get("ok") is False:
        raise HTTPException(status_code=404, detail="MCP server not found.")
    return {
        "ok": True,
        "server_id": server_id,
        "candidate_surface_hash": candidate["candidate_surface_hash"],
        "tool_count": candidate["tool_count"],
        "created_at": candidate["created_at"],
        "created_by": candidate["created_by"],
        "active_surface_hash": candidate["active_surface_hash"],
    }


@control_plane_router.post("/mcp/servers/{server_id}/rebaseline")
async def mcp_rebaseline_server(
    server_id: str,
    request: MCPRebaselineRequest,
    x_api_key: Optional[str] = Header(None),
):
    """
    Approve the staged candidate as the new active baseline —
    compare-and-swap protected and atomic. Requires the active-baseline
    hash the reviewer saw AND the exact candidate hash they reviewed; if
    either is stale (the baseline moved, or a newer discovery replaced the
    candidate) the request is rejected with 409 and the current hashes.
    """
    key_info, _ = proxy.require_scope(x_api_key, "admin")
    identity = _derived_identity(key_info)
    if not request.confirm_rebaseline:
        raise HTTPException(
            status_code=400,
            detail="MCP server rebaseline requires confirm_rebaseline=true.",
        )
    if not db.lookup_mcp_server(server_id):
        raise HTTPException(status_code=404, detail="MCP server not found.")
    if not request.expected_current_hash or not request.expected_candidate_hash:
        raise HTTPException(
            status_code=400,
            detail=(
                "MCP rebaseline is compare-and-swap protected: provide "
                "expected_current_hash (the active baseline you reviewed) and "
                "expected_candidate_hash (from /rebaseline/discover)."
            ),
        )

    result = db.promote_rebaseline_candidate(
        server_id,
        request.expected_current_hash,
        request.expected_candidate_hash,
        actor=identity,
    )
    if not result.get("ok"):
        raise HTTPException(
            status_code=409,
            detail={
                "error": result.get("error"),
                "message": (
                    "Rebaseline state changed since review: re-read the "
                    "current hashes and re-review before approving."
                ),
                "active_surface_hash": result.get("active_surface_hash"),
                "candidate_surface_hash": result.get("candidate_surface_hash"),
            },
        )
    return result


_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._~-]{32,128}$")

# A boundary review performs an outbound observation and appends evidence, so
# it is neither safe nor cacheable. `_NO_STORE_HEADERS` is the same dict the
# ASGI middleware applies; setting it here too keeps the route's own responses
# correct even if the middleware is ever detached, and the middleware
# de-duplicates rather than appending a second copy.


def _principal_binding(key_info: dict) -> Optional[str]:
    """Stable identity an idempotency key is bound to. Mirrors the Streamable
    HTTP transport's binding so a key cannot be replayed across identities."""
    key_id = key_info.get("id")
    key_hash = key_info.get("key_hash")
    if key_id is None or not isinstance(key_hash, str) or not key_hash:
        return None
    return f"{key_id}:{key_hash}"


def _idempotency_key(request: Request) -> tuple[Optional[str], bool]:
    """Resolve at most one well-formed Idempotency-Key. Returns
    ``(raw_key_or_None, malformed)``; duplicates fail closed."""
    values = request.headers.getlist("idempotency-key")
    if not values:
        return None, False
    if len(values) != 1 or not _IDEMPOTENCY_KEY_RE.fullmatch(values[0].strip()):
        return None, True
    return values[0].strip(), False


@router.post("/mcp/servers/{server_id}/boundary-review")
async def mcp_boundary_review(server_id: str, request: Request):
    """Read-only approved-vs-observed boundary review for one registered server.

    POST, not GET: the review performs an outbound observation and appends a
    hash-chained audit row, so it is neither safe nor idempotent at the HTTP
    level and must not be cached, prefetched, or silently retried by an
    intermediary.

    This is the endpoint the optional self-hosted CI boundary-review gate
    calls (`scripts/interlock_ci_gate.py`). It requires the narrow
    `mcp.review` scope and deliberately IGNORES any request body: the target
    URL, the approved baseline, the enforced review queue, and the recorded
    reviewer identity all come from server-side state. It never rebaselines,
    approves, quarantines, or changes policy.

    A caller may send `Idempotency-Key`. The raw key is never stored — only a
    digest, bound to the verified principal and this server id. A repeat with
    the same binding replays the original sanitized result without appending
    another audit row or snapshot set; a repeat under another identity or
    server fails closed with 409.

    Authentication is resolved from the raw header lists so duplicated or
    conflicting credentials fail closed rather than silently binding to
    whichever header arrived first.
    """
    credential = single_api_credential(request)
    if credential is None:
        raise HTTPException(
            status_code=401,
            detail="Missing or ambiguous API key.",
            headers=_NO_STORE_HEADERS,
        )
    key_info, raw_key = proxy.require_scope(credential, "mcp.review")
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    # Authenticated first, then bounded: the body is drained and discarded, so
    # it can never influence the server, baseline, reviewer, decision, or
    # evidence. Rejecting here happens before any review, audit, snapshot, or
    # idempotency write.
    body_error = await discard_bounded_body(
        request, ci_boundary_review_max_request_bytes()
    )
    if body_error is not None:
        raise HTTPException(
            status_code=413 if body_error == TOO_LARGE else 400,
            detail={
                "error": (
                    "request_body_too_large"
                    if body_error == TOO_LARGE
                    else "malformed_request_body"
                ),
                "message": (
                    "This endpoint ignores the request body; it is bounded by "
                    "INTERLOCK_CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES."
                ),
            },
            headers=_NO_STORE_HEADERS,
        )

    raw_idempotency, malformed = _idempotency_key(request)
    if malformed:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_idempotency_key",
                "message": (
                    "Idempotency-Key must be a single 32-128 character token "
                    "of [A-Za-z0-9._~-]."
                ),
            },
            headers=_NO_STORE_HEADERS,
        )

    binding = _principal_binding(key_info)
    if raw_idempotency and binding is None:
        raise HTTPException(
            status_code=401,
            detail="Credential cannot be bound to an idempotency key.",
            headers=_NO_STORE_HEADERS,
        )

    key_digest = ""
    if raw_idempotency and binding:
        key_digest = db.hash_idempotency_key(raw_idempotency)
        reservation = db.reserve_ci_review_idempotency(
            key_digest,
            binding,
            server_id,
            boundary_review_idempotency_ttl_seconds(),
        )
        outcome = reservation.get("outcome")
        if outcome == "replay":
            return JSONResponse(
                content=reservation["response"],
                headers={**_NO_STORE_HEADERS, "Idempotent-Replay": "true"},
            )
        if outcome == "conflict":
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "idempotency_key_conflict",
                    "message": (
                        "This Idempotency-Key is already bound to a different "
                        "principal or server."
                    ),
                },
                headers=_NO_STORE_HEADERS,
            )
        if outcome == "in_progress":
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "review_in_progress",
                    "message": "A review for this Idempotency-Key is already running.",
                },
                headers=_NO_STORE_HEADERS,
            )

    try:
        result = await run_boundary_review(
            server_id, principal=_derived_identity(key_info)
        )
    except BaseException:
        if key_digest:
            db.release_ci_review_idempotency(key_digest)
        raise

    if not result.get("ok"):
        if key_digest:
            db.release_ci_review_idempotency(key_digest)
        raise HTTPException(
            status_code=404,
            detail="MCP server not found.",
            headers=_NO_STORE_HEADERS,
        )

    if key_digest:
        receipt = (result.get("evidence") or {}).get("receipt") or {}
        audit_id = receipt.get("audit_id")
        receipt_valid = (
            isinstance(audit_id, int)
            and not isinstance(audit_id, bool)
            and audit_id > 0
            and receipt.get("hash_chained") is True
            and receipt.get("chain_verified") is True
            and receipt.get("tamper_evident") is True
            and receipt.get("receipt_verification_state") == "verified"
        )
        if not receipt_valid:
            db.release_ci_review_idempotency(key_digest)
        else:
            try:
                completed = db.complete_ci_review_idempotency(
                    key_digest,
                    result,
                    audit_id,
                    boundary_review_idempotency_ttl_seconds(),
                )
                if not completed:
                    db.release_ci_review_idempotency(key_digest)
            except Exception:
                proxy.logger.exception("Failed to persist boundary-review idempotency")
                db.release_ci_review_idempotency(key_digest)

    return JSONResponse(content=result, headers=_NO_STORE_HEADERS)


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


@control_plane_router.post(
    "/mcp/tools/{server_id}/{tool_name}/approve",
    response_model=MCPToolApprovalResponse,
)
async def mcp_approve_tool_baseline(
    server_id: str,
    tool_name: str,
    request: MCPToolApprovalRequest,
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
        expected_surface_hash=request.expected_surface_hash,
        reviewer=identity["reviewer"],
        reason=request.reason or "",
        principal_id=identity["principal_id"],
    )
    if result.get("error") == "stale_tool_surface":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "stale_tool_surface",
                "current_surface_hash": result.get("current_surface_hash") or "",
            },
        )
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="MCP tool metadata not found.")
    return {
        "ok": True,
        "approval": {
            key: result[key]
            for key in (
                "server_id",
                "tool_name",
                "status",
                "approved_surface_hash",
                "approval_audit_id",
                "approved_at",
            )
        },
    }


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
async def mcp_validate(request: Request, x_api_key: Optional[str] = Header(None)):
    """Validate a single MCP tool definition for security issues."""
    proxy.require_scope(x_api_key, "mcp.discover")
    body, body_error = await read_bounded_body(request, MAX_MCP_VALIDATE_BODY_BYTES)
    if body_error == TOO_LARGE:
        raise HTTPException(status_code=413, detail={"error": "request_body_too_large"})
    if body_error == MALFORMED or body is None:
        raise HTTPException(status_code=400, detail={"error": "malformed_request_body"})
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail={"error": "malformed_json"})
    try:
        parsed = MCPToolValidateRequest.model_validate(payload)
    except ValidationError:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_tool_definition_request"}
        )
    start = time.time()
    result = validate_mcp_tool_definition(parsed.tool_definition)
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
