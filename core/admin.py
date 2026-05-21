"""
Admin endpoints for API key management.

Protected by an ADMIN_TOKEN env var (single shared secret for now — fine for
single-tenant ops; replace with proper admin SSO when you have a team).
"""

import json as _json
import os
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from core import db

logger = logging.getLogger("interlock.admin")
router = APIRouter(prefix="/admin", tags=["admin"])

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")


def _require_admin(token: Optional[str]) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="ADMIN_TOKEN not configured on the server. Set it in .env to enable admin endpoints.",
        )
    if not token or token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token.")


# ── Request models ───────────────────────────────────────────────────────────
class CreateKeyRequest(BaseModel):
    plan: str = Field("free", description="free | developer | startup | enterprise")
    label: str = Field("", description="Human-readable label, e.g. customer name")
    webhook_url: Optional[str] = None
    fail_mode: Optional[str] = Field(None, description="fail_closed | fail_open | fail_open_safe")
    monthly_limit: Optional[int] = None
    rate_per_min: Optional[int] = None
    custom_policy: Optional[Dict[str, Any]] = None
    siem_configs: Optional[List[Dict[str, Any]]] = None


class UpdateKeyRequest(BaseModel):
    label: Optional[str] = None
    plan: Optional[str] = None
    monthly_limit: Optional[int] = None
    rate_per_min: Optional[int] = None
    fail_mode: Optional[str] = None
    webhook_url: Optional[str] = None
    custom_policy: Optional[Dict[str, Any]] = None
    siem_configs: Optional[List[Dict[str, Any]]] = None
    max_response_bytes: Optional[int] = None
    max_array_items: Optional[int] = None


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/keys")
def create_key(req: CreateKeyRequest, x_admin_token: Optional[str] = Header(None)):
    """Create a new API key. Returns the raw key ONCE — caller must store it."""
    _require_admin(x_admin_token)
    try:
        overrides = {k: v for k, v in req.model_dump().items() if k not in ("plan", "label") and v is not None}
        result = db.generate_key(plan=req.plan, label=req.label, **overrides)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@router.get("/keys")
def list_all_keys(
    include_inactive: bool = False,
    x_admin_token: Optional[str] = Header(None),
):
    _require_admin(x_admin_token)
    return {"keys": db.list_keys(include_inactive=include_inactive)}


@router.patch("/keys/{key_prefix}")
def update_existing_key(
    key_prefix: str,
    req: UpdateKeyRequest,
    x_admin_token: Optional[str] = Header(None),
):
    _require_admin(x_admin_token)
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update.")
    ok = db.update_key(key_prefix, **fields)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Key with prefix '{key_prefix}' not found.")
    return {"ok": True, "updated_fields": list(fields.keys())}


@router.delete("/keys/{key_prefix}")
def revoke_existing_key(key_prefix: str, x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    ok = db.revoke_key(key_prefix)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Active key with prefix '{key_prefix}' not found.")
    return {"ok": True, "revoked": key_prefix}


@router.get("/keys/{key_prefix}/usage")
def get_usage(key_prefix: str, x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    keys = db.list_keys(include_inactive=True)
    target = next((k for k in keys if k["key_prefix"] == key_prefix), None)
    if not target:
        raise HTTPException(status_code=404, detail="Key not found.")
    used = db.usage_this_month(target["id"])
    limit = target["monthly_limit"]
    return {
        "key_prefix": key_prefix,
        "plan": target["plan"],
        "used_this_month": used,
        "monthly_limit": limit,
        "remaining": max(0, limit - used) if limit > 0 else "unlimited",
    }


# ── MCP04: Provenance policy endpoints ───────────────────────────────────────
class ProvenancePolicyRequest(BaseModel):
    allowed_registries: List[str] = []
    allowed_source_urls: List[str] = []
    pinned_versions: Dict[str, str] = {}
    pinned_hashes: Dict[str, str] = {}


@router.get("/mcp/provenance-policy")
def get_provenance_policy(x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    return db.load_mcp04_policy()


@router.put("/mcp/provenance-policy")
def set_provenance_policy(req: ProvenancePolicyRequest,
                          x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    with db.get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)",
            ("mcp04_policy", _json.dumps(req.model_dump())),
        )
    return {"ok": True}


@router.patch("/mcp/servers/{server_id}/provenance")
def override_provenance(server_id: str, status: str,
                        x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    if status not in ("allowed", "denied"):
        raise HTTPException(status_code=400, detail="status must be 'allowed' or 'denied'")
    ok = db.update_mcp_server_provenance(server_id, status)
    if not ok:
        raise HTTPException(status_code=404, detail="Server not found")
    return {"ok": True, "server_id": server_id, "provenance_status": status}


# ── MCP09: Shadow server management endpoints ─────────────────────────────────
class ShadowTargetRequest(BaseModel):
    url: str
    probe_path: str = "/tools/list"
    enabled: bool = True


@router.post("/shadow/targets")
def add_shadow_target(req: ShadowTargetRequest,
                      x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    now = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO shadow_scan_targets (url, probe_path, enabled, added_at) VALUES (?,?,?,?)",
                (req.url, req.probe_path, int(req.enabled), now),
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "url": req.url}


@router.delete("/shadow/targets/{target_id}")
def delete_shadow_target(target_id: int,
                         x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    with db.get_conn() as conn:
        ok = conn.execute(
            "DELETE FROM shadow_scan_targets WHERE id=?", (target_id,)
        ).rowcount
    if not ok:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"ok": True}


@router.get("/shadow/targets")
def list_shadow_targets(x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT id, url, probe_path, enabled, added_at FROM shadow_scan_targets"
        ).fetchall()
    return {"targets": [{"id": r[0], "url": r[1], "probe_path": r[2],
                         "enabled": bool(r[3]), "added_at": r[4]} for r in rows]}


@router.get("/shadow/servers")
def list_shadow_servers(status: Optional[str] = None,
                        x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    with db.get_conn() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM shadow_mcp_servers WHERE status=?", (status,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM shadow_mcp_servers").fetchall()
        cols = [d[0] for d in conn.execute(
            "PRAGMA table_info(shadow_mcp_servers)"
        ).fetchall()]
    return {"servers": [dict(zip(cols, r)) for r in rows]}


class ShadowServerReviewRequest(BaseModel):
    status: str
    notes: Optional[str] = ""


@router.patch("/shadow/servers/{server_id}")
def review_shadow_server(server_id: int, req: ShadowServerReviewRequest,
                         x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    if req.status not in ("approved", "ignored", "quarantined"):
        raise HTTPException(status_code=400,
                            detail="status must be approved, ignored, or quarantined")
    now = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        ok = conn.execute(
            "UPDATE shadow_mcp_servers SET status=?, notes=? WHERE id=?",
            (req.status, req.notes or "", server_id),
        ).rowcount
        if not ok:
            raise HTTPException(status_code=404, detail="Shadow server not found")
        try:
            conn.execute(
                "INSERT INTO mcp_audit_log "
                "(ts, server_id, tool_name, role, action, matched_rule, reason, confidence, blocked_by) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (now, server_id, "", "operator", "shadow_reviewed",
                 "operator_action", req.notes or req.status, 1.0, None),
            )
        except Exception:
            logger.exception("Failed to write shadow_reviewed audit log")
    return {"ok": True, "id": server_id, "status": req.status}
