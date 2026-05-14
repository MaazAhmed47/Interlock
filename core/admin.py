"""
Admin endpoints for API key management.

Protected by an ADMIN_TOKEN env var (single shared secret for now — fine for
single-tenant ops; replace with proper admin SSO when you have a team).
"""

import os
import logging
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
