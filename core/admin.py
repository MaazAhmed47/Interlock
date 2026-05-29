"""
Admin endpoints for API key, retention, and security operations.

ADMIN_TOKEN remains the bootstrap root credential. Production operators can issue
scoped, revocable admin tokens for day-to-day work so teams do not share root.
"""

import json as _json
import os
import logging
import secrets as _secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set

import jwt

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from core import db

logger = logging.getLogger("interlock.admin")
router = APIRouter(prefix="/admin", tags=["admin"])

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
OIDC_ADMIN_ENABLED = os.getenv("OIDC_ADMIN_ENABLED", "false").lower() == "true"
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "").strip()
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", "").strip()
OIDC_JWKS_URL = os.getenv("OIDC_JWKS_URL", "").strip()
OIDC_GROUPS_CLAIM = os.getenv("OIDC_GROUPS_CLAIM", "groups").strip() or "groups"
OIDC_ROLE_CLAIM = os.getenv("OIDC_ROLE_CLAIM", "role").strip() or "role"
OIDC_EMAIL_CLAIM = os.getenv("OIDC_EMAIL_CLAIM", "email").strip() or "email"
OIDC_ADMIN_EMAIL_ALLOWLIST = os.getenv("OIDC_ADMIN_EMAIL_ALLOWLIST", "").strip()
OIDC_ADMIN_DOMAIN_ALLOWLIST = os.getenv("OIDC_ADMIN_DOMAIN_ALLOWLIST", "").strip()
OIDC_DEFAULT_ROLE = os.getenv("OIDC_DEFAULT_ROLE", "").strip()
OIDC_ALLOWED_ALGS = [
    alg.strip()
    for alg in os.getenv("OIDC_ALLOWED_ALGS", "RS256,RS384,RS512,ES256").split(",")
    if alg.strip()
]
OIDC_GROUP_ROLE_MAP_RAW = os.getenv("OIDC_GROUP_ROLE_MAP", "{}").strip() or "{}"
_OIDC_JWKS_CLIENT = None
_OIDC_JWKS_CLIENT_URL = ""
_OIDC_LAST_CONFIG_ERROR_AT = 0.0


@dataclass(frozen=True)
class AdminContext:
    auth_type: str
    role: str
    label: str
    permissions: Set[str]
    token_prefix: Optional[str] = None
    subject: Optional[str] = None
    email: Optional[str] = None


def _has_permission(context: AdminContext, permission: Optional[str]) -> bool:
    if not permission:
        return True
    permissions = context.permissions
    namespace = permission.split(":", 1)[0] + ":*"
    return "*" in permissions or permission in permissions or namespace in permissions


def _load_oidc_group_role_map() -> Dict[str, str]:
    try:
        loaded = _json.loads(OIDC_GROUP_ROLE_MAP_RAW)
    except (_json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {str(group): str(role) for group, role in loaded.items()}


def _oidc_configured() -> bool:
    return bool(
        OIDC_ADMIN_ENABLED
        and OIDC_ISSUER
        and OIDC_AUDIENCE
        and OIDC_JWKS_URL
        and OIDC_ALLOWED_ALGS
    )


def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _claim_values(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item]
    return [str(value)]


def _csv_values(value: str) -> Set[str]:
    return {
        item.strip().lower() for item in str(value or "").split(",") if item.strip()
    }


def _enforce_oidc_principal_allowlist(claims: Dict[str, Any]) -> None:
    email = str(claims.get(OIDC_EMAIL_CLAIM) or "").strip().lower()
    allowed_emails = _csv_values(OIDC_ADMIN_EMAIL_ALLOWLIST)
    allowed_domains = _csv_values(OIDC_ADMIN_DOMAIN_ALLOWLIST)
    if not allowed_emails and not allowed_domains:
        return

    domain = email.rsplit("@", 1)[1] if "@" in email else ""
    if email and email in allowed_emails:
        return
    if domain and domain in allowed_domains:
        return
    raise HTTPException(
        status_code=403, detail="OIDC user is not allowed to administer Interlock."
    )


def _get_oidc_signing_key(token: str):
    global _OIDC_JWKS_CLIENT, _OIDC_JWKS_CLIENT_URL
    if _OIDC_JWKS_CLIENT is None or _OIDC_JWKS_CLIENT_URL != OIDC_JWKS_URL:
        _OIDC_JWKS_CLIENT = jwt.PyJWKClient(OIDC_JWKS_URL)
        _OIDC_JWKS_CLIENT_URL = OIDC_JWKS_URL
    return _OIDC_JWKS_CLIENT.get_signing_key_from_jwt(token).key


def _role_from_oidc_claims(claims: Dict[str, Any]) -> str:
    role = claims.get(OIDC_ROLE_CLAIM)
    if isinstance(role, str) and role in db.ADMIN_ROLE_DEFAULTS:
        return role

    group_role_map = _load_oidc_group_role_map()
    for group in _claim_values(claims.get(OIDC_GROUPS_CLAIM)):
        mapped_role = group_role_map.get(group)
        if mapped_role in db.ADMIN_ROLE_DEFAULTS:
            return mapped_role

    if OIDC_DEFAULT_ROLE in db.ADMIN_ROLE_DEFAULTS:
        return OIDC_DEFAULT_ROLE

    raise HTTPException(
        status_code=403, detail="OIDC user is not mapped to an Interlock admin role."
    )


def _require_oidc_admin(authorization: Optional[str]) -> AdminContext:
    global _OIDC_LAST_CONFIG_ERROR_AT
    token = _extract_bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing OIDC bearer token.")
    if not _oidc_configured():
        now = time.time()
        if now - _OIDC_LAST_CONFIG_ERROR_AT > 60:
            logger.warning(
                "OIDC admin auth attempted but OIDC_ADMIN_ENABLED/OIDC_ISSUER/OIDC_AUDIENCE/OIDC_JWKS_URL are not fully configured"
            )
            _OIDC_LAST_CONFIG_ERROR_AT = now
        raise HTTPException(
            status_code=503, detail="OIDC admin auth is not configured."
        )

    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid OIDC token header.")

    alg = str(header.get("alg") or "")
    if alg not in OIDC_ALLOWED_ALGS or alg.lower() == "none":
        raise HTTPException(
            status_code=401, detail="OIDC token algorithm is not allowed."
        )

    try:
        signing_key = _get_oidc_signing_key(token)
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=OIDC_ALLOWED_ALGS,
            audience=OIDC_AUDIENCE,
            issuer=OIDC_ISSUER,
            options={"require": ["exp", "iss", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="OIDC token expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid OIDC token.")
    except Exception:
        logger.exception("OIDC token verification failed")
        raise HTTPException(status_code=401, detail="OIDC token verification failed.")

    _enforce_oidc_principal_allowlist(claims)
    role = _role_from_oidc_claims(claims)
    permissions = set(db.ADMIN_ROLE_DEFAULTS.get(role, []))
    subject = str(claims.get("sub") or "")
    email = str(claims.get(OIDC_EMAIL_CLAIM) or "")
    label = email or subject
    return AdminContext(
        auth_type="oidc",
        role=role,
        label=label,
        permissions=permissions,
        subject=subject,
        email=email or None,
    )


def _require_admin(
    token: Optional[str],
    permission: Optional[str] = None,
    authorization: Optional[str] = None,
) -> AdminContext:
    if not isinstance(token, str):
        token = None
    if not isinstance(authorization, str):
        authorization = None

    if token and ADMIN_TOKEN and _secrets.compare_digest(token, ADMIN_TOKEN):
        context = AdminContext(
            auth_type="bootstrap",
            role="owner",
            label="bootstrap",
            permissions={"*"},
        )
    elif token:
        record = db.lookup_admin_token(token)
        if not record:
            raise HTTPException(status_code=401, detail="Invalid admin token.")
        context = AdminContext(
            auth_type="scoped_token",
            role=record.get("role") or "operator",
            label=record.get("label") or "",
            permissions=set(record.get("permissions") or []),
            token_prefix=record.get("token_prefix"),
        )
    elif authorization:
        context = _require_oidc_admin(authorization)
    else:
        if not ADMIN_TOKEN and not _oidc_configured():
            raise HTTPException(
                status_code=503,
                detail="Admin auth is not configured. Set ADMIN_TOKEN, issue a scoped admin token, or configure OIDC admin auth.",
            )
        raise HTTPException(status_code=401, detail="Invalid admin token.")

    if not _has_permission(context, permission):
        raise HTTPException(
            status_code=403,
            detail=f"Admin token lacks required permission: {permission}",
        )
    return context


def _admin_actor_event_fields(context: AdminContext) -> Dict[str, Any]:
    return {
        "actor_auth_type": context.auth_type,
        "actor_role": context.role,
        "actor_label": context.label,
        "actor_email": context.email or "",
        "actor_subject": context.subject or "",
        "actor_token_prefix": context.token_prefix or "",
    }


def _audit_admin_action(
    context: AdminContext,
    action: str,
    target_type: str = "",
    target_id: str = "",
    result: str = "success",
    reason: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        event = _admin_actor_event_fields(context)
        event.update(
            {
                "action": action,
                "target_type": target_type,
                "target_id": str(target_id or ""),
                "result": result,
                "reason": reason,
                "details": details or {},
            }
        )
        db.log_admin_audit_event(event)
    except Exception:
        logger.exception("Failed to write admin audit event: %s", action)


# ── Request models ───────────────────────────────────────────────────────────
class CreateKeyRequest(BaseModel):
    plan: str = Field("free", description="free | developer | startup | enterprise")
    label: str = Field("", description="Human-readable label, e.g. customer name")
    webhook_url: Optional[str] = None
    fail_mode: Optional[str] = Field(
        None, description="fail_closed | fail_open | fail_open_safe"
    )
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


class RetentionPolicyRequest(BaseModel):
    scan_history_days: Optional[int] = Field(None, ge=1, le=3650)
    mcp_audit_days: Optional[int] = Field(None, ge=1, le=3650)
    admin_audit_days: Optional[int] = Field(None, ge=1, le=3650)
    usage_log_days: Optional[int] = Field(None, ge=1, le=3650)


class CreateAdminTokenRequest(BaseModel):
    label: str = Field(..., min_length=1, description="Human-readable owner/purpose")
    role: str = Field(
        "operator", description="owner | operator | security_reviewer | auditor"
    )
    permissions: Optional[List[str]] = Field(
        None, description="Optional explicit permission list"
    )


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/tokens")
def create_admin_token(
    req: CreateAdminTokenRequest,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(
        x_admin_token, "admin_tokens:write", authorization=authorization
    )
    try:
        result = db.generate_admin_token(
            label=req.label, role=req.role, permissions=req.permissions
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit_admin_action(
        context,
        "admin_token.created",
        "admin_token",
        result["token_prefix"],
        details={
            "label": req.label,
            "role": req.role,
            "permissions": result.get("permissions", []),
        },
    )
    return result


@router.get("/tokens")
def list_admin_tokens(
    include_inactive: bool = False,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _require_admin(x_admin_token, "admin_tokens:read", authorization=authorization)
    return {"tokens": db.list_admin_tokens(include_inactive=include_inactive)}


@router.get("/audit")
def list_admin_audit(
    limit: int = 100,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _require_admin(x_admin_token, "admin_audit:read", authorization=authorization)
    return {"events": db.list_admin_audit_logs(limit=limit)}


@router.delete("/tokens/{token_prefix}")
def revoke_admin_token(
    token_prefix: str,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(
        x_admin_token, "admin_tokens:write", authorization=authorization
    )
    ok = db.revoke_admin_token(token_prefix)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=f"Active admin token with prefix '{token_prefix}' not found.",
        )
    _audit_admin_action(context, "admin_token.revoked", "admin_token", token_prefix)
    return {"ok": True, "revoked": token_prefix}


@router.post("/keys")
def create_key(
    req: CreateKeyRequest,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    """Create a new API key. Returns the raw key ONCE — caller must store it."""
    context = _require_admin(x_admin_token, "keys:write", authorization=authorization)
    try:
        overrides = {
            k: v
            for k, v in req.model_dump().items()
            if k not in ("plan", "label") and v is not None
        }
        result = db.generate_key(plan=req.plan, label=req.label, **overrides)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit_admin_action(
        context,
        "api_key.created",
        "api_key",
        result["key_prefix"],
        details={
            "label": req.label,
            "plan": req.plan,
            "overrides": sorted(overrides.keys()),
        },
    )
    return result


@router.get("/keys")
def list_all_keys(
    include_inactive: bool = False,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _require_admin(x_admin_token, "keys:read", authorization=authorization)
    return {"keys": db.list_keys(include_inactive=include_inactive)}


@router.patch("/keys/{key_prefix}")
def update_existing_key(
    key_prefix: str,
    req: UpdateKeyRequest,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(x_admin_token, "keys:write", authorization=authorization)
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update.")
    ok = db.update_key(key_prefix, **fields)
    if not ok:
        raise HTTPException(
            status_code=404, detail=f"Key with prefix '{key_prefix}' not found."
        )
    _audit_admin_action(
        context,
        "api_key.updated",
        "api_key",
        key_prefix,
        details={"updated_fields": sorted(fields.keys())},
    )
    return {"ok": True, "updated_fields": list(fields.keys())}


@router.delete("/keys/{key_prefix}")
def revoke_existing_key(
    key_prefix: str,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(x_admin_token, "keys:write", authorization=authorization)
    ok = db.revoke_key(key_prefix)
    if not ok:
        raise HTTPException(
            status_code=404, detail=f"Active key with prefix '{key_prefix}' not found."
        )
    _audit_admin_action(context, "api_key.revoked", "api_key", key_prefix)
    return {"ok": True, "revoked": key_prefix}


@router.get("/keys/{key_prefix}/usage")
def get_usage(
    key_prefix: str,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _require_admin(x_admin_token, "keys:read", authorization=authorization)
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


# ── Retention policy endpoints ──────────────────────────────────────────────
@router.get("/retention")
def get_retention_policy(
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _require_admin(x_admin_token, "retention:read", authorization=authorization)
    return {"policy": db.get_retention_policy()}


@router.put("/retention")
def update_retention_policy(
    req: RetentionPolicyRequest,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(
        x_admin_token, "retention:write", authorization=authorization
    )
    payload = {k: v for k, v in req.model_dump().items() if v is not None}
    if not payload:
        raise HTTPException(status_code=400, detail="No retention fields to update.")
    policy = db.set_retention_policy(payload)
    _audit_admin_action(
        context,
        "retention.updated",
        "retention_policy",
        "default",
        details={"updated_fields": sorted(payload.keys()), "policy": policy},
    )
    return {"policy": policy}


@router.post("/retention/prune")
def prune_retention(
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(
        x_admin_token, "retention:write", authorization=authorization
    )
    result = db.prune_retention()
    _audit_admin_action(
        context,
        "retention.pruned",
        "retention_policy",
        "default",
        details={k: v for k, v in result.items() if k != "policy"},
    )
    return result


# ── MCP04: Provenance policy endpoints ───────────────────────────────────────
class ProvenancePolicyRequest(BaseModel):
    allowed_registries: List[str] = []
    allowed_source_urls: List[str] = []
    pinned_versions: Dict[str, str] = {}
    pinned_hashes: Dict[str, str] = {}


@router.get("/mcp/provenance-policy")
def get_provenance_policy(
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _require_admin(x_admin_token, "mcp:read", authorization=authorization)
    return db.load_mcp04_policy()


@router.put("/mcp/provenance-policy")
def set_provenance_policy(
    req: ProvenancePolicyRequest,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(x_admin_token, "mcp:write", authorization=authorization)
    payload = req.model_dump()
    with db.get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)",
            ("mcp04_policy", _json.dumps(payload)),
        )
    _audit_admin_action(
        context,
        "mcp.provenance_policy.updated",
        "system_config",
        "mcp04_policy",
        details={"fields": sorted(payload.keys())},
    )
    return {"ok": True}


@router.patch("/mcp/servers/{server_id}/provenance")
def override_provenance(
    server_id: str,
    status: str,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(x_admin_token, "mcp:write", authorization=authorization)
    if status not in ("allowed", "denied"):
        raise HTTPException(
            status_code=400, detail="status must be 'allowed' or 'denied'"
        )
    ok = db.update_mcp_server_provenance(server_id, status)
    if not ok:
        raise HTTPException(status_code=404, detail="Server not found")
    _audit_admin_action(
        context,
        "mcp.provenance_overridden",
        "mcp_server",
        server_id,
        details={"provenance_status": status},
    )
    return {"ok": True, "server_id": server_id, "provenance_status": status}


# ── MCP09: Shadow server management endpoints ─────────────────────────────────
class ShadowTargetRequest(BaseModel):
    url: str
    probe_path: str = "/tools/list"
    enabled: bool = True


@router.post("/shadow/targets")
def add_shadow_target(
    req: ShadowTargetRequest,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(x_admin_token, "shadow:write", authorization=authorization)
    now = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO shadow_scan_targets (url, probe_path, enabled, added_at) VALUES (?,?,?,?)",
                (req.url, req.probe_path, int(req.enabled), now),
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    _audit_admin_action(
        context,
        "shadow_target.added",
        "shadow_target",
        req.url,
        details={"probe_path": req.probe_path, "enabled": req.enabled},
    )
    return {"ok": True, "url": req.url}


@router.delete("/shadow/targets/{target_id}")
def delete_shadow_target(
    target_id: int,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(x_admin_token, "shadow:write", authorization=authorization)
    with db.get_conn() as conn:
        ok = conn.execute(
            "DELETE FROM shadow_scan_targets WHERE id=?", (target_id,)
        ).rowcount
    if not ok:
        raise HTTPException(status_code=404, detail="Target not found")
    _audit_admin_action(
        context, "shadow_target.deleted", "shadow_target", str(target_id)
    )
    return {"ok": True}


@router.get("/shadow/targets")
def list_shadow_targets(
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _require_admin(x_admin_token, "shadow:read", authorization=authorization)
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT id, url, probe_path, enabled, added_at FROM shadow_scan_targets"
        ).fetchall()
    return {
        "targets": [
            {
                "id": db.row_value(r, "id", 0),
                "url": db.row_value(r, "url", 1),
                "probe_path": db.row_value(r, "probe_path", 2),
                "enabled": bool(db.row_value(r, "enabled", 3)),
                "added_at": db.row_value(r, "added_at", 4),
            }
            for r in rows
        ]
    }


@router.get("/shadow/servers")
def list_shadow_servers(
    status: Optional[str] = None,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    _require_admin(x_admin_token, "shadow:read", authorization=authorization)
    with db.get_conn() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM shadow_mcp_servers WHERE status=?", (status,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM shadow_mcp_servers").fetchall()
        cols = db.table_columns("shadow_mcp_servers", conn=conn)
    return {"servers": [db.row_to_plain_dict(r, cols) for r in rows]}


class ShadowServerReviewRequest(BaseModel):
    status: str
    notes: Optional[str] = ""


@router.patch("/shadow/servers/{server_id}")
def review_shadow_server(
    server_id: int,
    req: ShadowServerReviewRequest,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    context = _require_admin(x_admin_token, "shadow:write", authorization=authorization)
    if req.status not in ("approved", "ignored", "quarantined"):
        raise HTTPException(
            status_code=400, detail="status must be approved, ignored, or quarantined"
        )
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
                (
                    now,
                    server_id,
                    "",
                    context.role,
                    "shadow_reviewed",
                    "operator_action",
                    req.notes or req.status,
                    1.0,
                    context.label,
                ),
            )
        except Exception:
            logger.exception("Failed to write shadow_reviewed audit log")
    _audit_admin_action(
        context,
        "shadow_server.reviewed",
        "shadow_server",
        str(server_id),
        reason=req.notes or req.status,
        details={"status": req.status},
    )
    return {"ok": True, "id": server_id, "status": req.status}
