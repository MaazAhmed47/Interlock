"""Manual effective-permission probes for MCP tools.

These probes detect opaque authorization drift by comparing a configured
expected outcome with a live, operator-triggered observation. They are not OAuth
introspection and they do not run automatically.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from core import db
from core import drift_evidence
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url

EXPECTED_OUTCOMES = {"denied", "allowed"}
OBSERVED_OUTCOMES = {
    "allowed",
    "accepted",
    "denied",
    "unknown",
    "inconclusive",
    "inconclusive_rate_limited",
    "inconclusive_upstream_error",
    "inconclusive_probe_error",
}
ALLOWED_OBSERVED_OUTCOMES = {"allowed", "accepted"}
DENIED_OBSERVED_OUTCOMES = {"denied"}
DENIAL_STATUS_CODES = {401, 403}
ACCEPTED_STATUS_CODES = {201, 202, 204}
DENIAL_MESSAGE_TOKENS = (
    "access denied",
    "forbidden",
    "insufficient scope",
    "insufficient_scope",
    "missing scope",
    "not authorized",
    "permission denied",
    "scope",
    "unauthorized",
)
AUTH_REDIRECT_TOKENS = ("login", "signin", "sign-in", "oauth", "authorize", "auth")


def arguments_hash(arguments: Dict[str, Any]) -> str:
    """Hash probe arguments without storing their raw values."""
    return drift_evidence.arguments_hash(arguments)


def normalize_observed_result(
    *,
    status_code: Optional[int] = None,
    json_body: Optional[Dict[str, Any]] = None,
    error_class: str = "",
    headers: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Normalize an upstream probe observation into an outcome bucket."""
    if error_class:
        outcome = _outcome_for_error_class(error_class)
        return {
            "outcome": outcome,
            "status_code": status_code,
            "error_class": str(error_class),
        }

    status = _coerce_status(status_code)
    body_is_malformed = json_body is None and status not in ACCEPTED_STATUS_CODES
    body = json_body if isinstance(json_body, dict) else {}
    error = body.get("error")

    if status in DENIAL_STATUS_CODES or _jsonrpc_error_is_denial(error):
        error_class = "auth_required" if status == 401 else ""
        return {
            "outcome": "denied",
            "status_code": status,
            "error_class": error_class,
        }

    if status is not None and 300 <= status < 400:
        if _is_auth_redirect(headers):
            return {
                "outcome": "denied",
                "status_code": status,
                "error_class": "auth_required",
            }
        return {"outcome": "unknown", "status_code": status, "error_class": "redirect"}

    if status == 429:
        return {
            "outcome": "inconclusive_rate_limited",
            "status_code": status,
            "error_class": "rate_limited",
        }

    if status is not None and status >= 500:
        return {
            "outcome": "inconclusive_upstream_error",
            "status_code": status,
            "error_class": f"http_{status}",
        }

    if status in ACCEPTED_STATUS_CODES and not error:
        return {"outcome": "accepted", "status_code": status, "error_class": ""}

    if status == 200 and "result" in body and not error:
        return {"outcome": "allowed", "status_code": status, "error_class": ""}

    if body_is_malformed and status is not None and 200 <= status < 300:
        return {
            "outcome": "inconclusive_probe_error",
            "status_code": status,
            "error_class": "malformed_response",
        }

    if status == 404:
        return {"outcome": "unknown", "status_code": status, "error_class": "not_found"}

    if status == 409:
        return {"outcome": "unknown", "status_code": status, "error_class": "conflict"}

    if status is not None and 400 <= status < 500:
        return {
            "outcome": "unknown",
            "status_code": status,
            "error_class": f"http_{status}",
        }

    if error:
        return {
            "outcome": "unknown",
            "status_code": status,
            "error_class": "jsonrpc_error",
        }

    return {"outcome": "unknown", "status_code": status, "error_class": ""}


def evaluate_effective_permission_probe(
    probe: Dict[str, Any], observed: Dict[str, Any]
) -> Dict[str, Any]:
    """Compare expected vs observed behavior without overclaiming inconclusive runs."""
    expected = str(probe.get("expected_outcome") or "").strip().lower()
    observed_outcome = str(observed.get("outcome") or "unknown").strip().lower()
    if expected not in EXPECTED_OUTCOMES:
        raise ValueError("expected_outcome must be denied or allowed")
    if observed_outcome not in OBSERVED_OUTCOMES:
        observed_outcome = "unknown"

    base: Dict[str, Any] = {
        "probe_id": str(probe.get("probe_id") or ""),
        "server_id": str(probe.get("server_id") or ""),
        "tool_name": str(probe.get("tool_name") or ""),
        "argument_hash": str(probe.get("argument_hash") or ""),
        "expected_outcome": expected,
        "observed_outcome": observed_outcome,
        "observed_status_code": observed.get("status_code"),
        "observed_error_class": str(observed.get("error_class") or ""),
        "drift_detected": False,
        "finding_type": "",
        "finding_types": [],
        "severity": "none",
        "decision": "allow",
        "reason": "Effective-permission probe matched the expected outcome.",
    }

    if observed_outcome == "unknown" or observed_outcome.startswith("inconclusive"):
        base.update(
            {
                "decision": "monitor",
                "reason": (
                    "Effective-permission probe was inconclusive; observed "
                    f"outcome={observed_outcome}."
                ),
            }
        )
        return base

    if expected == observed_outcome:
        return base
    if expected == "allowed" and observed_outcome == "accepted":
        return base

    if expected == "denied" and observed_outcome in ALLOWED_OBSERVED_OUTCOMES:
        base.update(
            {
                "drift_detected": True,
                "finding_type": "effective_permission_expansion",
                "finding_types": [
                    "effective_permission_expansion",
                    "behavioral_scope_drift",
                ],
                "severity": "high",
                "decision": "quarantine",
                "reason": (
                    "Expected the manual effective-permission probe to be denied, "
                    "but the upstream server allowed it. This indicates "
                    "behavioral scope drift."
                ),
            }
        )
        return base

    if expected == "allowed" and observed_outcome in DENIED_OBSERVED_OUTCOMES:
        base.update(
            {
                "drift_detected": True,
                "finding_type": "permission_regression",
                "finding_types": ["permission_regression"],
                "severity": "moderate",
                "decision": "monitor",
                "reason": (
                    "Expected the manual effective-permission probe to be allowed, "
                    "but the upstream server denied it. This indicates a permission "
                    "regression, not auth-scope expansion."
                ),
            }
        )
        return base

    base.update(
        {
            "decision": "monitor",
            "reason": (
                "Effective-permission probe behavior changed from the expected "
                f"outcome={expected} to observed outcome={observed_outcome}."
            ),
        }
    )
    return base


async def run_effective_permission_probe(
    server_id: str,
    probe_input: Dict[str, Any],
) -> Dict[str, Any]:
    """Run one explicit non-production probe against a registered MCP server."""
    start = time.perf_counter()
    probe = _build_probe(server_id, probe_input)
    if not probe["non_production"]:
        return {
            "ok": False,
            "error": "non_production_required",
            "message": "Effective-permission probes require non_production=true.",
        }
    if not probe["safety_note"].strip():
        return {
            "ok": False,
            "error": "safety_note_required",
            "message": "Effective-permission probes require a safety_note.",
        }
    server = db.lookup_mcp_server(server_id)
    preflight_error = _preflight_probe_target(server, server_id, probe["tool_name"])
    if preflight_error:
        return preflight_error
    # _preflight_probe_target returns an error for a missing server, so reaching
    # this point guarantees a non-None server record — narrow it for the checker.
    assert server is not None

    stored_probe = db.upsert_mcp_permission_probe(probe)
    observed = await _call_upstream_for_observation(server, probe)
    evaluation = evaluate_effective_permission_probe(stored_probe, observed)

    quarantine_applied = False
    if evaluation["decision"] == "quarantine":
        marked = db.mark_mcp_tool_effective_permission_drift(
            server_id=server_id,
            tool_name=probe["tool_name"],
            reason=evaluation["reason"],
        )
        quarantine_applied = bool(marked.get("ok"))

    audit = _log_probe_audit_event(
        probe=stored_probe,
        evaluation=evaluation,
        scan_time_ms=round((time.perf_counter() - start) * 1000, 2),
    )
    audit_id = int(audit.get("id") or 0)
    if not audit_id:
        persisted_audit = db.lookup_latest_mcp_audit_log_by_probe_id(probe["probe_id"])
        if persisted_audit:
            audit_id = int(persisted_audit.get("id") or 0)
            audit = persisted_audit

    db.update_mcp_permission_probe_result(
        probe_id=probe["probe_id"],
        evaluation=evaluation,
        audit_id=audit_id,
    )

    return {
        "ok": True,
        "probe": _public_probe(stored_probe),
        "evaluation": evaluation,
        "evidence": {
            "audit_id": audit_id,
            "call_id": audit.get("call_id") or "",
            "argument_hash": stored_probe["argument_hash"],
        },
        "quarantine_applied": quarantine_applied,
    }


def _build_probe(server_id: str, probe_input: Dict[str, Any]) -> Dict[str, Any]:
    probe_id = str(probe_input.get("probe_id") or "").strip()
    if not probe_id:
        digest = arguments_hash(probe_input.get("arguments") or {})[-16:]
        probe_id = f"{server_id}:{probe_input.get('tool_name', '')}:{digest}"
    return {
        "probe_id": probe_id,
        "server_id": server_id,
        "tool_name": str(probe_input.get("tool_name") or "").strip(),
        "arguments": dict(probe_input.get("arguments") or {}),
        "argument_hash": arguments_hash(probe_input.get("arguments") or {}),
        "expected_outcome": str(probe_input.get("expected_outcome") or "").lower(),
        "expected_status_code": probe_input.get("expected_status_code"),
        "expected_error_fingerprint": str(
            probe_input.get("expected_error_fingerprint") or ""
        ),
        "non_production": bool(probe_input.get("non_production")),
        "safety_note": str(probe_input.get("safety_note") or ""),
    }


def _preflight_probe_target(
    server: Optional[Dict[str, Any]], server_id: str, tool_name: str
) -> Optional[Dict[str, Any]]:
    if not server:
        return {
            "ok": False,
            "error": "untrusted_mcp_server",
            "message": f"MCP server '{server_id}' is not in the trusted registry.",
        }
    if not server.get("verified"):
        return {
            "ok": False,
            "error": "unverified_mcp_server",
            "message": f"MCP server '{server_id}' is registered but not verified.",
        }
    if tool_name in (server.get("blocked_tools") or []):
        return {
            "ok": False,
            "error": "tool_blocked",
            "message": f"Tool '{tool_name}' is blocked for server '{server_id}'.",
        }
    allowed = server.get("allowed_tools", [])
    if allowed is not None and (not allowed or tool_name not in allowed):
        return {
            "ok": False,
            "error": "tool_not_allowed",
            "message": f"Tool '{tool_name}' is not allowed for server '{server_id}'.",
        }
    return None


async def _call_upstream_for_observation(
    server: Dict[str, Any],
    probe: Dict[str, Any],
) -> Dict[str, Any]:
    from core.mcp_gateway import (
        UpstreamAuthConfigError,
        _mcp_post_kwargs,
        _resolve_upstream_auth_headers,
    )

    try:
        server_url = ensure_safe_outbound_url(server["url"], context="MCP probe")
        headers = _resolve_upstream_auth_headers(server)
        payload = {
            "jsonrpc": "2.0",
            "id": int(datetime.now(timezone.utc).timestamp()),
            "method": "tools/call",
            "params": {
                "name": probe["tool_name"],
                "arguments": probe.get("arguments") or {},
            },
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(server_url, **_mcp_post_kwargs(payload, headers))
            body: Optional[Dict[str, Any]] = {}
            try:
                candidate = resp.json()
                if isinstance(candidate, dict):
                    body = candidate
            except Exception:
                body = None
            return normalize_observed_result(
                status_code=getattr(resp, "status_code", None),
                json_body=body,
                headers=getattr(resp, "headers", None),
            )
    except OutboundUrlRejected:
        return normalize_observed_result(error_class="unsafe_mcp_server_url")
    except UpstreamAuthConfigError:
        return normalize_observed_result(error_class="upstream_auth_unavailable")
    except httpx.TimeoutException:
        return normalize_observed_result(error_class="timeout")
    except httpx.TransportError:
        return normalize_observed_result(error_class="network_error")
    except Exception as exc:
        return normalize_observed_result(error_class=exc.__class__.__name__)


def _approved_surface_hash(server_id: str, tool_name: str) -> str:
    """
    Content address of the tool surface the probe ran against. Behavioral
    drift is same-schema by definition, so the probe's audit row records this
    hash as BOTH baseline and current surface — proof the schema did not
    change while the observed behavior did. Best-effort: never breaks probes.
    """
    try:
        stored = db.lookup_mcp_tool_metadata(server_id, tool_name) or {}
        raw_def = stored.get("raw_tool_definition") or {}
        if not raw_def:
            return ""
        surface_hash = drift_evidence.tool_surface_hash(raw_def)
        db.save_tool_surface_snapshot(
            surface_hash, drift_evidence.canonical_surface_json(raw_def)
        )
        return surface_hash
    except Exception:
        return ""


def _log_probe_audit_event(
    *,
    probe: Dict[str, Any],
    evaluation: Dict[str, Any],
    scan_time_ms: float,
) -> Dict[str, Any]:
    finding_types = evaluation.get("finding_types") or []
    drift_detected = bool(evaluation.get("drift_detected"))
    action = evaluation.get("decision") or "monitor"
    surface_hash = _approved_surface_hash(probe["server_id"], probe["tool_name"])
    event = {
        "server_id": probe["server_id"],
        "tool_name": probe["tool_name"],
        "role": "operator",
        "action": action,
        "matched_rule": "effective_permission_probe",
        "reason": evaluation.get("reason") or "",
        "effects": [],
        "side_effect": "unknown",
        "data_classes": [],
        "externality": "unknown",
        "verification_level": "manual_behavioral_probe",
        "confidence": 0.9 if drift_detected else 0.0,
        "warnings": _probe_warnings(probe, evaluation),
        "argument_keys": [],
        "blocked_by": "effective_permission_probe" if action == "quarantine" else "",
        "drift_status": "behavioral_scope_drift" if drift_detected else "",
        "drift_severity": evaluation.get("severity") or "none",
        "drift_action": action,
        "drift_types": finding_types,
        "drift_reasons": [evaluation["reason"]] if drift_detected else [],
        "probe_id": probe["probe_id"],
        "argument_hash": probe["argument_hash"],
        "expected_outcome": probe["expected_outcome"],
        "expected_status_code": probe.get("expected_status_code"),
        "observed_outcome": evaluation.get("observed_outcome") or "unknown",
        "observed_status_code": evaluation.get("observed_status_code"),
        "observed_error_class": evaluation.get("observed_error_class") or "",
        "drift_baseline_hash": surface_hash,
        "drift_current_hash": surface_hash,
        "scan_time_ms": scan_time_ms,
    }
    return db.log_mcp_audit_event(event)


def _public_probe(probe: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "probe_id": probe["probe_id"],
        "server_id": probe["server_id"],
        "tool_name": probe["tool_name"],
        "argument_hash": probe["argument_hash"],
        "expected_outcome": probe["expected_outcome"],
        "expected_status_code": probe.get("expected_status_code"),
        "expected_error_fingerprint": probe.get("expected_error_fingerprint") or "",
        "non_production": bool(probe.get("non_production")),
        "safety_note": probe.get("safety_note") or "",
        "created_at": probe.get("created_at") or "",
        "updated_at": probe.get("updated_at") or "",
    }


def _probe_warnings(probe: Dict[str, Any], evaluation: Dict[str, Any]) -> list[str]:
    warnings = [
        "manual_effective_permission_probe",
        "non_production_required",
        f"probe_id={probe['probe_id']}",
        f"argument_hash={probe['argument_hash']}",
        f"expected_outcome={probe['expected_outcome']}",
        f"observed_outcome={evaluation.get('observed_outcome') or 'unknown'}",
    ]
    status_code = evaluation.get("observed_status_code")
    if status_code is not None:
        warnings.append(f"observed_status_code={status_code}")
    error_class = evaluation.get("observed_error_class") or ""
    if error_class:
        warnings.append(f"observed_error_class={error_class}")
    return warnings


def _outcome_for_error_class(error_class: str) -> str:
    normalized = str(error_class or "").strip().lower()
    if normalized in {"timeout", "network_error"}:
        return "inconclusive"
    if normalized == "rate_limited":
        return "inconclusive_rate_limited"
    if normalized.startswith("http_5"):
        return "inconclusive_upstream_error"
    return "inconclusive_probe_error"


def _is_auth_redirect(headers: Optional[Dict[str, Any]]) -> bool:
    if not headers:
        return False
    try:
        location = headers.get("location") or headers.get("Location") or ""
    except AttributeError:
        return False
    location = str(location).lower()
    return any(token in location for token in AUTH_REDIRECT_TOKENS)


def _jsonrpc_error_is_denial(error: Any) -> bool:
    if not error:
        return False
    if isinstance(error, dict):
        for key in ("status", "status_code", "statusCode", "http_status"):
            status = _coerce_status(error.get(key))
            if status in DENIAL_STATUS_CODES:
                return True
        data = error.get("data")
        if isinstance(data, dict):
            for key in ("status", "status_code", "statusCode", "http_status"):
                status = _coerce_status(data.get(key))
                if status in DENIAL_STATUS_CODES:
                    return True
        message = json.dumps(error, sort_keys=True, default=str).lower()
    else:
        message = str(error).lower()
    return any(token in message for token in DENIAL_MESSAGE_TOKENS)


def _coerce_status(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
