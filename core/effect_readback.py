"""Provider readback / canary effect observation.

This module detects hidden side effects by comparing an external-system readback
before and after a manually-triggered, non-production canary call. It does not
introspect provider internals and it does not run automatically.

The readback state profile hashes raw provider state but stores only hashes,
shape, paths, and counts. Raw objects, response bodies, arguments, auth headers,
and provider tokens are not persisted.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

import httpx

from core import db
from core import drift_evidence
from core.effect_drift import build_effect_profile
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url

SCHEMA_ID = "interlock.readback-effect-drift-record"
SCHEMA_VERSION = "1"
SCHEMA_URL = "https://getinterlock.dev/schemas/readback-effect-drift-record.v1.json"
CANONICALIZATION = "json/jcs-rfc8785"
EVIDENCE_TYPE = "readback-effect-drift"
DIGEST_ALG = "sha256"

EXPECTED_EFFECTS = {"no_change", "change_allowed"}
SAFE_REPORTED_EFFECTS = {"no_effect", "read", "preview", "dry_run", "plan", "unknown"}


def _digest_value(value: Any) -> str:
    return f"{DIGEST_ALG}:{hashlib.sha256(drift_evidence.canonical_json_bytes(value)).hexdigest()}"


def arguments_hash(arguments: Dict[str, Any]) -> str:
    canonical = drift_evidence.canonical_json_bytes(arguments or {})
    return f"{DIGEST_ALG}:{hashlib.sha256(canonical).hexdigest()}"


def combined_argument_hash(
    target_arguments: Dict[str, Any], readback_arguments: Dict[str, Any]
) -> str:
    return arguments_hash(
        {
            "target_arguments": target_arguments or {},
            "readback_arguments": readback_arguments or {},
        }
    )


def _normalize_key(key: Any) -> str:
    return str(key or "").strip().replace("-", "_").replace(" ", "_").lower()


def _shape_only(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _shape_only(child)
            for key, child in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(value, list):
        return ["list", len(value), [_shape_only(item) for item in value[:20]]]
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    return "string"


def _walk_paths(value: Any) -> Dict[str, Any]:
    field_names: Set[str] = set()
    field_paths: Set[str] = set()
    object_count = 0
    array_count = 0
    scalar_count = 0

    def visit(item: Any, path: str = "") -> None:
        nonlocal object_count, array_count, scalar_count
        if isinstance(item, dict):
            object_count += 1
            for key, child in item.items():
                normalized = _normalize_key(key)
                child_path = f"{path}.{normalized}" if path else normalized
                field_names.add(normalized)
                field_paths.add(child_path)
                visit(child, child_path)
            return
        if isinstance(item, list):
            array_count += 1
            for child in item[:100]:
                visit(child, path)
            return
        scalar_count += 1

    visit(value)
    return {
        "field_names": sorted(field_names),
        "field_paths": sorted(field_paths),
        "object_count": object_count,
        "array_count": array_count,
        "scalar_count": scalar_count,
    }


def _material_state_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "profile_version": profile.get("profile_version"),
        "state_hash": profile.get("state_hash"),
        "shape_hash": profile.get("shape_hash"),
        "field_names": list(profile.get("field_names") or []),
        "field_paths": list(profile.get("field_paths") or []),
        "object_count": int(profile.get("object_count") or 0),
        "array_count": int(profile.get("array_count") or 0),
        "scalar_count": int(profile.get("scalar_count") or 0),
    }


def build_readback_state_profile(observation: Any) -> Dict[str, Any]:
    """Build an evidence-safe provider-state profile from readback output."""
    walked = _walk_paths(observation)
    profile = {
        "profile_version": "1",
        "state_hash": _digest_value(observation),
        "shape_hash": _digest_value(_shape_only(observation)),
        "field_names": walked["field_names"],
        "field_paths": walked["field_paths"],
        "object_count": walked["object_count"],
        "array_count": walked["array_count"],
        "scalar_count": walked["scalar_count"],
    }
    profile["profile_hash"] = readback_profile_hash(profile)
    return profile


def readback_profile_hash(profile: Dict[str, Any]) -> str:
    return _digest_value(_material_state_profile(profile or {}))


def _target_reports_only_safe_effects(target_response: Any) -> bool:
    profile = build_effect_profile(target_response)
    effects = set(profile.get("effect_classes") or [])
    return bool(effects) and effects.issubset(SAFE_REPORTED_EFFECTS)


def _ordered_unique(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        value = str(value)
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def classify_readback_effect_drift(
    *,
    before_profile: Optional[Dict[str, Any]],
    after_profile: Optional[Dict[str, Any]],
    target_response: Any,
    expected_effect: str,
) -> Dict[str, Any]:
    """Compare before/after provider readback profiles for hidden side effects."""
    expected = str(expected_effect or "").strip().lower()
    if expected not in EXPECTED_EFFECTS:
        raise ValueError("expected_effect must be no_change or change_allowed")

    before_hash = readback_profile_hash(before_profile or {}) if before_profile else ""
    after_hash = readback_profile_hash(after_profile or {}) if after_profile else ""
    target_hash = _digest_value(target_response if target_response is not None else {})
    base = {
        "drift_detected": False,
        "severity": "none",
        "action": "allow",
        "types": [],
        "reasons": [],
        "reason": "Provider readback matched the expected effect boundary.",
        "expected_effect": expected,
        "before_state_hash": before_hash,
        "after_state_hash": after_hash,
        "target_response_hash": target_hash,
    }

    if not before_profile or not after_profile:
        base.update(
            {
                "action": "monitor",
                "reason": "Provider readback was inconclusive; no drift conclusion was made.",
            }
        )
        return base

    changed = before_hash != after_hash
    if expected == "no_change" and changed:
        types = [
            "readback_state_changed_after_no_effect_expected",
            "silent_side_effect_drift",
        ]
        if _target_reports_only_safe_effects(target_response):
            types.append("effect_response_contradicted_by_readback")
        reason = (
            "Provider readback changed even though the canary expected no external state change. "
            "This indicates a hidden or silent side effect."
        )
        return {
            **base,
            "drift_detected": True,
            "severity": "critical",
            "action": "quarantine",
            "types": _ordered_unique(types),
            "reasons": [reason],
            "reason": reason,
        }

    if expected == "change_allowed" and not changed:
        reason = "The target call was expected to change provider state, but readback did not observe a change."
        return {
            **base,
            "drift_detected": True,
            "severity": "moderate",
            "action": "monitor",
            "types": ["expected_provider_change_missing"],
            "reasons": [reason],
            "reason": reason,
        }

    return base


async def run_effect_readback_observer(
    server_id: str, probe_input: Dict[str, Any]
) -> Dict[str, Any]:
    """Run one explicit non-production readback canary against a registered MCP server."""
    start = time.perf_counter()
    probe = _build_probe(server_id, probe_input)
    if not probe["non_production"]:
        return {
            "ok": False,
            "error": "non_production_required",
            "message": "Readback effect probes require non_production=true.",
        }
    if not probe["safety_note"].strip():
        return {
            "ok": False,
            "error": "safety_note_required",
            "message": "Readback effect probes require a safety_note.",
        }

    server = db.lookup_mcp_server(server_id)
    preflight = _preflight_tool(server, server_id, probe["readback_tool_name"])
    if preflight:
        return preflight
    preflight = _preflight_tool(server, server_id, probe["target_tool_name"])
    if preflight:
        return preflight
    assert server is not None

    before_call = await _call_upstream_tool(
        server, probe["readback_tool_name"], probe["readback_arguments"]
    )
    if not before_call.get("ok"):
        evaluation = _inconclusive_evaluation(
            probe, before_call, phase="before_readback"
        )
        audit = _log_readback_audit_event(
            probe=probe, evaluation=evaluation, scan_time_ms=_elapsed_ms(start)
        )
        return _public_result(probe, evaluation, audit, quarantine_applied=False)

    target_call = await _call_upstream_tool(
        server, probe["target_tool_name"], probe["target_arguments"]
    )
    if not target_call.get("ok"):
        evaluation = _inconclusive_evaluation(probe, target_call, phase="target_call")
        audit = _log_readback_audit_event(
            probe=probe, evaluation=evaluation, scan_time_ms=_elapsed_ms(start)
        )
        return _public_result(probe, evaluation, audit, quarantine_applied=False)

    after_call = await _call_upstream_tool(
        server, probe["readback_tool_name"], probe["readback_arguments"]
    )
    before_profile = build_readback_state_profile(before_call.get("result"))
    after_profile = (
        build_readback_state_profile(after_call.get("result"))
        if after_call.get("ok")
        else None
    )
    evaluation = classify_readback_effect_drift(
        before_profile=before_profile,
        after_profile=after_profile,
        target_response=target_call.get("result"),
        expected_effect=probe["expected_effect"],
    )
    if not after_call.get("ok"):
        evaluation.update(
            {
                "action": "monitor",
                "reason": "Provider readback after the target call was inconclusive; no drift conclusion was made.",
            }
        )

    quarantine_applied = False
    if evaluation["action"] == "quarantine":
        marked = db.mark_mcp_tool_effect_drift(
            server_id=server_id,
            tool_name=probe["target_tool_name"],
            finding_types=evaluation.get("types") or [],
            reason=evaluation.get("reason") or "Readback observed hidden side effect.",
        )
        quarantine_applied = bool(marked.get("ok"))

    audit = _log_readback_audit_event(
        probe=probe,
        evaluation=evaluation,
        scan_time_ms=_elapsed_ms(start),
    )
    return _public_result(
        probe, evaluation, audit, quarantine_applied=quarantine_applied
    )


def _build_probe(server_id: str, probe_input: Dict[str, Any]) -> Dict[str, Any]:
    target = dict(probe_input.get("target") or {})
    readback = dict(probe_input.get("readback") or {})
    target_args = dict(target.get("arguments") or {})
    readback_args = dict(readback.get("arguments") or {})
    probe_id = str(probe_input.get("probe_id") or "").strip()
    if not probe_id:
        digest = combined_argument_hash(target_args, readback_args)[-16:]
        probe_id = f"{server_id}:{target.get('tool_name', '')}:{digest}"
    return {
        "probe_id": probe_id,
        "server_id": server_id,
        "target_tool_name": str(target.get("tool_name") or "").strip(),
        "target_arguments": target_args,
        "target_argument_hash": arguments_hash(target_args),
        "readback_tool_name": str(readback.get("tool_name") or "").strip(),
        "readback_arguments": readback_args,
        "readback_argument_hash": arguments_hash(readback_args),
        "argument_hash": combined_argument_hash(target_args, readback_args),
        "expected_effect": str(probe_input.get("expected_effect") or "")
        .strip()
        .lower(),
        "non_production": bool(probe_input.get("non_production")),
        "safety_note": str(probe_input.get("safety_note") or ""),
    }


def _preflight_tool(
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


async def _call_upstream_tool(
    server: Dict[str, Any], tool_name: str, arguments: Dict[str, Any]
) -> Dict[str, Any]:
    from core.mcp_gateway import (
        UpstreamAuthConfigError,
        _mcp_post_kwargs,
        _resolve_upstream_auth_headers,
    )

    try:
        server_url = ensure_safe_outbound_url(
            server["url"], context="MCP readback probe"
        )
        headers = _resolve_upstream_auth_headers(server)
        payload = {
            "jsonrpc": "2.0",
            "id": int(datetime.now(timezone.utc).timestamp()),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments or {}},
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(server_url, **_mcp_post_kwargs(payload, headers))
            status = getattr(resp, "status_code", None)
            body: Optional[Dict[str, Any]] = None
            try:
                candidate = resp.json()
                if isinstance(candidate, dict):
                    body = candidate
            except Exception:
                body = None
            if status is not None and status >= 500:
                return {
                    "ok": False,
                    "status_code": status,
                    "error_class": f"http_{status}",
                }
            if status == 429:
                return {
                    "ok": False,
                    "status_code": status,
                    "error_class": "rate_limited",
                }
            if status is not None and status >= 400:
                return {
                    "ok": False,
                    "status_code": status,
                    "error_class": f"http_{status}",
                }
            if not isinstance(body, dict) or "result" not in body or body.get("error"):
                return {
                    "ok": False,
                    "status_code": status,
                    "error_class": "malformed_response",
                }
            return {
                "ok": True,
                "status_code": status,
                "result": body.get("result"),
                "error_class": "",
            }
    except OutboundUrlRejected:
        return {
            "ok": False,
            "status_code": None,
            "error_class": "unsafe_mcp_server_url",
        }
    except UpstreamAuthConfigError:
        return {
            "ok": False,
            "status_code": None,
            "error_class": "upstream_auth_unavailable",
        }
    except httpx.TimeoutException:
        return {"ok": False, "status_code": None, "error_class": "timeout"}
    except httpx.TransportError:
        return {"ok": False, "status_code": None, "error_class": "network_error"}
    except Exception as exc:
        return {"ok": False, "status_code": None, "error_class": exc.__class__.__name__}


def _inconclusive_evaluation(
    probe: Dict[str, Any], observed: Dict[str, Any], phase: str
) -> Dict[str, Any]:
    return {
        "drift_detected": False,
        "severity": "none",
        "action": "monitor",
        "types": [],
        "reasons": [],
        "reason": f"Provider readback probe was inconclusive at phase={phase}; no drift conclusion was made.",
        "expected_effect": probe["expected_effect"],
        "before_state_hash": "",
        "after_state_hash": "",
        "target_response_hash": "",
        "observed_status_code": observed.get("status_code"),
        "observed_error_class": observed.get("error_class") or "",
    }


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


def _log_readback_audit_event(
    *, probe: Dict[str, Any], evaluation: Dict[str, Any], scan_time_ms: float
) -> Dict[str, Any]:
    drift_detected = bool(evaluation.get("drift_detected"))
    action = evaluation.get("action") or "monitor"
    event = {
        "server_id": probe["server_id"],
        "tool_name": probe["target_tool_name"],
        "role": "operator",
        "action": action,
        "matched_rule": "effect_readback_observer",
        "reason": evaluation.get("reason") or "",
        "effects": [],
        "side_effect": "unknown",
        "data_classes": [],
        "externality": "unknown",
        "verification_level": "manual_provider_readback",
        "confidence": 0.95 if drift_detected else 0.0,
        "warnings": _probe_warnings(probe, evaluation),
        "argument_keys": [],
        "blocked_by": "effect_readback_observer" if action == "quarantine" else "",
        "probe_id": probe["probe_id"],
        "argument_hash": probe["argument_hash"],
        "expected_outcome": probe["expected_effect"],
        "observed_outcome": (
            "state_changed"
            if evaluation.get("before_state_hash") != evaluation.get("after_state_hash")
            and evaluation.get("after_state_hash")
            else "state_unchanged"
        ),
        "observed_status_code": evaluation.get("observed_status_code"),
        "observed_error_class": evaluation.get("observed_error_class") or "",
        "drift_status": "readback_effect_drift" if drift_detected else "",
        "drift_severity": evaluation.get("severity") or "none",
        "drift_action": action,
        "drift_types": evaluation.get("types") or [],
        "drift_reasons": evaluation.get("reasons") or [],
        "drift_baseline_hash": evaluation.get("before_state_hash") or "",
        "drift_current_hash": evaluation.get("after_state_hash") or "",
        "scan_time_ms": scan_time_ms,
    }
    return db.log_mcp_audit_event(event)


def _public_result(
    probe: Dict[str, Any],
    evaluation: Dict[str, Any],
    audit: Dict[str, Any],
    quarantine_applied: bool,
) -> Dict[str, Any]:
    audit_id = int(audit.get("id") or 0)
    if not audit_id:
        persisted = db.lookup_latest_mcp_audit_log_by_probe_id(probe["probe_id"])
        if persisted:
            audit_id = int(persisted.get("id") or 0)
    return {
        "ok": True,
        "probe": _public_probe(probe),
        "evaluation": evaluation,
        "evidence": {
            "audit_id": audit_id,
            "argument_hash": probe["argument_hash"],
            "target_argument_hash": probe["target_argument_hash"],
            "readback_argument_hash": probe["readback_argument_hash"],
            "before_state_hash": evaluation.get("before_state_hash") or "",
            "after_state_hash": evaluation.get("after_state_hash") or "",
            "target_response_hash": evaluation.get("target_response_hash") or "",
        },
        "quarantine_applied": quarantine_applied,
    }


def _public_probe(probe: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "probe_id": probe["probe_id"],
        "server_id": probe["server_id"],
        "target_tool_name": probe["target_tool_name"],
        "target_argument_hash": probe["target_argument_hash"],
        "readback_tool_name": probe["readback_tool_name"],
        "readback_argument_hash": probe["readback_argument_hash"],
        "expected_effect": probe["expected_effect"],
        "non_production": bool(probe.get("non_production")),
        "safety_note": probe.get("safety_note") or "",
    }


def _probe_warnings(probe: Dict[str, Any], evaluation: Dict[str, Any]) -> List[str]:
    warnings = [
        "manual_provider_readback_probe",
        "non_production_required",
        f"probe_id={probe['probe_id']}",
        f"target_tool={probe['target_tool_name']}",
        f"readback_tool={probe['readback_tool_name']}",
        f"argument_hash={probe['argument_hash']}",
        f"expected_effect={probe['expected_effect']}",
    ]
    if evaluation.get("before_state_hash"):
        warnings.append(f"before_state_hash={evaluation['before_state_hash']}")
    if evaluation.get("after_state_hash"):
        warnings.append(f"after_state_hash={evaluation['after_state_hash']}")
    if evaluation.get("observed_error_class"):
        warnings.append(f"observed_error_class={evaluation['observed_error_class']}")
    return warnings


def build_readback_effect_drift_record(
    *,
    server_id: str,
    tool_name: str,
    before_state_hash: str,
    after_state_hash: str,
    finding_types: List[str],
    severity: str,
    decision: str,
) -> Dict[str, Any]:
    return {
        "record_type": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "server_id": str(server_id or ""),
        "tool_name": str(tool_name or ""),
        "baseline_profile_hash": str(before_state_hash or ""),
        "current_profile_hash": str(after_state_hash or ""),
        "diff_classification": "effect",
        "finding_types": [str(value) for value in (finding_types or []) if str(value)],
        "severity": str(severity or "none"),
        "decision": str(decision or "allow"),
    }


def compute_readback_effect_drift_digest(record: Dict[str, Any]) -> str:
    return _digest_value(record or {})


def build_readback_effect_drift_record_from_audit_row(
    row: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    finding_types = row.get("drift_types") or []
    if isinstance(finding_types, str):
        try:
            finding_types = json.loads(finding_types)
        except (json.JSONDecodeError, TypeError):
            finding_types = []
    finding_types = [str(value) for value in (finding_types or []) if str(value)]
    if not any(
        value.startswith("readback_")
        or value == "silent_side_effect_drift"
        or value == "effect_response_contradicted_by_readback"
        for value in finding_types
    ):
        return None
    severity = str(row.get("drift_severity") or "none").lower()
    if severity in ("", "none"):
        return None
    before_hash = str(row.get("drift_baseline_hash") or "")
    after_hash = str(row.get("drift_current_hash") or "")
    if not before_hash or not after_hash:
        return None
    return build_readback_effect_drift_record(
        server_id=row.get("server_id") or "",
        tool_name=row.get("tool_name") or "",
        before_state_hash=before_hash,
        after_state_hash=after_hash,
        finding_types=finding_types,
        severity=severity,
        decision=row.get("drift_action") or row.get("action") or "allow",
    )


def build_readback_effect_drift_evidence_ref(
    record: Dict[str, Any], ref: Optional[str] = None
) -> Dict[str, Any]:
    evidence_ref = {
        "type": EVIDENCE_TYPE,
        "digest": compute_readback_effect_drift_digest(record),
        "canonicalization": CANONICALIZATION,
        "schema": SCHEMA_URL,
    }
    if ref:
        evidence_ref["ref"] = ref
    return evidence_ref
