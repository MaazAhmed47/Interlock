"""Pre-execution multi-step MCP chain drift analysis.

This module catches risks that only appear across a sequence of MCP tool calls:
read sensitive data, then send it externally; plan/preview, then apply/deploy;
fetch a secret, then execute a command. It does not execute tools and it never
stores raw arguments.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Set

from core import db
from core.drift_evidence import canonical_json_bytes

SCHEMA_ID = "interlock.chain-drift-record"
SCHEMA_VERSION = "1"
SCHEMA_URL = "https://getinterlock.dev/schemas/chain-drift-record.v1.json"
CANONICALIZATION = "json/jcs-rfc8785"
EVIDENCE_TYPE = "chain-drift"
DIGEST_ALG = "sha256"

SEVERITY_ORDER = {"none": 0, "minor": 1, "moderate": 2, "high": 3, "critical": 4}
ACTION_BY_SEVERITY = {
    "none": "allow",
    "minor": "monitor",
    "moderate": "monitor",
    "high": "deny",
    "critical": "deny",
}

READ_EFFECTS = {"read", "preview", "dry_run", "plan"}
PREVIEW_EFFECTS = {"preview", "dry_run", "plan"}
MUTATING_EFFECTS = {"mutating", "created", "updated", "applied", "scheduled"}
EXTERNAL_EFFECTS = {
    "sent",
    "published",
    "submitted",
    "external_send",
    "exported",
    "shared",
}
DESTRUCTIVE_EFFECTS = {"deleted", "destroyed"}
DEPLOY_EFFECTS = {"deployed", "released"}
EXECUTION_EFFECTS = {"executed", "shell", "command"}
MONEY_EFFECTS = {"charged", "refunded", "transferred", "money_movement"}
SENSITIVE_DATA_CLASSES = {
    "pii",
    "email",
    "phone",
    "ssn",
    "credit_card",
    "card",
    "financial",
    "finance",
    "customer",
    "customer_data",
    "personal",
    "health",
    "medical",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "api_key",
    "token",
    "password",
}
SECRET_DATA_CLASSES = {
    "secret",
    "secrets",
    "credential",
    "credentials",
    "api_key",
    "token",
    "password",
}


def _digest_value(value: Any) -> str:
    return f"{DIGEST_ALG}:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def arguments_hash(arguments: Dict[str, Any]) -> str:
    return _digest_value(arguments or {})


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _as_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v)]
    if value in (None, ""):
        return []
    return [str(value)]


def _step_effects(step: Dict[str, Any]) -> Set[str]:
    effects = {_norm(v) for v in _as_list(step.get("effects"))}
    tool_name = _norm(step.get("tool_name"))
    if not effects:
        effects.add("read")
    for token, effect in (
        ("send", "sent"),
        ("post", "sent"),
        ("publish", "published"),
        ("submit", "submitted"),
        ("export", "exported"),
        ("share", "shared"),
        ("apply", "applied"),
        ("update", "updated"),
        ("delete", "deleted"),
        ("destroy", "destroyed"),
        ("deploy", "deployed"),
        ("release", "released"),
        ("execute", "executed"),
        ("shell", "executed"),
        ("charge", "charged"),
        ("refund", "refunded"),
        ("transfer", "transferred"),
    ):
        if token in tool_name:
            effects.add(effect)
    return effects


def _step_data_classes(step: Dict[str, Any]) -> Set[str]:
    return {_norm(v) for v in _as_list(step.get("data_classes"))}


def _step_externality(step: Dict[str, Any]) -> str:
    return _norm(step.get("externality") or "internal") or "internal"


def _finding(kind: str, severity: str, reason: str) -> Dict[str, str]:
    return {"type": kind, "severity": severity, "reason": reason}


def _max_severity(values: Iterable[str]) -> str:
    out = "none"
    for value in values:
        if SEVERITY_ORDER[value] > SEVERITY_ORDER[out]:
            out = value
    return out


def _ordered_unique(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        value = str(value)
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _is_external_effect(step: Dict[str, Any], effects: Set[str]) -> bool:
    return _step_externality(step) == "external" or bool(effects & EXTERNAL_EFFECTS)


def _material_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "profile_version": profile.get("profile_version"),
        "chain_id": profile.get("chain_id") or "",
        "step_count": int(profile.get("step_count") or 0),
        "tool_names": list(profile.get("tool_names") or []),
        "server_ids": list(profile.get("server_ids") or []),
        "effect_classes": list(profile.get("effect_classes") or []),
        "data_classes": list(profile.get("data_classes") or []),
        "externalities": list(profile.get("externalities") or []),
        "argument_hashes": list(profile.get("argument_hashes") or []),
    }


def build_chain_profile(
    steps: List[Dict[str, Any]], chain_id: str = ""
) -> Dict[str, Any]:
    """Build an evidence-safe profile for a planned MCP tool chain."""
    tool_names: List[str] = []
    server_ids: List[str] = []
    argument_hashes: List[str] = []
    effects: Set[str] = set()
    data_classes: Set[str] = set()
    externalities: Set[str] = set()

    for step in steps or []:
        tool_names.append(str(step.get("tool_name") or ""))
        server_ids.append(str(step.get("server_id") or ""))
        argument_hashes.append(arguments_hash(dict(step.get("arguments") or {})))
        step_effects = _step_effects(step)
        effects.update(step_effects)
        data_classes.update(_step_data_classes(step))
        externalities.add(_step_externality(step))

    profile = {
        "profile_version": "1",
        "chain_id": str(chain_id or ""),
        "step_count": len(steps or []),
        "tool_names": tool_names,
        "server_ids": _ordered_unique(server_ids),
        "effect_classes": sorted(effects),
        "data_classes": sorted(data_classes),
        "externalities": sorted(externalities),
        "argument_hashes": argument_hashes,
    }
    profile["argument_hash"] = _digest_value(argument_hashes)
    profile["profile_hash"] = _digest_value(_material_profile(profile))
    return profile


def classify_chain_drift(steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Classify risk that appears only across a planned sequence of calls."""
    findings: List[Dict[str, str]] = []
    prior_sensitive_read = False
    prior_secret_read = False
    prior_preview = False

    for raw_step in steps or []:
        step = dict(raw_step or {})
        effects = _step_effects(step)
        data_classes = _step_data_classes(step)
        has_sensitive_data = bool(data_classes & SENSITIVE_DATA_CLASSES)
        has_secret_data = bool(data_classes & SECRET_DATA_CLASSES)
        is_readish = bool(effects & READ_EFFECTS) or not effects
        is_external = _is_external_effect(step, effects)

        if (
            prior_sensitive_read
            and is_external
            and bool(
                effects
                & (
                    EXTERNAL_EFFECTS
                    | MUTATING_EFFECTS
                    | DEPLOY_EFFECTS
                    | EXECUTION_EFFECTS
                    | MONEY_EFFECTS
                )
            )
        ):
            findings.append(
                _finding(
                    "chain_sensitive_read_to_external_effect",
                    "critical",
                    "A prior step read sensitive data and a later step sends, exports, publishes, or mutates through an external boundary.",
                )
            )
        if prior_secret_read and bool(effects & EXECUTION_EFFECTS):
            findings.append(
                _finding(
                    "chain_secret_to_execution",
                    "critical",
                    "A prior step read secrets or credentials and a later step executes code or shell commands.",
                )
            )
        if prior_secret_read and is_external and bool(effects & EXTERNAL_EFFECTS):
            findings.append(
                _finding(
                    "chain_secret_to_external_effect",
                    "critical",
                    "A prior step read secrets or credentials and a later step sends or exports externally.",
                )
            )
        if prior_preview and bool(effects & DEPLOY_EFFECTS):
            findings.append(
                _finding(
                    "chain_preview_to_deploy",
                    "critical",
                    "A prior preview/plan step is followed by a deploy or release step in the same chain.",
                )
            )
        if prior_preview and bool(effects & DESTRUCTIVE_EFFECTS):
            findings.append(
                _finding(
                    "chain_preview_to_destructive",
                    "critical",
                    "A prior preview/plan step is followed by delete or destroy in the same chain.",
                )
            )
        if prior_preview and bool(effects & MONEY_EFFECTS):
            findings.append(
                _finding(
                    "chain_preview_to_money_movement",
                    "critical",
                    "A prior preview/plan step is followed by money movement in the same chain.",
                )
            )
        if prior_preview and bool(effects & EXECUTION_EFFECTS):
            findings.append(
                _finding(
                    "chain_preview_to_execution",
                    "critical",
                    "A prior preview/plan step is followed by execution in the same chain.",
                )
            )
        if prior_preview and bool(effects & EXTERNAL_EFFECTS):
            findings.append(
                _finding(
                    "chain_preview_to_external_effect",
                    "critical",
                    "A prior preview/plan step is followed by an external send/publish/export in the same chain.",
                )
            )
        if prior_preview and bool(effects & MUTATING_EFFECTS):
            findings.append(
                _finding(
                    "chain_preview_to_mutation",
                    "high",
                    "A prior preview/plan step is followed by mutation in the same chain.",
                )
            )

        if is_readish and has_sensitive_data:
            prior_sensitive_read = True
        if is_readish and has_secret_data:
            prior_secret_read = True
        if effects & PREVIEW_EFFECTS:
            prior_preview = True

    findings = _dedupe_findings(findings)
    severity = _max_severity(f["severity"] for f in findings)
    reason = "Planned MCP chain stays within the approved sequence boundary."
    if findings:
        reason = findings[0]["reason"]
    return {
        "drift_detected": severity != "none",
        "severity": severity,
        "action": ACTION_BY_SEVERITY[severity],
        "types": _ordered_unique(f["type"] for f in findings),
        "reasons": [f["reason"] for f in findings],
        "findings": findings,
        "reason": reason,
    }


def _dedupe_findings(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    out: List[Dict[str, str]] = []
    for finding in findings:
        key = finding["type"]
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def run_chain_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    chain_id = str(payload.get("chain_id") or "").strip()
    steps = [dict(step or {}) for step in (payload.get("steps") or [])]
    if not chain_id:
        chain_id = f"chain:{_digest_value(steps)[-16:]}"
    profile = build_chain_profile(steps, chain_id=chain_id)
    evaluation = classify_chain_drift(steps)
    audit = _log_chain_audit_event(
        chain_id=chain_id,
        profile=profile,
        evaluation=evaluation,
        role=str(payload.get("role") or "operator"),
    )
    audit_id = int(audit.get("id") or 0)
    return {
        "ok": True,
        "chain": {
            "chain_id": chain_id,
            "step_count": profile["step_count"],
            "profile_hash": profile["profile_hash"],
            "argument_hash": profile["argument_hash"],
        },
        "evaluation": evaluation,
        "evidence": {
            "audit_id": audit_id,
            "chain_profile_hash": profile["profile_hash"],
            "argument_hash": profile["argument_hash"],
        },
    }


def _log_chain_audit_event(
    *, chain_id: str, profile: Dict[str, Any], evaluation: Dict[str, Any], role: str
) -> Dict[str, Any]:
    action = evaluation.get("action") or "monitor"
    drift_detected = bool(evaluation.get("drift_detected"))
    event = {
        "server_id": "multi-step-chain",
        "tool_name": chain_id,
        "role": role or "operator",
        "action": action,
        "matched_rule": "chain_drift",
        "reason": evaluation.get("reason") or "",
        "effects": profile.get("effect_classes") or [],
        "side_effect": "chain",
        "data_classes": profile.get("data_classes") or [],
        "externality": (
            "external"
            if "external" in (profile.get("externalities") or [])
            else "internal"
        ),
        "verification_level": "pre_execution_chain_analysis",
        "confidence": 0.95 if drift_detected else 0.0,
        "warnings": [
            "pre_execution_chain_analysis",
            f"chain_id={chain_id}",
            f"step_count={profile.get('step_count')}",
            f"chain_profile_hash={profile.get('profile_hash')}",
            f"argument_hash={profile.get('argument_hash')}",
        ],
        "argument_keys": [],
        "blocked_by": "chain_drift" if action == "deny" else "",
        "probe_id": chain_id,
        "argument_hash": profile.get("argument_hash") or "",
        "expected_outcome": "chain_allowed",
        "observed_outcome": "chain_denied" if action == "deny" else "chain_allowed",
        "drift_status": "chain_drift" if drift_detected else "",
        "drift_severity": evaluation.get("severity") or "none",
        "drift_action": action,
        "drift_types": evaluation.get("types") or [],
        "drift_reasons": evaluation.get("reasons") or [],
        "drift_current_hash": profile.get("profile_hash") or "",
    }
    return db.log_mcp_audit_event(event)


def build_chain_drift_record(
    *,
    chain_id: str,
    chain_profile_hash: str,
    finding_types: List[str],
    severity: str,
    decision: str,
) -> Dict[str, Any]:
    return {
        "record_type": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "chain_id": str(chain_id or ""),
        "chain_profile_hash": str(chain_profile_hash or ""),
        "diff_classification": "chain",
        "finding_types": [str(value) for value in (finding_types or []) if str(value)],
        "severity": str(severity or "none"),
        "decision": str(decision or "allow"),
    }


def compute_chain_drift_digest(record: Dict[str, Any]) -> str:
    return _digest_value(record or {})


def build_chain_drift_record_from_audit_row(
    row: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    finding_types = row.get("drift_types") or []
    if isinstance(finding_types, str):
        try:
            finding_types = json.loads(finding_types)
        except (json.JSONDecodeError, TypeError):
            finding_types = []
    finding_types = [str(value) for value in (finding_types or []) if str(value)]
    if not any(value.startswith("chain_") for value in finding_types):
        return None
    severity = str(row.get("drift_severity") or "none").lower()
    if severity in ("", "none"):
        return None
    profile_hash = str(row.get("drift_current_hash") or "")
    if not profile_hash:
        return None
    return build_chain_drift_record(
        chain_id=row.get("probe_id") or row.get("tool_name") or "",
        chain_profile_hash=profile_hash,
        finding_types=finding_types,
        severity=severity,
        decision=row.get("drift_action") or row.get("action") or "allow",
    )


def build_chain_drift_evidence_ref(
    record: Dict[str, Any], ref: Optional[str] = None
) -> Dict[str, Any]:
    evidence_ref = {
        "type": EVIDENCE_TYPE,
        "digest": compute_chain_drift_digest(record),
        "canonicalization": CANONICALIZATION,
        "schema": SCHEMA_URL,
    }
    if ref:
        evidence_ref["ref"] = ref
    return evidence_ref


def build_observed_chain_steps(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert already-observed audit rows into evidence-safe chain steps.

    This is a post-hoc visibility path. It can analyze calls that passed through
    Interlock, but it cannot infer calls that bypassed the gateway or were never
    submitted by an orchestrator.
    """
    steps: List[Dict[str, Any]] = []
    for row in rows or []:
        step = {
            "server_id": str(row.get("server_id") or ""),
            "tool_name": str(row.get("tool_name") or ""),
            "arguments": {
                "audit_id": int(row.get("id") or 0),
                "argument_hash": str(row.get("argument_hash") or ""),
            },
            "effects": _as_list(row.get("effects")) or ["read"],
            "data_classes": _as_list(row.get("data_classes")),
            "externality": str(row.get("externality") or "internal"),
        }
        steps.append(step)
    return steps


def analyze_observed_audit_chain(
    rows: List[Dict[str, Any]], chain_id: str = ""
) -> Dict[str, Any]:
    """Analyze a sequence of already-observed MCP audit rows.

    This improves coverage for chains that were not submitted upfront but still
    traversed Interlock. It is not pre-execution prevention and it is explicitly
    not a claim that Interlock can detect calls it never sees.
    """
    chain_id = str(chain_id or "").strip() or f"observed:{_digest_value(rows)[-16:]}"
    steps = build_observed_chain_steps(rows)
    profile = build_chain_profile(steps, chain_id=chain_id)
    evaluation = classify_chain_drift(steps)
    return {
        "ok": True,
        "visibility": "observed_post_execution",
        "pre_execution_prevention_available": False,
        "chain": {
            "chain_id": chain_id,
            "step_count": profile["step_count"],
            "tool_names": profile["tool_names"],
            "server_ids": profile["server_ids"],
            "profile_hash": profile["profile_hash"],
            "argument_hash": profile["argument_hash"],
        },
        "evaluation": evaluation,
        "limits": [
            "cannot_detect_unobserved_chain",
            "post_hoc_only_for_calls_already_seen_by_interlock",
            "pre_execution_prevention_requires_planned_chain_submission",
        ],
    }
