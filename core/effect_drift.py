"""Outcome/effect drift profiling and classification.

This module answers a different question than surface or permission drift:

- surface drift: did the tool contract change?
- permission drift: did an expected denial become allowed?
- effect drift: did an approved preview/read/dry-run outcome start reporting
  mutation, send, publish, deploy, delete, execution, or money movement?

Profiles are evidence-safe. They keep effect classes, field names, counts, and
hashes, but never raw response values or resource identifiers.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Set

from core.drift_evidence import canonical_json_bytes

SCHEMA_ID = "interlock.effect-drift-record"
SCHEMA_VERSION = "1"
SCHEMA_URL = "https://getinterlock.dev/schemas/effect-drift-record.v1.json"
CANONICALIZATION = "json/jcs-rfc8785"
EVIDENCE_TYPE = "effect-drift"
DIGEST_ALG = "sha256"

SEVERITY_ORDER = {"none": 0, "minor": 1, "moderate": 2, "high": 3, "critical": 4}
ACTION_BY_SEVERITY = {
    "none": "allow",
    "minor": "monitor",
    "moderate": "monitor",
    "high": "quarantine",
    "critical": "quarantine",
}

SAFE_EFFECTS = {"no_effect", "read", "preview", "dry_run", "plan"}
TEMPORAL_EFFECTS = {"scheduled", "queued", "deferred", "delayed"}
MUTATING_EFFECTS = {
    "mutating",
    "created",
    "updated",
    "applied",
    "draft_created",
    *TEMPORAL_EFFECTS,
}
EXTERNAL_EFFECTS = {"sent", "published", "submitted", "external_send"}
DESTRUCTIVE_EFFECTS = {"deleted", "destroyed"}
DEPLOY_EFFECTS = {"deployed", "released"}
EXECUTION_EFFECTS = {"executed"}
MONEY_EFFECTS = {"charged", "refunded", "transferred", "money_movement"}
CRITICAL_EFFECTS = (
    EXTERNAL_EFFECTS
    | DESTRUCTIVE_EFFECTS
    | DEPLOY_EFFECTS
    | EXECUTION_EFFECTS
    | MONEY_EFFECTS
)

KEYWORD_EFFECTS = {
    "dry_run": "dry_run",
    "dryrun": "dry_run",
    "preview": "preview",
    "plan": "plan",
    "planned": "plan",
    "would_change": "preview",
    "would_apply": "preview",
    "would_send": "preview",
    "read_only": "read",
    "readonly": "read",
    "applied": "applied",
    "apply": "applied",
    "updated": "updated",
    "modified": "updated",
    "changed": "updated",
    "created": "created",
    "draft": "draft_created",
    "draft_created": "draft_created",
    "scheduled": "scheduled",
    "schedule": "scheduled",
    "scheduled_at": "scheduled",
    "scheduled_for": "scheduled",
    "send_at": "sent",
    "publish_at": "published",
    "submit_at": "submitted",
    "delete_at": "deleted",
    "destroy_at": "destroyed",
    "deploy_at": "deployed",
    "release_at": "released",
    "execute_at": "executed",
    "run_at": "executed",
    "charge_at": "charged",
    "refund_at": "refunded",
    "transfer_at": "transferred",
    "sent": "sent",
    "send": "sent",
    "emailed": "sent",
    "published": "published",
    "publish": "published",
    "submitted": "submitted",
    "submit": "submitted",
    "deleted": "deleted",
    "delete": "deleted",
    "destroyed": "destroyed",
    "destroy": "destroyed",
    "deployed": "deployed",
    "deploy": "deployed",
    "released": "released",
    "release": "released",
    "executed": "executed",
    "execute": "executed",
    "ran": "executed",
    "charged": "charged",
    "charge": "charged",
    "refunded": "refunded",
    "refund": "refunded",
    "transferred": "transferred",
    "transfer": "transferred",
}

STRING_EFFECT_TOKENS = {
    "dry run": "dry_run",
    "dry-run": "dry_run",
    "preview": "preview",
    "plan only": "plan",
    "planned": "plan",
    "no changes applied": "dry_run",
    "applied": "applied",
    "updated": "updated",
    "created": "created",
    "scheduled": "scheduled",
    "schedule": "scheduled",
    "scheduled_at": "scheduled",
    "scheduled_for": "scheduled",
    "send_at": "sent",
    "publish_at": "published",
    "submit_at": "submitted",
    "delete_at": "deleted",
    "destroy_at": "destroyed",
    "deploy_at": "deployed",
    "release_at": "released",
    "execute_at": "executed",
    "run_at": "executed",
    "charge_at": "charged",
    "refund_at": "refunded",
    "transfer_at": "transferred",
    "sent": "sent",
    "published": "published",
    "submitted": "submitted",
    "deleted": "deleted",
    "destroyed": "destroyed",
    "deployed": "deployed",
    "executed": "executed",
    "charged": "charged",
    "refunded": "refunded",
    "transferred": "transferred",
}

EFFECT_RANK = {
    "unknown": 0,
    "no_effect": 0,
    "read": 0,
    "preview": 1,
    "dry_run": 1,
    "plan": 1,
    "draft_created": 2,
    "scheduled": 2,
    "queued": 2,
    "deferred": 2,
    "delayed": 2,
    "created": 3,
    "updated": 3,
    "applied": 3,
    "mutating": 3,
    "sent": 4,
    "published": 4,
    "submitted": 4,
    "external_send": 4,
    "deleted": 5,
    "destroyed": 5,
    "deployed": 5,
    "released": 5,
    "executed": 5,
    "charged": 5,
    "refunded": 5,
    "transferred": 5,
    "money_movement": 5,
}


def _digest_value(value: Any) -> str:
    return f"{DIGEST_ALG}:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def _normalize_key(key: Any) -> str:
    return str(key or "").strip().lower().replace("-", "_").replace(" ", "_")


def _effect_for_key(key: str) -> Optional[str]:
    if key in KEYWORD_EFFECTS:
        return KEYWORD_EFFECTS[key]
    for token, effect in KEYWORD_EFFECTS.items():
        if token in key:
            return effect
    return None


def _effect_for_text(value: str) -> Optional[str]:
    text = str(value or "").strip().lower().replace("_", " ")
    if text in {"unknown", "pending", "inconclusive", "not reported"}:
        return None
    for token, effect in STRING_EFFECT_TOKENS.items():
        if token in text:
            return effect
    return None


def _truthy_effect_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value > 0
    if isinstance(value, str):
        return value.strip().lower() not in {"", "false", "0", "none", "no", "unknown"}
    return value not in (None, [], {})


def _walk_effects(value: Any) -> Dict[str, Any]:
    effects: Set[str] = set()
    field_names: Set[str] = set()
    boolean_true_count = 0
    numeric_signal_count = 0

    def visit(item: Any, key: str = "") -> None:
        nonlocal boolean_true_count, numeric_signal_count
        norm_key = _normalize_key(key)
        if isinstance(item, dict):
            for child_key, child in item.items():
                field_names.add(_normalize_key(child_key))
                visit(child, child_key)
            return
        if isinstance(item, list):
            for child in item:
                visit(child, norm_key)
            return

        key_effect = _effect_for_key(norm_key)
        if key_effect and _truthy_effect_value(item):
            effects.add(key_effect)
            if isinstance(item, bool) and item:
                boolean_true_count += 1
            if (
                isinstance(item, (int, float))
                and not isinstance(item, bool)
                and item > 0
            ):
                numeric_signal_count += 1

        if isinstance(item, str):
            text_effect = _effect_for_text(item)
            if text_effect:
                effects.add(text_effect)

    visit(value)
    if not effects and field_names:
        effects.add("unknown")
    if not effects:
        effects.add("no_effect")
    return {
        "effect_classes": effects,
        "field_names": field_names,
        "boolean_true_count": boolean_true_count,
        "numeric_signal_count": numeric_signal_count,
    }


def _material_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "profile_version": profile.get("profile_version"),
        "effect_classes": list(profile.get("effect_classes") or []),
        "effect_rank": int(profile.get("effect_rank") or 0),
        "field_names": list(profile.get("field_names") or []),
        "boolean_true_count": int(profile.get("boolean_true_count") or 0),
        "numeric_signal_count": int(profile.get("numeric_signal_count") or 0),
    }


def build_effect_profile(observation: Any) -> Dict[str, Any]:
    """Build an evidence-safe outcome/effect profile from a tool result."""
    walked = _walk_effects(observation)
    classes = sorted(walked["effect_classes"])
    rank = max(EFFECT_RANK.get(effect, 0) for effect in classes) if classes else 0
    profile = {
        "profile_version": "1",
        "observation_digest": _digest_value(observation),
        "effect_classes": classes,
        "effect_rank": rank,
        "field_names": sorted(walked["field_names"]),
        "boolean_true_count": int(walked["boolean_true_count"]),
        "numeric_signal_count": int(walked["numeric_signal_count"]),
    }
    profile["profile_hash"] = effect_profile_hash(profile)
    return profile


def effect_profile_hash(profile: Dict[str, Any]) -> str:
    return _digest_value(_material_profile(profile or {}))


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
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _is_safe_preview_effect(effects: Set[str]) -> bool:
    meaningful = effects - {"unknown"}
    return bool(meaningful) and meaningful.issubset(SAFE_EFFECTS)


def _is_temporal_effect(effects: Set[str]) -> bool:
    return bool(effects & TEMPORAL_EFFECTS)


def _is_mutating_effect(effects: Set[str]) -> bool:
    return bool(effects & MUTATING_EFFECTS)


def _is_critical_effect(effects: Set[str]) -> bool:
    return bool(effects & CRITICAL_EFFECTS)


def classify_effect_drift(
    baseline_profile: Optional[Dict[str, Any]],
    current_profile: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    baseline_profile = baseline_profile or {}
    current_profile = current_profile or {}
    baseline_effects = set(baseline_profile.get("effect_classes") or [])
    current_effects = set(current_profile.get("effect_classes") or [])
    if not current_effects or current_effects == {"unknown"}:
        severity = "none"
        return {
            "drift_detected": False,
            "severity": severity,
            "action": ACTION_BY_SEVERITY[severity],
            "types": [],
            "reasons": [],
            "findings": [],
            "baseline_profile_hash": effect_profile_hash(baseline_profile),
            "current_profile_hash": effect_profile_hash(current_profile),
        }

    findings: List[Dict[str, str]] = []
    baseline_safe = _is_safe_preview_effect(baseline_effects)
    added_effects = sorted(current_effects - baseline_effects)

    if baseline_safe and _is_temporal_effect(current_effects):
        if current_effects & EXTERNAL_EFFECTS:
            findings.append(
                _finding(
                    "effect_temporal_external_after_preview",
                    "critical",
                    "Observed a scheduled/deferred external send, publish, or submit after an approved preview/dry-run baseline.",
                )
            )
        if current_effects & DESTRUCTIVE_EFFECTS:
            findings.append(
                _finding(
                    "effect_temporal_destructive_after_preview",
                    "critical",
                    "Observed a scheduled/deferred delete or destroy after an approved preview/dry-run baseline.",
                )
            )
        if current_effects & DEPLOY_EFFECTS:
            findings.append(
                _finding(
                    "effect_temporal_deploy_after_preview",
                    "critical",
                    "Observed a scheduled/deferred deploy or release after an approved preview/dry-run baseline.",
                )
            )
        if current_effects & EXECUTION_EFFECTS:
            findings.append(
                _finding(
                    "effect_temporal_execution_after_preview",
                    "critical",
                    "Observed a scheduled/deferred code or command execution after an approved preview/dry-run baseline.",
                )
            )
        if current_effects & MONEY_EFFECTS:
            findings.append(
                _finding(
                    "effect_temporal_money_movement_after_preview",
                    "critical",
                    "Observed scheduled/deferred money movement after an approved preview/dry-run baseline.",
                )
            )
        if not (
            current_effects
            & (
                EXTERNAL_EFFECTS
                | DESTRUCTIVE_EFFECTS
                | DEPLOY_EFFECTS
                | EXECUTION_EFFECTS
                | MONEY_EFFECTS
            )
        ):
            findings.append(
                _finding(
                    "effect_temporal_action_after_preview",
                    "high",
                    "Observed a scheduled/deferred future action after an approved preview/dry-run baseline.",
                )
            )

    if baseline_safe and (current_effects & EXTERNAL_EFFECTS):
        findings.append(
            _finding(
                "effect_external_send_after_preview",
                "critical",
                "Observed external send/publish/submit effect after an approved preview/dry-run baseline.",
            )
        )
    if baseline_safe and (current_effects & DESTRUCTIVE_EFFECTS):
        findings.append(
            _finding(
                "effect_destructive_after_preview",
                "critical",
                "Observed delete/destroy effect after an approved preview/dry-run baseline.",
            )
        )
    if baseline_safe and (current_effects & DEPLOY_EFFECTS):
        findings.append(
            _finding(
                "effect_deploy_after_preview",
                "critical",
                "Observed deploy/release effect after an approved preview/dry-run baseline.",
            )
        )
    if baseline_safe and (current_effects & EXECUTION_EFFECTS):
        findings.append(
            _finding(
                "effect_execution_after_preview",
                "critical",
                "Observed execution effect after an approved preview/dry-run baseline.",
            )
        )
    if baseline_safe and (current_effects & MONEY_EFFECTS):
        findings.append(
            _finding(
                "effect_money_movement_after_preview",
                "critical",
                "Observed money movement effect after an approved preview/dry-run baseline.",
            )
        )
    if baseline_safe and _is_mutating_effect(current_effects):
        findings.append(
            _finding(
                "effect_mutation_after_preview",
                "high",
                "Observed mutation effect after an approved preview/dry-run baseline.",
            )
        )

    baseline_rank = int(baseline_profile.get("effect_rank") or 0)
    current_rank = int(current_profile.get("effect_rank") or 0)
    if (
        not baseline_safe
        and current_rank > baseline_rank
        and _is_critical_effect(current_effects)
    ):
        findings.append(
            _finding(
                "effect_critical_escalation",
                "critical",
                f"Observed effect severity increased from rank {baseline_rank} to {current_rank}: {added_effects}.",
            )
        )

    if baseline_rank >= 3 and current_rank <= 1 and not findings:
        findings.append(
            _finding(
                "effect_regression",
                "moderate",
                "Expected a mutating/effectful operation, but the observed effect profile regressed to preview/no-effect.",
            )
        )

    severity = _max_severity(f["severity"] for f in findings)
    return {
        "drift_detected": severity != "none",
        "severity": severity,
        "action": ACTION_BY_SEVERITY[severity],
        "types": _ordered_unique(f["type"] for f in findings),
        "reasons": [f["reason"] for f in findings],
        "findings": findings,
        "baseline_profile_hash": effect_profile_hash(baseline_profile),
        "current_profile_hash": effect_profile_hash(current_profile),
    }


def build_effect_drift_record(
    *,
    server_id: str,
    tool_name: str,
    baseline_profile_hash: str,
    current_profile_hash: str,
    finding_types: List[str],
    severity: str,
    decision: str,
) -> Dict[str, Any]:
    finding_types = [str(value) for value in (finding_types or []) if str(value)]
    return {
        "record_type": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "server_id": str(server_id or ""),
        "tool_name": str(tool_name or ""),
        "baseline_profile_hash": str(baseline_profile_hash or ""),
        "current_profile_hash": str(current_profile_hash or ""),
        "diff_classification": "effect",
        "finding_types": finding_types,
        "severity": str(severity or "none"),
        "decision": str(decision or "allow"),
    }


def compute_effect_drift_digest(record: Dict[str, Any]) -> str:
    return _digest_value(record or {})


def build_effect_drift_record_from_audit_row(
    row: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    finding_types = row.get("drift_types") or []
    if isinstance(finding_types, str):
        try:
            finding_types = json.loads(finding_types)
        except (json.JSONDecodeError, TypeError):
            finding_types = []
    finding_types = [str(value) for value in (finding_types or []) if str(value)]
    if not any(value.startswith("effect_") for value in finding_types):
        return None
    severity = str(row.get("drift_severity") or "none").lower()
    if severity in ("", "none"):
        return None
    baseline_hash = str(row.get("drift_baseline_hash") or "")
    current_hash = str(row.get("drift_current_hash") or "")
    if not baseline_hash or not current_hash:
        return None
    return build_effect_drift_record(
        server_id=row.get("server_id") or "",
        tool_name=row.get("tool_name") or "",
        baseline_profile_hash=baseline_hash,
        current_profile_hash=current_hash,
        finding_types=finding_types,
        severity=severity,
        decision=row.get("drift_action") or row.get("action") or "allow",
    )


def build_effect_drift_evidence_ref(
    record: Dict[str, Any], ref: Optional[str] = None
) -> Dict[str, Any]:
    evidence_ref = {
        "type": EVIDENCE_TYPE,
        "digest": compute_effect_drift_digest(record),
        "canonicalization": CANONICALIZATION,
        "schema": SCHEMA_URL,
    }
    if ref:
        evidence_ref["ref"] = ref
    return evidence_ref
