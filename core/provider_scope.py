"""Provider scope attestation helpers.

This module handles the case where a provider-specific integration can actually
read granted OAuth/API scopes. It does not claim universal OAuth introspection;
when scopes are opaque, Interlock should fall back to behavioral probes.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Set

from core.drift_evidence import canonical_json_bytes

WRITE_TOKENS = ("write", "update", "create", "modify", "manage", "send", "publish")
ADMIN_TOKENS = ("admin", "owner", "root", "all", "*", "delete", "destroy")


def _norm_scope(scope: Any) -> str:
    return str(scope or "").strip().lower()


def _scope_set(scopes: Iterable[Any]) -> Set[str]:
    return {_norm_scope(scope) for scope in scopes or [] if _norm_scope(scope)}


def _scope_hash(scopes: Iterable[Any]) -> str:
    normalized = sorted(_scope_set(scopes))
    return "sha256:" + hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()


def _contains_any(scope: str, tokens: Iterable[str]) -> bool:
    return any(token in scope for token in tokens)


def compare_provider_scope_attestation(
    *,
    provider: str,
    subject: str,
    baseline_scopes: Iterable[Any],
    current_scopes: Iterable[Any],
    introspection_available: bool,
) -> Dict[str, Any]:
    """Compare provider-read scope attestations without returning raw scopes."""
    baseline = _scope_set(baseline_scopes)
    current = _scope_set(current_scopes)
    provider_label = str(provider or "unknown").strip().lower() or "unknown"
    subject_hash = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(str(subject or ""))).hexdigest()
    )

    if not introspection_available:
        return {
            "ok": True,
            "provider": provider_label,
            "subject_hash": subject_hash,
            "drift_detected": False,
            "diff_classification": "auth-scope",
            "severity": "none",
            "decision": "monitor",
            "finding_types": ["provider_scope_introspection_unavailable"],
            "baseline_scope_hash": _scope_hash(baseline),
            "current_scope_hash": _scope_hash(current),
            "added_scope_count": 0,
            "removed_scope_count": 0,
            "limits": [
                "Provider scopes are opaque to this integration; use behavioral probes for denied-to-allowed drift.",
                "No raw provider scopes are stored in this result.",
            ],
        }

    added = sorted(current - baseline)
    removed = sorted(baseline - current)
    finding_types: List[str] = []
    severity = "none"
    decision = "allow"
    if added:
        finding_types.append("provider_scope_expanded")
        severity = "high"
        decision = "quarantine"
    if any(_contains_any(scope, WRITE_TOKENS) for scope in added):
        finding_types.append("provider_scope_write_added")
        severity = "high"
        decision = "quarantine"
    if any(_contains_any(scope, ADMIN_TOKENS) for scope in added):
        finding_types.append("provider_scope_admin_added")
        severity = "critical"
        decision = "quarantine"
    if removed and not added:
        finding_types.append("provider_scope_contracted")
        severity = "minor"
        decision = "monitor"

    return {
        "ok": True,
        "provider": provider_label,
        "subject_hash": subject_hash,
        "drift_detected": bool(added),
        "diff_classification": "auth-scope",
        "severity": severity,
        "decision": decision,
        "finding_types": finding_types,
        "baseline_scope_hash": _scope_hash(baseline),
        "current_scope_hash": _scope_hash(current),
        "added_scope_count": len(added),
        "removed_scope_count": len(removed),
        "limits": [
            "This compares provider scopes only when a provider-specific attestation/introspection source is available.",
            "No raw provider scopes are stored in this result.",
        ],
    }
