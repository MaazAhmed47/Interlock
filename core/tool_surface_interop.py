"""Strict tool-surface interop projection for composition/replay fixtures.

Interlock's internal receipts are intentionally useful for operator triage: they
may surface weak heuristic findings at monitor severity. This module is stricter
because it is meant for external replay/composition. It only emits `drifted`
when the evidence is verified, complete, and not based solely on inferred
metadata. Otherwise the bounded verdict is `not_verifiable`.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from core import drift_evidence

PROFILE = "interlock.tool-surface.v0"
SCHEMA_URL = "https://getinterlock.dev/schemas/tool-surface-interop.v0.json"
VERDICT_UNCHANGED = "unchanged"
VERDICT_DRIFTED = "drifted"
VERDICT_NOT_VERIFIABLE = "not_verifiable"
COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"

_RECORD_FIELDS = (
    "profile",
    "action_id",
    "run_id",
    "coverage",
    "approved_tool_surface_hash",
    "observed_tool_surface_hash",
    "evidence",
    "verdict",
    "finding",
    "finding_types",
)

_FINDING_INFERRED_FIELDS = {
    "effect_escalated": {"effects"},
    "side_effect_escalated": {"side_effect"},
    "data_class_escalated": {"data_classes"},
    "externality_escalated": {"externality"},
    "identity_mode_escalated": {"identity_mode"},
    "scope_escalated": {"required_scopes"},
}


def _as_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value in (None, ""):
        return []
    return [str(value)]


def _ordered_unique(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    for value in values:
        item = str(value or "")
        if item and item not in out:
            out.append(item)
    return out


def _valid_hash(value: str) -> bool:
    value = str(value or "")
    if not value.startswith("sha256:") or len(value) != 71:
        return False
    try:
        int(value[len("sha256:") :], 16)
    except ValueError:
        return False
    return True


def _finding_depends_only_on_inferred_fields(
    finding_types: Iterable[str], inferred_fields: Iterable[str]
) -> bool:
    """True when every finding is backed only by heuristic/inferred metadata."""
    findings = _ordered_unique(finding_types)
    inferred: Set[str] = {str(field) for field in inferred_fields if str(field)}
    if not findings or not inferred:
        return False

    for finding in findings:
        required = _FINDING_INFERRED_FIELDS.get(finding)
        if not required:
            return False
        if not required.issubset(inferred):
            return False
    return True


def _strict_verdict(
    *,
    approved_tool_surface_hash: str,
    observed_tool_surface_hash: str,
    coverage: str,
    evidence_verified: bool,
    finding_types: Iterable[str],
    inferred_fields: Iterable[str],
) -> str:
    if not evidence_verified:
        return VERDICT_NOT_VERIFIABLE
    if str(coverage or "") != COVERAGE_COMPLETE:
        return VERDICT_NOT_VERIFIABLE
    if not _valid_hash(approved_tool_surface_hash) or not _valid_hash(
        observed_tool_surface_hash
    ):
        return VERDICT_NOT_VERIFIABLE
    if approved_tool_surface_hash == observed_tool_surface_hash:
        return VERDICT_UNCHANGED
    if _finding_depends_only_on_inferred_fields(finding_types, inferred_fields):
        return VERDICT_NOT_VERIFIABLE
    return VERDICT_DRIFTED


def build_tool_surface_record(
    *,
    action_id: str,
    run_id: str,
    approved_tool_surface_hash: str,
    observed_tool_surface_hash: str,
    coverage: str = COVERAGE_COMPLETE,
    evidence_verified: bool = True,
    finding_types: Optional[List[str]] = None,
    inferred_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a strict replay/composition tool-surface record.

    The returned record is intentionally smaller and stricter than an Interlock
    Security Receipt. It is designed to compose with gateway/path evidence while
    preserving the bounded-verdict invariant: unverified or partial evidence
    cannot become `drifted`.
    """
    normalized_findings = _ordered_unique(finding_types or [])
    normalized_inferred = _ordered_unique(inferred_fields or [])
    verdict = _strict_verdict(
        approved_tool_surface_hash=str(approved_tool_surface_hash or ""),
        observed_tool_surface_hash=str(observed_tool_surface_hash or ""),
        coverage=str(coverage or ""),
        evidence_verified=bool(evidence_verified),
        finding_types=normalized_findings,
        inferred_fields=normalized_inferred,
    )

    emitted_findings = normalized_findings if verdict == VERDICT_DRIFTED else []
    if verdict == VERDICT_DRIFTED and normalized_inferred:
        emitted_findings = [
            finding
            for finding in normalized_findings
            if not _finding_depends_only_on_inferred_fields(
                [finding], normalized_inferred
            )
        ]

    return {
        "profile": PROFILE,
        "action_id": str(action_id or ""),
        "run_id": str(run_id or ""),
        "coverage": str(coverage or ""),
        "approved_tool_surface_hash": str(approved_tool_surface_hash or ""),
        "observed_tool_surface_hash": str(observed_tool_surface_hash or ""),
        "evidence": {"evidence_verified": bool(evidence_verified)},
        "verdict": verdict,
        "finding": emitted_findings[0] if emitted_findings else "",
        "finding_types": emitted_findings,
    }


def project_drift_record(
    drift_record: Dict[str, Any],
    *,
    action_id: str,
    run_id: str,
    coverage: str = COVERAGE_COMPLETE,
    evidence_verified: bool = True,
    inferred_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Project an Interlock drift evidence record into the strict interop shape."""
    drift_record = drift_record or {}
    return build_tool_surface_record(
        action_id=action_id,
        run_id=run_id,
        approved_tool_surface_hash=str(
            drift_record.get("approved_surface_hash")
            or drift_record.get("approved_tool_surface_hash")
            or ""
        ),
        observed_tool_surface_hash=str(
            drift_record.get("current_surface_hash")
            or drift_record.get("observed_tool_surface_hash")
            or ""
        ),
        coverage=coverage,
        evidence_verified=evidence_verified,
        finding_types=_as_list(drift_record.get("finding_types")),
        inferred_fields=inferred_fields or [],
    )


def compute_tool_surface_digest(record: Dict[str, Any]) -> str:
    """Digest a tool-surface interop record with Interlock's canonical JSON."""
    return drift_evidence.compute_digest(record)


def verify_tool_surface_record(
    record: Dict[str, Any], claimed_digest: str
) -> Dict[str, Any]:
    """Verify a strict tool-surface interop record against its claimed digest."""
    if not isinstance(record, dict):
        return {
            "verified": False,
            "computed_digest": "",
            "reason": "record_not_an_object",
        }
    missing = [field for field in _RECORD_FIELDS if field not in record]
    if missing:
        return {
            "verified": False,
            "computed_digest": "",
            "reason": f"missing_fields:{','.join(missing)}",
        }
    try:
        computed = compute_tool_surface_digest(record)
    except drift_evidence.CanonicalizationError as exc:
        return {"verified": False, "computed_digest": "", "reason": str(exc)}
    verified = computed == str(claimed_digest or "")
    return {
        "verified": verified,
        "computed_digest": computed,
        "reason": "verified" if verified else "digest_mismatch",
    }
