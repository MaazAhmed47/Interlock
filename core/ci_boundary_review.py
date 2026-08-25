"""
Read-only MCP boundary review for a CI release gate.

Answers one question about an ALREADY REGISTERED MCP server: does the
surface the server is serving right now still match the boundary Interlock
has on record, and is the gateway currently holding anything for it?

Everything here reuses the existing review path rather than re-deriving it:

  * server state     ``db.get_boundary_review_snapshot`` — registry row,
                     active baseline (hash AND the content it hashes), tool
                     metadata, and the enforced review queue, all read inside
                     the server's rebaseline lock domain. The snapshot is
                     re-read after the network observation; if its version
                     moved, the review reports ``inconclusive`` instead of
                     emitting a contradictory artifact.
  * observation      ``mcp_gateway.fetch_candidate_tool_surface`` — the same
                     read-only fetch rebaseline staging uses, here under an
                     explicit byte and tool-count budget. It persists
                     nothing: no metadata upsert, no candidate row, no
                     discovery receipt. No database lock is held across it.
  * classification   ``mcp_drift.classify_tool_drift`` /
                     ``classify_server_drift`` — the same classifier the
                     registry writes through.
  * evidence         ``drift_evidence`` refs plus one hash-chained
                     ``mcp_audit_log`` row, readable as a Security Receipt.

A review NEVER rebaselines, approves, quarantines, unquarantines, registers,
or changes policy. Its only writes are append-only evidence: content-
addressed tool-surface snapshots (capped) and exactly one audit row.

Two projections come out of :func:`run_boundary_review`:

  ``review``   the sanitized artifact handed to CI. Tool/schema text,
               arguments, headers, upstream bodies, local paths, detector
               reasons, actor identity, and the raw server id are all
               excluded by construction — the projection is built field by
               field, never by filtering a richer object.
  audit row    the internal record, which keeps the full drift reasons and
               the real server id.

The outcome vocabulary and exit codes below are the contract. The CLI in
``scripts/interlock_ci_gate.py`` carries a copy (it must run without this
repository checked out) and a test asserts the two stay identical.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from config import (
    boundary_review_idempotency_ttl_seconds,
    boundary_review_max_findings,
    boundary_review_max_response_bytes,
    boundary_review_max_tools,
    boundary_review_timeout_seconds,
    ci_boundary_review_max_request_bytes,
)
from core import db
from core import drift_evidence
from core.mcp_drift import ACTION_BY_SEVERITY, SEVERITY_ORDER
from core.mcp_drift import classify_server_drift, classify_tool_drift
from core.mcp_gateway import fetch_candidate_tool_surface
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url_async

logger = logging.getLogger("interlock.ci_boundary_review")

FORMAT_VERSION = "interlock.ci-boundary-review/v1"
GATE_NAME = "interlock-mcp-boundary-review"

# Stable named outcomes -> stable process exit codes. Changing a value here is
# a breaking change for every pipeline that consumes the gate.
OUTCOME_EXIT_CODES: Dict[str, int] = {
    # Pass.
    "clean": 0,
    "advisory": 0,
    # Boundary results.
    "review_required": 20,
    "quarantined": 21,
    "inconclusive": 22,
    # Gate-invocation results, deliberately distinct from boundary results.
    "config_error": 2,
    "auth_error": 3,
    "protocol_error": 4,
}

# Worst-first ranking used to combine results. `quarantined` outranks
# `inconclusive`: a held boundary is a definite finding, an unobservable one
# is not.
OUTCOME_RANK: Dict[str, int] = {
    "clean": 0,
    "advisory": 1,
    "review_required": 2,
    "inconclusive": 3,
    "quarantined": 4,
}

FAIL_POLICIES = ("material", "any-finding", "quarantine-only")
DEFAULT_FAIL_POLICY = "material"

# A finding is material when the classifier put it at or above `high`, or when
# the gateway would refuse to forward calls for it.
MATERIAL_SEVERITIES = frozenset({"high", "critical"})
MATERIAL_DECISIONS = frozenset({"deny", "quarantine"})

# What the gateway is refusing to forward RIGHT NOW, read off the persisted
# review queue. `deny` counts here: an artifact reporting enforced_now=true
# must never exit 0, whatever fail policy the pipeline selected.
ENFORCED_DECISIONS = frozenset({"deny", "quarantine"})

# A newly OBSERVED finding is a prediction about the next discovery, not
# something the gateway is enforcing yet, so only a quarantine-grade finding
# holds the boundary on its own. A `deny`-grade finding is material and fails
# the default policy; it does not masquerade as already-enforced state.
HELD_FINDING_DECISIONS = frozenset({"quarantine"})

# Backwards-compatible alias for the enforced set.
HELD_DECISIONS = ENFORCED_DECISIONS

SEVERITIES = frozenset({"none", "minor", "moderate", "high", "critical"})
DECISIONS = frozenset({"allow", "monitor", "deny", "quarantine"})
OBSERVATION_STATUSES = frozenset(
    {"observed", "observed_rejected", "unavailable", "superseded", "not_performed"}
)

# Upstream failure classes. Every one of these is inconclusive — never clean.
_ERROR_CLASSES = {
    "MCP server timeout": "upstream_timeout",
    "mcp_discovery_error": "upstream_protocol_error",
    "duplicate_tool_names": "upstream_protocol_error",
    "unsafe_mcp_server_url": "registry_url_rejected",
    "upstream_auth_unavailable": "upstream_auth_unavailable",
    "response_too_large": "upstream_response_too_large",
    "too_many_tools": "observed_surface_too_large",
}

_SAFE_REF_RE = re.compile(r"[^A-Za-z0-9._\-:]")
_MAX_REF_LEN = 80

REDACTION_PROFILE = "default"
REDACTED_CATEGORIES = [
    "tool_descriptions",
    "tool_input_output_schemas",
    "tool_call_arguments",
    "request_and_upstream_headers",
    "credentials_and_tokens",
    "upstream_response_bodies",
    "customer_data",
    "local_filesystem_paths",
    "registry_urls",
    "raw_server_identifiers",
    "detector_reasons_and_thresholds",
    "actor_identity",
]

LIMITATIONS = [
    "Optional self-hosted CI boundary-review gate. It is not policy-as-code "
    "and it does not gate deployment on its own.",
    "The review is read-only: it never rebaselines, approves, quarantines, or "
    "changes policy. Its only writes are append-only evidence.",
    "approved_surface_hash is the boundary Interlock has persisted for this "
    "server. Tools listed in review_queue are already flagged and have not "
    "been re-approved by an operator.",
    "Findings describe the tool surface the server advertised at the moment "
    "of observation. A server can serve a different surface later.",
    "Receipts are hash-chained and tamper-evident within this Interlock "
    "deployment. They are not externally signed and not anchored to an "
    "independent timestamping authority.",
    "Agents that connect to the MCP server directly bypass Interlock. The "
    "gate proves nothing about traffic the operator does not route through "
    "this deployment.",
    "Server identifiers are emitted only as an irreversible digest reference. "
    "The drift-evidence record itself is retrieved from the receipt, not "
    "carried in this artifact.",
]


# ── Sanitizers ────────────────────────────────────────────────────────────────
def safe_ref(value: Any) -> str:
    """Reduce an upstream- or operator-controlled name to a printable,
    bounded, non-path-like reference.

    Names travel from the registry or the MCP server into a JSON artifact, a
    Markdown summary, and a CI job summary, so they are treated as untrusted
    text. Everything outside ``[A-Za-z0-9._\\-:]`` is replaced (which removes
    ``<``, ``>``, ``&``, quotes, pipes, backticks, path separators, and every
    control character), traversal pairs are neutralized, and a name that had
    to be changed keeps a short digest so distinct names stay distinguishable.
    """
    text = str(value or "")
    cleaned = _SAFE_REF_RE.sub("_", text)
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "__")
    if cleaned != text or len(cleaned) > _MAX_REF_LEN:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
        return f"{cleaned[:_MAX_REF_LEN]}~{digest}"
    return cleaned


def opaque_ref(value: Any) -> str:
    """Content-addressed stand-in for an identifier."""
    digest = hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _max_severity(severities: List[str]) -> str:
    worst = "none"
    for severity in severities:
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(worst, 0):
            worst = severity
    return worst


def effective_caps() -> Dict[str, Any]:
    """Validated, operator-tunable limits for one review."""
    return {
        "timeout_seconds": boundary_review_timeout_seconds(),
        "max_response_bytes": boundary_review_max_response_bytes(),
        "max_request_bytes": ci_boundary_review_max_request_bytes(),
        "max_observed_tools": boundary_review_max_tools(),
        "max_findings": boundary_review_max_findings(),
        "idempotency_ttl_seconds": boundary_review_idempotency_ttl_seconds(),
    }


# ── Outcome vocabulary ────────────────────────────────────────────────────────
def _is_material(severity: str, decision: str) -> bool:
    return severity in MATERIAL_SEVERITIES or decision in MATERIAL_DECISIONS


def compute_semantic_outcome(
    *,
    verified: bool,
    observation_status: str,
    findings: List[Dict[str, Any]],
    review_queue: List[Dict[str, Any]],
    caps_exceeded: List[str],
    fail_policy: str,
) -> str:
    """Pure boundary-result evaluation, deliberately independent of evidence.

    Policy-independent by design, in strict precedence order: a held or
    denied boundary, a breached cap, and an observation that did not complete
    each fire under EVERY policy, including ``quarantine-only``. Receipt
    existence and chain verification are evaluated only after this semantic
    result has been written to the one audit row.
    """
    if fail_policy not in FAIL_POLICIES:
        fail_policy = DEFAULT_FAIL_POLICY

    held = (
        any(f.get("decision") in HELD_FINDING_DECISIONS for f in findings)
        or any(q.get("decision") in ENFORCED_DECISIONS for q in review_queue)
        or any(q.get("status") == "quarantined" for q in review_queue)
        or not verified
    )
    if held:
        return "quarantined"

    if caps_exceeded:
        return "inconclusive"

    if observation_status != "observed":
        return "inconclusive"

    if fail_policy == "quarantine-only":
        return "advisory" if (findings or review_queue) else "clean"

    if fail_policy == "any-finding":
        return "review_required" if (findings or review_queue) else "clean"

    material = bool(review_queue) or any(
        _is_material(str(f.get("severity") or "none"), str(f.get("decision") or ""))
        for f in findings
    )
    if material:
        return "review_required"
    return "advisory" if findings else "clean"


def _receipt_is_valid(receipt: Dict[str, Any]) -> bool:
    audit_id = receipt.get("audit_id")
    return (
        isinstance(audit_id, int)
        and not isinstance(audit_id, bool)
        and audit_id > 0
        and receipt.get("hash_chained") is True
        and receipt.get("tamper_evident") is True
        and receipt.get("chain_verified") is True
        and receipt.get("receipt_verification_state") == "verified"
        and receipt.get("externally_signed") is False
        and receipt.get("independently_anchored") is False
    )


def compute_outcome(review: Dict[str, Any], fail_policy: str) -> str:
    """Evidence-aware outcome. Invalid or absent receipt evidence fails closed."""
    semantic = compute_semantic_outcome(
        verified=bool((review.get("server") or {}).get("verified", False)),
        observation_status=str((review.get("observation") or {}).get("status") or ""),
        findings=list(review.get("findings") or []),
        review_queue=list(review.get("review_queue") or []),
        caps_exceeded=list((review.get("caps") or {}).get("exceeded") or []),
        fail_policy=fail_policy,
    )
    receipt = (review.get("evidence") or {}).get("receipt") or {}
    return semantic if _receipt_is_valid(receipt) else "inconclusive"


def exit_code_for(outcome: str) -> int:
    return OUTCOME_EXIT_CODES.get(outcome, OUTCOME_EXIT_CODES["protocol_error"])


# ── Observation ───────────────────────────────────────────────────────────────
async def _observe(
    server: Dict[str, Any], server_id: str, caps: Dict[str, int]
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Read-only fetch of the surface the server is serving right now.

    No database lock is held across this network call — the caller takes its
    coherent snapshot before, and re-checks it after.

    Returns ``(observation, result, hard_findings)``. ``result`` is None when
    nothing usable came back. A surface that fails validation is NOT an
    unavailable observation — it is a definite critical finding.
    """
    observation: Dict[str, Any] = {
        "status": "unavailable",
        "error_class": "",
        "read_only": True,
        "mutated_state": False,
    }
    try:
        server_url = await ensure_safe_outbound_url_async(
            server.get("url") or "", context="MCP discovery"
        )
    except OutboundUrlRejected:
        observation["error_class"] = "registry_url_rejected"
        return observation, None, []

    try:
        result = await fetch_candidate_tool_surface(
            server_url,
            timeout=boundary_review_timeout_seconds(),
            server_id=server_id,
            max_response_bytes=caps["max_response_bytes"],
            max_tools=caps["max_observed_tools"],
        )
    except Exception:
        logger.exception("Boundary review observation failed for %s", server_id)
        observation["error_class"] = "upstream_unreachable"
        return observation, None, []

    if result.get("ok"):
        observation["status"] = "observed"
        return observation, result, []

    error = str(result.get("error") or "")
    if error == "candidate_validation_failed":
        # The server IS reachable and its surface was read — it just contains
        # tool definitions the validator rejects. Definite, not inconclusive.
        observation["status"] = "observed_rejected"
        observation["error_class"] = "surface_validation_failed"
        findings = [
            {
                "scope": "tool",
                "tool_ref": safe_ref((blocked or {}).get("tool_name")),
                "change_types": ["surface_validation_failed"],
                "diff_classification": "surface_validation_failed",
                "threat_class": safe_ref(
                    (blocked or {}).get("threat_type") or "unknown"
                ),
                "severity": "critical",
                "decision": "quarantine",
                "approved_tool_surface_hash": "",
                "observed_tool_surface_hash": "",
            }
            for blocked in (result.get("blocked") or [])
        ]
        findings.sort(key=lambda f: (f["tool_ref"], f["threat_class"]))
        return observation, None, findings[: caps["max_findings"]]

    observation["error_class"] = _ERROR_CLASSES.get(error, "upstream_error")
    return observation, None, []


# ── Comparison ────────────────────────────────────────────────────────────────
def _persisted_surface(stored_tools: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    surface: Dict[str, Dict[str, Any]] = {}
    for tool in stored_tools:
        name = str(tool.get("tool_name") or "")
        if not name:
            continue
        surface[name] = {
            "definition": tool.get("raw_tool_definition") or {},
            "metadata": tool.get("normalized_metadata") or {},
        }
    return surface


def _observed_surface(result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    surface: Dict[str, Dict[str, Any]] = {}
    for entry in result.get("validated_tools") or []:
        definition = entry.get("tool") or {}
        name = str(definition.get("name") or "").strip()
        if not name:
            continue
        surface[name] = {
            "definition": definition,
            "metadata": entry.get("normalized_metadata") or {},
        }
    return surface


def _prepare_surface_snapshot(
    definition: Dict[str, Any],
) -> Tuple[str, Optional[Dict[str, str]]]:
    """Hash one surface without persisting it before receipt verification."""
    if not definition:
        return "", None
    try:
        surface_hash = drift_evidence.tool_surface_hash(definition)
        return surface_hash, {
            "surface_hash": surface_hash,
            "canonical_json": drift_evidence.canonical_surface_json(definition),
        }
    except Exception:
        logger.debug("Failed to prepare tool surface snapshot", exc_info=True)
        return "", None


def _finding_sort_key(finding: Dict[str, Any]) -> Tuple[int, str, str, str]:
    """Total order so two reviews of identical state serialize identically."""
    return (
        -SEVERITY_ORDER.get(str(finding.get("severity") or "none"), 0),
        str(finding.get("scope") or ""),
        str(finding.get("tool_ref") or ""),
        ",".join(str(t) for t in (finding.get("change_types") or [])),
    )


def _compare(
    server_id: str,
    persisted: Dict[str, Dict[str, Any]],
    observed: Dict[str, Dict[str, Any]],
) -> Tuple[
    List[Dict[str, Any]], List[Tuple[Dict[str, Any], Dict[str, Any]]], List[str]
]:
    """Classify persisted-vs-observed drift with the registry's own classifier.

    Returns ``(findings, definition_pairs, internal_reasons)``. Surface
    snapshots are deliberately NOT written here — the caller enforces the
    findings cap first, so a hostile upstream cannot drive unbounded
    evidence writes. Reason strings quote schema field names and classifier
    detail, so they are for the audit row only and never enter the artifact.
    """
    findings: List[Dict[str, Any]] = []
    pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    reasons: List[str] = []

    for name in sorted(set(persisted) & set(observed)):
        approved = persisted[name]
        current = observed[name]
        drift = classify_tool_drift(
            approved["definition"],
            current["definition"],
            approved["metadata"],
            current["metadata"],
        )
        severity = str(drift.get("severity") or "none")
        if severity == "none":
            continue
        reasons.extend(str(reason) for reason in (drift.get("reasons") or []))
        findings.append(
            {
                "scope": "tool",
                "tool_ref": safe_ref(name),
                "change_types": [str(t) for t in (drift.get("types") or [])],
                "diff_classification": drift_evidence.classify_finding_types(
                    drift.get("types") or []
                ),
                "threat_class": "",
                "severity": severity,
                "decision": str(
                    drift.get("action") or ACTION_BY_SEVERITY.get(severity, "monitor")
                ),
                "approved_tool_surface_hash": "",
                "observed_tool_surface_hash": "",
            }
        )
        pairs.append((approved["definition"], current["definition"]))

    if persisted:
        server_findings = classify_server_drift(
            server_id,
            set(persisted),
            set(observed),
            {name: entry["definition"] for name, entry in observed.items()},
        )
        for finding in server_findings:
            name = str(finding.get("tool_name") or "")
            severity = str(finding.get("severity") or "none")
            reasons.append(str(finding.get("reason") or ""))
            findings.append(
                {
                    "scope": "server",
                    "tool_ref": safe_ref(name),
                    "change_types": [str(finding.get("type") or "")],
                    "diff_classification": drift_evidence.classify_finding_types(
                        [str(finding.get("type") or "")]
                    ),
                    "threat_class": "",
                    "severity": severity,
                    "decision": ACTION_BY_SEVERITY.get(severity, "monitor"),
                    "approved_tool_surface_hash": "",
                    "observed_tool_surface_hash": "",
                }
            )
            pairs.append(
                (
                    (persisted.get(name) or {}).get("definition") or {},
                    (observed.get(name) or {}).get("definition") or {},
                )
            )

    order = sorted(range(len(findings)), key=lambda i: _finding_sort_key(findings[i]))
    return [findings[i] for i in order], [pairs[i] for i in order], reasons


def _review_queue(drifted: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """What the gateway is enforcing for this server right now."""
    queue = [
        {
            "tool_ref": safe_ref(tool.get("tool_name")),
            "status": str(tool.get("status") or "active"),
            "severity": str(tool.get("drift_severity") or "none"),
            "decision": str(tool.get("drift_action") or "allow"),
            "enforced_now": str(tool.get("drift_action") or "allow")
            in ENFORCED_DECISIONS,
        }
        for tool in drifted
    ]
    queue.sort(
        key=lambda q: (-SEVERITY_ORDER.get(str(q["severity"]), 0), q["tool_ref"])
    )
    return queue


# ── Evidence ──────────────────────────────────────────────────────────────────
def _top_finding(findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return findings[0] if findings else None


def _record_audit_event(
    server_id: str,
    principal: Dict[str, str],
    findings: List[Dict[str, Any]],
    queue: List[Dict[str, Any]],
    observation: Dict[str, Any],
    outcome: str,
    fail_policy: str,
    reasons: List[str],
    scan_time_ms: float,
    surface_snapshots: List[Dict[str, str]],
) -> Dict[str, Any]:
    """Append and verify exactly one hash-chained audit row for this review.

    The audit log is the internal record and deliberately keeps the full
    classifier reasons and the real server id. None of that reaches the CI
    artifact.
    """
    top = _top_finding(findings)
    severity = _max_severity(
        [str(f.get("severity") or "none") for f in findings]
        + [str(q.get("severity") or "none") for q in queue]
    )
    decision = "allow"
    if outcome == "quarantined":
        decision = "quarantine"
    elif outcome == "review_required":
        decision = "deny"
    elif outcome in ("advisory", "inconclusive"):
        decision = "monitor"

    # Reuse the registry's own drift_status vocabulary so receipts built from
    # this row read the same way as every other drift receipt.
    if severity == "none":
        drift_status = ""
    elif decision == "quarantine":
        drift_status = "quarantined"
    else:
        drift_status = "changed"

    event = {
        "server_id": server_id,
        "tool_name": str(top.get("tool_ref") or "") if top else "",
        "role": principal.get("reviewer") or "",
        "principal_id": principal.get("principal_id") or "",
        "action": decision,
        "matched_rule": "ci_boundary_review",
        "reason": (
            f"CI boundary review for '{server_id}': outcome={outcome}, "
            f"exit_code={exit_code_for(outcome)}, "
            f"observation={observation.get('status')}."
        ),
        "blocked_by": "",
        "verification_level": "chain_verified",
        "drift_status": drift_status,
        "drift_severity": severity,
        "drift_action": decision,
        "drift_types": (top.get("change_types") if top else []) or [],
        "drift_reasons": reasons,
        "drift_baseline_hash": (
            str(top.get("approved_tool_surface_hash") or "") if top else ""
        ),
        "drift_current_hash": (
            str(top.get("observed_tool_surface_hash") or "") if top else ""
        ),
        "observed_error_class": str(observation.get("error_class") or ""),
        # Probe expectations are not applicable to a boundary review.
        "expected_outcome": "",
        "observed_outcome": outcome,
        "observed_status_code": exit_code_for(outcome),
        "boundary_review_metadata": {
            "boundary_review_semantic_outcome": outcome,
            "boundary_review_final_outcome": outcome,
            "boundary_review_final_exit_code": exit_code_for(outcome),
            "fail_policy": fail_policy,
            "receipt_verification_state": "verified",
        },
        "scan_time_ms": round(scan_time_ms, 2),
    }
    try:
        return db.log_verified_mcp_audit_event(event, surface_snapshots)
    except db.MCPAuditReceiptVerificationError:
        logger.exception("CI boundary review receipt verification failed")
        return {"receipt_verification_state": "failed"}
    except Exception:
        logger.exception("Failed to record CI boundary review audit event")
        return {"receipt_verification_state": "append_failed"}


def _evidence_block(
    server_id: str, saved: Dict[str, Any], top: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    audit_id = saved.get("id")
    has_row = (
        isinstance(audit_id, int) and not isinstance(audit_id, bool) and audit_id > 0
    )
    receipt_verification_state = str(
        saved.get("receipt_verification_state") or "append_failed"
    )
    chain_verified = has_row and receipt_verification_state == "verified"
    evidence: Dict[str, Any] = {
        "receipt": {
            "audit_id": audit_id,
            "receipt_path": f"/audit/receipt/{audit_id}" if has_row else "",
            "hash_chained": has_row,
            "chain_verified": chain_verified,
            "tamper_evident": has_row and chain_verified,
            "receipt_verification_state": receipt_verification_state,
            # Stated exactly, not aspirationally.
            "externally_signed": False,
            "independently_anchored": False,
        },
        # The drift record itself carries the raw server id, so it is NOT
        # embedded here. Fetch it from the receipt with `audit.read` and
        # re-derive this digest against it.
        "evidence_ref": None,
        "canonicalization": drift_evidence.CANONICALIZATION,
    }

    if (
        top
        and top.get("approved_tool_surface_hash")
        and top.get("observed_tool_surface_hash")
    ):
        record = drift_evidence.build_drift_record(
            server_id=server_id,
            tool_name=str(top.get("tool_ref") or ""),
            approved_surface_hash=str(top.get("approved_tool_surface_hash") or ""),
            current_surface_hash=str(top.get("observed_tool_surface_hash") or ""),
            finding_types=list(top.get("change_types") or []),
            severity=str(top.get("severity") or "none"),
            decision=str(top.get("decision") or "allow"),
        )
        ref = f"audit://{audit_id}" if audit_id is not None else None
        evidence["evidence_ref"] = drift_evidence.build_evidence_ref(record, ref)
    return evidence


# ── Entry point ───────────────────────────────────────────────────────────────
async def run_boundary_review(
    server_id: str, *, principal: Dict[str, str]
) -> Dict[str, Any]:
    """Run one read-only boundary review and return the sanitized artifact.

    ``principal`` is derived server-side from the authenticated key record and
    is used only for the internal audit row — it never enters the artifact.
    """
    started = time.time()
    caps = effective_caps()
    snapshot = db.get_boundary_review_snapshot(server_id)
    if not snapshot.get("ok"):
        return {"ok": False, "error": "server_not_found"}

    server = snapshot["server"]
    observation, result, hard_findings = await _observe(server, server_id, caps)

    # Re-read the coherent snapshot AFTER the network call. If the baseline,
    # registry state, or review queue moved while we were observing, the
    # comparison we just made is stale: report it, never reconcile it.
    recheck = db.get_boundary_review_snapshot(server_id)
    superseded = not recheck.get("ok") or recheck.get(
        "snapshot_version"
    ) != snapshot.get("snapshot_version")
    if recheck.get("ok"):
        snapshot = recheck
        server = snapshot["server"]

    exceeded: List[str] = []
    findings: List[Dict[str, Any]] = []
    surface_snapshots: List[Dict[str, str]] = []
    reasons: List[str] = []
    observed_hash = ""
    observed_count = 0

    if superseded:
        observation = {
            "status": "superseded",
            "error_class": "snapshot_changed_during_review",
            "read_only": True,
            "mutated_state": False,
        }
    else:
        findings = list(hard_findings)
        if result:
            observed_hash = str(result.get("candidate_surface_hash") or "")
            observed_count = int(result.get("tool_count") or 0)
            compared, pairs, reasons = _compare(
                server_id,
                _persisted_surface(snapshot["tools"]),
                _observed_surface(result),
            )
            findings.extend(compared)
            findings.sort(key=_finding_sort_key)
            # Cap BEFORE any snapshot retention: a hostile upstream must not
            # be able to drive unbounded evidence writes or artifact size.
            if len(findings) > caps["max_findings"]:
                exceeded.append("max_findings")
                findings = findings[: caps["max_findings"]]
            else:
                for finding, (approved_def, observed_def) in zip(compared, pairs):
                    approved_surface_hash, approved_snapshot = (
                        _prepare_surface_snapshot(approved_def)
                    )
                    observed_surface_hash, observed_snapshot = (
                        _prepare_surface_snapshot(observed_def)
                    )
                    finding["approved_tool_surface_hash"] = approved_surface_hash
                    finding["observed_tool_surface_hash"] = observed_surface_hash
                    if approved_snapshot:
                        surface_snapshots.append(approved_snapshot)
                    if observed_snapshot:
                        surface_snapshots.append(observed_snapshot)
        if observation.get("error_class") == "observed_surface_too_large":
            exceeded.append("max_observed_tools")
        if observation.get("error_class") == "upstream_response_too_large":
            exceeded.append("max_response_bytes")

    queue = _review_queue(snapshot["drifted"])
    if len(queue) > caps["max_findings"]:
        exceeded.append("max_review_queue")
        queue = queue[: caps["max_findings"]]

    if observation.get("error_class"):
        reasons.append(f"observation:{observation['error_class']}")

    approved_hash = str((snapshot.get("active") or {}).get("surface_hash") or "")
    review: Dict[str, Any] = {
        "format_version": FORMAT_VERSION,
        "generated_at": _utc_now(),
        "gate": {
            "name": GATE_NAME,
            "outcome": "clean",
            "exit_code": 0,
            "fail_policy": DEFAULT_FAIL_POLICY,
            "evaluated_under": DEFAULT_FAIL_POLICY,
        },
        "server": {
            # Never the raw registered id, even if it is a printable safe
            # string: only an irreversible, stable digest reference.
            "server_ref": opaque_ref(server_id),
            "registered": True,
            "verified": bool(server.get("verified")),
            "registry_class": safe_ref(server.get("registry_class") or ""),
            "environment": safe_ref(server.get("environment") or ""),
        },
        "boundary": {
            "approved_surface_hash": approved_hash,
            "observed_surface_hash": observed_hash,
            "matches_approved_surface": bool(
                observed_hash and approved_hash == observed_hash and not superseded
            ),
            "approved_tool_count": int(
                (snapshot.get("active") or {}).get("tool_count") or 0
            ),
            "observed_tool_count": observed_count,
            "snapshot_version": str(snapshot.get("snapshot_version") or ""),
        },
        "observation": observation,
        "findings": findings,
        "review_queue": queue,
        "gateway_mediation": {
            "call_forwarded": False,
            "server_calls_held": not bool(server.get("verified")),
            "tool_calls_held": sum(
                1 for q in queue if q.get("decision") in ENFORCED_DECISIONS
            ),
            "note": (
                "A boundary review never forwards an MCP tool call. These "
                "counts describe what the gateway would hold for this server."
            ),
        },
        "severity_summary": {
            "max_severity": _max_severity(
                [str(f.get("severity") or "none") for f in findings]
                + [str(q.get("severity") or "none") for q in queue]
            ),
            "finding_count": len(findings),
            "review_queue_count": len(queue),
        },
        "caps": {
            "timeout_seconds": caps["timeout_seconds"],
            "max_response_bytes": caps["max_response_bytes"],
            "max_request_bytes": caps["max_request_bytes"],
            "max_observed_tools": caps["max_observed_tools"],
            "max_findings": caps["max_findings"],
            "idempotency_ttl_seconds": caps["idempotency_ttl_seconds"],
            "exceeded": sorted(set(exceeded)),
        },
        "limitations": list(LIMITATIONS),
        "redaction": {
            "profile": REDACTION_PROFILE,
            "excluded": list(REDACTED_CATEGORIES),
        },
    }

    semantic_outcome = compute_semantic_outcome(
        verified=bool(review["server"]["verified"]),
        observation_status=str(review["observation"].get("status") or ""),
        findings=findings,
        review_queue=queue,
        caps_exceeded=list(review["caps"]["exceeded"]),
        fail_policy=DEFAULT_FAIL_POLICY,
    )
    review["gate"]["boundary_review_semantic_outcome"] = semantic_outcome
    saved = _record_audit_event(
        server_id,
        principal,
        findings,
        queue,
        observation,
        semantic_outcome,
        DEFAULT_FAIL_POLICY,
        reasons[:20],
        (time.time() - started) * 1000,
        surface_snapshots,
    )
    review["evidence"] = _evidence_block(server_id, saved, _top_finding(findings))

    outcome = compute_outcome(review, DEFAULT_FAIL_POLICY)
    if _receipt_is_valid(review["evidence"]["receipt"]):
        assert outcome == semantic_outcome, (
            "evidence-aware boundary-review outcome diverged from its "
            "semantic audit outcome"
        )
    review["gate"]["outcome"] = outcome
    review["gate"]["exit_code"] = exit_code_for(outcome)
    review["gate"]["boundary_review_final_outcome"] = outcome
    review["gate"]["boundary_review_final_exit_code"] = exit_code_for(outcome)
    review["severity_summary"]["material"] = outcome in (
        "review_required",
        "quarantined",
    )
    review["ok"] = True
    return review
