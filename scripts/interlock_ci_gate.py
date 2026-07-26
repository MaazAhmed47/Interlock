#!/usr/bin/env python3
"""
Optional self-hosted CI boundary-review gate for one registered MCP server.

Calls a self-hosted Interlock deployment's read-only boundary-review endpoint,
writes a sanitized JSON + Markdown artifact, and exits with a stable code so a
release pipeline can stop on a boundary the operator has not approved.

Deliberately stdlib-only and free of Interlock imports, so it can be dropped
into a customer pipeline that does not check this repository out — the same
reason ``scripts/verify_drift_evidence.py`` is self-contained.

Transport is locked down on purpose:
  * redirects are never followed (a 3xx is a protocol_error, not a hop);
  * environment proxies are ignored, so HTTP_PROXY/HTTPS_PROXY can never
    receive the credential;
  * TLS certificates are verified;
  * HTTPS is required except for exact loopback development hosts;
  * the response is read under a hard byte budget and validated against a
    strict schema before any of it is trusted.

Usage:
  export INTERLOCK_BASE_URL=https://interlock.internal.example
  export INTERLOCK_CI_API_KEY=...        # environment ONLY, never an argument
  python interlock_ci_gate.py --server-id billing-mcp --output-dir ./artifacts

Exit codes:
  0   clean / advisory      no material review finding
  20  review_required       material drift, or tools awaiting operator review
  21  quarantined           gateway is holding or denying this server or a tool
  22  inconclusive          upstream unavailable, timed out, rate limited,
                            capped, or superseded — never reported as clean
  2   config_error          missing or invalid configuration / arguments
  3   auth_error            credential rejected, or lacks the mcp.review scope
  4   protocol_error        response not understood, redirected, or degenerate

See docs/integrations/ci-boundary-review-gate.md.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

FORMAT_VERSION = "interlock.ci-boundary-review/v1"
GATE_NAME = "interlock-mcp-boundary-review"

BASE_URL_ENV = "INTERLOCK_BASE_URL"
API_KEY_ENV = "INTERLOCK_CI_API_KEY"

JSON_FILENAME = "interlock-boundary-review.json"
MARKDOWN_FILENAME = "interlock-boundary-review.md"

# Hard client-side budget for the response body and therefore the artifact.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# Only these hosts may be reached over plain HTTP, for local development.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# MUST stay identical to core/ci_boundary_review.OUTCOME_EXIT_CODES.
# tests/test_ci_boundary_review_gate.py asserts the two tables match.
OUTCOME_EXIT_CODES = {
    "clean": 0,
    "advisory": 0,
    "review_required": 20,
    "quarantined": 21,
    "inconclusive": 22,
    "config_error": 2,
    "auth_error": 3,
    "protocol_error": 4,
}

OUTCOME_RANK = {
    "clean": 0,
    "advisory": 1,
    "review_required": 2,
    "inconclusive": 3,
    "quarantined": 4,
}

FAIL_POLICIES = ("material", "any-finding", "quarantine-only")
DEFAULT_FAIL_POLICY = "material"

MATERIAL_SEVERITIES = frozenset({"high", "critical"})
MATERIAL_DECISIONS = frozenset({"deny", "quarantine"})
# What the gateway refuses to forward right now (persisted review queue).
ENFORCED_DECISIONS = frozenset({"deny", "quarantine"})
# A newly observed finding only holds the boundary on its own at quarantine
# grade; a deny-grade finding is material, not already-enforced.
HELD_FINDING_DECISIONS = frozenset({"quarantine"})
HELD_DECISIONS = ENFORCED_DECISIONS

SEVERITIES = frozenset({"none", "minor", "moderate", "high", "critical"})
DECISIONS = frozenset({"allow", "monitor", "deny", "quarantine"})
OBSERVATION_STATUSES = frozenset(
    {"observed", "observed_rejected", "unavailable", "superseded", "not_performed"}
)
GATEWAY_OUTCOMES = frozenset(
    {"clean", "advisory", "review_required", "quarantined", "inconclusive"}
)

# Outcomes the gate must never soften, whatever fail policy was chosen: a held
# boundary and an unobservable one are facts, not policy preferences.
POLICY_INDEPENDENT = frozenset({"quarantined", "inconclusive"})

_SAFE_REF_RE = re.compile(r"[^A-Za-z0-9._\-:]")
_MAX_REF_LEN = 80
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# One reverse-proxy path segment: unreserved characters only.
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]+$")

ERROR_LIMITATIONS = [
    "Optional self-hosted CI boundary-review gate. It is not policy-as-code "
    "and it does not gate deployment on its own.",
    "This run did not complete a boundary review, so it proves nothing about "
    "the server's current tool surface.",
    "Agents that connect to the MCP server directly bypass Interlock.",
]

REDACTION = {
    "profile": "default",
    "excluded": [
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
    ],
}


# ── Sanitizers (mirror of core/ci_boundary_review.py) ─────────────────────────
def safe_ref(value):
    """Bounded, non-path-like, injection-safe reference for any name."""
    text = str(value if value is not None else "")
    cleaned = _SAFE_REF_RE.sub("_", text)
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "__")
    if cleaned != text or len(cleaned) > _MAX_REF_LEN:
        import hashlib

        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
        return f"{cleaned[:_MAX_REF_LEN]}~{digest}"
    return cleaned


def opaque_ref(value):
    digest = hashlib.sha256(
        str(value if value is not None else "").encode()
    ).hexdigest()
    return f"sha256:{digest[:16]}"


# ── Credential hygiene ────────────────────────────────────────────────────────
def redact(text, secret):
    """Never let the credential reach stdout, stderr, or an artifact."""
    out = str(text)
    if secret:
        out = out.replace(secret, "***")
    return out


class RedactingParser(argparse.ArgumentParser):
    """argparse echoes the offending token on error; this one does not."""

    secret = ""

    def error(self, message):
        # argparse includes offending argv verbatim. Never echo it: foreign
        # credential formats cannot be reliably recognized or redacted.
        sys.stderr.write("interlock-ci-gate: invalid arguments.\n")
        raise SystemExit(OUTCOME_EXIT_CODES["config_error"])


def credential_on_command_line(argv, secret):
    """True when the credential was passed as an argument instead of via env."""
    if not secret:
        return False
    return any(secret in str(item) for item in argv)


# ── Outcome vocabulary (mirror of core/ci_boundary_review.py) ─────────────────
def is_material(severity, decision):
    return severity in MATERIAL_SEVERITIES or decision in MATERIAL_DECISIONS


def compute_semantic_outcome(
    *,
    verified,
    observation_status,
    findings,
    review_queue,
    caps_exceeded,
    fail_policy,
):
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
        is_material(str(f.get("severity") or "none"), str(f.get("decision") or ""))
        for f in findings
    )
    if material:
        return "review_required"
    return "advisory" if findings else "clean"


def _receipt_is_valid(receipt):
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


def _receipt_verification_failed(receipt):
    """Distinguish a created-but-unverified receipt from a malformed pass.

    A positive audit id plus hash-chain membership means the gateway did create
    the receipt. False or contradictory verification flags are therefore an
    evidence failure (inconclusive), not a response-shape protocol error.
    """
    if receipt.get("receipt_verification_state") in {"failed", "append_failed"}:
        return True
    audit_id = receipt.get("audit_id")
    return (
        isinstance(audit_id, int)
        and not isinstance(audit_id, bool)
        and audit_id > 0
        and receipt.get("hash_chained") is True
        and not _receipt_is_valid(receipt)
    )


def compute_outcome(review, fail_policy):
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


def combine(local_outcome, server_outcome):
    """Take the local policy result, but never soften a policy-independent
    failure the gateway already reported."""
    if server_outcome in POLICY_INDEPENDENT and OUTCOME_RANK.get(
        server_outcome, 0
    ) > OUTCOME_RANK.get(local_outcome, 0):
        return server_outcome
    return local_outcome


# ── Strict response contract ──────────────────────────────────────────────────
class SchemaError(Exception):
    """The deployment's response does not satisfy the documented contract."""


def _require(condition, message):
    if not condition:
        raise SchemaError(message)


def _obj(parent, key):
    value = parent.get(key)
    _require(isinstance(value, dict), f"{key} must be an object")
    return value


def _seq(parent, key):
    value = parent.get(key)
    _require(isinstance(value, list), f"{key} must be a list")
    return value


def _text(parent, key, path):
    value = parent.get(key)
    _require(isinstance(value, str), f"{path}.{key} must be a string")
    return value


def _flag(parent, key, path):
    value = parent.get(key)
    _require(isinstance(value, bool), f"{path}.{key} must be a boolean")
    return value


def _count(parent, key, path):
    value = parent.get(key)
    _require(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0,
        f"{path}.{key} must be a non-negative integer",
    )
    return value


def _hash_field(parent, key, path, allow_empty=True):
    value = _text(parent, key, path)
    if value == "" and allow_empty:
        return value
    _require(bool(_HASH_RE.match(value)), f"{path}.{key} must be sha256:<64 hex>")
    return value


def validate_review(review):
    """Validate the versioned response contract. Raises SchemaError.

    Deliberately strict: unknown outcome names, wrong collection types,
    malformed entries, and missing required fields are all refused rather
    than coerced, so a truncated, stubbed, or half-deployed gateway can never
    read as a pass.
    """
    _require(isinstance(review, dict), "response must be a JSON object")
    _require(
        review.get("format_version") == FORMAT_VERSION,
        "unsupported format_version",
    )
    _require(
        isinstance(review.get("generated_at"), str), "generated_at must be a string"
    )

    gate = _obj(review, "gate")
    outcome = _text(gate, "outcome", "gate")
    _require(outcome in GATEWAY_OUTCOMES, f"unknown gate.outcome '{safe_ref(outcome)}'")
    _text(gate, "name", "gate")
    semantic_outcome = _text(gate, "boundary_review_semantic_outcome", "gate")
    final_outcome = _text(gate, "boundary_review_final_outcome", "gate")
    _require(
        semantic_outcome in GATEWAY_OUTCOMES,
        "gate.boundary_review_semantic_outcome is invalid",
    )
    _require(final_outcome == outcome, "gate final outcome contradicts gate.outcome")
    final_exit = gate.get("boundary_review_final_exit_code")
    _require(
        isinstance(final_exit, int) and not isinstance(final_exit, bool),
        "gate.boundary_review_final_exit_code must be an integer",
    )
    _require(
        final_exit == OUTCOME_EXIT_CODES[outcome],
        "gate final exit code contradicts gate.outcome",
    )

    server = _obj(review, "server")
    _text(server, "server_ref", "server")
    _require(
        bool(re.fullmatch(r"sha256:[0-9a-f]{16}", server["server_ref"])),
        "server.server_ref must be a digest-only identifier",
    )
    _flag(server, "registered", "server")
    _flag(server, "verified", "server")

    boundary = _obj(review, "boundary")
    _hash_field(boundary, "approved_surface_hash", "boundary")
    _hash_field(boundary, "observed_surface_hash", "boundary")
    _flag(boundary, "matches_approved_surface", "boundary")
    _count(boundary, "approved_tool_count", "boundary")
    _count(boundary, "observed_tool_count", "boundary")

    observation = _obj(review, "observation")
    status = _text(observation, "status", "observation")
    _require(
        status in OBSERVATION_STATUSES,
        f"unknown observation.status '{safe_ref(status)}'",
    )
    _text(observation, "error_class", "observation")

    caps = _obj(review, "caps")
    for name in (
        "timeout_seconds",
        "max_response_bytes",
        "max_request_bytes",
        "max_observed_tools",
        "max_findings",
        "idempotency_ttl_seconds",
    ):
        value = caps.get(name)
        _require(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value >= 0,
            f"caps.{name} must be a finite non-negative number",
        )
    _require(isinstance(caps.get("exceeded"), list), "caps.exceeded must be a list")
    for name in caps["exceeded"]:
        _require(isinstance(name, str), "caps.exceeded entries must be strings")

    for index, finding in enumerate(_seq(review, "findings")):
        path = f"findings[{index}]"
        _require(isinstance(finding, dict), f"{path} must be an object")
        _text(finding, "scope", path)
        _text(finding, "tool_ref", path)
        change_types = finding.get("change_types")
        _require(isinstance(change_types, list), f"{path}.change_types must be a list")
        for value in change_types:
            _require(
                isinstance(value, str), f"{path}.change_types entries must be strings"
            )
        severity = _text(finding, "severity", path)
        _require(severity in SEVERITIES, f"{path}.severity is not a known severity")
        decision = _text(finding, "decision", path)
        _require(decision in DECISIONS, f"{path}.decision is not a known decision")
        _hash_field(finding, "approved_tool_surface_hash", path)
        _hash_field(finding, "observed_tool_surface_hash", path)

    for index, entry in enumerate(_seq(review, "review_queue")):
        path = f"review_queue[{index}]"
        _require(isinstance(entry, dict), f"{path} must be an object")
        _text(entry, "tool_ref", path)
        _text(entry, "status", path)
        severity = _text(entry, "severity", path)
        _require(severity in SEVERITIES, f"{path}.severity is not a known severity")
        decision = _text(entry, "decision", path)
        _require(decision in DECISIONS, f"{path}.decision is not a known decision")
        _flag(entry, "enforced_now", path)

    summary = _obj(review, "severity_summary")
    _count(summary, "finding_count", "severity_summary")
    _count(summary, "review_queue_count", "severity_summary")

    mediation = _obj(review, "gateway_mediation")
    _flag(mediation, "call_forwarded", "gateway_mediation")
    _flag(mediation, "server_calls_held", "gateway_mediation")
    _count(mediation, "tool_calls_held", "gateway_mediation")

    receipt = _obj(_obj(review, "evidence"), "receipt")
    _flag(receipt, "hash_chained", "evidence.receipt")
    _flag(receipt, "chain_verified", "evidence.receipt")
    _flag(receipt, "tamper_evident", "evidence.receipt")
    _flag(receipt, "externally_signed", "evidence.receipt")
    _flag(receipt, "independently_anchored", "evidence.receipt")
    receipt_state = _text(receipt, "receipt_verification_state", "evidence.receipt")
    _require(
        receipt_state in {"verified", "failed", "append_failed"},
        "evidence.receipt.receipt_verification_state is invalid",
    )

    limitations = _seq(review, "limitations")
    _require(bool(limitations), "limitations must not be empty")
    for value in limitations:
        _require(isinstance(value, str), "limitations entries must be strings")

    redaction = _obj(review, "redaction")
    _text(redaction, "profile", "redaction")
    _require(
        isinstance(redaction.get("excluded"), list), "redaction.excluded must be a list"
    )


def require_evidence_for_pass(review):
    """A clean or advisory result must be backed by the evidence the contract
    documents. Anything degenerate is refused rather than passed."""
    server = review["server"]
    boundary = review["boundary"]
    receipt = review["evidence"]["receipt"]

    _require(server["registered"] is True, "clean result without a registered server")
    _require(server["verified"] is True, "clean result without a verified server")
    _require(
        review["observation"]["status"] == "observed",
        "clean result without a completed observation",
    )
    _require(
        not (review.get("caps") or {}).get("exceeded"),
        "clean result with a breached cap",
    )
    _hash_field(boundary, "approved_surface_hash", "boundary", allow_empty=False)
    _hash_field(boundary, "observed_surface_hash", "boundary", allow_empty=False)
    audit_id = receipt.get("audit_id")
    _require(
        isinstance(audit_id, int) and not isinstance(audit_id, bool) and audit_id > 0,
        "clean result without a receipt audit id",
    )
    _require(receipt["hash_chained"] is True, "clean result is not hash chained")
    _require(receipt["tamper_evident"] is True, "clean result is not tamper evident")
    _require(
        receipt["chain_verified"] is True,
        "clean result without a verified evidence chain",
    )
    _require(
        receipt["receipt_verification_state"] == "verified",
        "clean result without an explicitly verified receipt",
    )
    _require(
        receipt["externally_signed"] is False,
        "clean result contradicts the unsigned receipt contract",
    )
    _require(
        receipt["independently_anchored"] is False,
        "clean result contradicts the unanchored receipt contract",
    )
    _require(
        bool(receipt.get("receipt_path")), "clean result without a receipt reference"
    )


# ── Artifacts ─────────────────────────────────────────────────────────────────
def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def error_artifact(outcome, error_class, server_id, fail_policy):
    return {
        "format_version": FORMAT_VERSION,
        "generated_at": utc_now(),
        "gate": {
            "name": GATE_NAME,
            "outcome": outcome,
            "exit_code": OUTCOME_EXIT_CODES[outcome],
            "fail_policy": fail_policy,
            "boundary_review_semantic_outcome": None,
            "boundary_review_final_outcome": outcome,
            "boundary_review_final_exit_code": OUTCOME_EXIT_CODES[outcome],
        },
        # Sanitized reference only — never the raw --server-id value.
        "server": {"server_ref": opaque_ref(server_id), "registered": None},
        "boundary": {},
        "observation": {
            "status": "not_performed",
            "error_class": safe_ref(error_class),
            "read_only": True,
        },
        "findings": [],
        "review_queue": [],
        "severity_summary": {
            "max_severity": "unknown",
            "finding_count": 0,
            "review_queue_count": 0,
            "material": False,
        },
        "caps": {
            "timeout_seconds": None,
            "max_response_bytes": None,
            "max_request_bytes": None,
            "max_observed_tools": None,
            "max_findings": None,
            "idempotency_ttl_seconds": None,
            "exceeded": [],
        },
        "evidence": {"receipt": None, "evidence_ref": None},
        "limitations": list(ERROR_LIMITATIONS),
        "redaction": dict(REDACTION),
    }


def md_escape(value):
    """Neutralize Markdown table breakage AND raw-HTML injection.

    The Markdown file is fed to GitHub Step Summary and to arbitrary internal
    renderers, so `<`, `>`, and `&` are removed rather than trusted to a
    downstream sanitizer.
    """
    text = "".join(ch for ch in str(value if value is not None else "") if ch >= " ")
    for bad, good in (("|", r"\|"), ("`", "'"), ("<", "("), (">", ")"), ("&", "+")):
        text = text.replace(bad, good)
    return text[:200]


def render_markdown(artifact):
    gate = artifact.get("gate") or {}
    server = artifact.get("server") or {}
    boundary = artifact.get("boundary") or {}
    observation = artifact.get("observation") or {}
    summary = artifact.get("severity_summary") or {}
    caps = artifact.get("caps") or {}
    receipt = (artifact.get("evidence") or {}).get("receipt") or {}

    lines = [
        "## Interlock MCP boundary review",
        "",
        f"**Outcome:** `{md_escape(gate.get('outcome'))}` "
        f"(exit {md_escape(gate.get('exit_code'))}) "
        f"under fail policy `{md_escape(gate.get('fail_policy'))}`",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Semantic review outcome | "
        f"`{md_escape(gate.get('boundary_review_semantic_outcome'))}` |",
        "| Final gate outcome | "
        f"`{md_escape(gate.get('boundary_review_final_outcome'))}` "
        f"(exit {md_escape(gate.get('boundary_review_final_exit_code'))}) |",
        f"| Server ref | `{md_escape(server.get('server_ref'))}` |",
        f"| Registry verified | {md_escape(server.get('verified'))} |",
        "| Observation | {status}{detail} |".format(
            status=f"`{md_escape(observation.get('status'))}`",
            detail=(
                f" - `{md_escape(observation.get('error_class'))}`"
                if observation.get("error_class")
                else ""
            ),
        ),
        f"| Approved surface | `{md_escape(boundary.get('approved_surface_hash'))}` |",
        f"| Observed surface | `{md_escape(boundary.get('observed_surface_hash'))}` |",
        f"| Surfaces match | {md_escape(boundary.get('matches_approved_surface'))} |",
        f"| Max severity | `{md_escape(summary.get('max_severity'))}` |",
        f"| Findings | {md_escape(summary.get('finding_count'))} |",
        f"| Awaiting operator review | {md_escape(summary.get('review_queue_count'))} |",
        f"| Caps exceeded | `{md_escape(', '.join(caps.get('exceeded') or []) or 'none')}` |",
        f"| Receipt | `{md_escape(receipt.get('receipt_path'))}` "
        f"(verification state: "
        f"{md_escape(receipt.get('receipt_verification_state'))}; "
        f"chain verified: {md_escape(receipt.get('chain_verified'))}) |",
        "",
    ]

    findings = artifact.get("findings") or []
    if findings:
        lines += [
            "### Findings (approved vs observed)",
            "",
            "| Tool | Scope | Change types | Class | Severity | Decision |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for finding in findings:
            lines.append(
                "| `{tool}` | {scope} | {types} | {klass} | {sev} | {dec} |".format(
                    tool=md_escape(finding.get("tool_ref")),
                    scope=md_escape(finding.get("scope")),
                    types=md_escape(", ".join(finding.get("change_types") or [])),
                    klass=md_escape(finding.get("diff_classification")),
                    sev=md_escape(finding.get("severity")),
                    dec=md_escape(finding.get("decision")),
                )
            )
        lines.append("")

    queue = artifact.get("review_queue") or []
    if queue:
        lines += [
            "### Already awaiting operator review",
            "",
            "| Tool | Status | Severity | Decision | Enforced now |",
            "| --- | --- | --- | --- | --- |",
        ]
        for entry in queue:
            lines.append(
                "| `{tool}` | {status} | {sev} | {dec} | {enf} |".format(
                    tool=md_escape(entry.get("tool_ref")),
                    status=md_escape(entry.get("status")),
                    sev=md_escape(entry.get("severity")),
                    dec=md_escape(entry.get("decision")),
                    enf=md_escape(entry.get("enforced_now")),
                )
            )
        lines.append("")

    mediation = artifact.get("gateway_mediation") or {}
    if mediation:
        lines += [
            "### Gateway mediation",
            "",
            f"- Call forwarded by this review: {md_escape(mediation.get('call_forwarded'))}",
            "- All calls held (server not verified): "
            f"{md_escape(mediation.get('server_calls_held'))}",
            f"- Tools currently held: {md_escape(mediation.get('tool_calls_held'))}",
            "",
        ]

    lines += ["### Limitations", ""]
    for limitation in artifact.get("limitations") or []:
        lines.append(f"- {md_escape(limitation)}")
    lines += [
        "",
        f"_Generated {md_escape(artifact.get('generated_at'))} - "
        f"format `{md_escape(artifact.get('format_version'))}`._",
        "",
    ]
    return "\n".join(lines)


def write_artifacts(output_dir, artifact, secret):
    payload = redact(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False), secret
    )
    markdown = redact(render_markdown(artifact), secret)
    json_path = os.path.join(output_dir, JSON_FILENAME)
    md_path = os.path.join(output_dir, MARKDOWN_FILENAME)
    with open(json_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(payload + "\n")
    with open(md_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(markdown)
    return json_path, md_path


# ── Transport ─────────────────────────────────────────────────────────────────
class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect. Following one would re-send the CI credential to
    a host the operator never configured, and let that host dictate the gate
    result."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener():
    """Opener with no proxy handling, no redirects, and verified TLS."""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),  # ignore HTTP(S)_PROXY entirely
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )


def _is_tls_failure(reason):
    """True when a urllib failure was really a TLS/certificate rejection."""
    seen = 0
    while reason is not None and seen < 8:
        if isinstance(reason, ssl.SSLError):
            return True
        reason = getattr(reason, "reason", None)
        seen += 1
    return False


def normalize_path_prefix(path):
    """Return (normalized_prefix, error_class) for a reverse-proxy path prefix.

    A deployment behind a reverse proxy legitimately lives at something like
    ``https://host/interlock``. Everything else about the path is refused:
    percent-encoding (which could smuggle CR/LF or a second path), control
    characters, whitespace, backslashes, ``.``/``..`` segments, and doubled
    slashes whose meaning depends on the server.
    """
    raw = str(path or "")
    if raw in ("", "/"):
        return "", None
    if "%" in raw:
        return None, "base_url_path_percent_encoded"
    if "//" in raw:
        return None, "base_url_path_ambiguous"
    if "\\" in raw:
        return None, "base_url_path_invalid"
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        return None, "base_url_path_invalid"
    if not raw.startswith("/"):
        return None, "base_url_path_invalid"
    trimmed = raw[:-1] if raw.endswith("/") else raw
    if trimmed in ("", "/"):
        return "", None
    segments = trimmed.split("/")[1:]
    for segment in segments:
        if segment in ("", ".", ".."):
            return None, "base_url_path_traversal"
        if not _PATH_SEGMENT_RE.match(segment):
            return None, "base_url_path_invalid"
    return "/" + "/".join(segments), None


def validate_base_url(base_url):
    """Return (normalized_base, error_class). Fails closed on anything odd."""
    raw = str(base_url or "")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        return None, "invalid_base_url"
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError:
        return None, "invalid_base_url"
    if parts.scheme not in ("http", "https"):
        return None, "invalid_base_url_scheme"
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return None, "base_url_contains_userinfo"
    if "%" in parts.netloc:
        return None, "invalid_base_url_host"
    if parts.query or parts.fragment:
        return None, "base_url_contains_query_or_fragment"
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None, "invalid_base_url_host"
    if not host:
        return None, "invalid_base_url_host"
    authority = parts.netloc
    if authority.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::([0-9]+))?", authority)
        if not match:
            return None, "invalid_base_url_host"
        try:
            address = ipaddress.IPv6Address(match.group(1))
        except ValueError:
            return None, "invalid_base_url_host"
        if match.group(1).lower() != address.compressed:
            return None, "invalid_base_url_host"
        host = address.compressed
    else:
        match = re.fullmatch(r"([^:]+)(?::([0-9]+))?", authority)
        if not match:
            return None, "invalid_base_url_host"
        raw_host = match.group(1)
        if raw_host.endswith(".") or not raw_host.isascii():
            return None, "invalid_base_url_host"
        if re.fullmatch(r"[0-9.]+", raw_host):
            try:
                address = ipaddress.IPv4Address(raw_host)
            except ValueError:
                return None, "invalid_base_url_host"
            if raw_host != str(address):
                return None, "invalid_base_url_host"
            host = str(address)
        else:
            labels = raw_host.split(".")
            if any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
                for label in labels
            ):
                return None, "invalid_base_url_host"
            host = raw_host.lower()
    if parts.scheme == "http" and host not in LOOPBACK_HOSTS:
        return None, "insecure_base_url_scheme"
    prefix, path_error = normalize_path_prefix(parts.path)
    if path_error:
        return None, path_error
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority = f"{authority}:{port}"
    # Built by concatenation of already-validated parts. urljoin is avoided
    # deliberately: it would let a path or scheme in one component silently
    # replace another.
    return f"{parts.scheme}://{authority}{prefix}", None


def review_url(base_url, server_id):
    return "{base}/mcp/servers/{sid}/boundary-review".format(
        base=base_url,
        sid=urllib.parse.quote(server_id, safe=""),
    )


def fetch_review(base_url, server_id, api_key, timeout, idempotency_key):
    """Return ``(outcome_or_None, review_or_None, error_class)``.

    A non-None outcome means the gate stops here. Response bodies are never
    surfaced: only the status class travels into logs and artifacts.
    """
    request = urllib.request.Request(
        review_url(base_url, server_id),
        data=b"",
        headers={
            "x-api-key": api_key,
            "accept": "application/json",
            "content-type": "application/json",
            "content-length": "0",
            "idempotency-key": idempotency_key,
        },
        method="POST",
    )
    opener = build_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            if 300 <= getattr(response, "status", 200) < 400:
                return "protocol_error", None, "redirect_refused"
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        if 300 <= status < 400:
            # urllib surfaces a refused redirect as an HTTPError.
            return "protocol_error", None, "redirect_refused"
        if status in (401, 403):
            return "auth_error", None, f"http_{status}"
        if status == 404:
            return "config_error", None, "server_not_registered"
        if status == 409:
            code = _error_code(exc)
            if code == "idempotency_key_conflict":
                return "auth_error", None, "idempotency_key_conflict"
            return "inconclusive", None, "review_in_progress"
        if status == 429:
            return "inconclusive", None, "gateway_rate_limited"
        if status >= 500:
            return "inconclusive", None, f"gateway_http_{status}"
        return "protocol_error", None, f"http_{status}"
    except urllib.error.URLError as exc:
        # urllib wraps the real cause, so a certificate failure arrives as a
        # URLError whose .reason is an SSLError. Unwrap it: a TLS failure is a
        # refused peer identity, not a transient outage a pipeline should
        # retry through.
        if _is_tls_failure(getattr(exc, "reason", None)):
            return "protocol_error", None, "tls_verification_failed"
        return "inconclusive", None, "gateway_unreachable"
    except ssl.SSLError:
        return "protocol_error", None, "tls_verification_failed"
    except (socket.timeout, TimeoutError, OSError, ValueError):
        return "inconclusive", None, "gateway_unreachable"

    if len(raw) > MAX_RESPONSE_BYTES:
        return "protocol_error", None, "response_too_large"

    try:
        review = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "protocol_error", None, "unparseable_response"
    try:
        validate_review(review)
    except SchemaError:
        return "protocol_error", None, "response_schema_violation"
    return None, review, ""


def _error_code(exc):
    """Read the machine-readable error code from a gateway error body without
    surfacing any of its text."""
    try:
        body = json.loads(exc.read(8192).decode("utf-8"))
    except Exception:
        return ""
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict):
        code = detail.get("error")
        return code if isinstance(code, str) else ""
    return ""


# ── Entry point ───────────────────────────────────────────────────────────────
def build_parser(secret):
    parser = RedactingParser(
        prog="interlock_ci_gate.py",
        description=(
            "Optional self-hosted CI boundary-review gate for one registered "
            "MCP server."
        ),
    )
    parser.secret = secret
    parser.add_argument(
        "--server-id",
        required=True,
        help="Registered MCP server id to review.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory the sanitized JSON and Markdown artifacts are written to.",
    )
    parser.add_argument(
        "--fail-policy",
        choices=FAIL_POLICIES,
        default=DEFAULT_FAIL_POLICY,
        help=(
            "Which findings fail the gate. Default 'material'. A held or "
            "denied boundary, a breached cap, an incomplete observation, and "
            "an unverified evidence chain fail under every policy."
        ),
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=(
            f"Interlock base URL. Defaults to ${BASE_URL_ENV}. HTTPS is "
            "required except for loopback hosts. The credential is read from "
            "the environment only."
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=60.0,
        help="HTTP timeout for the review request (default 60).",
    )
    return parser


def note(message, secret):
    sys.stderr.write("interlock-ci-gate: " + redact(message, secret) + "\n")


def emit(args, artifact, outcome, secret):
    """Write both artifacts and return the exit code. Every failure the gate
    can attribute to a known output directory still produces evidence."""
    try:
        json_path, md_path = write_artifacts(args.output_dir, artifact, secret)
    except OSError:
        note("could not write artifacts to the requested output directory.", secret)
        return OUTCOME_EXIT_CODES["config_error"]

    exit_code = OUTCOME_EXIT_CODES[outcome]
    sys.stdout.write(
        "interlock-ci-gate: outcome={outcome} exit={code} policy={policy}\n".format(
            outcome=outcome, code=exit_code, policy=args.fail_policy
        )
    )
    sys.stdout.write("interlock-ci-gate: wrote JSON and Markdown artifacts\n")
    return exit_code


def run(args, argv, secret):
    def bail(outcome, error_class, message):
        note(message, secret)
        return emit(
            args,
            error_artifact(outcome, error_class, args.server_id, args.fail_policy),
            outcome,
            secret,
        )

    if credential_on_command_line(argv, secret):
        return bail(
            "config_error",
            "credential_on_command_line",
            f"the CI credential must be supplied through ${API_KEY_ENV} only, "
            "never as a command-line argument.",
        )
    if not secret:
        return bail("config_error", "missing_credential", f"${API_KEY_ENV} is not set.")

    raw_base = (args.base_url or os.environ.get(BASE_URL_ENV) or "").strip()
    if not raw_base:
        return bail(
            "config_error",
            "missing_base_url",
            f"no Interlock base URL: set ${BASE_URL_ENV} or pass --base-url.",
        )
    base_url, url_error = validate_base_url(raw_base)
    if url_error:
        return bail(
            "config_error",
            url_error,
            {
                "invalid_base_url": "base URL could not be parsed.",
                "invalid_base_url_scheme": "base URL must be an http(s) URL.",
                "invalid_base_url_host": "base URL has no usable host.",
                "base_url_contains_userinfo": (
                    "base URL must not embed credentials (user:password@host)."
                ),
                "base_url_contains_query_or_fragment": (
                    "base URL must not carry a query string or fragment."
                ),
                "insecure_base_url_scheme": (
                    "plain HTTP is only allowed for loopback hosts "
                    "(localhost, 127.0.0.1, [::1]); use HTTPS."
                ),
                "base_url_path_percent_encoded": (
                    "base URL path must not be percent-encoded."
                ),
                "base_url_path_ambiguous": (
                    "base URL path must not contain doubled slashes."
                ),
                "base_url_path_traversal": (
                    "base URL path must not contain '.' or '..' segments."
                ),
                "base_url_path_invalid": (
                    "base URL path may only be a simple prefix such as " "/interlock."
                ),
            }.get(url_error, "base URL rejected."),
        )
    if not str(args.server_id).strip():
        return bail(
            "config_error", "missing_server_id", "--server-id must not be empty."
        )
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        return bail(
            "config_error", "invalid_timeout", "--timeout-seconds must be positive."
        )

    outcome, review, error_class = fetch_review(
        base_url,
        args.server_id,
        secret,
        args.timeout_seconds,
        secrets.token_urlsafe(48)[:64],
    )

    if outcome is not None:
        return emit(
            args,
            error_artifact(outcome, error_class, args.server_id, args.fail_policy),
            outcome,
            secret,
        )

    artifact = {k: v for k, v in review.items() if k != "ok"}
    server_outcome = str((artifact.get("gate") or {}).get("outcome") or "")
    local_semantic = compute_semantic_outcome(
        verified=bool((artifact.get("server") or {}).get("verified", False)),
        observation_status=str((artifact.get("observation") or {}).get("status") or ""),
        findings=list(artifact.get("findings") or []),
        review_queue=list(artifact.get("review_queue") or []),
        caps_exceeded=list((artifact.get("caps") or {}).get("exceeded") or []),
        fail_policy=args.fail_policy,
    )
    # Preserve the strict protocol distinction for a response whose substantive
    # result would pass but whose claimed receipt is degenerate. A genuine
    # gateway-side evidence failure is already reported as inconclusive.
    if OUTCOME_EXIT_CODES[local_semantic] == 0:
        try:
            require_evidence_for_pass(artifact)
        except SchemaError:
            receipt = (artifact.get("evidence") or {}).get("receipt") or {}
            if not _receipt_verification_failed(receipt):
                return emit(
                    args,
                    error_artifact(
                        "protocol_error",
                        "incomplete_clean_response",
                        args.server_id,
                        args.fail_policy,
                    ),
                    "protocol_error",
                    secret,
                )

    local_outcome = compute_outcome(artifact, args.fail_policy)
    outcome = combine(local_outcome, server_outcome)

    artifact["gate"] = {
        "name": GATE_NAME,
        "outcome": outcome,
        "exit_code": OUTCOME_EXIT_CODES[outcome],
        "fail_policy": args.fail_policy,
        "boundary_review_semantic_outcome": local_semantic,
        "boundary_review_final_outcome": outcome,
        "boundary_review_final_exit_code": OUTCOME_EXIT_CODES[outcome],
        "gateway_outcome": server_outcome,
        "gateway_fail_policy": (review.get("gate") or {}).get("evaluated_under"),
    }
    return emit(args, artifact, outcome, secret)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    secret = (os.environ.get(API_KEY_ENV) or "").strip()

    # Unparsable arguments are the one failure with no artifact: the gate does
    # not yet know where the operator wanted it written.
    args = build_parser(secret).parse_args(argv)

    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            note("output directory could not be created.", secret)
            return OUTCOME_EXIT_CODES["config_error"]

    try:
        return run(args, argv, secret)
    except SystemExit:
        raise
    except BaseException:
        # No traceback, no undocumented exit 1: an unexpected internal error
        # is a protocol_error the pipeline can act on, and it still ships an
        # artifact because the output directory is already known.
        note("unexpected internal error; reporting protocol_error.", secret)
        return emit(
            args,
            error_artifact(
                "protocol_error", "internal_error", args.server_id, args.fail_policy
            ),
            "protocol_error",
            secret,
        )


if __name__ == "__main__":
    sys.exit(main())
