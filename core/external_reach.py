"""Destination-aware external reach drift profiling.

This module baselines where a tool is allowed to send or publish data. It is
separate from generic metadata externality: externality says a tool may reach
outside; this module tracks the approved destination boundary.

Profiles are evidence-safe. They keep URL hosts and email domains because those
are the security boundary, but do not store full URLs, email local-parts, raw
channels, buckets, paths, or payload values. Opaque destinations are hashed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from core.drift_evidence import canonical_json_bytes

SCHEMA_ID = "interlock.external-reach-drift-record"
SCHEMA_VERSION = "1"
SCHEMA_URL = "https://getinterlock.dev/schemas/external-reach-drift-record.v1.json"
CANONICALIZATION = "json/jcs-rfc8785"
EVIDENCE_TYPE = "external-reach-drift"
DIGEST_ALG = "sha256"

SEVERITY_ORDER = {"none": 0, "minor": 1, "moderate": 2, "high": 3, "critical": 4}
ACTION_BY_SEVERITY = {
    "none": "allow",
    "minor": "monitor",
    "moderate": "monitor",
    "high": "deny",
    "critical": "quarantine",
}

_DESTINATION_KEY_TOKENS = (
    "url",
    "uri",
    "webhook",
    "callback",
    "endpoint",
    "destination",
    "recipient",
    "email",
    "channel",
    "bucket",
    "topic",
    "queue",
    "host",
    "domain",
)

_OPAQUE_KEY_TOKENS = ("channel", "bucket", "topic", "queue")
_SENSITIVE_KEY_TOKENS = (
    "secret",
    "token",
    "api_key",
    "apikey",
    "password",
    "credential",
    "private_key",
    "ssn",
    "pii",
    "phi",
    "card",
    "key",
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_HOSTISH_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{1,5})?$")

_INTERNAL_SUFFIXES = (".local", ".internal", ".localhost")
_INTERNAL_HOSTS = {"localhost", "metadata.google.internal", "host.docker.internal"}


def _digest_value(value: Any) -> str:
    return f"{DIGEST_ALG}:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def _hash_opaque(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{kind}_hash:{digest}"


def _normalized_key(key: Any) -> str:
    return str(key or "").strip().lower().replace("-", "_")


def _is_destination_key(key: str) -> bool:
    return any(token in key for token in _DESTINATION_KEY_TOKENS)


def _is_opaque_key(key: str) -> bool:
    return any(token in key for token in _OPAQUE_KEY_TOKENS)


def _has_sensitive_indicator(key: str, value: Any) -> bool:
    if any(token in key for token in _SENSITIVE_KEY_TOKENS):
        if isinstance(value, bool):
            return bool(value)
        return value not in (None, "", [], {})
    if isinstance(value, dict):
        return any(
            _has_sensitive_indicator(_normalized_key(k), v) for k, v in value.items()
        )
    if isinstance(value, list):
        return any(_has_sensitive_indicator(key, item) for item in value)
    return False


def _strip_port(host: str) -> str:
    host = host.strip().lower().strip("[]")
    if ":" in host and not host.count(":") > 1:
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def _is_internal_host(host: str) -> bool:
    host = _strip_port(host)
    if not host:
        return False
    if host in _INTERNAL_HOSTS or host.endswith(_INTERNAL_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def _host_destination(host: str) -> tuple[str, str]:
    host = _strip_port(host)
    kind = (
        "internal_destinations" if _is_internal_host(host) else "external_destinations"
    )
    return kind, f"url_host:{host}"


def _destinations_from_string(key: str, value: str) -> Dict[str, Set[str]]:
    out = {
        "external_destinations": set(),
        "internal_destinations": set(),
        "hashed_destinations": set(),
    }
    value = str(value or "").strip()
    if not value:
        return out

    parsed = urlparse(value)
    if (
        parsed.scheme in {"http", "https", "ws", "wss", "ftp", "sftp"}
        and parsed.hostname
    ):
        bucket, item = _host_destination(parsed.hostname)
        out[bucket].add(item)
        return out

    if "@" in value:
        for token in re.split(r"[\s,;<>]+", value):
            token = token.strip().strip("'\"")
            if "@" not in token:
                continue
            domain = token.rsplit("@", 1)[1].strip().lower().rstrip(".")
            if not domain or "." not in domain:
                continue
            bucket = (
                "internal_destinations"
                if _is_internal_host(domain)
                else "external_destinations"
            )
            out[bucket].add(f"email_domain:{domain}")

    if out["external_destinations"] or out["internal_destinations"]:
        return out

    if _HOSTISH_RE.match(value):
        bucket, item = _host_destination(value)
        out[bucket].add(item)
        return out

    if _is_opaque_key(key):
        out["hashed_destinations"].add(_hash_opaque(key, value))

    return out


def _walk_arguments(value: Any, key: str = "") -> Dict[str, Any]:
    external: Set[str] = set()
    internal: Set[str] = set()
    hashed: Set[str] = set()
    destination_keys: Set[str] = set()
    sensitive = False

    def visit(item: Any, item_key: str) -> None:
        nonlocal sensitive
        norm_key = _normalized_key(item_key)
        sensitive = sensitive or _has_sensitive_indicator(norm_key, item)
        if isinstance(item, dict):
            for child_key, child_value in item.items():
                visit(child_value, child_key)
            return
        if isinstance(item, list):
            for child in item:
                visit(child, norm_key)
            return
        if not _is_destination_key(norm_key):
            return
        destination_keys.add(norm_key)
        found = _destinations_from_string(norm_key, str(item))
        external.update(found["external_destinations"])
        internal.update(found["internal_destinations"])
        hashed.update(found["hashed_destinations"])

    visit(value, key)
    return {
        "external_destinations": external,
        "internal_destinations": internal,
        "hashed_destinations": hashed,
        "destination_keys": destination_keys,
        "sensitive_payload_indicator": sensitive,
    }


def _profile_fingerprint(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "profile_version": profile.get("profile_version"),
        "external_destinations": list(profile.get("external_destinations") or []),
        "internal_destinations": list(profile.get("internal_destinations") or []),
        "hashed_destinations": list(profile.get("hashed_destinations") or []),
        "destination_kinds": list(profile.get("destination_kinds") or []),
        "sensitive_payload_indicator": bool(profile.get("sensitive_payload_indicator")),
    }


def build_external_reach_profile(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Build an evidence-safe destination profile from tool-call arguments."""
    walked = _walk_arguments(arguments or {})
    external = sorted(walked["external_destinations"])
    internal = sorted(walked["internal_destinations"])
    hashed = sorted(walked["hashed_destinations"])
    kinds = sorted({item.split(":", 1)[0] for item in [*external, *internal, *hashed]})
    profile = {
        "profile_version": "1",
        "external_destinations": external,
        "internal_destinations": internal,
        "hashed_destinations": hashed,
        "destination_keys": sorted(walked["destination_keys"]),
        "destination_kinds": kinds,
        "sensitive_payload_indicator": bool(walked["sensitive_payload_indicator"]),
    }
    profile["profile_hash"] = external_reach_profile_hash(profile)
    return profile


def external_reach_profile_hash(profile: Dict[str, Any]) -> str:
    return _digest_value(_profile_fingerprint(profile or {}))


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


def classify_external_reach_drift(
    baseline_profile: Optional[Dict[str, Any]],
    current_profile: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    baseline_profile = baseline_profile or {}
    current_profile = current_profile or {}
    baseline_external = set(baseline_profile.get("external_destinations") or [])
    current_external = set(current_profile.get("external_destinations") or [])
    baseline_hashed = set(baseline_profile.get("hashed_destinations") or [])
    current_hashed = set(current_profile.get("hashed_destinations") or [])
    added_external = sorted(current_external - baseline_external)
    added_hashed = sorted(current_hashed - baseline_hashed)

    findings: List[Dict[str, str]] = []
    if added_external or added_hashed:
        if current_profile.get("sensitive_payload_indicator"):
            findings.append(
                _finding(
                    "external_secret_destination_added",
                    "critical",
                    "External destination expanded while sensitive payload indicators were present.",
                )
            )
        else:
            reasons = []
            if added_external:
                reasons.append(f"new external destinations: {added_external}")
            if added_hashed:
                reasons.append(f"new opaque destination hashes: {added_hashed}")
            findings.append(
                _finding(
                    "external_destination_added",
                    "high",
                    "External reach expanded beyond the approved destination baseline: "
                    + "; ".join(reasons)
                    + ".",
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
        "baseline_profile_hash": external_reach_profile_hash(baseline_profile),
        "current_profile_hash": external_reach_profile_hash(current_profile),
    }


def build_external_reach_drift_record(
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
        "diff_classification": "external-reach",
        "finding_types": finding_types,
        "severity": str(severity or "none"),
        "decision": str(decision or "allow"),
    }


def compute_external_reach_drift_digest(record: Dict[str, Any]) -> str:
    return _digest_value(record or {})


def build_external_reach_drift_record_from_audit_row(
    row: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    finding_types = row.get("drift_types") or []
    if isinstance(finding_types, str):
        try:
            finding_types = json.loads(finding_types)
        except (json.JSONDecodeError, TypeError):
            finding_types = []
    finding_types = [str(value) for value in (finding_types or []) if str(value)]
    if not any(value.startswith("external_") for value in finding_types):
        return None
    severity = str(row.get("drift_severity") or "none").lower()
    if severity in ("", "none"):
        return None
    baseline_hash = str(row.get("drift_baseline_hash") or "")
    current_hash = str(row.get("drift_current_hash") or "")
    if not baseline_hash or not current_hash:
        return None
    return build_external_reach_drift_record(
        server_id=row.get("server_id") or "",
        tool_name=row.get("tool_name") or "",
        baseline_profile_hash=baseline_hash,
        current_profile_hash=current_hash,
        finding_types=finding_types,
        severity=severity,
        decision=row.get("drift_action") or row.get("action") or "allow",
    )


def build_external_reach_drift_evidence_ref(
    record: Dict[str, Any], ref: Optional[str] = None
) -> Dict[str, Any]:
    evidence_ref = {
        "type": EVIDENCE_TYPE,
        "digest": compute_external_reach_drift_digest(record),
        "canonicalization": CANONICALIZATION,
        "schema": SCHEMA_URL,
    }
    if ref:
        evidence_ref["ref"] = ref
    return evidence_ref
