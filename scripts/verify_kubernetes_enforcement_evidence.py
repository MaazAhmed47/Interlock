"""Fail-closed verifier for retained Kubernetes enforcement evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

try:
    from scripts.kubernetes_enforcement_cases import REQUIRED_CASES
except ModuleNotFoundError:  # direct script execution
    from kubernetes_enforcement_cases import REQUIRED_CASES  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT
    / "deploy"
    / "kubernetes-enforcement"
    / "evidence-schema"
    / "report.schema.json"
)
PROFILE = ROOT / "deploy" / "kubernetes-enforcement"
PROBE_PREFIX = "INTERLOCK_K8S_RESULT "
MAX_EVIDENCE_AGE = timedelta(hours=24)
SENSITIVE_PATTERNS = (
    re.compile(r"authorization\s*:", re.IGNORECASE),
    re.compile(r"proxy-authorization\s*:", re.IGNORECASE),
    re.compile(r"\b(?:postgres(?:ql)?|redis|mysql)://", re.IGNORECASE),
    re.compile(r"https?://[^\s\"']*\?[^\s\"']+", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\blf_(?:free|developer|team|enterprise)_[A-Za-z0-9_-]+"),
    re.compile(
        r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
        r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
    ),
)


class EvidenceVerificationError(RuntimeError):
    """Evidence is incomplete, inconsistent, stale, or unsafe to retain."""


def _bundle_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.as_posix()):
        relative = path.relative_to(ROOT).as_posix().encode()
        body = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return digest.hexdigest()


def expected_profile_digests() -> dict[str, str]:
    """Recompute the checked-in configuration identities the report must bind."""

    manifest_paths = list((PROFILE / "manifests").glob("*.yaml"))
    manifest_paths.append(PROFILE / "kind" / "cluster.yaml")
    versions_path = PROFILE / "kind" / "versions.json"
    versions = json.loads(versions_path.read_text(encoding="utf-8"))
    return {
        "manifest_bundle_sha256": _bundle_digest(manifest_paths),
        "config_sha256": _bundle_digest([versions_path]),
        "calico_manifest_sha256": versions["calico"]["manifest_sha256"],
    }


def _reject_sensitive_text(text: str) -> None:
    if any(pattern.search(text) for pattern in SENSITIVE_PATTERNS):
        raise EvidenceVerificationError("sensitive value in evidence")


def parse_probe_output(stdout: str) -> dict[str, Any]:
    """Extract exactly one sanitized machine record from pod output."""

    _reject_sensitive_text(stdout)
    records = [
        line[len(PROBE_PREFIX) :]
        for line in stdout.splitlines()
        if line.startswith(PROBE_PREFIX)
    ]
    if not records:
        raise EvidenceVerificationError("missing probe result")
    if len(records) != 1:
        raise EvidenceVerificationError("duplicate probe result")
    try:
        value = json.loads(records[0])
    except json.JSONDecodeError as exc:
        raise EvidenceVerificationError("malformed probe result") from exc
    if not isinstance(value, dict):
        raise EvidenceVerificationError("malformed probe result")
    return value


def _parse_utc(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise EvidenceVerificationError(f"malformed {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise EvidenceVerificationError(f"{field} is not UTC")
    return parsed


def _validate_schema(report: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(report), key=lambda e: list(e.path)
    )
    if errors:
        location = ".".join(str(item) for item in errors[0].path) or "root"
        raise EvidenceVerificationError(f"schema validation failed at {location}")


def verify_report(
    report: dict[str, Any],
    *,
    expected_source_sha: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate schema, exact case set, identity, freshness, and counters."""

    _reject_sensitive_text(json.dumps(report, sort_keys=True))
    raw_cases = report.get("cases")
    if isinstance(raw_cases, list):
        raw_ids = [item.get("case_id") for item in raw_cases if isinstance(item, dict)]
        if len(raw_ids) != len(set(raw_ids)):
            raise EvidenceVerificationError("duplicate case")
        if set(REQUIRED_CASES) - set(raw_ids):
            raise EvidenceVerificationError("missing required case")
    _validate_schema(report)
    if report["source_sha"] != expected_source_sha:
        raise EvidenceVerificationError("source SHA mismatch")
    if report["digests"] != expected_profile_digests():
        raise EvidenceVerificationError("repository digest mismatch")

    started = _parse_utc(report["run_started_at"], "run_started_at")
    completed = _parse_utc(report["run_completed_at"], "run_completed_at")
    if completed < started:
        raise EvidenceVerificationError("run timestamp order mismatch")
    if now is not None:
        normalized_now = now.astimezone(timezone.utc)
        if (
            completed > normalized_now + timedelta(minutes=5)
            or normalized_now - completed > MAX_EVIDENCE_AGE
        ):
            raise EvidenceVerificationError("stale evidence")

    cases = report["cases"]
    ids = [item["case_id"] for item in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise EvidenceVerificationError("duplicate case")
    missing = sorted(set(REQUIRED_CASES) - set(ids))
    unknown = sorted(set(ids) - set(REQUIRED_CASES))
    if missing:
        raise EvidenceVerificationError("missing required case")
    if unknown:
        raise EvidenceVerificationError("unknown case")

    manifest_digest = report["digests"]["manifest_bundle_sha256"]
    config_digest = report["digests"]["config_sha256"]
    for item in cases:
        expected = REQUIRED_CASES[item["case_id"]]
        if item["status"] != "passed":
            raise EvidenceVerificationError("non-passing status")
        if item["expected_result"] != expected.expected_result:
            raise EvidenceVerificationError("expectation registry mismatch")
        if item["actual_result"] != expected.expected_result:
            raise EvidenceVerificationError("result mismatch")
        if item["source_workload"] != expected.source_workload:
            raise EvidenceVerificationError("source workload mismatch")
        if item["destination_class"] != expected.destination_class:
            raise EvidenceVerificationError("destination class mismatch")
        if item["enforcement_layer"] != expected.enforcement_layer:
            raise EvidenceVerificationError("enforcement layer mismatch")
        if item["failure_category"] != expected.failure_category:
            raise EvidenceVerificationError("failure category mismatch")
        if item["source_sha"] != expected_source_sha:
            raise EvidenceVerificationError("case source SHA mismatch")
        if item["manifest_bundle_sha256"] != manifest_digest:
            raise EvidenceVerificationError("manifest digest mismatch")
        if item["config_sha256"] != config_digest:
            raise EvidenceVerificationError("config digest mismatch")
        if item["verifier_outcome"] != "accepted":
            raise EvidenceVerificationError("case verifier outcome mismatch")
        case_started = _parse_utc(item["started_at"], "case started_at")
        case_completed = _parse_utc(item["completed_at"], "case completed_at")
        if not (started <= case_started <= case_completed <= completed):
            raise EvidenceVerificationError("case timestamp mismatch")

    controls = report["negative_controls"]
    if not all(controls.values()):
        raise EvidenceVerificationError("negative control failed")

    observations = report["observations"]
    loaded_image = observations["loaded_image"]
    expected_image_reference = f"interlock-kubernetes-enforcement:{expected_source_sha}"
    if loaded_image["reference"] != expected_image_reference:
        raise EvidenceVerificationError("loaded image reference mismatch")
    if loaded_image["build_image_id"] != report["environment"]["lab_image"]:
        raise EvidenceVerificationError("loaded image build identity mismatch")
    identities = [item["identity"] for item in observations["workloads"]]
    if set(identities) != {"agent", "gateway", "mcp_test_server", "unrelated"} or len(
        identities
    ) != len(set(identities)):
        raise EvidenceVerificationError("workload identity mismatch")
    if any(
        item["image_id"] != loaded_image["runtime_image_id"]
        for item in observations["workloads"]
    ):
        raise EvidenceVerificationError("workload image mismatch")

    expected_summary = {
        "required": len(REQUIRED_CASES),
        "passed": len(REQUIRED_CASES),
        "failed": 0,
        "skipped": 0,
        "errored": 0,
        "xfailed": 0,
        "xpassed": 0,
        "partial": 0,
    }
    if report["summary"] != expected_summary:
        raise EvidenceVerificationError("summary mismatch")

    required_boundaries = {
        "network_denial",
        "interlock_audit",
        "deployment_configuration",
    }
    if set(report["evidence_boundaries"]) != required_boundaries:
        raise EvidenceVerificationError("evidence boundary mismatch")
    boundary_ids = {
        case_id
        for values in report["evidence_boundaries"].values()
        for case_id in values
    }
    if not boundary_ids <= set(REQUIRED_CASES):
        raise EvidenceVerificationError("evidence boundary case mismatch")

    return {
        "verified": True,
        "case_count": len(cases),
        "source_sha": expected_source_sha,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--allow-stale", action="store_true")
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    result = verify_report(
        report,
        expected_source_sha=args.source_sha,
        now=None if args.allow_stale else datetime.now(timezone.utc),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
