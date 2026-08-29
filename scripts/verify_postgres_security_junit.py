"""Verify complete, current-run PostgreSQL security-test execution evidence."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET

from scripts.postgres_security_contract import (
    CRITICAL_NODE_IDS,
    EVIDENCE_PROFILE,
    EXECUTION_FORMAT_VERSION,
    MANIFEST_FORMAT_VERSION,
    SELECTED_FILES,
    file_sha256,
    load_json_object,
    node_ids_digest,
    normalized_node_id,
    validate_run_nonce,
    validate_source_sha,
)

MAX_XML_BYTES = 10 * 1024 * 1024
PROVENANCE_PROPERTIES = {
    "interlock_evidence_profile": EVIDENCE_PROFILE,
    "interlock_source_sha": None,
    "interlock_run_nonce": None,
    "interlock_manifest_digest": None,
}


class VerificationError(RuntimeError):
    """The evidence does not prove complete PostgreSQL security execution."""


@dataclass(frozen=True)
class ReportSummary:
    total: int
    skipped: int
    failed: int
    errors: int
    source_sha: str
    manifest_digest: str


def _summarize(items: list[str] | set[str], limit: int = 5) -> str:
    ordered = sorted(items)
    rendered = ", ".join(ordered[:limit])
    if len(ordered) > limit:
        rendered += f" (+{len(ordered) - limit} more)"
    return rendered


def _load_manifest(path: Path, source_sha: str, run_nonce: str) -> dict:
    try:
        manifest = load_json_object(path, label="collection manifest")
    except ValueError as exc:
        raise VerificationError(str(exc)) from exc
    if manifest.get("format_version") != MANIFEST_FORMAT_VERSION:
        raise VerificationError("collection manifest version is unsupported")
    if manifest.get("profile") != EVIDENCE_PROFILE:
        raise VerificationError("collection manifest profile is incorrect")
    if manifest.get("source_sha") != source_sha:
        raise VerificationError("collection manifest source SHA is incorrect")
    if manifest.get("run_nonce") != run_nonce:
        raise VerificationError("collection manifest run nonce is incorrect")
    if manifest.get("selected_files") != list(SELECTED_FILES):
        raise VerificationError("collection manifest selected files are incorrect")
    node_ids = manifest.get("node_ids")
    if not isinstance(node_ids, list) or not node_ids:
        raise VerificationError("collection manifest contains no node IDs")
    if not all(isinstance(node_id, str) and node_id for node_id in node_ids):
        raise VerificationError("collection manifest node IDs are invalid")
    if len(node_ids) != len(set(node_ids)):
        raise VerificationError("collection manifest contains duplicate node IDs")
    if node_ids != sorted(node_ids):
        raise VerificationError("collection manifest node IDs are not sorted")
    normalized = [normalized_node_id(node_id) for node_id in node_ids]
    if normalized != node_ids:
        raise VerificationError("collection manifest node IDs are not canonical")
    if manifest.get("node_ids_sha256") != node_ids_digest(node_ids):
        raise VerificationError("collection manifest node-ID digest is incorrect")
    collected_files = sorted({node_id.split("::", 1)[0] for node_id in node_ids})
    if collected_files != sorted(SELECTED_FILES):
        raise VerificationError("collection manifest does not cover selected files")
    missing_critical = CRITICAL_NODE_IDS - set(node_ids)
    if missing_critical:
        raise VerificationError(
            "collection manifest is missing critical case(s): "
            + _summarize(missing_critical)
        )
    return manifest


def _parse_xml(path: Path) -> ET.Element:
    if not path.is_file():
        raise VerificationError("JUnit report does not exist")
    try:
        size = path.stat().st_size
        if size == 0:
            raise VerificationError("JUnit report is empty")
        if size > MAX_XML_BYTES:
            raise VerificationError("JUnit report is too large")
        raw = path.read_bytes()
    except OSError as exc:
        raise VerificationError("JUnit report cannot be read") from exc
    lowered = raw.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise VerificationError("JUnit report contains a prohibited XML declaration")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise VerificationError("JUnit report is not valid XML") from exc


def _load_execution(
    path: Path,
    *,
    report_path: Path,
    manifest: dict,
    source_sha: str,
    run_nonce: str,
) -> dict:
    try:
        execution = load_json_object(path, label="execution metadata")
    except ValueError as exc:
        raise VerificationError(str(exc)) from exc
    try:
        report_digest = file_sha256(report_path)
    except OSError as exc:
        raise VerificationError("JUnit report cannot be hashed") from exc
    expected = {
        "format_version": EXECUTION_FORMAT_VERSION,
        "profile": EVIDENCE_PROFILE,
        "source_sha": source_sha,
        "run_nonce": run_nonce,
        "selected_files": list(SELECTED_FILES),
        "manifest_digest": manifest["node_ids_sha256"],
        "expected_count": len(manifest["node_ids"]),
        "pytest_exit_code": 0,
        "junit_file": report_path.name,
        "junit_sha256": report_digest,
    }
    for key, value in expected.items():
        if execution.get(key) != value:
            raise VerificationError(f"execution metadata field is incorrect: {key}")
    started = execution.get("started_at_ns")
    finished = execution.get("finished_at_ns")
    if (
        not isinstance(started, int)
        or not isinstance(finished, int)
        or started > finished
    ):
        raise VerificationError("execution metadata timestamps are invalid")
    try:
        report_mtime = report_path.stat().st_mtime_ns
    except OSError as exc:
        raise VerificationError("JUnit report metadata cannot be read") from exc
    tolerance_ns = 5_000_000_000
    if report_mtime < started - tolerance_ns or report_mtime > finished + tolerance_ns:
        raise VerificationError(
            "JUnit report does not belong to the current execution window"
        )
    return execution


def _properties(element: ET.Element) -> dict[str, str]:
    result: dict[str, str] = {}
    properties = element.find("properties")
    if properties is None:
        return result
    for prop in properties.findall("property"):
        name = prop.get("name")
        value = prop.get("value")
        if name and value is not None:
            if name in result:
                raise VerificationError(f"duplicate JUnit property: {name}")
            result[name] = value
    return result


def _require_suite_provenance(
    root: ET.Element, *, source_sha: str, run_nonce: str, manifest_digest: str
) -> None:
    expected = {
        "interlock_evidence_profile": EVIDENCE_PROFILE,
        "interlock_source_sha": source_sha,
        "interlock_run_nonce": run_nonce,
        "interlock_manifest_digest": manifest_digest,
    }
    matching = 0
    for suite in root.iter("testsuite"):
        properties = _properties(suite)
        present = {key: properties.get(key) for key in PROVENANCE_PROPERTIES}
        if any(value is not None for value in present.values()):
            if present != expected:
                raise VerificationError(
                    "JUnit suite provenance is incomplete or incorrect"
                )
            matching += 1
    if matching != 1:
        raise VerificationError("JUnit report must contain one provenance-bound suite")


def _identity_from_junit(testcase: ET.Element) -> str:
    properties = _properties(testcase)
    node_id = normalized_node_id(properties.get("interlock_node_id", ""))
    outcome = properties.get("interlock_outcome", "")
    if not node_id or not outcome:
        raise VerificationError(
            "JUnit testcase is missing Interlock identity properties"
        )
    if "::" not in node_id:
        raise VerificationError("JUnit testcase node ID is invalid")
    test_file, remainder = node_id.split("::", 1)
    if test_file not in SELECTED_FILES:
        raise VerificationError("JUnit testcase comes from an unexpected source file")
    parts = remainder.split("::")
    expected_name = parts[-1]
    expected_classname = test_file.removesuffix(".py").replace("/", ".")
    if len(parts) > 1:
        expected_classname += "." + ".".join(parts[:-1])
    classname = (testcase.get("classname") or "").strip()
    name = (testcase.get("name") or "").strip()
    if classname != expected_classname or name != expected_name:
        raise VerificationError("JUnit testcase path/name does not match its node ID")
    return node_id


def _recomputed_counts(element: ET.Element) -> dict[str, int]:
    testcases = list(element.iter("testcase"))
    return {
        "tests": len(testcases),
        "failures": sum(case.find("failure") is not None for case in testcases),
        "errors": sum(case.find("error") is not None for case in testcases),
        "skipped": sum(case.find("skipped") is not None for case in testcases),
    }


def _validate_aggregate_counters(root: ET.Element) -> None:
    elements = [root]
    elements.extend(suite for suite in root.iter("testsuite") if suite is not root)
    for element in elements:
        counts = _recomputed_counts(element)
        for attribute, actual in counts.items():
            raw = element.get(attribute)
            if raw is None:
                continue
            try:
                declared = int(raw)
            except ValueError as exc:
                raise VerificationError(
                    f"JUnit aggregate counter is invalid: {attribute}"
                ) from exc
            if declared != actual:
                raise VerificationError(
                    f"JUnit aggregate counter is inconsistent: {attribute}"
                )


def verify_report(
    report_path: Path,
    *,
    manifest_path: Path,
    execution_path: Path,
    source_sha: str,
    run_nonce: str,
) -> ReportSummary:
    try:
        source_sha = validate_source_sha(source_sha)
        run_nonce = validate_run_nonce(run_nonce)
    except ValueError as exc:
        raise VerificationError(str(exc)) from exc
    if len({report_path.parent, manifest_path.parent, execution_path.parent}) != 1:
        raise VerificationError("evidence files must share one current-run directory")
    manifest = _load_manifest(manifest_path, source_sha, run_nonce)
    root = _parse_xml(report_path)
    _load_execution(
        execution_path,
        report_path=report_path,
        manifest=manifest,
        source_sha=source_sha,
        run_nonce=run_nonce,
    )
    _require_suite_provenance(
        root,
        source_sha=source_sha,
        run_nonce=run_nonce,
        manifest_digest=manifest["node_ids_sha256"],
    )
    _validate_aggregate_counters(root)

    testcases = list(root.iter("testcase"))
    if not testcases:
        raise VerificationError("JUnit report contains no test cases")
    executed: list[str] = []
    skipped: list[str] = []
    failed: list[str] = []
    errors: list[str] = []
    non_pass: list[str] = []
    for testcase in testcases:
        node_id = _identity_from_junit(testcase)
        executed.append(node_id)
        properties = _properties(testcase)
        outcome = properties["interlock_outcome"]
        if testcase.find("skipped") is not None:
            skipped.append(node_id)
        if testcase.find("failure") is not None:
            failed.append(node_id)
        if testcase.find("error") is not None:
            errors.append(node_id)
        if outcome != "passed":
            non_pass.append(f"{node_id} ({outcome})")

    duplicates = {node_id for node_id in executed if executed.count(node_id) > 1}
    if duplicates:
        raise VerificationError(
            "JUnit report contains duplicate testcase identities: "
            + _summarize(duplicates)
        )
    if skipped:
        raise VerificationError(
            "JUnit report contains skipped PostgreSQL security case(s): "
            + _summarize(skipped)
        )
    if failed:
        raise VerificationError(
            "JUnit report contains failed PostgreSQL security case(s): "
            + _summarize(failed)
        )
    if errors:
        raise VerificationError(
            "JUnit report contains errored PostgreSQL security case(s): "
            + _summarize(errors)
        )
    if non_pass:
        raise VerificationError(
            "JUnit report contains non-passing outcome(s): " + _summarize(non_pass)
        )

    expected = set(manifest["node_ids"])
    actual = set(executed)
    missing = expected - actual
    unexpected = actual - expected
    if missing:
        raise VerificationError(
            "collected PostgreSQL case missing from JUnit report: "
            + _summarize(missing)
        )
    if unexpected:
        raise VerificationError(
            "JUnit report contains uncollected PostgreSQL case: "
            + _summarize(unexpected)
        )
    if len(executed) != len(manifest["node_ids"]):
        raise VerificationError(
            "JUnit testcase count does not match collection manifest"
        )

    return ReportSummary(
        total=len(executed),
        skipped=0,
        failed=0,
        errors=0,
        source_sha=source_sha,
        manifest_digest=manifest["node_ids_sha256"],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--execution", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-nonce", required=True)
    args = parser.parse_args(argv)
    try:
        summary = verify_report(
            args.junit,
            manifest_path=args.manifest,
            execution_path=args.execution,
            source_sha=args.source_sha,
            run_nonce=args.run_nonce,
        )
    except VerificationError as exc:
        print(f"PostgreSQL security verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        "PostgreSQL security verification passed: "
        f"sha={summary.source_sha}, expected={summary.total}, "
        f"executed={summary.total}, skipped=0, failures=0, errors=0, "
        f"manifest={summary.manifest_digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
