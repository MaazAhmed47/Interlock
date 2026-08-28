"""Fail CI unless the selected PostgreSQL security cases really executed."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET

ALLOWED_FILES = {
    "tests/test_audit_chain_concurrency.py",
    "tests/test_postgres_ci_boundary_review_gate.py",
    "tests/test_postgres_rebaseline_cas.py",
}

REQUIRED_NODE_IDS = {
    "tests/test_postgres_rebaseline_cas.py::"
    "test_server_advisory_lock_does_not_serialize_another_server_on_postgres",
    "tests/test_postgres_rebaseline_cas.py::"
    "test_discovery_wins_first_old_approval_is_stale_on_postgres",
    "tests/test_postgres_rebaseline_cas.py::"
    "test_promotion_wins_first_new_discovery_waits_and_is_not_lost_on_postgres",
    "tests/test_postgres_rebaseline_cas.py::"
    "test_concurrent_promotes_exactly_one_succeeds_on_postgres",
    "tests/test_postgres_rebaseline_cas.py::"
    "test_injected_failure_rolls_back_transactionally_on_postgres",
    "tests/test_postgres_rebaseline_cas.py::"
    "test_per_tool_approval_rejects_stale_surface_on_postgres",
    "tests/test_postgres_rebaseline_cas.py::"
    "test_per_tool_approval_and_audit_bind_matching_surface_on_postgres",
    "tests/test_postgres_rebaseline_cas.py::"
    "test_per_tool_approval_audit_failure_rolls_back_on_postgres",
    "tests/test_postgres_rebaseline_cas.py::"
    "test_per_tool_approval_timestamp_lifecycle_on_postgres",
    "tests/test_postgres_ci_boundary_review_gate.py::"
    "test_postgres_receipt_verification_failure_rolls_back_final_row[false]",
    "tests/test_postgres_ci_boundary_review_gate.py::"
    "test_postgres_receipt_verification_failure_rolls_back_final_row[exception]",
    "tests/test_postgres_ci_boundary_review_gate.py::"
    "test_clean_review_on_postgres_exits_zero_with_a_verified_chain",
    "tests/test_audit_chain_concurrency.py::"
    "test_concurrent_replica_appends_cannot_fork_the_chain[mcp]",
    "tests/test_audit_chain_concurrency.py::"
    "test_concurrent_replica_appends_cannot_fork_the_chain[admin]",
}


class VerificationError(RuntimeError):
    """The JUnit report does not prove PostgreSQL security execution."""


@dataclass(frozen=True)
class ReportSummary:
    total: int
    skipped: int
    failed: int
    errors: int
    files: set[str]


def _summarize(items: list[str], limit: int = 5) -> str:
    ordered = sorted(items)
    rendered = ", ".join(ordered[:limit])
    if len(ordered) > limit:
        rendered += f" (+{len(ordered) - limit} more)"
    return rendered


def _node_id(testcase: ET.Element) -> tuple[str, str]:
    classname = (testcase.get("classname") or "").strip()
    name = (testcase.get("name") or "").strip()
    if not classname or not name:
        raise VerificationError("JUnit testcase is missing classname or name")
    test_file = classname.replace(".", "/") + ".py"
    return test_file, f"{test_file}::{name}"


def verify_report(report_path: Path) -> ReportSummary:
    if not report_path.is_file():
        raise VerificationError(f"JUnit report does not exist: {report_path.name}")
    try:
        root = ET.parse(report_path).getroot()
    except ET.ParseError as exc:
        raise VerificationError("JUnit report is not valid XML") from exc

    testcases = list(root.iter("testcase"))
    if not testcases:
        raise VerificationError("JUnit report contains no test cases")

    files: set[str] = set()
    node_ids: set[str] = set()
    skipped_nodes: list[str] = []
    failed_nodes: list[str] = []
    error_nodes: list[str] = []
    for testcase in testcases:
        test_file, node_id = _node_id(testcase)
        files.add(test_file)
        node_ids.add(node_id)
        if testcase.find("skipped") is not None:
            skipped_nodes.append(node_id)
        if testcase.find("failure") is not None:
            failed_nodes.append(node_id)
        if testcase.find("error") is not None:
            error_nodes.append(node_id)

    unexpected_files = sorted(files - ALLOWED_FILES)
    if unexpected_files:
        raise VerificationError(
            "JUnit report contains unexpected test file(s): "
            + _summarize(unexpected_files)
        )
    missing_files = sorted(ALLOWED_FILES - files)
    if missing_files:
        raise VerificationError(
            "JUnit report is missing selected test file(s): " + ", ".join(missing_files)
        )
    if skipped_nodes:
        raise VerificationError(
            "JUnit report contains skipped PostgreSQL security case(s): "
            + _summarize(skipped_nodes)
        )
    if failed_nodes:
        raise VerificationError(
            "JUnit report contains failed PostgreSQL security case(s): "
            + _summarize(failed_nodes)
        )
    if error_nodes:
        raise VerificationError(
            "JUnit report contains errored PostgreSQL security case(s): "
            + _summarize(error_nodes)
        )
    missing_nodes = sorted(REQUIRED_NODE_IDS - node_ids)
    if missing_nodes:
        raise VerificationError(
            "required PostgreSQL case missing from JUnit report: "
            + _summarize(missing_nodes)
        )

    return ReportSummary(
        total=len(testcases),
        skipped=len(skipped_nodes),
        failed=len(failed_nodes),
        errors=len(error_nodes),
        files=files,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="pytest JUnit XML report")
    args = parser.parse_args(argv)
    try:
        summary = verify_report(args.report)
    except VerificationError as exc:
        print(f"PostgreSQL security verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        "PostgreSQL security verification passed: "
        f"{summary.total} executed, {summary.skipped} skipped, "
        f"{summary.failed} failed, {summary.errors} errors"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
