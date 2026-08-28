from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from scripts.verify_postgres_security_junit import VerificationError, verify_report

REQUIRED_NODE_IDS = (
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
)


def _write_report(tmp_path: Path, node_ids=REQUIRED_NODE_IDS, outcomes=None) -> Path:
    outcomes = outcomes or {}
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", name="pytest")
    for node_id in node_ids:
        path, name = node_id.split("::", 1)
        classname = path.removesuffix(".py").replace("/", ".")
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        outcome = outcomes.get(node_id)
        if outcome:
            ET.SubElement(case, outcome, message=f"synthetic {outcome}")
    report = tmp_path / "postgres-security.xml"
    ET.ElementTree(root).write(report, encoding="utf-8", xml_declaration=True)
    return report


def test_accepts_passing_required_postgres_security_cases(tmp_path):
    summary = verify_report(_write_report(tmp_path))

    assert summary.total == len(REQUIRED_NODE_IDS)
    assert summary.skipped == 0
    assert summary.failed == 0
    assert summary.errors == 0
    assert summary.files == {
        "tests/test_audit_chain_concurrency.py",
        "tests/test_postgres_ci_boundary_review_gate.py",
        "tests/test_postgres_rebaseline_cas.py",
    }


def test_rejects_missing_report(tmp_path):
    with pytest.raises(VerificationError, match="report does not exist"):
        verify_report(tmp_path / "missing.xml")


def test_rejects_zero_collected_cases(tmp_path):
    with pytest.raises(VerificationError, match="contains no test cases"):
        verify_report(_write_report(tmp_path, node_ids=()))


def test_rejects_any_skipped_postgres_case(tmp_path):
    skipped = REQUIRED_NODE_IDS[0]
    with pytest.raises(VerificationError, match="skipped PostgreSQL security case"):
        verify_report(_write_report(tmp_path, outcomes={skipped: "skipped"}))


def test_rejects_failed_required_case(tmp_path):
    failed = REQUIRED_NODE_IDS[1]
    with pytest.raises(VerificationError, match="failed PostgreSQL security case"):
        verify_report(_write_report(tmp_path, outcomes={failed: "failure"}))


def test_rejects_missing_required_approval_cas_case(tmp_path):
    missing = next(node for node in REQUIRED_NODE_IDS if "rejects_stale" in node)
    remaining = tuple(node for node in REQUIRED_NODE_IDS if node != missing)
    with pytest.raises(VerificationError, match="required PostgreSQL case missing"):
        verify_report(_write_report(tmp_path, node_ids=remaining))


def test_rejects_unexpected_suite_file(tmp_path):
    unexpected = (*REQUIRED_NODE_IDS, "tests/test_unrelated.py::test_unrelated")
    with pytest.raises(VerificationError, match="unexpected test file"):
        verify_report(_write_report(tmp_path, node_ids=unexpected))
