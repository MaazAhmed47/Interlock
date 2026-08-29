"""Pytest provenance and exact-outcome annotations for PostgreSQL CI."""

from __future__ import annotations

import pytest

from scripts.postgres_security_contract import (
    EVIDENCE_PROFILE,
    validate_run_nonce,
    validate_source_sha,
)


def pytest_addoption(parser) -> None:
    group = parser.getgroup("interlock-postgres-security")
    group.addoption("--interlock-source-sha")
    group.addoption("--interlock-run-nonce")
    group.addoption("--interlock-manifest-digest")


@pytest.fixture(scope="session", autouse=True)
def _record_interlock_postgres_provenance(pytestconfig, record_testsuite_property):
    source_sha = validate_source_sha(pytestconfig.getoption("--interlock-source-sha"))
    run_nonce = validate_run_nonce(pytestconfig.getoption("--interlock-run-nonce"))
    manifest_digest = str(pytestconfig.getoption("--interlock-manifest-digest") or "")
    # Validate the digest shape without accepting an empty or arbitrary value.
    if not manifest_digest.startswith("sha256:") or len(manifest_digest) != 71:
        raise pytest.UsageError("interlock manifest digest is invalid")
    record_testsuite_property("interlock_source_sha", source_sha)
    record_testsuite_property("interlock_run_nonce", run_nonce)
    record_testsuite_property("interlock_manifest_digest", manifest_digest)
    record_testsuite_property("interlock_evidence_profile", EVIDENCE_PROFILE)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return
    if hasattr(report, "wasxfail"):
        exact_outcome = "xpass" if report.passed or report.failed else "xfail"
    elif report.passed:
        exact_outcome = "passed"
    elif report.failed:
        exact_outcome = "failed"
    else:
        exact_outcome = "skipped"
    # pytest's JUnit writer finalizes testcase properties from the teardown
    # report. Persist on the item so the later teardown report carries them.
    item.user_properties.append(("interlock_node_id", item.nodeid.replace("\\", "/")))
    item.user_properties.append(("interlock_outcome", exact_outcome))
