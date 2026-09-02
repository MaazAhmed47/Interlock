"""Fail-closed evidence tests for the Kubernetes enforcement profile."""

import copy
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.kubernetes_enforcement_cases import REQUIRED_CASES
from scripts.run_kubernetes_enforcement_acceptance import AcceptanceError, run
from scripts.verify_kubernetes_enforcement_evidence import (
    EvidenceVerificationError,
    expected_profile_digests,
    parse_probe_output,
    verify_report,
)

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
DIGESTS = expected_profile_digests()


def _report() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    cases = []
    for case_id, expected in REQUIRED_CASES.items():
        cases.append(
            {
                "case_id": case_id,
                "expected_result": expected.expected_result,
                "actual_result": expected.expected_result,
                "status": "passed",
                "source_workload": expected.source_workload,
                "destination_class": expected.destination_class,
                "enforcement_layer": expected.enforcement_layer,
                "failure_category": expected.failure_category,
                "source_sha": SHA,
                "manifest_bundle_sha256": DIGESTS["manifest_bundle_sha256"],
                "config_sha256": DIGESTS["config_sha256"],
                "started_at": now,
                "completed_at": now,
                "verifier_outcome": "accepted",
            }
        )
    return {
        "schema_version": "interlock.kubernetes-enforcement-evidence.v1",
        "source_sha": SHA,
        "run_id": "sha256:" + "c" * 64,
        "run_started_at": now,
        "run_completed_at": now,
        "environment": {
            "kind": "v0.33.0",
            "kubernetes": "v1.36.4",
            "cni": "calico-v3.32.2",
            "node_image": "sha256:" + "d" * 64,
            "lab_image": "sha256:" + "e" * 64,
        },
        "digests": {
            **DIGESTS,
        },
        "evidence_boundaries": {
            "network_denial": ["KE-002", "KE-003", "KE-004", "KE-005"],
            "interlock_audit": ["KE-001", "KE-017"],
            "deployment_configuration": ["KE-008", "KE-018"],
        },
        "negative_controls": {
            "same_target_reachable_without_policy": True,
            "mutated_evidence_rejected": True,
            "policy_restored_and_reverified": True,
        },
        "observations": {
            "cni": {
                "ready_nodes": 1,
                "expected_nodes": 1,
                "runtime_image_ids": ["sha256:" + "1" * 64],
            },
            "workloads": [
                {"identity": identity, "ready": True, "image_id": "sha256:" + "e" * 64}
                for identity in ("agent", "gateway", "mcp_test_server", "unrelated")
            ],
            "network_policies": {"expected": 12, "observed": 12},
            "service_account_tokens_disabled": True,
            "log_scan_passed": True,
            "cluster_deleted": True,
        },
        "log_digests": {
            "gateway": "2" * 64,
            "mcp": "3" * 64,
            "agent": "4" * 64,
            "unrelated": "5" * 64,
        },
        "cases": cases,
        "summary": {
            "required": len(REQUIRED_CASES),
            "passed": len(REQUIRED_CASES),
            "failed": 0,
            "skipped": 0,
            "errored": 0,
            "xfailed": 0,
            "xpassed": 0,
            "partial": 0,
        },
    }


def test_complete_fresh_report_verifies():
    verified = verify_report(_report(), expected_source_sha=SHA, now=None)
    assert verified["verified"] is True
    assert verified["case_count"] == len(REQUIRED_CASES)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda report: report["cases"].pop(), "missing required case"),
        (
            lambda report: report["cases"].append(copy.deepcopy(report["cases"][0])),
            "duplicate case",
        ),
        (
            lambda report: report["cases"][0].update(status="skipped"),
            "non-passing status",
        ),
        (
            lambda report: report["cases"][0].update(actual_result="network_denied"),
            "result mismatch",
        ),
        (
            lambda report: report.update(source_sha="9" * 40),
            "source SHA mismatch",
        ),
        (
            lambda report: report["cases"][0].update(source_sha="9" * 40),
            "case source SHA mismatch",
        ),
        (
            lambda report: report["cases"][0].update(manifest_bundle_sha256="9" * 64),
            "manifest digest mismatch",
        ),
        (
            lambda report: report["summary"].update(passed=0),
            "summary mismatch",
        ),
        (
            lambda report: report["negative_controls"].update(
                same_target_reachable_without_policy=False
            ),
            "negative control failed",
        ),
    ],
)
def test_report_verifier_rejects_incomplete_or_mismatched_evidence(mutation, message):
    report = _report()
    mutation(report)
    with pytest.raises(EvidenceVerificationError, match=message):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_report_schema_rejects_missing_required_field():
    report = _report()
    del report["environment"]["cni"]
    with pytest.raises(EvidenceVerificationError, match="schema"):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_stale_report_is_rejected():
    report = _report()
    report["run_started_at"] = "2025-01-01T00:00:00+00:00"
    report["run_completed_at"] = "2025-01-01T00:00:00+00:00"
    with pytest.raises(EvidenceVerificationError, match="stale"):
        verify_report(
            report,
            expected_source_sha=SHA,
            now=datetime(2026, 9, 2, tzinfo=timezone.utc),
        )


def test_probe_parser_requires_exactly_one_machine_record():
    payload = {
        "case_id": "KE-002",
        "actual_result": "network_denied",
        "failure_category": "connect_timeout",
    }
    parsed = parse_probe_output("noise\nINTERLOCK_K8S_RESULT " + json.dumps(payload))
    assert parsed == payload

    with pytest.raises(EvidenceVerificationError, match="missing probe result"):
        parse_probe_output("ordinary log")
    doubled = "\n".join(["INTERLOCK_K8S_RESULT " + json.dumps(payload)] * 2)
    with pytest.raises(EvidenceVerificationError, match="duplicate probe result"):
        parse_probe_output(doubled)
    with pytest.raises(EvidenceVerificationError, match="malformed probe result"):
        parse_probe_output("INTERLOCK_K8S_RESULT {")


def test_command_timeout_is_fail_closed_and_does_not_echo_arguments(monkeypatch):
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["kind", "sensitive"], 1)

    monkeypatch.setattr("subprocess.run", timeout)
    with pytest.raises(AcceptanceError, match="kind command timed out") as raised:
        run(["kind", "sensitive"], timeout=1)
    assert "sensitive" not in str(raised.value)


@pytest.mark.parametrize(
    "secret_text",
    [
        "Authorization: Bearer abc",
        "Proxy-Authorization: token",
        "postgresql://user:pass@db.example/test",
        "https://example.test/path?token=value",
        "-----BEGIN PRIVATE KEY-----",
        "lf_developer_not_allowed_here",
        "10.96.0.10",
    ],
)
def test_probe_parser_rejects_sensitive_output(secret_text):
    payload = {
        "case_id": "KE-002",
        "actual_result": "network_denied",
        "failure_category": secret_text,
    }
    with pytest.raises(EvidenceVerificationError, match="sensitive"):
        parse_probe_output("INTERLOCK_K8S_RESULT " + json.dumps(payload))
