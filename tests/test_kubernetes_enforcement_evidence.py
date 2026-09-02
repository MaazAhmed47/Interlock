"""Fail-closed evidence tests for the Kubernetes enforcement profile."""

import copy
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts import run_kubernetes_enforcement_acceptance as acceptance_module
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
NEGATIVE_CONTROL_FIELDS = (
    "direct_target_reachable_after_policy_removal",
    "policy_restored_and_direct_target_reblocked",
    "mutated_restored_denial_evidence_rejected",
)


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
            "direct_target_reachable_after_policy_removal": True,
            "policy_restored_and_direct_target_reblocked": True,
            "mutated_restored_denial_evidence_rejected": True,
        },
        "observations": {
            "loaded_image": {
                "reference": "interlock-kubernetes-enforcement:" + SHA,
                "build_image_id": "sha256:" + "e" * 64,
                "containerd_image_id": "sha256:" + "8" * 64,
                "runtime_image_id": "sha256:" + "f" * 64,
                "rootfs_diff_ids_sha256": "6" * 64,
            },
            "cni": {
                "ready_nodes": 1,
                "expected_nodes": 1,
                "runtime_image_ids": ["sha256:" + "1" * 64],
            },
            "workloads": [
                {"identity": identity, "ready": True, "image_id": "sha256:" + "f" * 64}
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


def test_runner_emits_the_three_distinct_negative_controls():
    expected = _report()
    generated = acceptance_module.build_report(
        source_sha=SHA,
        run_id=expected["run_id"],
        started_at=expected["run_started_at"],
        completed_at=expected["run_completed_at"],
        node_image_id=expected["environment"]["node_image"],
        lab_image_id=expected["environment"]["lab_image"],
        manifest_digest=expected["digests"]["manifest_bundle_sha256"],
        config_digest=expected["digests"]["config_sha256"],
        calico_digest=expected["digests"]["calico_manifest_sha256"],
        cases=expected["cases"],
        observations=expected["observations"],
        log_digests=expected["log_digests"],
    )

    assert generated["negative_controls"] == {
        field: True for field in NEGATIVE_CONTROL_FIELDS
    }


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
            lambda report: report["observations"]["loaded_image"].update(
                reference="interlock-kubernetes-enforcement:" + "b" * 40
            ),
            "loaded image reference mismatch",
        ),
        (
            lambda report: report["observations"]["workloads"][0].update(
                image_id="sha256:" + "7" * 64
            ),
            "workload image mismatch",
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


@pytest.mark.parametrize("field", NEGATIVE_CONTROL_FIELDS)
def test_report_schema_requires_each_distinct_negative_control(field):
    report = _report()
    del report["negative_controls"][field]

    with pytest.raises(EvidenceVerificationError, match="schema"):
        verify_report(report, expected_source_sha=SHA, now=None)


@pytest.mark.parametrize("field", NEGATIVE_CONTROL_FIELDS)
def test_report_verifier_fails_closed_when_any_negative_control_is_false(field):
    report = _report()
    report["negative_controls"][field] = False

    with pytest.raises(EvidenceVerificationError, match="negative control failed"):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_readme_separates_live_controls_from_evidence_integrity_mutation():
    readme = (ROOT / "deploy" / "kubernetes-enforcement" / "README.md").read_text(
        encoding="utf-8"
    )
    lower = " ".join(readme.lower().split())

    assert (
        "Policy removal proves live reachability; a separate synthetic mutation "
        "proves verifier integrity."
    ) in readme
    assert "live policy-removal reachability control" in lower
    assert "live restoration control" in lower
    assert "evidence-integrity mutation control" in lower
    assert "policy-removal verifier rejection" not in lower
    assert "policy removal causes verifier rejection" not in lower
    assert "removes the isolation policy, confirms the verifier rejects" not in lower


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


def test_loaded_image_identity_binds_exact_tag_and_rootfs(monkeypatch):
    layer = "sha256:" + "1" * 64
    containerd_id = "sha256:" + "2" * 64
    runtime_id = "sha256:" + "4" * 64
    image = "interlock-kubernetes-enforcement:" + SHA
    payload = {
        "status": {
            "id": containerd_id,
            "repoTags": ["docker.io/library/" + image],
            "repoDigests": ["docker.io/library/import@" + runtime_id],
        },
        "info": {"imageSpec": {"rootfs": {"diff_ids": [layer]}}},
    }
    monkeypatch.setattr(
        acceptance_module,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )

    identity = acceptance_module.inspect_loaded_image(
        "test-cluster", image, "sha256:" + "3" * 64, [layer]
    )

    assert identity["reference"] == image
    assert identity["containerd_image_id"] == containerd_id
    assert identity["runtime_image_id"] == runtime_id


def test_loaded_image_identity_rejects_rootfs_mismatch(monkeypatch):
    image = "interlock-kubernetes-enforcement:" + SHA
    payload = {
        "status": {
            "id": "sha256:" + "2" * 64,
            "repoTags": ["docker.io/library/" + image],
            "repoDigests": ["docker.io/library/import@sha256:" + "5" * 64],
        },
        "info": {"imageSpec": {"rootfs": {"diff_ids": ["sha256:" + "4" * 64]}}},
    }
    monkeypatch.setattr(
        acceptance_module,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )

    with pytest.raises(AcceptanceError, match="root filesystem identity mismatch"):
        acceptance_module.inspect_loaded_image(
            "test-cluster",
            image,
            "sha256:" + "3" * 64,
            ["sha256:" + "1" * 64],
        )


def test_loaded_image_identity_rejects_unexpected_tag(monkeypatch):
    layer = "sha256:" + "1" * 64
    image = "interlock-kubernetes-enforcement:" + SHA
    payload = {
        "status": {
            "id": "sha256:" + "2" * 64,
            "repoTags": ["docker.io/library/interlock-kubernetes-enforcement:other"],
            "repoDigests": ["docker.io/library/import@sha256:" + "5" * 64],
        },
        "info": {"imageSpec": {"rootfs": {"diff_ids": [layer]}}},
    }
    monkeypatch.setattr(
        acceptance_module,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )

    with pytest.raises(AcceptanceError, match="exact source image"):
        acceptance_module.inspect_loaded_image(
            "test-cluster", image, "sha256:" + "3" * 64, [layer]
        )


def test_api_stability_gate_requires_consecutive_ready_results(monkeypatch):
    results = iter([1, 0, 0, 0, 0, 0])
    monkeypatch.setattr(
        acceptance_module,
        "kubectl",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=next(results), stdout="ok", stderr=""
        ),
    )
    monkeypatch.setattr(acceptance_module.time, "sleep", lambda _seconds: None)

    acceptance_module.wait_for_kubernetes_api_stability(
        "test-context", max_attempts=6, required_consecutive=5
    )


def test_api_stability_gate_rejects_persistent_unavailability(monkeypatch):
    monkeypatch.setattr(
        acceptance_module,
        "kubectl",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="unavailable"
        ),
    )
    monkeypatch.setattr(acceptance_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(AcceptanceError, match="did not remain ready"):
        acceptance_module.wait_for_kubernetes_api_stability(
            "test-context", max_attempts=5, required_consecutive=5
        )


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
