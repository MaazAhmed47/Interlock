"""Fail-closed evidence tests for the Kubernetes enforcement profile."""

import copy
import hashlib
import json
import shutil
import subprocess
import traceback
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts import run_kubernetes_enforcement_acceptance as acceptance_module
from scripts import verify_kubernetes_enforcement_evidence as verifier_module
from scripts.kubernetes_enforcement_cases import REQUIRED_CASES
from scripts.kubernetes_enforcement_source_digest import (
    CanonicalSourceDigestError,
    canonical_source_bundle_sha256,
)
from scripts.run_kubernetes_enforcement_acceptance import AcceptanceError, run
from scripts.verify_kubernetes_enforcement_evidence import (
    EvidenceVerificationError,
    build_network_policy_evidence_map,
    canonical_policy_sha256,
    expected_network_policy_evidence_map,
    expected_profile_digests,
    load_evidence_json,
    network_policy_evidence_sha256,
    parse_probe_output,
    verify_network_policy_evidence_map,
    verify_report,
)

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
DIGESTS = expected_profile_digests()
SOURCE_POLICY_MAP = expected_network_policy_evidence_map()
NEGATIVE_CONTROL_FIELDS = (
    "direct_target_reachable_after_policy_removal",
    "policy_restored_and_direct_target_reblocked",
    "mutated_restored_denial_evidence_rejected",
)


def _bundle_entry_sha256(relative_path: str, body: bytes) -> str:
    digest = hashlib.sha256()
    relative = relative_path.encode("utf-8")
    digest.update(len(relative).to_bytes(4, "big"))
    digest.update(relative)
    digest.update(len(body).to_bytes(8, "big"))
    digest.update(body)
    return digest.hexdigest()


def _copied_profile_with_line_endings(
    tmp_path: Path, line_ending: bytes
) -> tuple[Path, Path]:
    copied_root = tmp_path / "checkout"
    copied_profile = copied_root / "deploy" / "kubernetes-enforcement"
    shutil.copytree(ROOT / "deploy" / "kubernetes-enforcement", copied_profile)
    digest_paths = list((copied_profile / "manifests").glob("*.yaml"))
    digest_paths.extend(
        [
            copied_profile / "kind" / "cluster.yaml",
            copied_profile / "kind" / "versions.json",
        ]
    )
    for path in digest_paths:
        canonical = path.read_bytes().replace(b"\r\n", b"\n")
        assert b"\r" not in canonical
        path.write_bytes(canonical.replace(b"\n", line_ending))
    return copied_root, copied_profile


def _use_copied_profile(monkeypatch, copied_root: Path, copied_profile: Path) -> None:
    monkeypatch.setattr(verifier_module, "ROOT", copied_root)
    monkeypatch.setattr(verifier_module, "PROFILE", copied_profile)
    monkeypatch.setattr(
        verifier_module,
        "NETWORK_POLICY_MANIFEST",
        copied_profile / "manifests" / "network-policies.yaml",
    )


@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"])
def test_canonical_source_digest_accepts_lf_and_equivalent_crlf(tmp_path, line_ending):
    source = tmp_path / "manifests" / "source.yaml"
    source.parent.mkdir()
    canonical = b"apiVersion: v1\nkind: ConfigMap\n"
    source.write_bytes(canonical.replace(b"\n", line_ending))

    assert canonical_source_bundle_sha256([source], root=tmp_path) == (
        _bundle_entry_sha256("manifests/source.yaml", canonical)
    )


def test_canonical_source_digest_rejects_bare_cr_without_disclosing_content(tmp_path):
    source = tmp_path / "config.json"
    sensitive_sentinel = "canonical-digest-sensitive-sentinel"
    source.write_bytes(b'{"name":"safe"}\r' + sensitive_sentinel.encode("utf-8"))

    with pytest.raises(CanonicalSourceDigestError, match="bare CR") as raised:
        canonical_source_bundle_sha256([source], root=tmp_path)

    rendered_exception = "".join(
        traceback.format_exception(
            type(raised.value), raised.value, raised.value.__traceback__
        )
    )
    assert sensitive_sentinel not in rendered_exception
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_canonical_source_digest_rejects_invalid_utf8_without_disclosing_content(
    tmp_path,
):
    source = tmp_path / "config.json"
    sensitive_sentinel = "canonical-digest-sensitive-sentinel"
    source.write_bytes(sensitive_sentinel.encode("utf-8") + b"\xff")

    with pytest.raises(CanonicalSourceDigestError, match="valid UTF-8") as raised:
        canonical_source_bundle_sha256([source], root=tmp_path)

    rendered_exception = "".join(
        traceback.format_exception(
            type(raised.value), raised.value, raised.value.__traceback__
        )
    )
    assert sensitive_sentinel not in rendered_exception
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"])
def test_report_verifier_accepts_lf_and_windows_autocrlf_source(
    tmp_path, monkeypatch, line_ending
):
    copied_root, copied_profile = _copied_profile_with_line_endings(
        tmp_path, line_ending
    )
    _use_copied_profile(monkeypatch, copied_root, copied_profile)

    verified = verify_report(_report(), expected_source_sha=SHA, now=None)

    assert verified["verified"] is True
    assert verified["case_count"] == len(REQUIRED_CASES)
    assert verified["network_policy_count"] == len(SOURCE_POLICY_MAP)


def test_non_line_ending_source_mutation_still_fails_report_verification(
    tmp_path, monkeypatch
):
    copied_root, copied_profile = _copied_profile_with_line_endings(tmp_path, b"\r\n")
    policy_manifest = copied_profile / "manifests" / "network-policies.yaml"
    policy_manifest.write_bytes(
        policy_manifest.read_bytes() + b"# non-line-ending-content-mutation\r\n"
    )
    _use_copied_profile(monkeypatch, copied_root, copied_profile)

    with pytest.raises(EvidenceVerificationError, match="repository digest mismatch"):
        verify_report(_report(), expected_source_sha=SHA, now=None)


def test_report_verifier_rejects_bare_cr_source_without_disclosure(
    tmp_path, monkeypatch
):
    copied_root, copied_profile = _copied_profile_with_line_endings(tmp_path, b"\r\n")
    sensitive_sentinel = "canonical-digest-sensitive-sentinel"
    versions = copied_profile / "kind" / "versions.json"
    versions.write_bytes(
        versions.read_bytes() + b"\r" + sensitive_sentinel.encode("utf-8")
    )
    _use_copied_profile(monkeypatch, copied_root, copied_profile)

    with pytest.raises(EvidenceVerificationError, match="bare CR") as raised:
        verify_report(_report(), expected_source_sha=SHA, now=None)

    rendered_exception = "".join(
        traceback.format_exception(
            type(raised.value), raised.value, raised.value.__traceback__
        )
    )
    assert sensitive_sentinel not in rendered_exception
    assert sensitive_sentinel not in str(raised.value.__context__)


def test_runner_and_verifier_use_one_shared_canonical_source_digest():
    assert (
        acceptance_module.canonical_source_bundle_sha256
        is verifier_module.canonical_source_bundle_sha256
    )


def _report() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    policy_evidence_sha256 = network_policy_evidence_sha256(
        SOURCE_POLICY_MAP,
        source_sha=SHA,
        manifest_bundle_sha256=DIGESTS["manifest_bundle_sha256"],
    )
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
            "network_policy_evidence_sha256": policy_evidence_sha256,
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
            "network_policies": {
                "expected": len(SOURCE_POLICY_MAP),
                "observed": len(SOURCE_POLICY_MAP),
                "source_sha": SHA,
                "manifest_bundle_sha256": DIGESTS["manifest_bundle_sha256"],
                "evidence_sha256": policy_evidence_sha256,
                "policies": copy.deepcopy(SOURCE_POLICY_MAP),
            },
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


def _rebind_policy_evidence(report: dict) -> None:
    evidence = report["observations"]["network_policies"]
    evidence["observed"] = len(evidence["policies"])
    digest = network_policy_evidence_sha256(
        evidence["policies"],
        source_sha=evidence["source_sha"],
        manifest_bundle_sha256=evidence["manifest_bundle_sha256"],
    )
    evidence["evidence_sha256"] = digest
    report["digests"]["network_policy_evidence_sha256"] = digest


def test_complete_fresh_report_verifies():
    verified = verify_report(_report(), expected_source_sha=SHA, now=None)
    assert verified["verified"] is True
    assert verified["case_count"] == len(REQUIRED_CASES)
    assert verified["network_policy_count"] == len(SOURCE_POLICY_MAP)


def test_happy_path_live_policy_evidence_verifies_against_source():
    verified = verify_report(_report(), expected_source_sha=SHA, now=None)

    assert len(SOURCE_POLICY_MAP) == 12
    assert list(SOURCE_POLICY_MAP) == sorted(SOURCE_POLICY_MAP)
    assert verified["network_policy_evidence_sha256"] == (
        _report()["digests"]["network_policy_evidence_sha256"]
    )


def test_changed_live_policy_content_is_rejected_even_when_rehashed():
    report = _report()
    entry = report["observations"]["network_policies"]["policies"][
        "interlock-agent/agent-to-gateway"
    ]
    entry["canonical"]["egress"][0]["ports"][0]["port"] = 9000
    entry["sha256"] = canonical_policy_sha256(entry["canonical"])
    _rebind_policy_evidence(report)

    with pytest.raises(
        EvidenceVerificationError, match="NetworkPolicy content mismatch"
    ):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_missing_expected_live_policy_is_rejected():
    report = _report()
    report["observations"]["network_policies"]["policies"].pop(
        "interlock-agent/default-deny"
    )
    _rebind_policy_evidence(report)

    with pytest.raises(EvidenceVerificationError, match="missing NetworkPolicy"):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_unexpected_live_policy_is_rejected():
    report = _report()
    policies = report["observations"]["network_policies"]["policies"]
    unexpected = copy.deepcopy(policies["interlock-agent/default-deny"])
    unexpected["canonical"]["name"] = "unexpected-policy"
    unexpected["sha256"] = canonical_policy_sha256(unexpected["canonical"])
    policies["interlock-agent/unexpected-policy"] = unexpected
    _rebind_policy_evidence(report)

    with pytest.raises(EvidenceVerificationError, match="unexpected NetworkPolicy"):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_duplicate_live_policy_identity_is_rejected():
    report = _report()
    policies = report["observations"]["network_policies"]["policies"]
    policies["interlock-agent/duplicate-alias"] = copy.deepcopy(
        policies["interlock-agent/default-deny"]
    )
    _rebind_policy_evidence(report)

    with pytest.raises(
        EvidenceVerificationError, match="duplicate NetworkPolicy identity"
    ):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_duplicate_raw_live_policy_identity_is_rejected_before_retention():
    canonical = SOURCE_POLICY_MAP["interlock-agent/default-deny"]["canonical"]
    raw = {
        "apiVersion": canonical["apiVersion"],
        "kind": canonical["kind"],
        "metadata": {
            "namespace": canonical["namespace"],
            "name": canonical["name"],
        },
        "spec": {
            "podSelector": canonical["podSelector"],
            "policyTypes": canonical["policyTypes"],
            "ingress": canonical["ingress"],
            "egress": canonical["egress"],
        },
    }

    with pytest.raises(
        EvidenceVerificationError, match="duplicate NetworkPolicy identity"
    ):
        build_network_policy_evidence_map([raw, copy.deepcopy(raw)])


def test_duplicate_policy_json_key_is_rejected_before_semantic_verification():
    entry = json.dumps(SOURCE_POLICY_MAP["interlock-agent/default-deny"])
    duplicated = (
        '{"policies":{"interlock-agent/default-deny":'
        + entry
        + ',"interlock-agent/default-deny":'
        + entry
        + "}}"
    )

    with pytest.raises(EvidenceVerificationError, match="duplicate JSON key"):
        load_evidence_json(duplicated)


def test_malformed_retained_canonical_policy_data_is_rejected():
    policies = copy.deepcopy(SOURCE_POLICY_MAP)
    policies["interlock-agent/default-deny"]["canonical"]["uid"] = "not-allowed"

    with pytest.raises(EvidenceVerificationError, match="malformed canonical"):
        verify_network_policy_evidence_map(policies)


@pytest.mark.parametrize("mutation", ["hash", "canonical"])
def test_altered_retained_policy_hash_or_canonical_payload_is_rejected(mutation):
    report = _report()
    entry = report["observations"]["network_policies"]["policies"][
        "interlock-agent/default-deny"
    ]
    if mutation == "hash":
        entry["sha256"] = "0" * 64
    else:
        entry["canonical"]["policyTypes"] = ["Ingress"]

    with pytest.raises(EvidenceVerificationError, match="NetworkPolicy hash mismatch"):
        verify_report(report, expected_source_sha=SHA, now=None)


@pytest.mark.parametrize("location", ["report_digest", "policy_evidence_digest"])
def test_altered_policy_set_digest_is_rejected(location):
    report = _report()
    if location == "report_digest":
        report["digests"]["network_policy_evidence_sha256"] = "0" * 64
    else:
        report["observations"]["network_policies"]["evidence_sha256"] = "0" * 64

    with pytest.raises(EvidenceVerificationError, match="evidence digest mismatch"):
        verify_report(report, expected_source_sha=SHA, now=None)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source_sha", "b" * 40, "NetworkPolicy source SHA mismatch"),
        (
            "manifest_bundle_sha256",
            "b" * 64,
            "NetworkPolicy manifest digest mismatch",
        ),
    ],
)
def test_policy_evidence_source_or_manifest_binding_mismatch_is_rejected(
    field, value, message
):
    report = _report()
    report["observations"]["network_policies"][field] = value

    with pytest.raises(EvidenceVerificationError, match=message):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_report_manifest_digest_mismatch_is_rejected():
    report = _report()
    report["digests"]["manifest_bundle_sha256"] = "b" * 64

    with pytest.raises(EvidenceVerificationError, match="repository digest mismatch"):
        verify_report(report, expected_source_sha=SHA, now=None)


def test_network_policy_sanitization_excludes_metadata_and_sensitive_sentinels():
    source = SOURCE_POLICY_MAP["interlock-agent/default-deny"]["canonical"]
    raw = {
        "apiVersion": source["apiVersion"],
        "kind": source["kind"],
        "metadata": {
            "namespace": source["namespace"],
            "name": source["name"],
            "uid": "uid-synthetic-sentinel",
            "resourceVersion": "resource-version-synthetic-sentinel",
            "creationTimestamp": "timestamp-synthetic-sentinel",
            "managedFields": [{"manager": "managed-fields-synthetic-sentinel"}],
            "annotations": {
                "secret": "secret-value-synthetic-sentinel",
                "authorization": "Authorization: Bearer auth-synthetic-sentinel",
                "query": "https://example.test/path?token=query-synthetic-sentinel",
                "dsn": "postgresql://user:dsn-synthetic-sentinel@example.test/db",
            },
        },
        "spec": {
            "podSelector": source["podSelector"],
            "policyTypes": source["policyTypes"],
            "ingress": source["ingress"],
            "egress": source["egress"],
        },
        "status": {"state": "status-synthetic-sentinel"},
    }

    rendered = json.dumps(
        build_network_policy_evidence_map([raw]), sort_keys=True
    ).lower()
    forbidden = (
        "uid",
        "resourceversion",
        "managedfields",
        "creationtimestamp",
        "annotations",
        "status",
        "secret",
        "authorization",
        "https://",
        "postgresql://",
        "synthetic-sentinel",
        "secret-value-synthetic-sentinel",
        "auth-synthetic-sentinel",
        "query-synthetic-sentinel",
        "dsn-synthetic-sentinel",
        "managed-fields-synthetic-sentinel",
        "timestamp-synthetic-sentinel",
    )
    for value in forbidden:
        assert value not in rendered


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
    assert generated["observations"]["network_policies"]["policies"] == (
        SOURCE_POLICY_MAP
    )
    assert (
        generated["digests"]["network_policy_evidence_sha256"]
        == generated["observations"]["network_policies"]["evidence_sha256"]
    )


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
