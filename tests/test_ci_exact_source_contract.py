"""Repository-wide exact-source identity contract for the CI workflow."""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"

CI_JOBS = {
    "backend": "Backend tests",
    "postgres-security": "PostgreSQL security tests",
    "phase2-docker": "Docker Phase 2 egress profile",
    "kubernetes-enforcement": "Kubernetes enforcement reference profile",
    "dependency-audit": "Dependency audit",
    "secret-scan": "Secret scan",
    "frontend": "Dashboard build",
    "helm": "Helm chart",
    "docker": "Docker image build",
}

PR_SHA = "${{ github.event.pull_request.head.sha }}"
PUSH_SHA = "${{ github.sha }}"
VERIFIED_SHA = "${{ steps.source.outputs.sha }}"
VERIFIED_SOURCE = "steps.source.outputs.verified == 'true'"
SOURCE_SUCCESS = "steps.source.outcome == 'success'"
SOURCE_VERIFIER = 'python -I "$GITHUB_WORKSPACE/scripts/verify_ci_source.py"'
FAILURE_SWALLOWING = ("|| true", "exit 0", "set +e", "| true")


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _named_steps(job: dict) -> dict[str, dict]:
    return {step.get("name"): step for step in job["steps"] if step.get("name")}


def _assert_exact_source_job(job_id: str, job: dict) -> None:
    assert job.get("name") == CI_JOBS[job_id]
    assert job.get("continue-on-error") is not True

    steps = job["steps"]
    named = _named_steps(job)
    assert [step.get("name") for step in steps[:3]] == [
        "Checkout pull-request head",
        "Checkout event SHA",
        "Verify checked-out source identity",
    ], f"{job_id} must verify source identity before any substantive step"

    pr_checkout = named["Checkout pull-request head"]
    assert pr_checkout.get("if") == "github.event_name == 'pull_request'"
    assert pr_checkout.get("uses") == "actions/checkout@v4"
    assert pr_checkout.get("with", {}).get("ref") == PR_SHA

    push_checkout = named["Checkout event SHA"]
    assert push_checkout.get("if") == "github.event_name != 'pull_request'"
    assert push_checkout.get("uses") == "actions/checkout@v4"
    assert push_checkout.get("with", {}).get("ref") == PUSH_SHA

    identity = named["Verify checked-out source identity"]
    assert identity.get("id") == "source"
    assert identity.get("shell") == "bash"
    assert identity.get("continue-on-error") is not True
    assert "if" not in identity
    command = str(identity.get("run", ""))
    assert command.startswith("set -euo pipefail\n")
    assert "github.event.pull_request.head.sha" in command
    assert "github.sha" in command
    assert 'git config --global --add safe.directory "$GITHUB_WORKSPACE"' in command
    assert "safe.directory '*'" not in command
    assert SOURCE_VERIFIER in command
    assert '--expected "$expected"' in command
    assert '--repo "$GITHUB_WORKSPACE"' in command
    assert '--github-output "$GITHUB_OUTPUT"' in command
    assert "$(" not in command
    for swallowed in FAILURE_SWALLOWING:
        assert swallowed not in command

    for step in steps:
        assert step.get("continue-on-error") is not True

    # Outside the push checkout and the verification comparison, raw event SHAs
    # are not evidence identities. Downstream steps must consume the verified
    # output instead.
    for step in steps[3:]:
        rendered = str(step)
        assert "github.sha" not in rendered
        assert "github.event.pull_request.head.sha" not in rendered


def _assert_verified_artifacts(workflow: dict) -> None:
    for job_id, job in workflow["jobs"].items():
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("actions/upload-artifact"):
                name = str(step.get("with", {}).get("name", ""))
                assert VERIFIED_SHA in name, f"{job_id} artifact is not source-bound"

    secret_scan = _named_steps(workflow["jobs"]["secret-scan"])["Run gitleaks"]
    assert secret_scan["env"]["GITLEAKS_ENABLE_UPLOAD_ARTIFACT"] == "false"


def test_every_ci_job_checks_out_and_verifies_the_exact_event_source_first():
    workflow = _workflow()
    assert set(workflow["jobs"]) == set(CI_JOBS)
    failures = []
    for job_id, job in workflow["jobs"].items():
        try:
            _assert_exact_source_job(job_id, job)
        except (AssertionError, KeyError) as exc:
            failures.append(f"{job_id}: {exc}")
    assert not failures, "exact-source contract failures:\n" + "\n".join(failures)


def test_all_explicit_artifacts_use_only_the_verified_source_identity():
    _assert_verified_artifacts(_workflow())


def test_dependency_reports_and_docker_image_use_the_verified_source_identity():
    workflow = _workflow()
    dependency = _named_steps(workflow["jobs"]["dependency-audit"])
    identity = dependency["Verify checked-out source identity"]["run"]
    assert "dependency-audit-evidence-$expected-" in identity
    for name in (
        "Record Python audit JSON",
        "Gate production dependencies (npm audit --omit=dev, blocking)",
        "Gate build/development dependencies (blocking)",
    ):
        command = dependency[name]["run"]
        assert "steps.source.outputs.evidence_dir" in command
        assert VERIFIED_SHA in command
    upload = dependency["Upload audit artifacts"]
    assert upload["with"]["path"] == "${{ steps.source.outputs.evidence_dir }}"

    docker = _named_steps(workflow["jobs"]["docker"])["Build runtime image"]
    assert docker["run"] == f"docker build -t interlock:{VERIFIED_SHA} ."


def _assert_dependency_audit_fails_closed_after_source_failure(job: dict) -> None:
    named = _named_steps(job)
    source_index = job["steps"].index(named["Verify checked-out source identity"])
    protected_steps = {
        "Install dependencies and pip-audit",
        "Audit Python dependencies (pip-audit, blocking)",
        "Record Python audit JSON",
        "Install frontend dependencies",
        "Gate production dependencies (npm audit --omit=dev, blocking)",
        "Gate build/development dependencies (blocking)",
        "Upload audit artifacts",
        "Dependency audit verdict",
    }
    assert protected_steps <= set(named)

    for step in job["steps"][source_index + 1 :]:
        condition = str(step.get("if", ""))
        if condition:
            assert VERIFIED_SOURCE in condition
            assert SOURCE_SUCCESS in condition
        if step.get("name") in protected_steps:
            # With source verification failed, the default success() gate blocks
            # steps without `if`; every explicit gate requires verified=true.
            runs_with_failed_source = (
                bool(condition) and VERIFIED_SOURCE not in condition
            )
            assert not runs_with_failed_source, step.get("name")
            assert step.get("continue-on-error") is not True

    upload = named["Upload audit artifacts"]
    assert VERIFIED_SHA in upload["with"]["name"]
    assert upload["with"]["path"] == "${{ steps.source.outputs.evidence_dir }}"


def test_dependency_audit_source_failure_blocks_every_downstream_operation():
    _assert_dependency_audit_fails_closed_after_source_failure(
        _workflow()["jobs"]["dependency-audit"]
    )


def test_dependency_audit_rejects_identity_bypass_mutations():
    job = _workflow()["jobs"]["dependency-audit"]
    for step_name in (
        "Audit Python dependencies (pip-audit, blocking)",
        "Record Python audit JSON",
        "Install frontend dependencies",
        "Gate production dependencies (npm audit --omit=dev, blocking)",
        "Gate build/development dependencies (blocking)",
        "Upload audit artifacts",
        "Dependency audit verdict",
    ):
        for bypass in ("always()", "failure()", "!cancelled()"):
            mutated = copy.deepcopy(job)
            _named_steps(mutated)[step_name]["if"] = bypass
            with pytest.raises(AssertionError):
                _assert_dependency_audit_fails_closed_after_source_failure(mutated)


def test_contract_rejects_merge_ref_reordering_unverified_artifacts_and_swallowing():
    workflow = _workflow()
    base = workflow["jobs"]["backend"]
    mutations: list[dict] = []

    missing_ref = copy.deepcopy(base)
    _named_steps(missing_ref)["Checkout pull-request head"]["with"].pop("ref")
    mutations.append(missing_ref)

    merge_sha = copy.deepcopy(base)
    _named_steps(merge_sha)["Checkout pull-request head"]["with"]["ref"] = PUSH_SHA
    mutations.append(merge_sha)

    reordered = copy.deepcopy(base)
    reordered["steps"].insert(0, reordered["steps"].pop(3))
    mutations.append(reordered)

    nonblocking = copy.deepcopy(base)
    _named_steps(nonblocking)["Verify checked-out source identity"][
        "continue-on-error"
    ] = True
    mutations.append(nonblocking)

    swallowed = copy.deepcopy(base)
    identity = _named_steps(swallowed)["Verify checked-out source identity"]
    identity["run"] = f"{identity['run']}\ncommand || true"
    mutations.append(swallowed)

    missing_verifier = copy.deepcopy(base)
    identity = _named_steps(missing_verifier)["Verify checked-out source identity"]
    identity["run"] = identity["run"].replace(SOURCE_VERIFIER, "python -c 'pass'")
    mutations.append(missing_verifier)

    relative_verifier = copy.deepcopy(base)
    identity = _named_steps(relative_verifier)["Verify checked-out source identity"]
    identity["run"] = identity["run"].replace(
        SOURCE_VERIFIER, "python -I scripts/verify_ci_source.py"
    )
    mutations.append(relative_verifier)

    for mutated in mutations:
        with pytest.raises((AssertionError, KeyError)):
            _assert_exact_source_job("backend", mutated)

    artifact_mutation = copy.deepcopy(workflow)
    upload = next(
        step
        for step in artifact_mutation["jobs"]["dependency-audit"]["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact")
    )
    upload["with"]["name"] = "dependency-audit-${{ github.sha }}"
    with pytest.raises(AssertionError):
        _assert_verified_artifacts(artifact_mutation)


def test_workflow_has_no_status_swallowing_in_identity_or_critical_named_steps():
    workflow = _workflow()
    critical_name = re.compile(
        r"verify|prove|audit|test|build|lint|compile|acceptance|gitleaks", re.I
    )
    for job_id, job in workflow["jobs"].items():
        assert job.get("continue-on-error") is not True
        for step in job["steps"]:
            if critical_name.search(str(step.get("name", ""))):
                assert step.get("continue-on-error") is not True
                command = str(step.get("run", ""))
                for swallowed in FAILURE_SWALLOWING:
                    assert swallowed not in command, f"{job_id}: {step.get('name')}"


def test_no_always_condition_can_bypass_failed_source_verification():
    workflow = _workflow()
    for job_id, job in workflow["jobs"].items():
        source_index = job["steps"].index(
            _named_steps(job)["Verify checked-out source identity"]
        )
        for step in job["steps"][source_index + 1 :]:
            condition = str(step.get("if", ""))
            if "always()" in condition:
                assert VERIFIED_SOURCE in condition, f"{job_id}: {step.get('name')}"
                assert SOURCE_SUCCESS in condition, f"{job_id}: {step.get('name')}"
