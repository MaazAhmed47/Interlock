import ast
import copy
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
REBASELINE_TEST = ROOT / "tests" / "test_postgres_rebaseline_cas.py"
AUDIT_CONCURRENCY_TEST = ROOT / "tests" / "test_audit_chain_concurrency.py"
SECURITY_CONTRACT = ROOT / "scripts" / "postgres_security_contract.py"
DATABASE_GUARD = ROOT / "scripts" / "postgres_test_database.py"

CRITICAL_POSTGRES_STEPS = {
    "Checkout pull-request head",
    "Checkout event SHA",
    "Verify checked-out source identity",
    "Authorize disposable PostgreSQL session",
    "Collect PostgreSQL security manifest",
    "Run PostgreSQL security cases",
    "Prove PostgreSQL cases executed",
    "Verify PostgreSQL cleanup",
    "Clear disposable PostgreSQL session marker",
    "Upload PostgreSQL security report",
}


def _function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _workflow_job():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return workflow["jobs"]["postgres-security"]


def _assert_postgres_job_is_blocking(job):
    assert job.get("continue-on-error") is not True
    assert "if" not in job
    steps = {step.get("name"): step for step in job["steps"]}
    assert CRITICAL_POSTGRES_STEPS <= set(steps)
    for name in CRITICAL_POSTGRES_STEPS:
        step = steps[name]
        assert step.get("continue-on-error") is not True
        if name in {
            "Verify PostgreSQL cleanup",
            "Clear disposable PostgreSQL session marker",
            "Upload PostgreSQL security report",
        }:
            assert str(step.get("if", "")).startswith("always() &&")
        elif name == "Checkout pull-request head":
            assert step.get("if") == "github.event_name == 'pull_request'"
        elif name == "Checkout event SHA":
            assert step.get("if") == "github.event_name != 'pull_request'"
        else:
            assert "if" not in step
        command = str(step.get("run", ""))
        for swallowed_status in ("|| true", "exit 0", "set +e", "| true"):
            assert swallowed_status not in command
        assert re.search(r"(?<!\|)\|(?!\|)", command) is None


def _assert_exact_source_binding(job):
    steps = {step.get("name"): step for step in job["steps"]}
    pr_checkout = steps["Checkout pull-request head"]
    assert pr_checkout["if"] == "github.event_name == 'pull_request'"
    assert pr_checkout["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"

    push_checkout = steps["Checkout event SHA"]
    assert push_checkout["if"] == "github.event_name != 'pull_request'"
    assert push_checkout["with"]["ref"] == "${{ github.sha }}"

    identity = steps["Verify checked-out source identity"]
    assert identity["id"] == "source"
    assert identity["run"].startswith("set -euo pipefail\n")
    assert "python -I scripts/verify_ci_source.py" in identity["run"]
    assert '--expected "$expected"' in identity["run"]
    assert '--github-output "$GITHUB_OUTPUT"' in identity["run"]
    assert "github.event.pull_request.head.sha" in identity["run"]
    assert "github.sha" in identity["run"]
    assert (
        'git config --global --add safe.directory "$GITHUB_WORKSPACE"'
        in identity["run"]
    )
    assert "$(" not in identity["run"]

    artifact = steps["Upload PostgreSQL security report"]
    assert (
        artifact["with"]["name"] == "postgres-security-${{ steps.source.outputs.sha }}"
    )
    assert "github.sha" not in str(artifact)
    for step_name in (
        "Collect PostgreSQL security manifest",
        "Run PostgreSQL security cases",
        "Prove PostgreSQL cases executed",
    ):
        assert "--source-sha ${{ steps.source.outputs.sha }}" in steps[step_name]["run"]


def test_postgres_job_is_digest_pinned_service_network_only_and_url_scoped():
    raw = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw)
    job = workflow["jobs"]["postgres-security"]
    service = job["services"]["postgres"]

    assert job["timeout-minutes"] == 15
    assert re.fullmatch(
        r"python:3\.12\.9-bookworm@sha256:[0-9a-f]{64}", job["container"]["image"]
    )
    assert re.fullmatch(r"postgres:16@sha256:[0-9a-f]{64}", service["image"])
    assert "ports" not in service
    assert service["env"] == {
        "POSTGRES_USER": "interlock_test",
        "POSTGRES_PASSWORD": "interlock_ci_disposable_only",
        "POSTGRES_DB": "interlock_test",
    }
    options = service["options"]
    assert "pg_isready -U interlock_test -d interlock_test" in options
    assert "--health-retries 12" in options

    assert "env" not in job
    steps = {step.get("name"): step for step in job["steps"]}
    postgres_env_steps = {
        "Authorize disposable PostgreSQL session",
        "Run PostgreSQL security cases",
        "Verify PostgreSQL cleanup",
        "Clear disposable PostgreSQL session marker",
    }
    expected_env = {
        "INTERLOCK_TEST_DATABASE_URL",
        "INTERLOCK_ALLOW_DESTRUCTIVE_TEST_DATABASE",
        "INTERLOCK_DESTRUCTIVE_TEST_RUN_ID",
        "INTERLOCK_DESTRUCTIVE_TEST_SESSION_TOKEN",
    }
    for name, step in steps.items():
        if name in postgres_env_steps:
            assert set(step["env"]) == expected_env
            assert (
                "@postgres:5432/interlock_test"
                in step["env"]["INTERLOCK_TEST_DATABASE_URL"]
            )
            assert (
                step["env"]["INTERLOCK_ALLOW_DESTRUCTIVE_TEST_DATABASE"]
                == "interlock-disposable-only"
            )
        else:
            assert "INTERLOCK_TEST_DATABASE_URL" not in str(step.get("env", {}))
        command = str(step.get("run", ""))
        assert "set -x" not in command
        assert "INTERLOCK_TEST_DATABASE_URL" not in command
        assert "postgresql://" not in command
    assert raw.count("INTERLOCK_TEST_DATABASE_URL") == 1
    contract_source = SECURITY_CONTRACT.read_text(encoding="utf-8")
    for test_file in (
        "tests/test_postgres_rebaseline_cas.py",
        "tests/test_postgres_ci_boundary_review_gate.py",
        "tests/test_audit_chain_concurrency.py",
    ):
        assert test_file in contract_source

    pytest_step = steps["Run PostgreSQL security cases"]
    assert "scripts.run_postgres_security_tests" in pytest_step["run"]
    assert "--manifest" in pytest_step["run"]
    assert "--execution" in pytest_step["run"]

    verifier_step = steps["Prove PostgreSQL cases executed"]
    assert "env" not in verifier_step
    assert "scripts.verify_postgres_security_junit" in verifier_step["run"]
    assert "--manifest" in verifier_step["run"]
    assert "--execution" in verifier_step["run"]


def test_postgres_job_checks_out_and_binds_evidence_to_exact_event_source():
    job = _workflow_job()
    _assert_exact_source_binding(job)


def test_exact_source_binding_rejects_merge_ref_and_unverified_artifacts():
    job = _workflow_job()
    mutations = []

    merge_ref = copy.deepcopy(job)
    checkout = next(
        step
        for step in merge_ref["steps"]
        if step.get("name") == "Checkout pull-request head"
    )
    checkout["with"].pop("ref")
    mutations.append(merge_ref)

    github_sha_artifact = copy.deepcopy(job)
    artifact = next(
        step
        for step in github_sha_artifact["steps"]
        if step.get("name") == "Upload PostgreSQL security report"
    )
    artifact["with"]["name"] = "postgres-security-${{ github.sha }}"
    mutations.append(github_sha_artifact)

    no_identity_assertion = copy.deepcopy(job)
    identity = next(
        step
        for step in no_identity_assertion["steps"]
        if step.get("name") == "Verify checked-out source identity"
    )
    identity["run"] = identity["run"].replace(
        "python -I scripts/verify_ci_source.py", "python -c 'pass'"
    )
    mutations.append(no_identity_assertion)

    for mutated in mutations:
        with pytest.raises((AssertionError, KeyError)):
            _assert_exact_source_binding(mutated)


def test_postgres_job_and_critical_steps_cannot_be_non_blocking():
    job = _workflow_job()
    _assert_postgres_job_is_blocking(job)

    mutated = copy.deepcopy(job)
    mutated["continue-on-error"] = True
    with pytest.raises(AssertionError):
        _assert_postgres_job_is_blocking(mutated)

    for step_name in CRITICAL_POSTGRES_STEPS:
        mutated = copy.deepcopy(job)
        next(step for step in mutated["steps"] if step.get("name") == step_name)[
            "continue-on-error"
        ] = True
        with pytest.raises(AssertionError):
            _assert_postgres_job_is_blocking(mutated)


def test_postgres_critical_steps_cannot_swallow_or_hide_failure():
    job = _workflow_job()
    for mutation in ("command || true", "command; exit 0", "set +e\ncommand"):
        mutated = copy.deepcopy(job)
        pytest_step = next(
            step
            for step in mutated["steps"]
            if step.get("name") == "Run PostgreSQL security cases"
        )
        pytest_step["run"] = mutation
        with pytest.raises(AssertionError):
            _assert_postgres_job_is_blocking(mutated)

    mutated = copy.deepcopy(job)
    pytest_step = next(
        step
        for step in mutated["steps"]
        if step.get("name") == "Run PostgreSQL security cases"
    )
    pytest_step["if"] = "always()"
    with pytest.raises(AssertionError):
        _assert_postgres_job_is_blocking(mutated)


def test_postgres_execution_verifier_cannot_be_omitted():
    job = _workflow_job()
    mutated = copy.deepcopy(job)
    mutated["steps"] = [
        step
        for step in mutated["steps"]
        if step.get("name") != "Prove PostgreSQL cases executed"
    ]
    with pytest.raises(AssertionError):
        _assert_postgres_job_is_blocking(mutated)


def test_concurrent_reviewer_harness_keeps_bounded_synchronization_and_errors():
    function = _function(
        REBASELINE_TEST,
        "test_concurrent_promotes_exactly_one_succeeds_on_postgres",
    )
    calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]

    assert any(
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "threading"
        and call.func.attr == "Barrier"
        and any(isinstance(arg, ast.Constant) and arg.value == 3 for arg in call.args)
        for call in calls
    )
    assert any(
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "wait"
        and any(keyword.arg == "timeout" for keyword in call.keywords)
        for call in calls
    )
    assert any(
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "join"
        and any(keyword.arg == "timeout" for keyword in call.keywords)
        for call in calls
    )
    rendered = ast.unparse(function)
    assert "errors.append(exc)" in rendered
    assert "assert errors == []" in rendered
    assert "assert len(results) == 2" in rendered


def test_real_postgres_race_fixture_resets_after_yield():
    fixture = _function(AUDIT_CONCURRENCY_TEST, "clean_race_database")
    guarded = next(
        statement for statement in fixture.body if isinstance(statement, ast.Try)
    )
    assert any(isinstance(node, ast.Yield) for node in ast.walk(guarded))
    cleanup = ast.unparse(ast.Module(body=guarded.finalbody, type_ignores=[]))
    assert "_run_snippet(_RESET_SRC, [url])" in cleanup


def test_quarantine_writer_proves_a_real_postgres_advisory_lock_wait():
    function = _function(
        REBASELINE_TEST,
        "test_quarantine_waits_for_promote_and_is_not_silently_lost_on_postgres",
    )
    rendered = ast.unparse(function)

    assert "_advisory_waiters" in rendered
    assert "quarantine_waited" in rendered
    assert "assert quarantine_waited" in rendered


def test_rebaseline_cleanup_inventory_cannot_drop_surface_snapshots():
    module = ast.parse(
        DATABASE_GUARD.read_text(encoding="utf-8"), filename=str(DATABASE_GUARD)
    )
    assignment = next(
        node
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "REBASELINE_OWNED_TABLES"
            for target in node.targets
        )
    )
    tables = ast.literal_eval(assignment.value)
    assert "tool_surface_snapshots" in tables

    cleanup = ast.unparse(_function(REBASELINE_TEST, "_clear_rebaseline_state"))
    assert "REBASELINE_OWNED_TABLES" in cleanup
    assert "assert_disposable_database" in cleanup
