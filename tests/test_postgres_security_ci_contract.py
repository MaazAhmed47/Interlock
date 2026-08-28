import ast
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
REBASELINE_TEST = ROOT / "tests" / "test_postgres_rebaseline_cas.py"
AUDIT_CONCURRENCY_TEST = ROOT / "tests" / "test_audit_chain_concurrency.py"


def _function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


def test_postgres_job_is_digest_pinned_service_network_only_and_url_scoped():
    raw = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw)
    job = workflow["jobs"]["postgres-security"]
    service = job["services"]["postgres"]

    assert re.fullmatch(
        r"python:3\.12\.9-bookworm@sha256:[0-9a-f]{64}", job["container"]["image"]
    )
    assert re.fullmatch(r"postgres:16@sha256:[0-9a-f]{64}", service["image"])
    assert "ports" not in service
    assert service["env"] == {
        "POSTGRES_USER": "interlock_ci",
        "POSTGRES_PASSWORD": "interlock_ci_disposable_only",
        "POSTGRES_DB": "interlock_ci",
    }
    options = service["options"]
    assert "pg_isready -U interlock_ci -d interlock_ci" in options
    assert "--health-retries 12" in options

    pytest_step = next(
        step
        for step in job["steps"]
        if step.get("name") == "Run PostgreSQL security cases"
    )
    assert set(pytest_step["env"]) == {"INTERLOCK_TEST_DATABASE_URL"}
    assert (
        "@postgres:5432/interlock_ci"
        in pytest_step["env"]["INTERLOCK_TEST_DATABASE_URL"]
    )
    assert raw.count("INTERLOCK_TEST_DATABASE_URL") == 1
    for test_file in (
        "tests/test_postgres_rebaseline_cas.py",
        "tests/test_postgres_ci_boundary_review_gate.py",
        "tests/test_audit_chain_concurrency.py",
    ):
        assert test_file in pytest_step["run"]
    assert "--tb=short" in pytest_step["run"]
    assert "--junitxml=postgres-security-junit.xml" in pytest_step["run"]

    verifier_step = next(
        step
        for step in job["steps"]
        if step.get("name") == "Prove PostgreSQL cases executed"
    )
    assert "env" not in verifier_step
    assert "verify_postgres_security_junit.py" in verifier_step["run"]


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
    yield_index = next(
        index
        for index, statement in enumerate(fixture.body)
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Yield)
    )
    cleanup = ast.unparse(
        ast.Module(body=fixture.body[yield_index + 1 :], type_ignores=[])
    )
    assert "_run_snippet(_RESET_SRC, [url])" in cleanup
