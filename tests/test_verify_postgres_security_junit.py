import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from scripts.postgres_security_contract import (
    CRITICAL_NODE_IDS,
    EVIDENCE_PROFILE,
    EXECUTION_FORMAT_VERSION,
    MANIFEST_FORMAT_VERSION,
    SELECTED_FILES,
    file_sha256,
    node_ids_digest,
)
from scripts.verify_postgres_security_junit import VerificationError, verify_report

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=ROOT,
    capture_output=True,
    check=True,
    text=True,
).stdout.strip()
RUN_NONCE = "unit-verifier-run-0001"


@pytest.fixture(scope="session")
def collected_manifest(tmp_path_factory) -> dict:
    evidence = tmp_path_factory.mktemp("postgres-collection")
    manifest = evidence / "manifest.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.collect_postgres_security_manifest",
            "--output",
            str(manifest),
            "--source-sha",
            SOURCE_SHA,
            "--run-nonce",
            RUN_NONCE,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    value = json.loads(manifest.read_text(encoding="utf-8"))
    assert len(value["node_ids"]) > len(CRITICAL_NODE_IDS)
    return value


def _junit_identity(node_id: str) -> tuple[str, str]:
    path, remainder = node_id.split("::", 1)
    parts = remainder.split("::")
    classname = path.removesuffix(".py").replace("/", ".")
    if len(parts) > 1:
        classname += "." + ".".join(parts[:-1])
    return classname, parts[-1]


def _set_counters(element: ET.Element) -> None:
    cases = list(element.iter("testcase"))
    element.set("tests", str(len(cases)))
    element.set(
        "failures", str(sum(case.find("failure") is not None for case in cases))
    )
    element.set("errors", str(sum(case.find("error") is not None for case in cases)))
    element.set("skipped", str(sum(case.find("skipped") is not None for case in cases)))


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _refresh_execution(evidence: dict) -> None:
    report = evidence["report"]
    execution = json.loads(evidence["execution"].read_text(encoding="utf-8"))
    execution["junit_sha256"] = file_sha256(report)
    mtime = report.stat().st_mtime_ns
    execution["started_at_ns"] = mtime - 1_000_000_000
    execution["finished_at_ns"] = mtime + 1_000_000_000
    _write_json(evidence["execution"], execution)


def _make_evidence(
    tmp_path: Path,
    collected_manifest: dict,
    *,
    executed_node_ids: list[str] | None = None,
    outcomes: dict[str, str] | None = None,
    nested: bool = False,
) -> dict:
    manifest_value = deepcopy(collected_manifest)
    manifest_value["source_sha"] = SOURCE_SHA
    manifest_value["run_nonce"] = RUN_NONCE
    manifest_value["profile"] = EVIDENCE_PROFILE
    manifest = tmp_path / "manifest.json"
    report = tmp_path / "report.xml"
    execution = tmp_path / "execution.json"
    _write_json(manifest, manifest_value)

    root = ET.Element("testsuites")
    outer = ET.SubElement(root, "testsuite", name="outer") if nested else None
    suite_parent = outer if outer is not None else root
    suite = ET.SubElement(suite_parent, "testsuite", name="pytest")
    properties = ET.SubElement(suite, "properties")
    for name, value in (
        ("interlock_evidence_profile", EVIDENCE_PROFILE),
        ("interlock_source_sha", SOURCE_SHA),
        ("interlock_run_nonce", RUN_NONCE),
        ("interlock_manifest_digest", manifest_value["node_ids_sha256"]),
    ):
        ET.SubElement(properties, "property", name=name, value=value)

    outcomes = outcomes or {}
    nodes = (
        list(manifest_value["node_ids"])
        if executed_node_ids is None
        else executed_node_ids
    )
    for node_id in nodes:
        classname, name = _junit_identity(node_id)
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        case_properties = ET.SubElement(case, "properties")
        exact_outcome = outcomes.get(node_id, "passed")
        ET.SubElement(
            case_properties,
            "property",
            name="interlock_node_id",
            value=node_id,
        )
        ET.SubElement(
            case_properties,
            "property",
            name="interlock_outcome",
            value=exact_outcome,
        )
        if exact_outcome in {"skipped", "xfail"}:
            ET.SubElement(case, "skipped", message="synthetic skip")
        elif exact_outcome == "failed":
            ET.SubElement(case, "failure", message="synthetic failure")
        elif exact_outcome == "error":
            ET.SubElement(case, "error", message="synthetic error")

    _set_counters(suite)
    if outer is not None:
        _set_counters(outer)
    _set_counters(root)
    ET.ElementTree(root).write(report, encoding="utf-8", xml_declaration=True)
    mtime = report.stat().st_mtime_ns
    execution_value = {
        "format_version": EXECUTION_FORMAT_VERSION,
        "profile": EVIDENCE_PROFILE,
        "source_sha": SOURCE_SHA,
        "run_nonce": RUN_NONCE,
        "selected_files": list(SELECTED_FILES),
        "manifest_digest": manifest_value["node_ids_sha256"],
        "expected_count": len(manifest_value["node_ids"]),
        "pytest_exit_code": 0,
        "junit_file": report.name,
        "junit_sha256": file_sha256(report),
        "started_at_ns": mtime - 1_000_000_000,
        "finished_at_ns": mtime + 1_000_000_000,
    }
    _write_json(execution, execution_value)
    return {
        "manifest": manifest,
        "report": report,
        "execution": execution,
        "source_sha": SOURCE_SHA,
        "run_nonce": RUN_NONCE,
    }


def _verify(evidence: dict):
    return verify_report(
        evidence["report"],
        manifest_path=evidence["manifest"],
        execution_path=evidence["execution"],
        source_sha=evidence["source_sha"],
        run_nonce=evidence["run_nonce"],
    )


def test_accepts_complete_current_collection(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)

    summary = _verify(evidence)

    assert summary.total == len(collected_manifest["node_ids"])
    assert summary.skipped == summary.failed == summary.errors == 0
    assert summary.source_sha == SOURCE_SHA
    for path in (evidence["manifest"], evidence["report"], evidence["execution"]):
        rendered = path.read_text(encoding="utf-8")
        assert "postgresql://" not in rendered
        assert "INTERLOCK_TEST_DATABASE_URL" not in rendered


def test_accepts_nested_suites_with_consistent_data(tmp_path, collected_manifest):
    summary = _verify(_make_evidence(tmp_path, collected_manifest, nested=True))

    assert summary.total == len(collected_manifest["node_ids"])


def test_rejects_missing_junit(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    evidence["report"].unlink()
    with pytest.raises(VerificationError, match="report does not exist"):
        _verify(evidence)


def test_rejects_evidence_split_across_directories(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    moved = elsewhere / evidence["report"].name
    evidence["report"].replace(moved)
    evidence["report"] = moved
    with pytest.raises(VerificationError, match="share one current-run directory"):
        _verify(evidence)


def test_rejects_malformed_xml(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    evidence["report"].write_text("<testsuites>", encoding="utf-8")
    with pytest.raises(VerificationError, match="not valid XML"):
        _verify(evidence)


def test_rejects_xml_entity_declarations(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    evidence["report"].write_text(
        '<!DOCTYPE x [<!ENTITY e "x">]><testsuites/>', encoding="utf-8"
    )
    with pytest.raises(VerificationError, match="prohibited XML"):
        _verify(evidence)


def test_rejects_empty_suite(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest, executed_node_ids=[])
    with pytest.raises(VerificationError, match="contains no test cases"):
        _verify(evidence)


def test_rejects_missing_manifest(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    evidence["manifest"].unlink()
    with pytest.raises(VerificationError, match="manifest does not exist"):
        _verify(evidence)


def test_rejects_malformed_manifest(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    evidence["manifest"].write_text("not-json", encoding="utf-8")
    with pytest.raises(VerificationError, match="not valid JSON"):
        _verify(evidence)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("format_version", MANIFEST_FORMAT_VERSION + 1, "version"),
        ("profile", "wrong-profile", "profile"),
        ("source_sha", "0" * 40, "source SHA"),
        ("run_nonce", "stale-run-nonce", "run nonce"),
        ("selected_files", list(SELECTED_FILES[:-1]), "selected files"),
    ],
)
def test_rejects_wrong_manifest_provenance(
    tmp_path, collected_manifest, field, value, message
):
    evidence = _make_evidence(tmp_path, collected_manifest)
    manifest = json.loads(evidence["manifest"].read_text(encoding="utf-8"))
    manifest[field] = value
    _write_json(evidence["manifest"], manifest)
    with pytest.raises(VerificationError, match=message):
        _verify(evidence)


def test_rejects_duplicate_manifest_node_ids(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    manifest = json.loads(evidence["manifest"].read_text(encoding="utf-8"))
    manifest["node_ids"].append(manifest["node_ids"][0])
    manifest["node_ids_sha256"] = node_ids_digest(manifest["node_ids"])
    _write_json(evidence["manifest"], manifest)
    with pytest.raises(VerificationError, match="duplicate node IDs"):
        _verify(evidence)


def test_rejects_duplicate_junit_identities(tmp_path, collected_manifest):
    nodes = list(collected_manifest["node_ids"])
    evidence = _make_evidence(
        tmp_path, collected_manifest, executed_node_ids=[*nodes, nodes[0]]
    )
    with pytest.raises(VerificationError, match="duplicate testcase identities"):
        _verify(evidence)


def test_rejects_one_missing_executed_case(tmp_path, collected_manifest):
    evidence = _make_evidence(
        tmp_path,
        collected_manifest,
        executed_node_ids=list(collected_manifest["node_ids"][:-1]),
    )
    with pytest.raises(VerificationError, match="missing from JUnit"):
        _verify(evidence)


def test_rejects_one_unexpected_case(tmp_path, collected_manifest):
    unexpected = SELECTED_FILES[0] + "::test_uncollected_synthetic_case"
    evidence = _make_evidence(
        tmp_path,
        collected_manifest,
        executed_node_ids=[*collected_manifest["node_ids"], unexpected],
    )
    with pytest.raises(VerificationError, match="uncollected PostgreSQL case"):
        _verify(evidence)


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        ("skipped", "skipped PostgreSQL"),
        ("failed", "failed PostgreSQL"),
        ("error", "errored PostgreSQL"),
        ("xfail", "skipped PostgreSQL"),
        ("xpass", "non-passing outcome"),
    ],
)
def test_rejects_non_passing_outcomes(tmp_path, collected_manifest, outcome, message):
    node_id = collected_manifest["node_ids"][0]
    evidence = _make_evidence(tmp_path, collected_manifest, outcomes={node_id: outcome})
    with pytest.raises(VerificationError, match=message):
        _verify(evidence)


@pytest.mark.parametrize("counter", ["tests", "failures", "errors", "skipped"])
def test_rejects_inconsistent_aggregate_counters(tmp_path, collected_manifest, counter):
    evidence = _make_evidence(tmp_path, collected_manifest)
    tree = ET.parse(evidence["report"])
    suite = tree.find(".//testsuite")
    assert suite is not None
    suite.set(counter, str(int(suite.get(counter, "0")) + 1))
    tree.write(evidence["report"], encoding="utf-8", xml_declaration=True)
    _refresh_execution(evidence)
    with pytest.raises(VerificationError, match="counter is inconsistent"):
        _verify(evidence)


def test_rejects_nested_suite_with_hidden_failure(tmp_path, collected_manifest):
    node_id = collected_manifest["node_ids"][0]
    evidence = _make_evidence(
        tmp_path,
        collected_manifest,
        outcomes={node_id: "failed"},
        nested=True,
    )
    with pytest.raises(VerificationError, match="failed PostgreSQL"):
        _verify(evidence)


def test_rejects_stale_execution_nonce(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    execution = json.loads(evidence["execution"].read_text(encoding="utf-8"))
    execution["run_nonce"] = "stale-execution-run"
    _write_json(evidence["execution"], execution)
    with pytest.raises(VerificationError, match="run_nonce"):
        _verify(evidence)


def test_rejects_stale_execution_sha(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    execution = json.loads(evidence["execution"].read_text(encoding="utf-8"))
    execution["source_sha"] = "0" * 40
    _write_json(evidence["execution"], execution)
    with pytest.raises(VerificationError, match="source_sha"):
        _verify(evidence)


def test_rejects_pytest_collection_or_process_failure(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    execution = json.loads(evidence["execution"].read_text(encoding="utf-8"))
    execution["pytest_exit_code"] = 2
    _write_json(evidence["execution"], execution)
    with pytest.raises(VerificationError, match="pytest_exit_code"):
        _verify(evidence)


def test_rejects_report_outside_execution_window(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    execution = json.loads(evidence["execution"].read_text(encoding="utf-8"))
    execution["started_at_ns"] = 1
    execution["finished_at_ns"] = 2
    _write_json(evidence["execution"], execution)
    with pytest.raises(VerificationError, match="execution window"):
        _verify(evidence)


def test_rejects_wrong_classname_with_matching_short_name(tmp_path, collected_manifest):
    evidence = _make_evidence(tmp_path, collected_manifest)
    tree = ET.parse(evidence["report"])
    case = tree.find(".//testcase")
    assert case is not None
    case.set("classname", "tests.test_wrong_file")
    tree.write(evidence["report"], encoding="utf-8", xml_declaration=True)
    _refresh_execution(evidence)
    with pytest.raises(VerificationError, match="does not match its node ID"):
        _verify(evidence)


def test_rejects_old_fourteen_case_partial_report(tmp_path, collected_manifest):
    evidence = _make_evidence(
        tmp_path,
        collected_manifest,
        executed_node_ids=sorted(CRITICAL_NODE_IDS),
    )
    with pytest.raises(VerificationError, match="missing from JUnit"):
        _verify(evidence)
