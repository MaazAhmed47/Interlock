from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import verify_phase2_docker_evidence as verifier

PROFILE = Path(__file__).resolve().parents[1] / "deploy" / "phase2-docker"
sys.path.insert(0, str(PROFILE))
from phase2_cases import REQUIRED_CASES  # noqa: E402


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_evidence(path: Path) -> None:
    path.mkdir()
    results = [
        {"case": name, "category": "", "outcome": "passed"} for name in REQUIRED_CASES
    ]
    results_path = path / "results.jsonl"
    results_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
        encoding="utf-8",
    )
    suite = ET.Element(
        "testsuite",
        tests=str(len(results)),
        failures="0",
        errors="0",
        skipped="0",
    )
    for item in results:
        ET.SubElement(suite, "testcase", name=item["case"])
    junit = path / "junit.xml"
    ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    log = path / "proxy.log"
    log.write_text("safe numeric log\n", encoding="utf-8")
    artifacts = {item.name: _digest(item) for item in (results_path, junit, log)}
    manifest = {
        "schema": "interlock.phase2-docker-evidence.v1",
        "source_sha": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "source_dirty_development_run": False,
        "squid_image": verifier.SQUID_IMAGE,
        "squid_image_digest": verifier.SQUID_DIGEST,
        "squid_policy_sha256": _digest(PROFILE / "squid.conf"),
        "squid_allowed_domains_sha256": _digest(PROFILE / "allowed-domains.txt"),
        "squid_policy_bundle_sha256": hashlib.sha256(
            (PROFILE / "squid.conf").read_bytes()
            + (PROFILE / "allowed-domains.txt").read_bytes()
        ).hexdigest(),
        "compose_source_sha256": _digest(PROFILE / "compose.yaml"),
        "compose_rendered_sha256": "b" * 64,
        "compose_project_name": "interlock-p2-123456789abc",
        "project_name_hash": hashlib.sha256(b"interlock-p2-123456789abc").hexdigest(),
        "test_source_sha256": verifier.test_source_digest(),
        "sentinel_sha256": {
            "authorization": "c" * 64,
            "proxy_credential": "d" * 64,
            "query": "e" * 64,
        },
        "required_cases": list(REQUIRED_CASES),
        "expected_case_count": len(results),
        "executed_case_count": len(results),
        "passed_case_count": len(results),
        "failed_case_count": 0,
        "results_sha256": _digest(results_path),
        "artifact_sha256": artifacts,
    }
    (path / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )


def _verify(monkeypatch: pytest.MonkeyPatch, path: Path) -> int:
    monkeypatch.setattr(
        verifier, "rendered_compose_digest", lambda _sha, _project: "b" * 64
    )
    monkeypatch.setattr(sys, "argv", ["verify", str(path)])
    return verifier.main()


def _rehash(path: Path) -> None:
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["results_sha256"] = _digest(path / "results.jsonl")
    manifest["artifact_sha256"] = {
        item.name: _digest(item)
        for item in path.iterdir()
        if item.is_file() and item.name != "manifest.json"
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")


def test_verifier_accepts_exact_complete_evidence(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    assert _verify(monkeypatch, evidence) == 0


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "failed", "malformed"])
def test_verifier_rejects_result_mutations(tmp_path, monkeypatch, mutation):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    path = evidence / "results.jsonl"
    values = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
    if mutation == "missing":
        values.pop()
    elif mutation == "duplicate":
        values[-1] = values[0]
    elif mutation == "failed":
        values[-1]["outcome"] = "failed"
    else:
        values[-1]["unexpected"] = True
    path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in values),
        encoding="utf-8",
    )
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize("node", ["failure", "error", "skipped"])
def test_verifier_rejects_junit_non_pass_nodes(tmp_path, monkeypatch, node):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    junit = evidence / "junit.xml"
    suite = ET.parse(junit).getroot()
    suite.set(node if node != "skipped" else "skipped", "1")
    ET.SubElement(suite.findall("testcase")[0], node)
    ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize("marker", ["xfail", "xpass"])
def test_verifier_rejects_pytest_outcome_markers(tmp_path, monkeypatch, marker):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    junit = evidence / "junit.xml"
    suite = ET.parse(junit).getroot()
    suite.findall("testcase")[0].set("status", marker)
    ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


def test_verifier_rejects_stale_artifact_digest(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    (evidence / "proxy.log").write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize(
    "disclosure",
    [
        "postgresql://user:password@database:5432/name",
        "http://squid:3128",
        "Authorization: Bearer retained-value",
        "https://allowed.phase2.test/path?query=retained-value",
    ],
)
def test_verifier_rejects_retained_sensitive_output(tmp_path, monkeypatch, disclosure):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    (evidence / "proxy.log").write_text(disclosure + "\n", encoding="utf-8")
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


def test_verifier_rejects_counter_inconsistency(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    manifest_path = evidence / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["passed_case_count"] -= 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


def test_verifier_rejects_stale_rendered_compose(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    manifest_path = evidence / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["compose_rendered_sha256"] = "a" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)
