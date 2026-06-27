"""Tests for the buyer-facing Interlock proof-suite runner.

Run: python3 -m pytest tests/test_interlock_proof_suite.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.interlock_proof_suite import run_interlock_proof_suite, write_markdown_report


def _by_key(report):
    return {result["key"]: result for result in report["results"]}


def test_interlock_proof_suite_can_run_selected_safe_pack():
    report = run_interlock_proof_suite(selected=["database-admin-local"])
    results = _by_key(report)

    assert report["suite"] == "interlock-drift-proof-suite"
    assert report["summary"]["all_passed"] is True
    assert report["summary"]["passed"] == 1
    assert report["summary"]["failed"] == 0
    assert report["summary"]["scenario_count"] >= 8
    assert results["database-admin-local"]["status"] == "PASS"
    assert results["database-admin-local"]["receipt_count"] >= 1
    assert results["database-admin-local"]["critical_or_high_count"] >= 4
    assert results["database-admin-local"]["decisions"]["deny"] >= 1


def test_interlock_proof_suite_reports_credential_gated_skips_honestly():
    report = run_interlock_proof_suite(selected=["docker-mysql-gated"])
    result = report["results"][0]

    assert report["summary"]["all_passed"] is True
    assert report["summary"]["skipped"] == 1
    assert result["status"] == "SKIP"
    assert result["credential_gated"] is True
    assert "skipped" in result["reason"]
    assert result["scenario_count"] == 0


def test_interlock_proof_suite_markdown_output_is_buyer_readable(tmp_path):
    report = run_interlock_proof_suite(selected=["payments-mock"])
    out = tmp_path / "suite.md"

    write_markdown_report(report, out)
    text = out.read_text()

    assert "# Interlock Drift Proof Suite Run" in text
    assert "Payments/billing proof pack" in text
    assert "High/critical detections" in text
    assert "not treated as a compliance certificate" in text


def test_interlock_proof_suite_cli_selected_json_runs():
    script = (
        Path(__file__).resolve().parents[1] / "demo" / "run_interlock_proof_suite.py"
    )
    out = subprocess.run(
        [sys.executable, str(script), "--only", "response-data-exposure", "--json"],
        check=True,
        text=True,
        capture_output=True,
    )
    report = json.loads(out.stdout)

    assert report["summary"]["all_passed"] is True
    assert report["results"][0]["key"] == "response-data-exposure"
    assert report["results"][0]["status"] == "PASS"
