"""Tests for the buyer-facing Interlock proof-suite runner.

Run: python3 -m pytest tests/test_interlock_proof_suite.py -q -s
"""

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.interlock_proof_suite import run_interlock_proof_suite, write_markdown_report

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text):
    return ANSI_RE.sub("", text)


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


def test_db_drift_demo_output_has_real_hashes_and_clean_control_call():
    script = Path(__file__).resolve().parents[1] / "demo" / "run_db_drift_ab.py"

    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )
    text = _plain(out.stdout)

    assert "rbac_violation" not in text
    assert "approved_surface_hash (none)" not in text
    assert "current_surface_hash  (none)" not in text
    assert re.search(r"approved_surface_hash\s+sha256:[0-9a-f]{20,}", text)
    assert re.search(r"current_surface_hash\s+sha256:[0-9a-f]{20,}", text)
    assert re.search(r"chain_verified\s+True", text)


def test_clean_demo_command_runs_only_behavioral_and_capability_proofs():
    script = Path(__file__).resolve().parents[1] / "demo" / "run_interlock_demo.py"

    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )
    text = _plain(out.stdout)

    assert "403->200" in text
    assert "effective_permission_expansion" in text
    assert "approved_surface_hash" in text
    assert "current_surface_hash" in text
    assert "chain_verified" in text
    assert "SKIP" not in text
    assert "response-data-exposure" not in text
    assert "chain drift" not in text.lower()


def test_clean_demo_command_has_scoped_render_repopulate_dry_run():
    script = Path(__file__).resolve().parents[1] / "demo" / "run_interlock_demo.py"

    out = subprocess.run(
        [
            sys.executable,
            str(script),
            "--repopulate-render",
            "--dry-run",
            "--skip-local-proof",
            "--mock-url",
            "https://example.test/mcp",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    text = _plain(out.stdout)

    assert "Render re-populate" in text
    assert "POST /mcp/servers" in text
    assert "POST /mcp/servers/clean-proof-docs/verify" in text
    assert "POST /mcp/servers/clean-proof-docs/rebaseline" in text
    assert "POST /mcp/discover" in text
    assert "POST /mcp/call" in text
    assert "read_document" in text
    assert "response-data-exposure" not in text
    assert "external-reach" not in text
    assert "chain drift" not in text.lower()
