"""Tests for the real local Terraform CLI proof pack.

Run: python3 -m pytest tests/test_terraform_cli_proof_pack.py -q -s
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.terraform_cli import (
    find_terraform_binary,
    run_terraform_cli_proof_pack,
)


def require_terraform():
    binary = find_terraform_binary()
    if not binary or not Path(binary).exists():
        pytest.skip("Terraform CLI is not available in this environment")
    return binary


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_terraform_cli_pack_runs_real_plan_apply_destroy_and_readback():
    binary = require_terraform()
    report = run_terraform_cli_proof_pack(terraform_bin=binary)
    scenarios = _by_name(report)

    assert report["provider"] == "terraform"
    assert report["mode"] == "local_terraform_cli_sandbox"
    assert report["summary"]["all_passed"] is True
    assert report["terraform"]["binary"] == binary
    assert report["terraform"]["version"]
    assert set(scenarios) == {
        "real_plan_false_positive_control",
        "real_apply_readback_drift",
        "real_destroy_readback_drift",
        "real_plan_apply_destroy_chain_drift",
    }

    clean = scenarios["real_plan_false_positive_control"]
    assert clean["ok"] is True
    assert clean["severity"] == "none"
    assert clean["decision"] == "allow"
    assert clean["before_state_hash"] == clean["after_state_hash"]

    apply = scenarios["real_apply_readback_drift"]
    assert apply["ok"] is True
    assert apply["severity"] == "critical"
    assert apply["decision"] == "quarantine"
    assert "silent_side_effect_drift" in apply["finding_types"]
    assert apply["before_state_hash"] != apply["after_state_hash"]
    assert apply["readback"]["before_resource_count"] == 0
    assert apply["readback"]["after_resource_count"] == 1
    assert (
        apply["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    destroy = scenarios["real_destroy_readback_drift"]
    assert destroy["ok"] is True
    assert destroy["severity"] == "critical"
    assert destroy["decision"] == "quarantine"
    assert "silent_side_effect_drift" in destroy["finding_types"]
    assert destroy["readback"]["before_resource_count"] == 1
    assert destroy["readback"]["after_resource_count"] == 0

    chain = scenarios["real_plan_apply_destroy_chain_drift"]
    assert chain["ok"] is True
    assert chain["severity"] == "critical"
    assert chain["decision"] == "deny"
    assert "chain_preview_to_deploy" in chain["finding_types"]
    assert "chain_preview_to_destructive" in chain["finding_types"]


def test_terraform_cli_pack_is_evidence_safe_and_honest():
    binary = require_terraform()
    report = run_terraform_cli_proof_pack(terraform_bin=binary)
    encoded = json.dumps(report, sort_keys=True)

    assert "real terraform cli" in " ".join(report["limitations"]).lower()
    assert "no terraform cloud" in " ".join(report["limitations"]).lower()
    assert "no cloud credentials" in " ".join(report["limitations"]).lower()
    assert "interlock-local-secret" not in encoded
    assert "tfstate-secret" not in encoded
    assert "sha256:" in encoded


def test_terraform_cli_pack_cli_runs_if_terraform_available():
    binary = require_terraform()
    script = (
        Path(__file__).resolve().parents[1] / "demo" / "run_terraform_cli_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script), "--terraform-bin", binary],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "PASS real_plan_false_positive_control" in out.stdout
    assert "PASS real_apply_readback_drift" in out.stdout
    assert "PASS real_destroy_readback_drift" in out.stdout
    assert "PASS real_plan_apply_destroy_chain_drift" in out.stdout
