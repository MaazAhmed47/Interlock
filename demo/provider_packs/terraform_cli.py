"""Real local Terraform CLI proof pack for Interlock.

This pack runs Terraform CLI in a temporary local sandbox using the built-in
``terraform_data`` resource. It does not contact Terraform Cloud, remote
backends, cloud providers, or external provider registries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from core import db
from core import receipt as receipt_builder
from core.chain_drift import build_chain_profile, classify_chain_drift
from core.drift_evidence import canonical_json_bytes
from core.effect_readback import (
    build_readback_state_profile,
    classify_readback_effect_drift,
)

PROVIDER = "terraform"
MODE = "local_terraform_cli_sandbox"
DEFAULT_LOCAL_TERRAFORM = Path("/tmp/interlock-terraform-bin/terraform")

TERRAFORM_CONFIG = """terraform {
  required_version = ">= 1.4.0"
}

resource "terraform_data" "interlock_canary" {
  input = {
    label   = "interlock-local-secret"
    purpose = "mcp-drift-proof"
  }
}

output "canary_id" {
  value = terraform_data.interlock_canary.id
}
"""


def find_terraform_binary() -> Optional[str]:
    """Find a Terraform binary without guessing or installing globally."""
    env_path = os.getenv("INTERLOCK_TERRAFORM_BIN")
    if env_path and Path(env_path).exists():
        return env_path
    if DEFAULT_LOCAL_TERRAFORM.exists():
        return str(DEFAULT_LOCAL_TERRAFORM)
    path = shutil.which("terraform")
    return path


def run_terraform_cli_proof_pack(terraform_bin: Optional[str] = None) -> Dict[str, Any]:
    """Run a real local Terraform CLI sandbox proof pack."""
    terraform_bin = terraform_bin or find_terraform_binary()
    if not terraform_bin:
        raise RuntimeError(
            "Terraform CLI is not available. Set INTERLOCK_TERRAFORM_BIN."
        )
    terraform_bin = str(Path(terraform_bin))
    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_terraform_cli_proof_pack.db")
    with tempfile.TemporaryDirectory(prefix="interlock-tf-cli-") as workspace:
        db.DB_PATH = tmp_db
        try:
            db.init_db()
            workspace_path = Path(workspace)
            _write_terraform_config(workspace_path)
            version = _terraform_version(terraform_bin)
            _run_tf(
                terraform_bin,
                workspace_path,
                ["init", "-backend=false", "-input=false", "-no-color"],
            )
            scenarios: List[Dict[str, Any]] = [
                _real_plan_false_positive_control(terraform_bin, workspace_path),
                _real_apply_readback_drift(terraform_bin, workspace_path),
                _real_destroy_readback_drift(terraform_bin, workspace_path),
                _real_plan_apply_destroy_chain_drift(),
            ]
            return {
                "provider": PROVIDER,
                "mode": MODE,
                "terraform": {
                    "binary": terraform_bin,
                    "version": version,
                    "workspace_hash": _safe_hash({"workspace": str(workspace_path)}),
                },
                "summary": {
                    "scenario_count": len(scenarios),
                    "all_passed": all(bool(s.get("ok")) for s in scenarios),
                },
                "scenarios": scenarios,
                "limitations": [
                    "Real Terraform CLI local sandbox using the built-in terraform_data resource.",
                    "No Terraform Cloud, remote backend, cloud provider, or production MCP server was contacted.",
                    "No cloud credentials are required or loaded; no external provider plugin is used.",
                    "This proves local Terraform plan/apply/destroy readback behavior, not AWS/GCP/Azure blast radius.",
                ],
            }
        finally:
            db.DB_PATH = old_db_path
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(tmp_db + suffix)
                except OSError:
                    pass


def _write_terraform_config(workspace: Path) -> None:
    (workspace / "main.tf").write_text(TERRAFORM_CONFIG, encoding="utf-8")


def _real_plan_false_positive_control(
    terraform_bin: str, workspace: Path
) -> Dict[str, Any]:
    before = _state_readback(workspace)
    _run_tf(
        terraform_bin, workspace, ["plan", "-input=false", "-no-color", "-out=tfplan"]
    )
    after = _state_readback(workspace)
    decision = classify_readback_effect_drift(
        before_profile=build_readback_state_profile(before),
        after_profile=build_readback_state_profile(after),
        target_response={"plan": True, "dry_run": True},
        expected_effect="no_change",
    )
    return _scenario(
        name="real_plan_false_positive_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        before=before,
        after=after,
        receipt=None,
    )


def _real_apply_readback_drift(terraform_bin: str, workspace: Path) -> Dict[str, Any]:
    before = _state_readback(workspace)
    _run_tf(
        terraform_bin,
        workspace,
        ["apply", "-input=false", "-auto-approve", "-no-color", "tfplan"],
    )
    after = _state_readback(workspace)
    decision = classify_readback_effect_drift(
        before_profile=build_readback_state_profile(before),
        after_profile=build_readback_state_profile(after),
        target_response={"plan": True, "dry_run": True},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name="real_apply_readback_drift",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name="real_apply_readback_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
            and before["resource_count"] == 0
            and after["resource_count"] == 1
        ),
        decision=decision,
        before=before,
        after=after,
        receipt=receipt,
    )


def _real_destroy_readback_drift(terraform_bin: str, workspace: Path) -> Dict[str, Any]:
    before = _state_readback(workspace)
    _run_tf(
        terraform_bin,
        workspace,
        ["destroy", "-input=false", "-auto-approve", "-no-color"],
    )
    after = _state_readback(workspace)
    decision = classify_readback_effect_drift(
        before_profile=build_readback_state_profile(before),
        after_profile=build_readback_state_profile(after),
        target_response={"plan": True, "dry_run": True},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name="real_destroy_readback_drift",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name="real_destroy_readback_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
            and before["resource_count"] == 1
            and after["resource_count"] == 0
        ),
        decision=decision,
        before=before,
        after=after,
        receipt=receipt,
    )


def _real_plan_apply_destroy_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "terraform-cli",
            "tool_name": "terraform_plan",
            "arguments": {"workspace": "interlock-local-secret"},
            "effects": ["plan"],
            "data_classes": ["infra"],
            "externality": "internal",
        },
        {
            "server_id": "terraform-cli",
            "tool_name": "terraform_apply",
            "arguments": {"plan_file": "tfstate-secret"},
            "effects": ["applied", "deployed"],
            "data_classes": ["infra"],
            "externality": "external",
        },
        {
            "server_id": "terraform-cli",
            "tool_name": "terraform_destroy",
            "arguments": {"resource": "interlock-local-secret"},
            "effects": ["deleted", "destroyed"],
            "data_classes": ["infra"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(
        steps, chain_id="real-terraform-cli-plan-apply-destroy"
    )
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="real_plan_apply_destroy_chain_drift", decision=decision, profile=profile
    )
    return _scenario(
        name="real_plan_apply_destroy_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_preview_to_deploy" in decision["types"]
            and "chain_preview_to_destructive" in decision["types"]
        ),
        decision=decision,
        before={"resource_count": 0},
        after={"resource_count": 0},
        receipt=receipt,
    )


def _state_readback(workspace: Path) -> Dict[str, Any]:
    state_path = workspace / "terraform.tfstate"
    if not state_path.exists():
        return {
            "state_exists": False,
            "resource_count": 0,
            "managed_resource_types": [],
            "state_hash": _safe_hash({}),
        }
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        state = {}
    resources = [r for r in state.get("resources", []) if r.get("mode") == "managed"]
    material = {
        "lineage": state.get("lineage") or "",
        "serial": state.get("serial") or 0,
        "resources": [
            {
                "type": r.get("type") or "",
                "name": r.get("name") or "",
                "instance_count": len(r.get("instances") or []),
            }
            for r in resources
        ],
    }
    return {
        "state_exists": True,
        "resource_count": sum(len(r.get("instances") or []) for r in resources),
        "managed_resource_types": sorted({str(r.get("type") or "") for r in resources}),
        "serial": int(state.get("serial") or 0),
        "state_hash": _safe_hash(material),
    }


def _scenario(
    *,
    name: str,
    expected_ok: bool,
    decision: Dict[str, Any],
    before: Dict[str, Any],
    after: Dict[str, Any],
    receipt: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    out = {
        "name": name,
        "ok": bool(expected_ok),
        "drift_detected": bool(decision.get("drift_detected")),
        "severity": decision.get("severity") or "none",
        "decision": decision.get("action") or "allow",
        "finding_types": list(decision.get("types") or []),
        "reason": decision.get("reason") or _first(decision.get("reasons") or []),
        "before_state_hash": decision.get("before_state_hash")
        or before.get("state_hash")
        or "",
        "after_state_hash": decision.get("after_state_hash")
        or after.get("state_hash")
        or "",
        "readback": {
            "before_resource_count": int(before.get("resource_count") or 0),
            "after_resource_count": int(after.get("resource_count") or 0),
        },
    }
    if receipt is not None:
        out["receipt"] = receipt
    return out


def _readback_receipt(
    *, name: str, decision: Dict[str, Any], before_hash: str, after_hash: str
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "terraform-cli-proof-pack",
            "tool_name": "terraform_plan",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "real_terraform_cli_local_readback",
            "confidence": 0.95,
            "warnings": [
                "terraform_cli_provider_proof_pack",
                "local_terraform_cli_sandbox",
            ],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": "sha256:" + "3" * 64,
            "expected_outcome": "no_change",
            "observed_outcome": "state_changed",
            "drift_status": "readback_effect_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_baseline_hash": before_hash,
            "drift_current_hash": after_hash,
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


def _chain_receipt(
    *, name: str, decision: Dict[str, Any], profile: Dict[str, Any]
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "multi-step-chain",
            "tool_name": "real-terraform-cli-chain",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "chain_drift",
            "reason": decision["reason"],
            "effects": profile["effect_classes"],
            "side_effect": "chain",
            "data_classes": profile["data_classes"],
            "externality": "external",
            "verification_level": "real_terraform_cli_chain_analysis",
            "confidence": 0.95,
            "warnings": [
                "terraform_cli_provider_proof_pack",
                "pre_execution_chain_analysis",
            ],
            "argument_keys": [],
            "blocked_by": "chain_drift",
            "probe_id": name,
            "argument_hash": profile["argument_hash"],
            "expected_outcome": "chain_allowed",
            "observed_outcome": "chain_denied",
            "drift_status": "chain_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_current_hash": profile["profile_hash"],
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


def _terraform_version(terraform_bin: str) -> str:
    proc = _run_raw(terraform_bin, Path.cwd(), ["version", "-json"])
    try:
        payload = json.loads(proc.stdout)
        return str(payload.get("terraform_version") or "")
    except (json.JSONDecodeError, AttributeError):
        return proc.stdout.strip().splitlines()[0] if proc.stdout else "unknown"


def _run_tf(
    terraform_bin: str, cwd: Path, args: List[str]
) -> subprocess.CompletedProcess[str]:
    return _run_raw(terraform_bin, cwd, args)


def _run_raw(
    terraform_bin: str, cwd: Path, args: List[str]
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(
        {
            "CHECKPOINT_DISABLE": "1",
            "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0",
        }
    )
    return subprocess.run(
        [terraform_bin, *args],
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def _safe_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _first(values: List[str]) -> str:
    return values[0] if values else ""


def print_report(report: Dict[str, Any]) -> None:
    print(f"Terraform CLI proof pack ({report['mode']})")
    print(f"Terraform version: {report['terraform']['version']}")
    for scenario in report["scenarios"]:
        status = "PASS" if scenario["ok"] else "FAIL"
        findings = ",".join(scenario.get("finding_types") or []) or "none"
        print(
            f"{status} {scenario['name']} severity={scenario['severity']} "
            f"decision={scenario['decision']} findings={findings}"
        )
    print("Limitations:")
    for item in report["limitations"]:
        print(f"- {item}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the real local Terraform CLI proof pack."
    )
    parser.add_argument(
        "--terraform-bin", default=None, help="Path to Terraform CLI binary"
    )
    args = parser.parse_args(argv)
    report = run_terraform_cli_proof_pack(terraform_bin=args.terraform_bin)
    print_report(report)
    return 0 if report["summary"]["all_passed"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
