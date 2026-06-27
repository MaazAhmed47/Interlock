"""Buyer-facing Interlock drift proof suite orchestration.

The suite collects the existing proof packs into one evidence-safe report. It is
intentionally honest: credential-gated providers return SKIP unless explicitly
configured by the operator, and skipped live proofs are not counted as executed
coverage.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from demo.provider_packs.app_store import run_app_store_proof_pack
from demo.provider_packs.database_admin import run_database_admin_proof_pack
from demo.provider_packs.database_docker import run_database_docker_proof_pack
from demo.provider_packs.database_mysql_docker import (
    run_database_mysql_docker_proof_pack,
)
from demo.provider_packs.email import run_email_proof_pack
from demo.provider_packs.email_live import run_email_live_proof_pack
from demo.provider_packs.email_smtp import run_email_smtp_proof_pack
from demo.provider_packs.kubernetes import run_kubernetes_proof_pack
from demo.provider_packs.kubernetes_live import run_kubernetes_live_proof_pack
from demo.provider_packs.payments import run_payments_proof_pack
from demo.provider_packs.payments_live import run_payments_live_proof_pack
from demo.provider_packs.terraform import run_terraform_proof_pack
from demo.provider_packs.terraform_cli import (
    find_terraform_binary,
    run_terraform_cli_proof_pack,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ProofSpec:
    key: str
    title: str
    drift_class: str
    buyer_value: str
    proof_level: str
    runner: Optional[Callable[[], Dict[str, Any]]] = None
    command: Optional[List[str]] = None
    timeout_seconds: int = 180
    credential_gated: bool = False


SCRIPT_SPECS: List[ProofSpec] = [
    ProofSpec(
        key="surface-drift-matrix",
        title="Surface and capability drift matrix",
        drift_class="surface/capability/schema/metadata",
        proof_level="local HTTP mock through gateway discovery path",
        buyer_value="Shows the core wedge: the same approved MCP tool becomes more dangerous and is held for review before continued use.",
        command=[sys.executable, "demo/run_drift_matrix.py"],
        timeout_seconds=180,
    ),
    ProofSpec(
        key="effective-permission-behavior",
        title="Behavioral effective-permission drift",
        drift_class="auth-scope/effective permission",
        proof_level="local live-style HTTP probe through real probe route",
        buyer_value="Catches the hard case where the manifest is unchanged but a call that used to be denied now succeeds.",
        command=[sys.executable, "demo/run_effective_permission_probe_live.py"],
        timeout_seconds=120,
    ),
    ProofSpec(
        key="response-data-exposure",
        title="Response/data-exposure drift",
        drift_class="response/data exposure",
        proof_level="local response-profile evidence record",
        buyer_value="Detects outputs that start exposing PII, secrets, or much larger result sets after approval.",
        command=[sys.executable, "demo/run_response_drift.py"],
        timeout_seconds=60,
    ),
    ProofSpec(
        key="external-reach-destination",
        title="Destination-aware external reach drift",
        drift_class="external reach",
        proof_level="local destination-profile evidence record",
        buyer_value="Detects a trusted tool adding a new external destination, especially when secrets may ride along.",
        command=[sys.executable, "demo/run_external_reach_drift.py"],
        timeout_seconds=60,
    ),
]


STRUCTURED_SPECS: List[ProofSpec] = [
    ProofSpec(
        key="terraform-mock",
        title="Terraform infra proof pack",
        drift_class="deploy/destructive/chain",
        proof_level="local Terraform-shaped sandbox",
        buyer_value="Proves plan-only workflows escalating to apply/destroy are quarantined or denied.",
        runner=run_terraform_proof_pack,
    ),
    ProofSpec(
        key="email-mock",
        title="Email and messaging proof pack",
        drift_class="external send/temporal/chain",
        proof_level="local email-shaped sandbox",
        buyer_value="Proves preview/draft-only messaging tools cannot silently become send/post tools without detection.",
        runner=run_email_proof_pack,
    ),
    ProofSpec(
        key="smtp-local",
        title="Real local SMTP readback proof",
        drift_class="hidden side effect/readback",
        proof_level="local SMTP protocol boundary on 127.0.0.1",
        buyer_value="Shows hidden sends are caught by provider readback, not just by trusting the tool response.",
        runner=run_email_smtp_proof_pack,
    ),
    ProofSpec(
        key="database-admin-local",
        title="Database/admin SaaS proof pack",
        drift_class="database mutation/admin/chain",
        proof_level="local SQLite sandbox",
        buyer_value="Proves read-only database/admin tools drifting to writes, drops, privilege changes, or secret-to-exec chains are caught.",
        runner=run_database_admin_proof_pack,
    ),
    ProofSpec(
        key="kubernetes-mock",
        title="Kubernetes/DevOps proof pack",
        drift_class="deploy/destructive/secret-to-exec chain",
        proof_level="local Kubernetes-shaped sandbox",
        buyer_value="Proves dry-run/inventory tools drifting to apply/delete/exec are quarantined or denied.",
        runner=run_kubernetes_proof_pack,
    ),
    ProofSpec(
        key="app-store-mock",
        title="App Store/release automation proof pack",
        drift_class="release/submission/temporal/chain",
        proof_level="local release-automation sandbox",
        buyer_value="Proves metadata-preview workflows drifting to submit/release/tester invite are caught.",
        runner=run_app_store_proof_pack,
    ),
    ProofSpec(
        key="payments-mock",
        title="Payments/billing proof pack",
        drift_class="money movement/temporal/chain",
        proof_level="local payment-shaped sandbox",
        buyer_value="Proves quote/preview flows drifting to charge/refund/transfer are quarantined or denied.",
        runner=run_payments_proof_pack,
    ),
    ProofSpec(
        key="email-live-gated",
        title="Credential-gated live Gmail/Slack/IMAP proof",
        drift_class="live messaging provider readback",
        proof_level="credential-gated sandbox provider harness",
        buyer_value="When sandbox credentials are configured, proves hidden send/post behavior against Gmail, Slack, or IMAP/SMTP readback.",
        runner=run_email_live_proof_pack,
        credential_gated=True,
    ),
    ProofSpec(
        key="docker-postgres-gated",
        title="Credential-gated Docker Postgres proof",
        drift_class="live local database readback",
        proof_level="disposable local Docker Postgres container",
        buyer_value="When explicitly enabled, proves hidden INSERT, DROP, role grant, and data-export/secret-exec chains against real Postgres SQL readback.",
        runner=run_database_docker_proof_pack,
        credential_gated=True,
    ),
    ProofSpec(
        key="docker-mysql-gated",
        title="Credential-gated Docker MySQL proof",
        drift_class="live local database readback",
        proof_level="disposable local Docker MySQL container",
        buyer_value="When explicitly enabled, proves hidden INSERT, DROP, admin-user grant, and data-export/secret-exec chains against real MySQL SQL readback.",
        runner=run_database_mysql_docker_proof_pack,
        credential_gated=True,
    ),
    ProofSpec(
        key="kubernetes-live-gated",
        title="Credential-gated kubectl sandbox proof",
        drift_class="live Kubernetes provider readback",
        proof_level="explicit sandbox kubectl context/namespace",
        buyer_value="When configured, proves hidden apply/delete and risky chains against a real sandbox Kubernetes context.",
        runner=run_kubernetes_live_proof_pack,
        credential_gated=True,
    ),
    ProofSpec(
        key="stripe-test-gated",
        title="Credential-gated Stripe test-mode proof",
        drift_class="live payment provider readback",
        proof_level="Stripe test-mode harness only",
        buyer_value="When a test-mode key is configured, proves hidden charge/refund and payment chains against Stripe test-mode readback.",
        runner=run_payments_live_proof_pack,
        credential_gated=True,
    ),
]


def all_specs(*, include_terraform_cli: bool = False) -> List[ProofSpec]:
    specs = [*SCRIPT_SPECS, *STRUCTURED_SPECS]
    if include_terraform_cli:
        specs.append(
            ProofSpec(
                key="terraform-cli-local",
                title="Real local Terraform CLI proof",
                drift_class="local infra readback",
                proof_level="Terraform CLI local state using terraform_data",
                buyer_value="Proves plan/apply/destroy readback with real Terraform CLI and no cloud provider.",
                runner=_run_terraform_cli_or_skip,
                credential_gated=True,
            )
        )
    return specs


def run_interlock_proof_suite(
    *,
    selected: Optional[Iterable[str]] = None,
    include_terraform_cli: bool = False,
) -> Dict[str, Any]:
    selected_set = set(selected or [])
    specs = all_specs(include_terraform_cli=include_terraform_cli)
    if selected_set:
        specs = [spec for spec in specs if spec.key in selected_set]
    results = [_run_spec(spec) for spec in specs]
    failed = [result for result in results if result["status"] == "FAIL"]
    passed = [result for result in results if result["status"] == "PASS"]
    skipped = [result for result in results if result["status"] == "SKIP"]
    scenario_count = sum(int(result.get("scenario_count") or 0) for result in results)
    receipt_count = sum(int(result.get("receipt_count") or 0) for result in results)
    critical_count = sum(
        int(result.get("critical_or_high_count") or 0) for result in results
    )
    return {
        "suite": "interlock-drift-proof-suite",
        "purpose": "Buyer-facing proof that Interlock detects post-approval MCP drift across surface, behavior, data exposure, external reach, hidden effects, provider readback, and multi-step chains.",
        "summary": {
            "all_passed": not failed,
            "passed": len(passed),
            "skipped": len(skipped),
            "failed": len(failed),
            "scenario_count": scenario_count,
            "receipt_count": receipt_count,
            "critical_or_high_count": critical_count,
        },
        "results": results,
        "honest_limits": [
            "SKIP means the credential-gated provider was not configured and was not contacted.",
            "Local/mock proofs demonstrate Interlock's classifiers, receipts, and enforcement decisions without production credentials.",
            "Docker, Slack, Gmail, Kubernetes, Stripe, and Terraform CLI claims should only be made when the matching credential-gated harness produced PASS output in that environment.",
            "This suite is proof of drift detection behavior, not a compliance certification or guarantee that every provider edge case has been exhaustively tested.",
        ],
    }


def _run_spec(spec: ProofSpec) -> Dict[str, Any]:
    if spec.runner is not None:
        try:
            report = spec.runner()
        except Exception as exc:  # pragma: no cover - defensive for CLI diagnostics
            return _base_result(
                spec, status="FAIL", reason=f"runner_error:{type(exc).__name__}:{exc}"
            )
        return _result_from_report(spec, report)
    if spec.command is not None:
        return _result_from_command(spec)
    return _base_result(spec, status="FAIL", reason="missing_runner")


def _result_from_report(spec: ProofSpec, report: Dict[str, Any]) -> Dict[str, Any]:
    summary = report.get("summary") or {}
    scenarios = list(report.get("scenarios") or [])
    executed = summary.get("executed")
    status_text = str(summary.get("status") or "")
    if executed is False or status_text.startswith("skipped"):
        status = "SKIP"
    elif summary.get("all_passed") is True:
        status = "PASS"
    else:
        status = "FAIL"
    result = _base_result(
        spec, status=status, reason=status_text or _reason_for_status(status)
    )
    result.update(
        {
            "provider": report.get("provider") or spec.key,
            "mode": report.get("mode") or "unknown",
            "scenario_count": len(scenarios),
            "receipt_count": _receipt_count(scenarios),
            "critical_or_high_count": _critical_or_high_count(scenarios),
            "decisions": _decision_counts(scenarios),
            "sample_findings": _sample_findings(scenarios),
            "limitations": list(report.get("limitations") or []),
        }
    )
    return result


def _result_from_command(spec: ProofSpec) -> Dict[str, Any]:
    assert spec.command is not None
    env = _subprocess_env()
    try:
        proc = subprocess.run(
            spec.command,
            cwd=str(REPO_ROOT),
            env=env,
            text=True,
            capture_output=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _base_result(spec, status="FAIL", reason="timeout")
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    clean_stdout = _strip_ansi(stdout)
    status = "PASS" if proc.returncode == 0 else "FAIL"
    pass_lines = [
        line for line in clean_stdout.splitlines() if line.strip().startswith("PASS")
    ]
    fail_lines = [
        line for line in clean_stdout.splitlines() if line.strip().startswith("FAIL")
    ]
    result = _base_result(
        spec,
        status=status,
        reason="exit_0" if proc.returncode == 0 else f"exit_{proc.returncode}",
    )
    result.update(
        {
            "provider": spec.key,
            "mode": "script",
            "scenario_count": len(pass_lines) + len(fail_lines),
            "receipt_count": stdout.count("receipt") + stdout.count("sha256:"),
            "critical_or_high_count": clean_stdout.lower().count("critical")
            + clean_stdout.lower().count("severity=high")
            + clean_stdout.lower().count("high / quarantine"),
            "decisions": {},
            "sample_findings": _sample_script_findings(stdout),
            "limitations": _script_limitations(spec.key),
            "stdout_tail": "\n".join(stdout.splitlines()[-12:]),
            "stderr_tail": "\n".join(stderr.splitlines()[-8:]),
        }
    )
    return result


def _subprocess_env() -> Dict[str, str]:
    import os

    env = dict(os.environ)
    # Keep temp proof databases inside the writable Linux temp root. Some host
    # shells expose Windows TEMP/TMP paths under /mnt/c, which can break local
    # proof scripts when they later scan their throwaway SQLite DB files.
    env["TMPDIR"] = "/tmp"
    env["TEMP"] = "/tmp"
    env["TMP"] = "/tmp"
    env.setdefault("PYTHON_DOTENV_DISABLED", "1")
    # Proof scripts must never accidentally write to a hosted database loaded
    # from the parent shell or .env. They create their own throwaway SQLite DBs.
    env.pop("DATABASE_URL", None)
    return env


def _base_result(spec: ProofSpec, *, status: str, reason: str) -> Dict[str, Any]:
    return {
        "key": spec.key,
        "title": spec.title,
        "status": status,
        "reason": reason,
        "drift_class": spec.drift_class,
        "buyer_value": spec.buyer_value,
        "proof_level": spec.proof_level,
        "credential_gated": spec.credential_gated,
        "scenario_count": 0,
        "receipt_count": 0,
        "critical_or_high_count": 0,
        "decisions": {},
        "sample_findings": [],
        "limitations": [],
    }


def _run_terraform_cli_or_skip() -> Dict[str, Any]:
    terraform_bin = find_terraform_binary()
    if not terraform_bin:
        return {
            "provider": "terraform",
            "mode": "local_terraform_cli_sandbox",
            "summary": {
                "executed": False,
                "status": "skipped_missing_terraform_cli",
                "all_passed": True,
            },
            "scenarios": [],
            "limitations": [
                "Terraform CLI was not found, so no local Terraform process was run.",
                "Set INTERLOCK_TERRAFORM_BIN or install Terraform to run this optional local-state proof.",
            ],
        }
    return run_terraform_cli_proof_pack(terraform_bin=terraform_bin)


def _reason_for_status(status: str) -> str:
    return {"PASS": "all_scenarios_passed", "SKIP": "not_configured"}.get(
        status, "failed"
    )


def _receipt_count(scenarios: List[Dict[str, Any]]) -> int:
    return sum(1 for scenario in scenarios if scenario.get("receipt"))


def _critical_or_high_count(scenarios: List[Dict[str, Any]]) -> int:
    return sum(
        1 for scenario in scenarios if scenario.get("severity") in {"high", "critical"}
    )


def _decision_counts(scenarios: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for scenario in scenarios:
        decision = str(scenario.get("decision") or "unknown")
        out[decision] = out.get(decision, 0) + 1
    return out


def _sample_findings(scenarios: List[Dict[str, Any]], *, limit: int = 6) -> List[str]:
    findings: List[str] = []
    for scenario in scenarios:
        for finding in scenario.get("finding_types") or []:
            if finding not in findings:
                findings.append(str(finding))
            if len(findings) >= limit:
                return findings
    return findings


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)


def _sample_script_findings(stdout: str, *, limit: int = 6) -> List[str]:
    findings: List[str] = []
    for marker in (
        "side_effect_escalated",
        "sensitive_field_added",
        "effective_permission_expansion",
        "behavioral_scope_drift",
        "financial.card",
        "external_secret_destination_added",
        "silent_side_effect_drift",
    ):
        if marker in stdout and marker not in findings:
            findings.append(marker)
        if len(findings) >= limit:
            break
    return findings


def _script_limitations(key: str) -> List[str]:
    if key == "surface-drift-matrix":
        return [
            "Runs against a local mock MCP server and throwaway database; not a production-server proof."
        ]
    if key == "effective-permission-behavior":
        return [
            "Runs against a local Genesys-shaped mock over HTTP; it detects behavior, not provider-side OAuth introspection."
        ]
    if key == "response-data-exposure":
        return [
            "Uses local synthetic responses; no real customer data is loaded or stored."
        ]
    if key == "external-reach-destination":
        return [
            "Uses synthetic destination profiles; no outbound webhook call is made."
        ]
    return []


def print_suite(report: Dict[str, Any]) -> None:
    summary = report["summary"]
    print("Interlock Drift Proof Suite")
    print(
        "Purpose: prove post-approval MCP drift detection across surface, behavior, data, reach, effects, providers, and chains."
    )
    print(
        "Summary: "
        f"{summary['passed']} passed, {summary['skipped']} skipped, {summary['failed']} failed, "
        f"{summary['scenario_count']} scenarios, {summary['receipt_count']} receipts, "
        f"{summary['critical_or_high_count']} high/critical detections"
    )
    print("")
    for result in report["results"]:
        status = result["status"]
        line = (
            f"{status:<4} {result['key']:<34} "
            f"scenarios={result['scenario_count']:<2} receipts={result['receipt_count']:<2} "
            f"class={result['drift_class']}"
        )
        print(line)
        print(f"     {result['buyer_value']}")
        if result["status"] == "SKIP":
            print(f"     skipped: {result['reason']}")
        if result.get("sample_findings"):
            print(f"     findings: {', '.join(result['sample_findings'])}")
    print("")
    print("Honest limits:")
    for item in report["honest_limits"]:
        print(f"- {item}")


def write_markdown_report(report: Dict[str, Any], path: Path) -> None:
    summary = report["summary"]
    lines = [
        "# Interlock Drift Proof Suite Run",
        "",
        "This is a generated run summary from `python3 demo/run_interlock_proof_suite.py`. It is meant to be attached to a design-partner or pilot conversation, not treated as a compliance certificate.",
        "",
        "## Summary",
        "",
        f"- Passed packs: {summary['passed']}",
        f"- Skipped credential-gated packs: {summary['skipped']}",
        f"- Failed packs: {summary['failed']}",
        f"- Scenarios observed: {summary['scenario_count']}",
        f"- Receipts emitted: {summary['receipt_count']}",
        f"- High/critical detections: {summary['critical_or_high_count']}",
        "",
        "## Results",
        "",
        "| Status | Proof | Drift class | Scenarios | Receipts | Why it matters |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for result in report["results"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    result["status"],
                    result["title"],
                    result["drift_class"],
                    str(result["scenario_count"]),
                    str(result["receipt_count"]),
                    result["buyer_value"].replace("|", "/"),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Honest Limits", ""])
    for item in report["honest_limits"]:
        lines.append(f"- {item}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Interlock drift proof suite.")
    parser.add_argument(
        "--json", action="store_true", help="Print JSON instead of text."
    )
    parser.add_argument(
        "--markdown-output",
        default="",
        help="Write a markdown run report to this path.",
    )
    parser.add_argument(
        "--include-terraform-cli",
        action="store_true",
        help="Run or safe-skip the optional local Terraform CLI proof.",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help="Run only this proof key. Can be repeated.",
    )
    args = parser.parse_args(argv)

    report = run_interlock_proof_suite(
        selected=args.only or None,
        include_terraform_cli=args.include_terraform_cli,
    )
    if args.markdown_output:
        write_markdown_report(report, Path(args.markdown_output))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_suite(report)
    return 0 if report["summary"]["all_passed"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
