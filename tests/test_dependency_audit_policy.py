"""Contracts for the dependency-audit gate.

A dependency-audit job is only worth having if its green state is honest. These
tests pin three things:

1. the npm gate actually blocks an un-excepted advisory (it is not a no-op);
2. every exception in the policy file is narrow, justified, owned, unexpired,
   and backed by a compensating control that exists on disk;
3. the CI workflow runs both ecosystems and never swallows an audit exit code.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github" / "dependency-audit-policy.json"
GATE = ROOT / "scripts" / "audit_npm.py"
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"

REQUIRED_FIELDS = (
    "id",
    "package",
    "severity",
    "scope",
    "reason",
    "exploitability",
    "compensatingControl",
    "owner",
    "expires",
)


def _policy() -> dict:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def _run_gate(tmp_path: Path, audit: dict, scope: str, today: str | None = None):
    payload = tmp_path / "audit.json"
    payload.write_text(json.dumps(audit), encoding="utf-8")
    cmd = [sys.executable, str(GATE), "--audit-json", str(payload), "--scope", scope]
    if today:
        cmd += ["--today", today]
    return subprocess.run(cmd, capture_output=True, text=True)


def _audit_fixture(advisory_id: str, severity: str = "high", package: str = "left-pad"):
    """Minimal `npm audit --json` shape carrying exactly one advisory."""
    return {
        "vulnerabilities": {
            package: {
                "name": package,
                "severity": severity,
                "isDirect": True,
                "range": "<9.9.9",
                "nodes": [f"node_modules/{package}"],
                "via": [
                    {
                        "source": 1,
                        "name": package,
                        "title": "Synthetic fixture advisory",
                        "url": f"https://github.com/advisories/{advisory_id}",
                        "severity": severity,
                        "range": "<9.9.9",
                    }
                ],
            }
        },
        "metadata": {"vulnerabilities": {severity: 1, "total": 1}},
    }


# ── the gate is not a no-op ──────────────────────────────────────────────────


def test_gate_blocks_an_unexcepted_advisory(tmp_path):
    r = _run_gate(tmp_path, _audit_fixture("GHSA-xxxx-not-excepted"), "production")
    assert r.returncode == 1, f"gate must fail on an un-excepted advisory:\n{r.stdout}"
    assert "NOT EXCEPTED -> blocking" in r.stdout
    assert "RESULT: FAIL" in r.stdout


def test_gate_blocks_critical_and_high(tmp_path):
    for severity in ("high", "critical"):
        r = _run_gate(
            tmp_path, _audit_fixture(f"GHSA-{severity}-fixture", severity), "production"
        )
        assert r.returncode == 1, f"{severity} must block:\n{r.stdout}"


def test_gate_ignores_advisories_below_threshold(tmp_path):
    # development scope: isolates the threshold rule from the production-only
    # stale-entry rule, which a single-advisory fixture would always trip.
    r = _run_gate(tmp_path, _audit_fixture("GHSA-low-fixture", "low"), "development")
    assert r.returncode == 0
    assert "below threshold" in r.stdout


def test_gate_blocks_when_an_exception_has_expired(tmp_path):
    entry = _policy()["exceptions"][0]
    audit = _audit_fixture(entry["id"], entry["severity"], entry["package"])
    # development scope: a single-advisory fixture leaves the other real
    # exceptions unmatched, and the stale-entry rule is production-only.
    fresh = _run_gate(tmp_path, audit, "development", today="2026-01-01")
    assert fresh.returncode == 0, f"unexpired exception should pass:\n{fresh.stdout}"
    stale = _run_gate(tmp_path, audit, "development", today="2099-01-01")
    assert stale.returncode == 1, f"expired exception must block:\n{stale.stdout}"
    assert "EXCEPTION EXPIRED" in stale.stdout


def test_gate_blocks_stale_policy_entries(tmp_path):
    """An exception that matches nothing must not linger and widen silently."""
    r = _run_gate(tmp_path, {"vulnerabilities": {}}, "production")
    assert r.returncode == 1
    assert "stale policy entries" in r.stdout


def test_gate_passes_cleanly_when_all_exceptions_are_exercised(tmp_path):
    """The real policy against the real advisory set is the CI happy path."""
    audit = {"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}}
    for entry in _policy()["exceptions"]:
        audit["vulnerabilities"].setdefault(
            entry["package"],
            {
                "name": entry["package"],
                "severity": entry["severity"],
                "isDirect": True,
                "range": "x",
                "nodes": [f"node_modules/{entry['package']}"],
                "via": [],
            },
        )["via"].append(
            {
                "source": 1,
                "name": entry["package"],
                "title": entry["title"],
                "url": f"https://github.com/advisories/{entry['id']}",
                "severity": entry["severity"],
                "range": "x",
            }
        )
    r = _run_gate(tmp_path, audit, "production")
    assert r.returncode == 0, r.stdout
    assert "0 blocking" in r.stdout and "0 stale" in r.stdout


# ── every exception stays narrow and justified ───────────────────────────────


def test_every_exception_is_complete_and_owned():
    for entry in _policy()["exceptions"]:
        for field in REQUIRED_FIELDS:
            assert entry.get(field), f"{entry.get('id')} missing {field}"
        assert "@" in entry["owner"], f"{entry['id']} needs a contactable owner"
        assert len(entry["reason"]) > 40, f"{entry['id']} reason is not a justification"
        assert (
            len(entry["exploitability"]) > 40
        ), f"{entry['id']} needs exploitability analysis"


def test_no_exception_is_permanent():
    today = dt.date.today()
    for entry in _policy()["exceptions"]:
        expires = dt.date.fromisoformat(entry["expires"])
        assert expires > today, f"{entry['id']} expired on {expires}; re-triage it"
        assert (expires - today).days <= 365, f"{entry['id']} expiry is too far out"


def test_every_compensating_control_exists_on_disk():
    """A control that does not exist is not a control."""
    for entry in _policy()["exceptions"]:
        refs = [
            token.split("::")[0]
            for token in entry["compensatingControl"].replace(",", " ").split()
            if "/" in token and token.endswith((".ts", ".tsx", ".py"))
        ]
        assert refs, f"{entry['id']} cites no concrete control file"
        for ref in refs:
            assert (ROOT / ref).exists(), f"{entry['id']} cites missing control {ref}"


def test_policy_is_not_a_blanket_suppression():
    policy = _policy()
    assert policy["failOnSeverity"] in {"low", "moderate", "high", "critical"}
    ids = [e["id"] for e in policy["exceptions"]]
    assert len(ids) == len(set(ids)), "duplicate exception ids"
    for entry in policy["exceptions"]:
        assert entry["id"].startswith("GHSA-"), "exceptions must name an exact advisory"
        assert "*" not in entry["package"], "wildcard packages are not allowed"


# ── the workflow itself must stay honest ─────────────────────────────────────


def _audit_job() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"][
        "dependency-audit"
    ]


def test_audit_job_never_swallows_an_exit_code():
    job = _audit_job()
    for step in job["steps"]:
        assert not step.get("continue-on-error"), (
            f"step {step.get('name')!r} uses continue-on-error; "
            "the audit job's green state would be meaningless"
        )
        run = step.get("run", "")
        assert (
            "|| true" not in run
        ), f"step {step.get('name')!r} swallows failure with '|| true'"
        assert "|| exit 0" not in run, f"step {step.get('name')!r} swallows failure"
        assert not run.strip().startswith(
            "set +e"
        ), f"step {step.get('name')!r} disables errexit"


def test_audit_job_covers_python_and_npm_separately():
    job = _audit_job()
    runs = " ".join(step.get("run", "") for step in job["steps"])
    assert "pip-audit" in runs, "Python audit missing"
    assert "npm ci" in runs, "frontend deps must be installed reproducibly"
    assert (
        "--scope production" in runs and "--scope development" in runs
    ), "production and development results must be reported separately"
    # The job delegates the npm invocation to the gate so no shell redirect
    # needs `|| true`; the gate is therefore where npm audit must be verified.
    gate = GATE.read_text(encoding="utf-8")
    assert '"npm", "audit", "--json"' in gate, "gate must invoke npm audit"
    assert '"--omit=dev"' in gate, "gate must support a production-only scope"


def test_audit_job_pins_actions_and_uses_least_permissions():
    job = _audit_job()
    assert job.get("permissions") == {"contents": "read"}, "job needs least privilege"
    for step in job["steps"]:
        uses = step.get("uses")
        if uses:
            assert "@" in uses and not uses.endswith(
                "@main"
            ), f"unpinned action: {uses}"
