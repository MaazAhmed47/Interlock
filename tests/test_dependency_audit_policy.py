"""Contracts for the dependency-audit gate.

A dependency-audit job is only worth having if its green state is honest. These
tests pin four things:

1. an exception approves only the advisory it actually assessed — matching id,
   package, severity, scope, installed version and affected range — so a
   severity escalation or any metadata drift blocks and forces re-review;
2. an npm audit run that cannot be trusted (ENOAUDIT, malformed, incomplete,
   unsupported report version) fails closed instead of reading as a clean tree;
3. every exception is narrow, owned, unexpired, and backed by a compensating
   control that exists on disk;
4. the workflow audits both ecosystems independently and never swallows an
   exit code, while still failing overall if either ecosystem fails.
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
LOCKFILE = ROOT / "interlock-web" / "package-lock.json"

REQUIRED_FIELDS = (
    "id",
    "package",
    "installedVersion",
    "severity",
    "affectedRange",
    "scope",
    "reason",
    "exploitability",
    "compensatingControl",
    "owner",
    "expires",
)

# The advisory set actually observed at this commit. Every hostile fixture is a
# single-fact mutation of this, so a failure names exactly one broken guarantee.
OBSERVED = [
    ("GHSA-jjmj-jmhj-qwj2", "react-router-dom", "moderate", ">=6.30.2 <=6.30.4"),
    ("GHSA-wrjc-x8rr-h8h6", "react-router", "moderate", ">=6.0.0 <7.18.0"),
    ("GHSA-337j-9hxr-rhxg", "react-router", "moderate", ">=6.4.0 <7.18.0"),
]

CLEAN = 0
BLOCKED = 1
UNUSABLE = 2

_FIELD_INDEX = {"id": 0, "package": 1, "severity": 2, "range": 3}


def _policy() -> dict:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def _report(entries):
    """Build a structurally valid npm audit report from (id, pkg, sev, range)."""
    vulns: dict = {}
    for advisory_id, package, severity, vrange in entries:
        node = vulns.setdefault(
            package,
            {
                "name": package,
                "severity": severity,
                "isDirect": True,
                "range": vrange,
                "nodes": [f"node_modules/{package}"],
                "via": [],
            },
        )
        node["via"].append(
            {
                "source": 1,
                "name": package,
                "title": "fixture advisory",
                "url": f"https://github.com/advisories/{advisory_id}",
                "severity": severity,
                "range": vrange,
            }
        )
    return {
        "auditReportVersion": 2,
        "vulnerabilities": vulns,
        "metadata": {"vulnerabilities": {"total": len(entries)}},
    }


def _run_gate(tmp_path, payload, scope="production", lockfile=None, today=None):
    report = tmp_path / "audit.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    cmd = [
        sys.executable,
        str(GATE),
        "--audit-json",
        str(report),
        "--scope",
        scope,
        "--lockfile",
        str(lockfile or LOCKFILE),
    ]
    if today:
        cmd += ["--today", today]
    return subprocess.run(cmd, capture_output=True, text=True)


def _mutate(index, **changes):
    """OBSERVED with exactly one advisory field changed."""
    rows = [list(r) for r in OBSERVED]
    for key, value in changes.items():
        rows[index][_FIELD_INDEX[key]] = value
    return [tuple(r) for r in rows]


# ── the accepted set still passes ────────────────────────────────────────────


def test_exact_current_exceptions_pass(tmp_path):
    r = _run_gate(tmp_path, _report(OBSERVED))
    assert r.returncode == CLEAN, r.stdout
    assert "3 advisories, 0 blocking, 3 accepted, 0 stale" in r.stdout


def test_real_lockfile_versions_back_the_policy():
    """The recorded installedVersion must be what is really installed."""
    lock = json.loads(LOCKFILE.read_text(encoding="utf-8"))
    for entry in _policy()["exceptions"]:
        node = lock["packages"].get(f"node_modules/{entry['package']}")
        assert node, f"{entry['package']} not in package-lock.json"
        assert node["version"] == entry["installedVersion"], (
            f"{entry['id']}: policy records {entry['installedVersion']}, "
            f"lockfile has {node['version']}"
        )


# ── an exception must describe the advisory it approves ──────────────────────


def test_same_id_with_wrong_package_fails(tmp_path):
    r = _run_gate(tmp_path, _report(_mutate(0, package="totally-different-pkg")))
    assert r.returncode == BLOCKED, r.stdout
    assert "NOT EXCEPTED" in r.stdout


def test_same_id_escalated_to_critical_fails(tmp_path):
    r = _run_gate(tmp_path, _report(_mutate(0, severity="critical")))
    assert r.returncode == BLOCKED, r.stdout
    assert "DOES NOT MATCH OBSERVED ADVISORY" in r.stdout
    assert "severity:" in r.stdout


def test_changed_advisory_range_fails_closed(tmp_path):
    r = _run_gate(tmp_path, _report(_mutate(0, range=">=1.0.0 <99.0.0")))
    assert r.returncode == BLOCKED, r.stdout
    assert "affectedRange:" in r.stdout


def test_installed_version_mismatch_fails(tmp_path):
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react-router-dom": {"version": "6.99.0"},
                    "node_modules/react-router": {"version": "6.30.4"},
                },
            }
        ),
        encoding="utf-8",
    )
    r = _run_gate(tmp_path, _report(OBSERVED), lockfile=lock)
    assert r.returncode == BLOCKED, r.stdout
    assert "installedVersion: policy='6.30.4' lockfile='6.99.0'" in r.stdout


def test_package_absent_from_lockfile_fails(tmp_path):
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/react-router": {"version": "6.30.4"}},
            }
        ),
        encoding="utf-8",
    )
    r = _run_gate(tmp_path, _report(OBSERVED), lockfile=lock)
    assert r.returncode == BLOCKED, r.stdout
    assert "not present in package-lock.json" in r.stdout


def test_wrong_scope_fails(tmp_path):
    """Production-scoped exceptions must not silence a development finding."""
    r = _run_gate(tmp_path, _report(OBSERVED), scope="development")
    assert r.returncode == BLOCKED, r.stdout
    assert "NOT EXCEPTED" in r.stdout


# ── unexcepted advisories keep blocking ──────────────────────────────────────


def test_unexcepted_advisories_block_at_every_severity(tmp_path):
    for severity in ("moderate", "high", "critical"):
        payload = _report(
            OBSERVED + [(f"GHSA-new-{severity}", "left-pad", severity, "<1")]
        )
        r = _run_gate(tmp_path, payload)
        assert r.returncode == BLOCKED, f"{severity} must block:\n{r.stdout}"
        assert "NOT EXCEPTED -> blocking" in r.stdout


def test_below_threshold_advisories_are_informational(tmp_path):
    payload = _report(OBSERVED + [("GHSA-new-low", "left-pad", "low", "<1")])
    r = _run_gate(tmp_path, payload)
    assert r.returncode == CLEAN, r.stdout
    assert "below threshold" in r.stdout


# ── expiry and staleness ─────────────────────────────────────────────────────


def test_expired_exception_fails(tmp_path):
    fresh = _run_gate(tmp_path, _report(OBSERVED), today="2026-08-02")
    assert fresh.returncode == CLEAN, fresh.stdout
    expired = _run_gate(tmp_path, _report(OBSERVED), today="2099-01-01")
    assert expired.returncode == BLOCKED, expired.stdout
    assert "EXCEPTION EXPIRED" in expired.stdout


def test_stale_exception_fails(tmp_path):
    r = _run_gate(tmp_path, _report([]))
    assert r.returncode == BLOCKED, r.stdout
    assert "stale production policy entries" in r.stdout


# ── operational failures fail closed ─────────────────────────────────────────


def test_enoaudit_payload_fails_closed(tmp_path):
    r = _run_gate(tmp_path, {"error": {"code": "ENOAUDIT", "summary": "registry 503"}})
    assert r.returncode == UNUSABLE, r.stdout
    assert "ENOAUDIT" in r.stdout
    assert "an untrusted audit is not a clean tree" in r.stdout


def test_malformed_and_incomplete_payloads_fail_closed(tmp_path):
    cases = {
        "empty object": {},
        "missing auditReportVersion": {
            "vulnerabilities": {},
            "metadata": {"vulnerabilities": {}},
        },
        "unsupported report version": {
            "auditReportVersion": 99,
            "vulnerabilities": {},
            "metadata": {"vulnerabilities": {}},
        },
        "no metadata": {"auditReportVersion": 2, "vulnerabilities": {}},
        "null vulnerabilities": {
            "auditReportVersion": 2,
            "vulnerabilities": None,
            "metadata": {"vulnerabilities": {}},
        },
        "not an object": [],
    }
    for label, payload in cases.items():
        r = _run_gate(tmp_path, payload)
        assert r.returncode == UNUSABLE, f"{label} must fail closed:\n{r.stdout}"
        assert "AUDIT UNUSABLE" in r.stdout, label


def test_unparsable_json_fails_closed(tmp_path):
    bad = tmp_path / "audit.json"
    bad.write_text("{not json", encoding="utf-8")
    r = subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--audit-json",
            str(bad),
            "--scope",
            "production",
            "--lockfile",
            str(LOCKFILE),
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == UNUSABLE
    assert "not valid JSON" in r.stdout


def test_failed_audit_still_writes_evidence_when_structure_allows(tmp_path):
    """A blocked-but-parsable run must still leave an artifact behind."""
    out = tmp_path / "evidence.json"
    report = tmp_path / "audit.json"
    report.write_text(
        json.dumps(_report(_mutate(0, severity="critical"))), encoding="utf-8"
    )
    r = subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--audit-json",
            str(report),
            "--scope",
            "production",
            "--lockfile",
            str(LOCKFILE),
            "--write",
            str(out),
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == BLOCKED, r.stdout
    assert out.exists(), "evidence artifact must be written even when the gate blocks"
    assert json.loads(out.read_text(encoding="utf-8"))["auditReportVersion"] == 2


# ── every exception stays narrow, owned and backed ───────────────────────────


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
    keys = [(e["id"], e["package"]) for e in policy["exceptions"]]
    assert len(keys) == len(set(keys)), "duplicate (id, package) exceptions"
    for entry in policy["exceptions"]:
        assert entry["id"].startswith("GHSA-"), "exceptions must name an exact advisory"
        assert "*" not in entry["package"], "wildcard packages are not allowed"
        assert "*" not in entry["affectedRange"], "wildcard ranges are not allowed"
        assert entry["scope"] in {"production", "development"}


def test_no_unvalidated_cvss_is_carried():
    """A score the gate never checks is misleading metadata, not evidence."""
    for entry in _policy()["exceptions"]:
        assert "cvss" not in entry, (
            f"{entry['id']} carries a cvss field the gate does not validate; "
            "remove it or start validating it"
        )


# ── the workflow itself must stay honest ─────────────────────────────────────


def _audit_job() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"][
        "dependency-audit"
    ]


def test_audit_job_never_swallows_an_exit_code():
    for step in _audit_job()["steps"]:
        assert not step.get("continue-on-error"), (
            f"step {step.get('name')!r} uses continue-on-error; "
            "the audit job's green state would be meaningless"
        )
        run = step.get("run", "")
        assert "|| true" not in run, f"step {step.get('name')!r} swallows failure"
        assert "|| exit 0" not in run, f"step {step.get('name')!r} swallows failure"
        assert not run.strip().startswith(
            "set +e"
        ), f"step {step.get('name')!r} disables errexit"


def test_python_and_npm_audits_run_independently():
    """A Python advisory must not stop the npm gates producing evidence."""
    steps = {s.get("id"): s for s in _audit_job()["steps"] if s.get("id")}
    for required in ("pip_audit", "npm_install", "npm_production", "npm_development"):
        assert required in steps, f"missing audit step id {required}"
        assert (
            steps[required].get("if") == "always()"
        ), f"step {required} must run even after an earlier ecosystem fails"


def test_a_single_verdict_step_preserves_overall_failure():
    job = _audit_job()
    verdict = [s for s in job["steps"] if s.get("name") == "Dependency audit verdict"]
    assert (
        verdict
    ), "no aggregating verdict step; independent steps could soften the result"
    run = verdict[0]["run"]
    for name in ("PIP_AUDIT", "NPM_PRODUCTION", "NPM_DEVELOPMENT"):
        assert name in run, f"verdict ignores {name}"
    assert "exit 1" in run, "verdict must fail the job"
    assert verdict[0].get("if") == "always()"


def test_audit_job_covers_python_and_npm_separately():
    job = _audit_job()
    runs = " ".join(step.get("run", "") for step in job["steps"])
    assert "pip-audit" in runs, "Python audit missing"
    assert "npm ci" in runs, "frontend deps must be installed reproducibly"
    assert "--scope production" in runs and "--scope development" in runs
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
