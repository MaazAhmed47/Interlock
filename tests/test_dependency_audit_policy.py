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

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_npm  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github" / "dependency-audit-policy.json"
GATE = ROOT / "scripts" / "audit_npm.py"
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
LOCKFILE = ROOT / "interlock-web" / "package-lock.json"
VERIFIED_SOURCE_GUARD = (
    "always() && steps.source.outcome == 'success' "
    "&& steps.source.outputs.verified == 'true'"
)

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

# Historical React Router findings retained only as synthetic fixtures. Every
# hostile fixture is a single-fact mutation, so failures name one broken gate
# guarantee without requiring a live vulnerable dependency graph.
OBSERVED = [
    ("GHSA-jjmj-jmhj-qwj2", "react-router-dom", "moderate", ">=6.30.2 <=6.30.4"),
    ("GHSA-wrjc-x8rr-h8h6", "react-router", "moderate", ">=6.0.0 <7.18.0"),
    ("GHSA-337j-9hxr-rhxg", "react-router", "moderate", ">=6.4.0 <7.18.0"),
]

FIXTURE_EXCEPTIONS = [
    {
        "id": advisory_id,
        "package": package,
        "installedVersion": "6.30.4",
        "severity": severity,
        "affectedRange": affected_range,
        "scope": "production",
        "title": "synthetic React Router policy fixture",
        "reason": "Synthetic exception used only to exercise exact-match audit policy behavior.",
        "exploitability": "Synthetic test metadata; no exception is present in the repository policy.",
        "compensatingControl": "interlock-web/src/auth.ts",
        "owner": "security@getinterlock.dev",
        "expires": "2026-11-01",
    }
    for advisory_id, package, severity, affected_range in OBSERVED
]

CLEAN = 0
BLOCKED = 1
UNUSABLE = 2

_FIELD_INDEX = {"id": 0, "package": 1, "severity": 2, "range": 3}


def _policy() -> dict:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def _metadata_for(vulns: dict) -> dict:
    """npm-consistent metadata: buckets sum to total, total == package nodes."""
    buckets = {k: 0 for k in ("info", "low", "moderate", "high", "critical")}
    for node in vulns.values():
        sev = str(node.get("severity", "")).lower()
        if sev in buckets:
            buckets[sev] += 1
    return {"vulnerabilities": {**buckets, "total": len(vulns)}}


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
        "metadata": _metadata_for(vulns),
    }


def _run_gate(
    tmp_path, payload, scope="production", lockfile=None, today=None, policy=None
):
    report = tmp_path / "audit.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    if lockfile is None:
        lockfile = tmp_path / "fixture-lock.json"
        lockfile.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/react-router-dom": {"version": "6.30.4"},
                        "node_modules/react-router": {"version": "6.30.4"},
                    },
                }
            ),
            encoding="utf-8",
        )
    if policy is None:
        policy = tmp_path / "fixture-policy.json"
        policy.write_text(
            json.dumps({**_policy(), "exceptions": FIXTURE_EXCEPTIONS}),
            encoding="utf-8",
        )

    cmd = [
        sys.executable,
        str(GATE),
        "--audit-json",
        str(report),
        "--scope",
        scope,
        "--lockfile",
        str(lockfile),
        "--policy",
        str(policy),
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


def test_exact_synthetic_exceptions_pass(tmp_path):
    r = _run_gate(tmp_path, _report(OBSERVED))
    assert r.returncode == CLEAN, r.stdout
    assert "3 advisories, 0 blocking, 3 accepted, 0 stale" in r.stdout


def test_real_lockfile_versions_back_the_policy():
    """The repository policy is exception-free on the secure router graph."""
    lock = json.loads(LOCKFILE.read_text(encoding="utf-8"))
    assert _policy()["exceptions"] == []
    assert lock["packages"]["node_modules/react-router"]["version"] == "8.3.0"
    assert "node_modules/react-router-dom" not in lock["packages"]


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
    # An advisory whose vulnerable instance cannot be located in the lockfile is
    # unverifiable, so the gate fails closed rather than merely blocking.
    assert r.returncode == UNUSABLE, r.stdout
    assert "cannot be verified against the lockfile" in r.stdout
    assert "not found in package-lock.json" in r.stdout


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
    lockfile = tmp_path / "fixture-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react-router-dom": {"version": "6.30.4"},
                    "node_modules/react-router": {"version": "6.30.4"},
                },
            }
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "fixture-policy.json"
    policy.write_text(
        json.dumps({**_policy(), "exceptions": FIXTURE_EXCEPTIONS}),
        encoding="utf-8",
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
            str(lockfile),
            "--policy",
            str(policy),
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


def test_repository_policy_has_no_react_router_exceptions():
    router_ids = {
        "GHSA-337j-9hxr-rhxg",
        "GHSA-wrjc-x8rr-h8h6",
        "GHSA-jjmj-jmhj-qwj2",
        "GHSA-qwww-vcr4-c8h2",
    }
    assert not router_ids.intersection(entry["id"] for entry in _policy()["exceptions"])


@pytest.mark.parametrize(
    ("advisory_id", "package", "severity", "affected_range", "version"),
    [
        (
            "GHSA-337j-9hxr-rhxg",
            "react-router",
            "moderate",
            ">=6.4.0 <7.18.0",
            "6.30.4",
        ),
        (
            "GHSA-wrjc-x8rr-h8h6",
            "react-router",
            "moderate",
            ">=6.0.0 <7.18.0",
            "6.30.4",
        ),
        (
            "GHSA-jjmj-jmhj-qwj2",
            "react-router-dom",
            "moderate",
            ">=6.30.2 <=6.30.4",
            "6.30.4",
        ),
        (
            "GHSA-qwww-vcr4-c8h2",
            "react-router",
            "high",
            ">=7.12.0 <8.3.0",
            "7.18.2",
        ),
    ],
)
def test_vulnerable_react_router_advisory_reintroduction_blocks(
    tmp_path, advisory_id, package, severity, affected_range, version
):
    lockfile = tmp_path / "vulnerable-router-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {f"node_modules/{package}": {"version": version}},
            }
        ),
        encoding="utf-8",
    )
    result = _run_gate(
        tmp_path,
        _report([(advisory_id, package, severity, affected_range)]),
        lockfile=lockfile,
        policy=_exceptionless_policy(tmp_path),
    )
    assert result.returncode == BLOCKED, result.stdout
    assert advisory_id in result.stdout
    assert "NOT EXCEPTED -> blocking" in result.stdout


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
            steps[required].get("if") == VERIFIED_SOURCE_GUARD
        ), f"step {required} must continue only after verified source"


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
    assert verdict[0].get("if") == VERIFIED_SOURCE_GUARD


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


# ── B1: production / full-tree differencing must be fail-closed ──────────────


def _row(advisory_id, package, severity, vrange, nodes):
    return (advisory_id, package, severity, vrange, nodes)


def _report_with_nodes(entries):
    """Like _report but with explicit vulnerable node paths per package."""
    vulns: dict = {}
    for advisory_id, package, severity, vrange, nodes in entries:
        node = vulns.setdefault(
            package,
            {
                "name": package,
                "severity": severity,
                "isDirect": True,
                "range": vrange,
                "nodes": list(nodes),
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
        "metadata": _metadata_for(vulns),
    }


BASE_ROW = _row("GHSA-x", "pkg-a", "moderate", ">=1.0.0 <2.0.0", ["node_modules/pkg-a"])
EXTRA_PROD_ROW = _row("GHSA-y", "pkg-b", "high", "<1.0.0", ["node_modules/pkg-b"])


def _difference(full_entries, production_entries):
    return audit_npm.development_only(
        audit_npm.advisories(_report_with_nodes(full_entries)),
        audit_npm.advisories(_report_with_nodes(production_entries)),
    )


def test_identical_production_and_full_rows_subtract():
    assert _difference([BASE_ROW], [BASE_ROW]) == []


def test_critical_severity_only_in_full_tree_blocks():
    escalated = _row(
        "GHSA-x", "pkg-a", "critical", ">=1.0.0 <2.0.0", ["node_modules/pkg-a"]
    )
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        _difference([escalated], [BASE_ROW])
    assert "disagree" in str(excinfo.value)
    assert "severity" in str(excinfo.value)


def test_changed_range_only_in_full_tree_blocks():
    widened = _row(
        "GHSA-x", "pkg-a", "moderate", ">=0.1.0 <9.0.0", ["node_modules/pkg-a"]
    )
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        _difference([widened], [BASE_ROW])
    assert "range" in str(excinfo.value)


def test_additional_vulnerable_node_is_kept_as_development_only():
    extra = _row(
        "GHSA-x",
        "pkg-a",
        "moderate",
        ">=1.0.0 <2.0.0",
        ["node_modules/pkg-a", "node_modules/build-tool/node_modules/pkg-a"],
    )
    remaining = _difference([extra], [BASE_ROW])
    assert len(remaining) == 1, "the dev-only instance must stay visible"
    assert remaining[0]["paths"] == ["node_modules/build-tool/node_modules/pkg-a"]
    assert remaining[0].get("dev_only_instances") is True


def test_genuinely_dev_only_advisory_remains_visible():
    dev_only = _row("GHSA-y", "dev-pkg", "high", "<1.0.0", ["node_modules/dev-pkg"])
    remaining = _difference([BASE_ROW, dev_only], [BASE_ROW])
    assert [r["id"] for r in remaining] == ["GHSA-y"]


def test_dev_only_advisory_blocks_through_the_full_gate(tmp_path):
    """End-to-end: a new dev-only advisory must fail the development gate."""
    prod = tmp_path / "prod.json"
    full = tmp_path / "full.json"
    prod.write_text(json.dumps(_report_with_nodes([BASE_ROW])), encoding="utf-8")
    full.write_text(
        json.dumps(
            _report_with_nodes(
                [
                    BASE_ROW,
                    _row(
                        "GHSA-y", "dev-pkg", "high", "<1.0.0", ["node_modules/dev-pkg"]
                    ),
                ]
            )
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--audit-json",
            str(prod),
            "--full-audit-json",
            str(full),
            "--scope",
            "development",
            "--lockfile",
            str(LOCKFILE),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == BLOCKED, result.stdout
    assert "GHSA-y" in result.stdout
    assert "NOT EXCEPTED -> blocking" in result.stdout


# ── B1: multiple installed versions must never collapse ──────────────────────


def _multi_version_lock(tmp_path):
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/postcss": {"version": "8.5.25"},
                    "node_modules/some-tool/node_modules/postcss": {"version": "7.0.1"},
                },
            }
        ),
        encoding="utf-8",
    )
    return lock


def test_multiple_installed_versions_are_all_retained(tmp_path):
    instances = audit_npm.installed_instances(_multi_version_lock(tmp_path))
    assert instances == {
        "node_modules/postcss": "8.5.25",
        "node_modules/some-tool/node_modules/postcss": "7.0.1",
    }
    versions = set(audit_npm.versions_for_package(instances, "postcss").values())
    assert versions == {"8.5.25", "7.0.1"}, "no instance may be silently dropped"


def test_node_paths_resolve_to_the_specific_installed_instance(tmp_path):
    instances = audit_npm.installed_instances(_multi_version_lock(tmp_path))
    nested = audit_npm.implicated_versions(
        instances, "postcss", ["node_modules/some-tool/node_modules/postcss"]
    )
    assert set(nested.values()) == {"7.0.1"}
    hoisted = audit_npm.implicated_versions(
        instances, "postcss", ["node_modules/postcss"]
    )
    assert set(hoisted.values()) == {"8.5.25"}
    # No usable paths -> conservatively consider every instance.
    assert set(audit_npm.implicated_versions(instances, "postcss", []).values()) == {
        "8.5.25",
        "7.0.1",
    }


def test_ambiguous_installed_versions_block_an_exception(tmp_path):
    """One recorded version cannot describe two vulnerable instances."""
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react-router-dom": {"version": "6.30.4"},
                    "node_modules/nested/node_modules/react-router-dom": {
                        "version": "6.20.0"
                    },
                    "node_modules/react-router": {"version": "6.30.4"},
                },
            }
        ),
        encoding="utf-8",
    )
    payload = _report_with_nodes(
        [
            _row(
                "GHSA-jjmj-jmhj-qwj2",
                "react-router-dom",
                "moderate",
                ">=6.30.2 <=6.30.4",
                [
                    "node_modules/react-router-dom",
                    "node_modules/nested/node_modules/react-router-dom",
                ],
            ),
            _row(
                "GHSA-wrjc-x8rr-h8h6",
                "react-router",
                "moderate",
                ">=6.0.0 <7.18.0",
                ["node_modules/react-router"],
            ),
            _row(
                "GHSA-337j-9hxr-rhxg",
                "react-router",
                "moderate",
                ">=6.4.0 <7.18.0",
                ["node_modules/react-router"],
            ),
        ]
    )
    r = _run_gate(tmp_path, payload, lockfile=lock)
    assert r.returncode == BLOCKED, r.stdout
    assert "versions are installed" in r.stdout


# ── B2: npm process completion must be validated ─────────────────────────────


class _FakeCompleted:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


EMPTY_REPORT = json.dumps(
    {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": 0,
                "critical": 0,
                "total": 0,
            }
        },
    }
)
ADVISORY_REPORT = json.dumps(
    {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "pkg-a": {
                "name": "pkg-a",
                "severity": "high",
                "isDirect": True,
                "range": "<1",
                "nodes": ["node_modules/pkg-a"],
                "via": [
                    {
                        "source": 1,
                        "name": "pkg-a",
                        "title": "t",
                        "url": "https://github.com/advisories/GHSA-z",
                        "severity": "high",
                        "range": "<1",
                    }
                ],
            }
        },
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": 1,
                "critical": 0,
                "total": 1,
            }
        },
    }
)


def _fake_npm(monkeypatch, returncode, stdout, stderr=""):
    monkeypatch.setattr(
        audit_npm.subprocess,
        "run",
        lambda *a, **k: _FakeCompleted(returncode, stdout, stderr),
    )


def test_exit_zero_with_empty_report_succeeds(monkeypatch):
    _fake_npm(monkeypatch, 0, EMPTY_REPORT)
    report = audit_npm.run_npm_audit(ROOT / "interlock-web", production_only=True)
    assert report["vulnerabilities"] == {}


def test_exit_one_with_advisories_reaches_policy_evaluation(monkeypatch):
    _fake_npm(monkeypatch, 1, ADVISORY_REPORT)
    report = audit_npm.run_npm_audit(ROOT / "interlock-web", production_only=False)
    rows = audit_npm.advisories(report)
    assert [r["id"] for r in rows] == ["GHSA-z"], "exit 1 must be a usable verdict"


def test_exit_two_with_valid_looking_report_fails_closed(monkeypatch):
    _fake_npm(monkeypatch, 2, EMPTY_REPORT, "npm ERR! code E500")
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.run_npm_audit(ROOT / "interlock-web", production_only=True)
    assert "npm exited 2" in str(excinfo.value)
    assert "does not represent a completed audit" in str(excinfo.value)


def test_arbitrary_operational_exit_codes_fail_closed(monkeypatch):
    for code in (3, 127, 254, -1):
        _fake_npm(monkeypatch, code, ADVISORY_REPORT, "npm ERR! boom")
        with pytest.raises(audit_npm.AuditUnusable) as excinfo:
            audit_npm.run_npm_audit(ROOT / "interlock-web", production_only=True)
        assert f"npm exited {code}" in str(excinfo.value)


def test_failure_diagnostics_include_exit_code_and_sanitized_stderr(monkeypatch):
    leaky = (
        "npm ERR! code E401\n"
        "npm ERR! authorization: Bearer PLACEHOLDER-NOT-A-REAL-TOKEN\n"
        "npm ERR! //registry.npmjs.org/:_authToken=PLACEHOLDER-LOCK-VALUE\n"
        "npm ERR! plain network error\n"
    )
    _fake_npm(monkeypatch, 4, EMPTY_REPORT, leaky)
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.run_npm_audit(ROOT / "interlock-web", production_only=True)
    message = str(excinfo.value)
    assert "npm exited 4" in message
    for secret in (
        "PLACEHOLDER-NOT-A-REAL-TOKEN",
        "PLACEHOLDER-LOCK-VALUE",
        "Bearer",
        "_authToken",
    ):
        assert (
            secret in leaky
        ), f"fixture no longer contains {secret!r}; test is vacuous"
        assert secret not in message, f"diagnostic leaked {secret!r}"
    # The benign line survives, so redaction is line-scoped rather than total.
    assert "plain network error" in message
    assert "[redacted: credential-bearing line]" in message


def test_sanitize_stderr_caps_length_and_line_count():
    long_stderr = "\n".join(f"npm ERR! line {i} " + "x" * 80 for i in range(40))
    summary = audit_npm.sanitize_stderr(long_stderr)
    assert len(summary) <= 241
    assert summary.count("|") <= 3
    assert audit_npm.sanitize_stderr("") == "(no stderr)"


# ── F1: the full tree must be a verified superset of production ──────────────


def test_production_row_absent_from_full_fails():
    """A one-way scan cannot notice a production finding going missing."""
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        _difference([BASE_ROW], [BASE_ROW, EXTRA_PROD_ROW])
    message = str(excinfo.value)
    assert "GHSA-y" in message
    assert "must be a superset" in message


def test_production_vulnerable_path_absent_from_full_fails():
    prod = _row(
        "GHSA-x",
        "pkg-a",
        "moderate",
        ">=1.0.0 <2.0.0",
        ["node_modules/pkg-a", "node_modules/only-in-prod/node_modules/pkg-a"],
    )
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        _difference([BASE_ROW], [prod])
    assert "vulnerable instances" in str(excinfo.value)
    assert "only-in-prod" in str(excinfo.value)


def test_duplicate_identities_union_paths_instead_of_overwriting():
    """Two rows sharing an identity must contribute both path sets."""
    first = {**audit_npm.advisories(_report_with_nodes([BASE_ROW]))[0]}
    second = {**first, "paths": ["node_modules/second-copy/node_modules/pkg-a"]}
    grouped = audit_npm._group_by_identity([first, second])
    assert len(grouped) == 1
    (only,) = grouped.values()
    assert only["paths"] == [
        "node_modules/pkg-a",
        "node_modules/second-copy/node_modules/pkg-a",
    ], "a later duplicate must not overwrite the earlier row's paths"


def test_duplicate_production_paths_are_not_lost_during_subtraction():
    """Union semantics must hold across the production side too."""
    prod_rows = audit_npm.advisories(_report_with_nodes([BASE_ROW]))
    duplicate = {
        **prod_rows[0],
        "paths": ["node_modules/dup/node_modules/pkg-a"],
    }
    full = _row(
        "GHSA-x",
        "pkg-a",
        "moderate",
        ">=1.0.0 <2.0.0",
        ["node_modules/pkg-a", "node_modules/dup/node_modules/pkg-a"],
    )
    # Both production paths are covered by full, so nothing remains and no
    # superset violation is raised.
    remaining = audit_npm.development_only(
        audit_npm.advisories(_report_with_nodes([full])),
        [*prod_rows, duplicate],
    )
    assert remaining == []


def test_full_only_identity_remains_a_development_finding():
    remaining = _difference([BASE_ROW, EXTRA_PROD_ROW], [BASE_ROW])
    assert [r["id"] for r in remaining] == ["GHSA-y"]


def test_full_only_path_remains_a_development_finding():
    full = _row(
        "GHSA-x",
        "pkg-a",
        "moderate",
        ">=1.0.0 <2.0.0",
        ["node_modules/pkg-a", "node_modules/only-in-full/node_modules/pkg-a"],
    )
    remaining = _difference([full], [BASE_ROW])
    assert len(remaining) == 1
    assert remaining[0]["paths"] == ["node_modules/only-in-full/node_modules/pkg-a"]


# ── F2: vulnerable node paths must resolve completely ────────────────────────


def _single_instance_lock(tmp_path):
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/pkg-a": {"version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    return audit_npm.installed_instances(lock)


def test_one_known_plus_one_unknown_node_path_fails(tmp_path):
    instances = _single_instance_lock(tmp_path)
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.implicated_versions(
            instances,
            "pkg-a",
            ["node_modules/pkg-a", "node_modules/ghost/node_modules/pkg-a"],
        )
    message = str(excinfo.value)
    assert "not found in package-lock.json" in message
    assert "ghost" in message


def test_wrong_package_node_path_fails(tmp_path):
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/other": {"version": "9.9.9"}},
            }
        ),
        encoding="utf-8",
    )
    instances = audit_npm.installed_instances(lock)
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.implicated_versions(instances, "pkg-a", ["node_modules/other"])
    assert "resolve to another package" in str(excinfo.value)


def test_empty_nodes_uses_conservative_all_instance_evaluation(tmp_path):
    instances = audit_npm.installed_instances(_multi_version_lock(tmp_path))
    assert set(audit_npm.implicated_versions(instances, "postcss", []).values()) == {
        "8.5.25",
        "7.0.1",
    }
    assert set(audit_npm.implicated_versions(instances, "postcss", None).values()) == {
        "8.5.25",
        "7.0.1",
    }


def test_malformed_nodes_value_fails(tmp_path):
    instances = _single_instance_lock(tmp_path)
    for bad in ("node_modules/pkg-a", ["", "node_modules/pkg-a"], [None], [123]):
        with pytest.raises(audit_npm.AuditUnusable):
            audit_npm.implicated_versions(instances, "pkg-a", bad)


# ── F3: metadata must agree with the report body ─────────────────────────────


def _payload(vulns, counts):
    return {
        "auditReportVersion": 2,
        "vulnerabilities": vulns,
        "metadata": {"vulnerabilities": counts},
    }


def _buckets(**overrides):
    base = {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0}
    base.update(overrides)
    return base


def _one_node(severity="high"):
    return {
        "pkg-a": {
            "name": "pkg-a",
            "severity": severity,
            "isDirect": True,
            "range": "<1",
            "nodes": ["node_modules/pkg-a"],
            "via": [],
        }
    }


def test_empty_vulnerabilities_with_total_one_fails():
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(_payload({}, _buckets(high=1, total=1)), "fixture")
    assert "vulnerable package nodes" in str(excinfo.value)


def test_non_empty_vulnerabilities_with_total_zero_fails():
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(_payload(_one_node(), _buckets()), "fixture")
    assert "vulnerable package nodes" in str(excinfo.value)


def test_severity_buckets_not_summing_to_total_fails():
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(
            _payload(_one_node(), _buckets(moderate=1, total=5)), "fixture"
        )
    assert "sum of severity buckets" in str(excinfo.value)


def test_missing_negative_string_and_boolean_counts_fail():
    cases = {
        "missing bucket": {"total": 1, "high": 1},
        "negative total": _buckets(high=1, total=-1),
        "negative bucket": _buckets(high=-1, total=-1),
        "string total": _buckets(high=1, total="1"),
        "string bucket": _buckets(high="1", total=1),
        "boolean total": _buckets(high=1, total=True),
        "boolean bucket": _buckets(high=True, total=1),
    }
    for label, counts in cases.items():
        with pytest.raises(audit_npm.AuditUnusable) as excinfo:
            audit_npm.validate_report(_payload(_one_node(), counts), "fixture")
        assert "metadata.vulnerabilities" in str(excinfo.value), label


def test_malformed_vulnerability_nodes_fail():
    cases = {
        "node not an object": {"pkg-a": "oops"},
        "bad severity": {
            "pkg-a": {
                "severity": "spicy",
                "via": [],
                "nodes": ["node_modules/pkg-a"],
                "range": "<1",
            }
        },
        "via not a list": {
            "pkg-a": {
                "severity": "high",
                "via": {},
                "nodes": ["node_modules/pkg-a"],
                "range": "<1",
            }
        },
        "via bad member": {
            "pkg-a": {
                "severity": "high",
                "via": [123],
                "nodes": ["node_modules/pkg-a"],
                "range": "<1",
            }
        },
        "nodes not a list": {
            "pkg-a": {
                "severity": "high",
                "via": [],
                "nodes": "node_modules/pkg-a",
                "range": "<1",
            }
        },
        "nodes has empty string": {
            "pkg-a": {"severity": "high", "via": [], "nodes": [""], "range": "<1"}
        },
        "range not a string": {
            "pkg-a": {
                "severity": "high",
                "via": [],
                "nodes": ["node_modules/pkg-a"],
                "range": 5,
            }
        },
    }
    for label, vulns in cases.items():
        with pytest.raises(audit_npm.AuditUnusable) as excinfo:
            audit_npm.validate_report(
                _payload(vulns, _buckets(high=1, total=1)), "fixture"
            )
        assert "vulnerabilities[" in str(excinfo.value), label


def test_via_may_mix_advisory_objects_and_indirect_name_strings():
    """npm reports may do this; validation must not reject the shape.

    Shape taken from the retired report: `react-router-dom` carried its own
    advisory object AND the plain string `react-router`, which names the other
    vulnerable node that also makes it vulnerable.
    """
    vulns = {
        "pkg-a": {
            "severity": "high",
            "range": "<1",
            "nodes": ["node_modules/pkg-a"],
            "via": [
                {
                    "source": 1,
                    "name": "pkg-a",
                    "url": "https://github.com/advisories/GHSA-a",
                    "severity": "high",
                    "range": "<1",
                },
                "pkg-b",
            ],
        },
        "pkg-b": {
            "severity": "high",
            "range": "<1",
            "nodes": ["node_modules/pkg-b"],
            "via": [
                {
                    "source": 2,
                    "name": "pkg-b",
                    "url": "https://github.com/advisories/GHSA-b",
                    "severity": "high",
                    "range": "<1",
                }
            ],
        },
    }
    audit_npm.validate_report(_payload(vulns, _buckets(high=2, total=2)), "fixture")


def test_current_real_npm_reports_remain_accepted():
    """The live production and full trees must still validate end-to-end."""
    npm_dir = ROOT / "interlock-web"
    for production_only in (True, False):
        report = audit_npm.run_npm_audit(npm_dir, production_only=production_only)
        counts = report["metadata"]["vulnerabilities"]
        assert counts["total"] == len(report["vulnerabilities"])
        assert counts["total"] == sum(
            counts[b] for b in audit_npm.SEVERITY_BUCKETS
        ), "real npm metadata must satisfy the invariant the gate enforces"


# ── F4: a declared vulnerability must reach a real advisory ──────────────────
#
# The gate's verdict is computed from FLATTENED advisory rows, but a package
# node declares that it is vulnerable in `metadata` and `severity` — fields the
# flattening never reads. A report can therefore be internally consistent by
# every count-based check and still flatten to nothing, which reads as "no
# advisories in this scope" and passes. These tests close that gap: a declared
# vulnerability must be backed by a reachable advisory object.


def _advisory(package, advisory_id="GHSA-z", severity="high", vrange="<1", **override):
    """An advisory object shaped like the ones real npm emits."""
    obj = {
        "source": 1124268,
        "name": package,
        "dependency": package,
        "title": "fixture advisory",
        "url": f"https://github.com/advisories/{advisory_id}",
        "severity": severity,
        "range": vrange,
    }
    obj.update(override)
    for key, value in list(obj.items()):
        if value is _ABSENT:
            del obj[key]
    return obj


class _Absent:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return "<absent>"


_ABSENT = _Absent()


def _node(package, severity="high", via=None, vrange="<1"):
    return {
        "name": package,
        "severity": severity,
        "isDirect": True,
        "range": vrange,
        "nodes": [f"node_modules/{package}"],
        "via": [] if via is None else list(via),
    }


def _graph_report(vulns):
    """A report whose metadata is derived from the nodes, so counts agree."""
    return {
        "auditReportVersion": 2,
        "vulnerabilities": vulns,
        "metadata": _metadata_for(vulns),
    }


def _exceptionless_policy(tmp_path):
    """Write the repository's exception-free policy to an isolated fixture."""
    path = tmp_path / "exceptionless-policy.json"
    path.write_text(json.dumps({**_policy(), "exceptions": []}), encoding="utf-8")
    return path


def test_declared_high_severity_with_empty_via_cannot_pass(tmp_path):
    """The blocker: consistent metadata, `via: []`, zero rows — and PASS.

    Everything about this report agrees with itself: one vulnerable package
    node, metadata total 1, high bucket 1. Only the advisory itself is missing,
    so the flattening yields nothing and the gate has nothing to block on.
    """
    payload = _graph_report({"pkg-a": _node("pkg-a", "high", via=[])})
    result = _run_gate(tmp_path, payload, policy=_exceptionless_policy(tmp_path))
    assert result.returncode == UNUSABLE, result.stdout
    assert "RESULT: PASS" not in result.stdout
    assert "no advisories in this scope" not in result.stdout


def test_empty_via_is_rejected_at_validation():
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(
            _graph_report({"pkg-a": _node("pkg-a", "high", via=[])}), "fixture"
        )
    message = str(excinfo.value)
    assert "pkg-a" in message
    assert "advisory" in message


def test_via_edge_naming_an_absent_package_fails():
    """A dangling edge means the report does not contain its own cause."""
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(
            _graph_report({"pkg-a": _node("pkg-a", via=["ghost"])}), "fixture"
        )
    message = str(excinfo.value)
    assert "ghost" in message
    assert "pkg-a" in message


def test_dangling_edge_fails_even_when_another_via_carries_an_advisory():
    """An unreachable cause is a defect on its own, not excused by a sibling."""
    vulns = {
        "pkg-a": _node("pkg-a", via=[_advisory("pkg-a"), "ghost"]),
    }
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(_graph_report(vulns), "fixture")
    assert "ghost" in str(excinfo.value)


def test_cyclic_via_graph_without_an_advisory_fails():
    """Two nodes blaming each other reach no advisory and must not pass."""
    vulns = {
        "pkg-a": _node("pkg-a", via=["pkg-b"]),
        "pkg-b": _node("pkg-b", via=["pkg-a"]),
    }
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(_graph_report(vulns), "fixture")
    message = str(excinfo.value)
    assert "advisory" in message
    assert "pkg-a" in message or "pkg-b" in message


def test_self_referential_via_without_an_advisory_fails():
    vulns = {"pkg-a": _node("pkg-a", via=["pkg-a"])}
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(_graph_report(vulns), "fixture")
    assert "pkg-a" in str(excinfo.value)


def test_via_string_chain_that_reaches_an_advisory_is_accepted():
    """Indirection is legitimate as long as the chain terminates in evidence."""
    vulns = {
        "pkg-a": _node("pkg-a", via=["pkg-b"]),
        "pkg-b": _node("pkg-b", via=["pkg-c"]),
        "pkg-c": _node("pkg-c", via=[_advisory("pkg-c")]),
    }
    audit_npm.validate_report(_graph_report(vulns), "fixture")


def test_cycle_with_an_advisory_reachable_through_it_is_accepted():
    """A cycle is only fatal when nothing in it carries an advisory."""
    vulns = {
        "pkg-a": _node("pkg-a", via=["pkg-b"]),
        "pkg-b": _node("pkg-b", via=["pkg-a", _advisory("pkg-b")]),
    }
    audit_npm.validate_report(_graph_report(vulns), "fixture")


# ── F4: advisory objects must carry the facts the gate decides on ────────────


def test_advisory_object_fields_are_validated():
    """Each field the verdict depends on must be present and well-formed.

    `severity`, `range` and `name` feed exception matching and production/full
    differencing; `source` and `url` are what the advisory id is derived from.
    A missing or malformed one silently becomes an empty string in the flattened
    row, which is a fact the gate would then compare against.
    """
    cases = {
        "missing source": {"source": _ABSENT, "url": _ABSENT},
        "boolean source": {"source": True},
        "negative source": {"source": -1},
        "string source": {"source": "1124268"},
        "missing name": {"name": _ABSENT},
        "empty name": {"name": "  "},
        "non-string name": {"name": 5},
        "name is a different package": {"name": "other-pkg"},
        "missing severity": {"severity": _ABSENT},
        "unknown severity": {"severity": "spicy"},
        "non-string severity": {"severity": 3},
        "missing range": {"range": _ABSENT},
        "empty range": {"range": ""},
        "non-string range": {"range": 5},
        "empty url": {"url": ""},
        "non-string url": {"url": 7},
    }
    for label, override in cases.items():
        vulns = {"pkg-a": _node("pkg-a", via=[_advisory("pkg-a", **override)])}
        with pytest.raises(audit_npm.AuditUnusable) as excinfo:
            audit_npm.validate_report(_graph_report(vulns), "fixture")
        message = str(excinfo.value)
        assert "via[0]" in message, label
        assert "pkg-a" in message, label


def test_advisory_object_without_url_but_with_source_is_accepted():
    """npm always sends a url; a numeric source alone still identifies it."""
    vulns = {"pkg-a": _node("pkg-a", via=[_advisory("pkg-a", url=_ABSENT)])}
    audit_npm.validate_report(_graph_report(vulns), "fixture")
    rows = audit_npm.advisories(_graph_report(vulns))
    assert rows[0]["id"] == "1124268", "id must fall back to the advisory source"


# ── F5: metadata severities must match the body, bucket by bucket ────────────


def test_metadata_bucket_disagreeing_with_node_severity_fails():
    """Totals can agree while the severities do not.

    `total` and the bucket sum both equal 1 here, and there is exactly one
    vulnerable package node — every count-based check passes. But npm says the
    finding is moderate while the node says high, so one of the two is fiction.
    """
    vulns = {"pkg-a": _node("pkg-a", "high", via=[_advisory("pkg-a")])}
    payload = {
        "auditReportVersion": 2,
        "vulnerabilities": vulns,
        "metadata": {"vulnerabilities": _buckets(moderate=1, total=1)},
    }
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.validate_report(payload, "fixture")
    message = str(excinfo.value)
    assert "high" in message and "moderate" in message


def test_metadata_buckets_matching_node_severities_are_accepted():
    vulns = {
        "pkg-a": _node("pkg-a", "high", via=[_advisory("pkg-a")]),
        "pkg-b": _node(
            "pkg-b", "moderate", via=[_advisory("pkg-b", severity="moderate")]
        ),
    }
    payload = {
        "auditReportVersion": 2,
        "vulnerabilities": vulns,
        "metadata": {"vulnerabilities": _buckets(high=1, moderate=1, total=2)},
    }
    audit_npm.validate_report(payload, "fixture")


def test_severity_bucket_swap_across_two_nodes_fails():
    """Bucket counts must be per-severity, not merely the right shape overall."""
    vulns = {
        "pkg-a": _node(
            "pkg-a", "critical", via=[_advisory("pkg-a", severity="critical")]
        ),
        "pkg-b": _node("pkg-b", "low", via=[_advisory("pkg-b", severity="low")]),
    }
    payload = {
        "auditReportVersion": 2,
        "vulnerabilities": vulns,
        "metadata": {"vulnerabilities": _buckets(high=1, moderate=1, total=2)},
    }
    with pytest.raises(audit_npm.AuditUnusable):
        audit_npm.validate_report(payload, "fixture")


# ── F5: declared vulnerabilities must survive the flattening ─────────────────


def test_declared_total_cannot_flatten_to_zero_advisories():
    """The last-line invariant, independent of how the report got this far.

    Even if some future validation gap lets a via-less node through, the
    flattening itself must refuse to report zero advisories for a report that
    declares some.
    """
    payload = {
        "auditReportVersion": 2,
        "vulnerabilities": {"pkg-a": _node("pkg-a", "high", via=[])},
        "metadata": {"vulnerabilities": _buckets(high=1, total=1)},
    }
    with pytest.raises(audit_npm.AuditUnusable) as excinfo:
        audit_npm.advisories(payload)
    message = str(excinfo.value)
    assert "1" in message
    assert "advisor" in message.lower()


def test_zero_declared_vulnerabilities_still_flattens_to_nothing():
    """The invariant must not fire on a genuinely clean tree."""
    payload = {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": _buckets()},
    }
    assert audit_npm.advisories(payload) == []


def test_a_clean_tree_still_passes_the_gate(tmp_path):
    """The new invariant must not turn a genuinely empty report into a failure."""
    payload = {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": _buckets()},
    }
    result = _run_gate(tmp_path, payload, policy=_exceptionless_policy(tmp_path))
    assert result.returncode == CLEAN, result.stdout
    assert "no advisories in this scope" in result.stdout


# ── F6: every failure is a clean diagnostic, never a traceback ───────────────


def test_graph_failures_print_a_clean_diagnostic(tmp_path):
    payload = _graph_report({"pkg-a": _node("pkg-a", "high", via=["ghost"])})
    result = _run_gate(tmp_path, payload)
    assert result.returncode == UNUSABLE
    assert "AUDIT UNUSABLE" in result.stdout
    assert "Traceback" not in result.stderr
    assert "Traceback" not in result.stdout


def test_unreadable_policy_file_fails_closed_without_a_traceback(tmp_path):
    """A crash currently exits 1, which is indistinguishable from 'blocked'."""
    bad_policy = tmp_path / "policy.json"
    bad_policy.write_text("{not json", encoding="utf-8")
    result = _run_gate(tmp_path, _report(OBSERVED), policy=bad_policy)
    assert result.returncode == UNUSABLE, result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def test_malformed_policy_exception_fails_closed_without_a_traceback(tmp_path):
    """A policy entry the gate cannot read must not crash mid-verdict."""
    cases = {
        "bad expiry": {"expires": "not-a-date"},
        "missing expiry": {"expires": None},
        "missing id": {"id": None},
        "missing compensating control": {"compensatingControl": None},
    }
    for label, override in cases.items():
        entry = dict(FIXTURE_EXCEPTIONS[0])
        for key, value in override.items():
            if value is None:
                entry.pop(key, None)
            else:
                entry[key] = value
        policy_file = tmp_path / f"policy-{label.replace(' ', '-')}.json"
        policy_file.write_text(
            json.dumps({**_policy(), "exceptions": [entry]}), encoding="utf-8"
        )
        result = _run_gate(tmp_path, _report(OBSERVED), policy=policy_file)
        assert result.returncode == UNUSABLE, f"{label}: {result.stdout}{result.stderr}"
        assert "Traceback" not in result.stderr, label


def test_bad_today_override_fails_closed_without_a_traceback(tmp_path):
    result = _run_gate(tmp_path, _report(OBSERVED), today="31-12-2026")
    assert result.returncode == UNUSABLE, result.stdout + result.stderr
    assert "Traceback" not in result.stderr


# ── F6: the live reports must survive every new check ────────────────────────


def test_current_real_npm_reports_pass_advisory_graph_validation():
    """Production and full npm trees are clean and flatten to no advisories."""
    npm_dir = ROOT / "interlock-web"
    for production_only in (True, False):
        label = "production" if production_only else "full"
        report = audit_npm.run_npm_audit(npm_dir, production_only=production_only)
        rows = audit_npm.advisories(report)
        declared = report["metadata"]["vulnerabilities"]["total"]
        assert declared == 0, f"{label}: expected a clean dependency graph"
        assert rows == [], f"{label}: clean report flattened unexpected advisories"
