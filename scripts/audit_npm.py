#!/usr/bin/env python3
"""Policy-aware npm audit gate.

`npm audit --audit-level=...` cannot express "block everything except these
three advisories, and only until they expire". This gate can, without becoming
a blanket suppression:

  * production and build/development advisories are evaluated separately, from
    the tree each one actually belongs to;
  * anything at or above the policy severity threshold fails the build;
  * an advisory is tolerated only when EVERY recorded fact still matches the
    observed advisory — id, package, severity, scope, installed version and
    affected range — and the exception has not expired;
  * a severity escalation or any metadata drift blocks and demands re-review,
    because the thing that was assessed is no longer the thing observed;
  * an exception that matches nothing in its own scope fails, so the policy
    file cannot accumulate dead entries that quietly widen over time.

Fail-closed posture: an advisory is blocked unless an exception proves
otherwise, and an audit run that cannot be shown to be a complete, well-formed
npm report is a failure rather than an empty (and therefore "clean") result.
`npm audit` exits non-zero whenever it finds anything, so shelling it into a
file needs `|| true` — exactly the exit-swallowing that this gate exists to
avoid. It runs npm itself instead.

Usage:
    python scripts/audit_npm.py --npm-dir interlock-web --scope production \\
        --write out.json
    python scripts/audit_npm.py --audit-json prod.json --scope development \\
        --full-audit-json all.json          # fixtures / tests

Exit codes: 0 clean or fully excepted, 1 policy violation, 2 bad invocation or
an npm audit run that could not be trusted.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / ".github" / "dependency-audit-policy.json"
SUPPORTED_AUDIT_REPORT_VERSIONS = {2}


class AuditUnusable(Exception):
    """The npm audit output cannot be trusted, so it must not be interpreted."""


# ── input validation ─────────────────────────────────────────────────────────


def validate_report(payload: object, source: str) -> dict:
    """Return a usable npm audit report or raise AuditUnusable.

    npm emits a JSON object on failure too (ENOAUDIT, ENETUNREACH, EAI_AGAIN),
    and that object simply has no `vulnerabilities`. Interpreting it would read
    a registry outage as a clean dependency tree, so every structural
    expectation is asserted here instead of being assumed.
    """
    if not isinstance(payload, dict):
        raise AuditUnusable(
            f"{source}: expected a JSON object, got {type(payload).__name__}"
        )
    if not payload:
        raise AuditUnusable(f"{source}: empty JSON object")

    error = payload.get("error")
    if error:
        if isinstance(error, dict):
            code = error.get("code") or "unknown"
            summary = error.get("summary") or error.get("detail") or ""
            raise AuditUnusable(
                f"{source}: npm reported error {code}: {summary}".strip()
            )
        raise AuditUnusable(f"{source}: npm reported error {error}")

    version = payload.get("auditReportVersion")
    if version is None:
        raise AuditUnusable(
            f"{source}: missing auditReportVersion (not an npm audit report)"
        )
    if version not in SUPPORTED_AUDIT_REPORT_VERSIONS:
        raise AuditUnusable(
            f"{source}: unsupported auditReportVersion {version!r}; "
            f"expected one of {sorted(SUPPORTED_AUDIT_REPORT_VERSIONS)}"
        )

    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, dict):
        raise AuditUnusable(f"{source}: 'vulnerabilities' missing or not an object")

    metadata = payload.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(
        metadata.get("vulnerabilities"), dict
    ):
        raise AuditUnusable(
            f"{source}: 'metadata.vulnerabilities' missing or not an object"
        )

    return payload


def run_npm_audit(npm_dir: pathlib.Path, production_only: bool) -> dict:
    """Run `npm audit --json` and validate what comes back.

    npm exits 1 when advisories exist, which is not an error here: the policy
    decides. Anything that is not a parsable, complete report is fatal.
    """
    if not (npm_dir / "package-lock.json").exists():
        raise AuditUnusable(
            f"{npm_dir}: no package-lock.json; cannot audit reproducibly"
        )
    cmd = ["npm", "audit", "--json"]
    if production_only:
        cmd.insert(2, "--omit=dev")
    label = " ".join(cmd)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(npm_dir),
            capture_output=True,
            text=True,
            shell=(sys.platform == "win32"),
        )
    except OSError as exc:  # npm missing / not executable
        raise AuditUnusable(f"{label}: could not execute npm ({exc})") from exc

    if not proc.stdout.strip():
        raise AuditUnusable(
            f"{label}: produced no stdout (exit {proc.returncode}); "
            f"stderr: {proc.stderr.strip()[:300]}"
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AuditUnusable(
            f"{label}: stdout was not JSON (exit {proc.returncode}): {exc}; "
            f"head: {proc.stdout[:200]!r}"
        ) from exc
    return validate_report(payload, label)


def load_report_file(path: pathlib.Path) -> dict:
    if not path.exists():
        raise AuditUnusable(f"audit json missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AuditUnusable(f"{path}: not valid JSON: {exc}") from exc
    return validate_report(payload, str(path))


# ── observed facts ───────────────────────────────────────────────────────────


def installed_versions(lock_path: pathlib.Path) -> dict[str, str]:
    """Map package name -> installed version from package-lock.json.

    Structured parse of the lockfile `packages` map rather than trusting the
    audit payload to describe what is installed.
    """
    if not lock_path.exists():
        raise AuditUnusable(f"{lock_path}: package-lock.json not found")
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AuditUnusable(f"{lock_path}: not valid JSON: {exc}") from exc
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise AuditUnusable(
            f"{lock_path}: no 'packages' map (lockfileVersion too old?)"
        )

    versions: dict[str, str] = {}
    for key, meta in packages.items():
        if not key or not isinstance(meta, dict):
            continue
        marker = "node_modules/"
        idx = key.rfind(marker)
        if idx == -1:
            continue
        name = key[idx + len(marker) :]
        version = meta.get("version")
        if name and isinstance(version, str):
            versions.setdefault(name, version)
    return versions


def advisories(report: dict) -> list[dict]:
    """Flatten an npm audit report into one row per (package, advisory)."""
    rows: list[dict] = []
    for name, node in (report.get("vulnerabilities") or {}).items():
        if not isinstance(node, dict):
            continue
        for via in node.get("via") or []:
            if not isinstance(via, dict):
                continue  # a string `via` is an indirect edge, not an advisory
            url = via.get("url") or ""
            rows.append(
                {
                    "package": name,
                    "advisory_package": via.get("name") or name,
                    "id": url.rsplit("/", 1)[-1] if url else str(via.get("source", "")),
                    "severity": (
                        via.get("severity") or node.get("severity") or ""
                    ).lower(),
                    "title": via.get("title") or "",
                    "range": via.get("range") or "",
                    "node_range": node.get("range") or "",
                    "direct": bool(node.get("isDirect")),
                    "paths": node.get("nodes") or [],
                }
            )
    return rows


def at_or_above(severity: str, threshold: str, order: list[str]) -> bool:
    try:
        return order.index(severity) >= order.index(threshold)
    except ValueError:
        return True  # unknown severity: fail closed


# ── exception matching ───────────────────────────────────────────────────────


def mismatches(
    row: dict, entry: dict, scope: str, versions: dict[str, str]
) -> list[str]:
    """Every recorded fact that no longer matches the observed advisory.

    An empty list means the exception still describes reality. Anything else
    means the assessed advisory and the observed advisory are not the same
    thing, so the exception must not apply.
    """
    problems: list[str] = []

    if entry.get("package") != row["advisory_package"]:
        problems.append(
            f"package: policy={entry.get('package')!r} observed={row['advisory_package']!r}"
        )
    if str(entry.get("severity", "")).lower() != row["severity"]:
        problems.append(
            f"severity: policy={entry.get('severity')!r} observed={row['severity']!r}"
        )
    if str(entry.get("scope", "")).lower() != scope:
        problems.append(f"scope: policy={entry.get('scope')!r} gate={scope!r}")

    recorded_version = entry.get("installedVersion")
    observed_version = versions.get(row["advisory_package"])
    if recorded_version is None:
        problems.append("installedVersion: not recorded in policy")
    elif observed_version is None:
        problems.append(
            f"installedVersion: {row['advisory_package']} not present in package-lock.json"
        )
    elif recorded_version != observed_version:
        problems.append(
            f"installedVersion: policy={recorded_version!r} lockfile={observed_version!r}"
        )

    recorded_range = entry.get("affectedRange")
    if recorded_range is not None and recorded_range != row["range"]:
        problems.append(
            f"affectedRange: policy={recorded_range!r} observed={row['range']!r}"
        )

    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--audit-json", help="pre-captured npm audit report for this scope"
    )
    src.add_argument("--npm-dir", help="run npm audit in this directory")
    ap.add_argument("--scope", required=True, choices=["production", "development"])
    ap.add_argument(
        "--full-audit-json",
        help="full-tree report; with --audit-json and --scope development, "
        "dev-only findings are the full tree minus the production tree",
    )
    ap.add_argument(
        "--lockfile", default=None, help="package-lock.json for version facts"
    )
    ap.add_argument("--policy", default=str(POLICY_PATH))
    ap.add_argument("--write", default=None, help="persist the evaluated report here")
    ap.add_argument("--today", default=None, help="override date (testing only)")
    args = ap.parse_args()

    policy_path = pathlib.Path(args.policy)
    if not policy_path.exists():
        sys.stderr.write(f"policy file missing: {policy_path}\n")
        return 2
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    order = [
        s.lower()
        for s in policy.get("severityOrder", ["low", "moderate", "high", "critical"])
    ]
    threshold = str(policy.get("failOnSeverity", "moderate")).lower()
    today = (
        _dt.date.fromisoformat(args.today)
        if args.today
        else _dt.datetime.now(_dt.timezone.utc).date()
    )

    npm_dir = pathlib.Path(args.npm_dir) if args.npm_dir else None
    lock_path = (
        pathlib.Path(args.lockfile)
        if args.lockfile
        else (npm_dir / "package-lock.json" if npm_dir else None)
    )

    # Production findings come from the --omit=dev tree. Development findings
    # are the FULL tree minus the production tree, so a production advisory can
    # never be relabelled as a build/dev finding.
    written: dict | None = None
    try:
        # `production` is the --omit=dev tree, used to subtract production
        # findings from the full tree. It stays None only when a caller supplies
        # a single pre-captured report and no full-tree companion.
        production: dict | None = None
        if npm_dir is not None:
            production = run_npm_audit(npm_dir, production_only=True)
            if args.scope == "production":
                evaluated = production
            else:
                evaluated = run_npm_audit(npm_dir, production_only=False)
        else:
            primary = load_report_file(pathlib.Path(args.audit_json))
            evaluated = primary
            if args.scope == "development" and args.full_audit_json:
                production = primary
                evaluated = load_report_file(pathlib.Path(args.full_audit_json))
        written = evaluated

        if lock_path is None:
            raise AuditUnusable("no lockfile given; cannot verify installed versions")
        versions = installed_versions(lock_path)

        rows = advisories(evaluated)
        if args.scope == "development" and production is not None:
            prod_keys = {
                (r["id"], r["advisory_package"]) for r in advisories(production)
            }
            rows = [
                r for r in rows if (r["id"], r["advisory_package"]) not in prod_keys
            ]
    except AuditUnusable as exc:
        # Still emit sanitized evidence when we have something structural.
        if args.write and written is not None:
            out = pathlib.Path(args.write)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(written, indent=2, sort_keys=True), encoding="utf-8"
            )
        print(f"== npm audit gate :: scope={args.scope} ==")
        print(f"  AUDIT UNUSABLE: {exc}")
        print("  RESULT: FAIL (fail-closed; an untrusted audit is not a clean tree)")
        return 2

    if args.write:
        out = pathlib.Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(written, indent=2, sort_keys=True), encoding="utf-8")

    # Exceptions are indexed by (id, package) and only apply in their own scope,
    # so a policy entry can never approve a different package on a shared id.
    scoped = [
        e
        for e in policy.get("exceptions", [])
        if str(e.get("scope", "")).lower() == args.scope
    ]
    by_key = {(e["id"], e.get("package")): e for e in scoped}

    print(f"== npm audit gate :: scope={args.scope} threshold={threshold} ==")
    if not rows:
        print("  no advisories in this scope")

    blocking, accepted, used = [], [], set()
    for row in sorted(rows, key=lambda r: (r["severity"], r["package"], r["id"])):
        tag = "direct" if row["direct"] else "transitive"
        print(f"  {row['severity'].upper():8} {row['package']} ({tag}) {row['id']}")
        print(f"           {row['title']}")
        print(f"           vulnerable={row['range']} paths={','.join(row['paths'])}")
        if not at_or_above(row["severity"], threshold, order):
            print("           below threshold — informational")
            continue

        entry = by_key.get((row["id"], row["advisory_package"]))
        if entry is None:
            blocking.append(row)
            print("           NOT EXCEPTED -> blocking")
            continue

        drift = mismatches(row, entry, args.scope, versions)
        if drift:
            blocking.append(row)
            print("           EXCEPTION DOES NOT MATCH OBSERVED ADVISORY -> blocking")
            for problem in drift:
                print(f"             - {problem}")
            print("             re-review required; the assessed advisory changed")
            continue

        used.add((row["id"], row["advisory_package"]))
        expires = _dt.date.fromisoformat(entry["expires"])
        if expires < today:
            blocking.append(row)
            print(f"           EXCEPTION EXPIRED {expires} (today {today}) -> blocking")
        else:
            accepted.append(row)
            print(
                f"           accepted until {expires} — {entry['compensatingControl']}"
            )

    stale = [k for k in by_key if k not in used]
    if stale:
        print(f"\n  stale {args.scope} policy entries matching no observed advisory:")
        for gid, pkg in sorted(stale):
            print(f"    - {gid} ({pkg})")
        print("  remove them; a policy file must not accumulate dead exceptions")

    print(
        f"\n  summary: {len(rows)} advisories, {len(blocking)} blocking, "
        f"{len(accepted)} accepted, {len(stale)} stale"
    )
    if blocking or stale:
        print("  RESULT: FAIL")
        return 1
    print("  RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
