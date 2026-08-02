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

Fail-closed posture. An audit run is trusted only when npm exited 0 or 1 (the
two codes that mean "the audit completed") AND stdout is a complete, well-formed
report; anything else is a failure rather than an empty — and therefore
"clean" — result. Production/full-tree differencing compares the whole security
identity of an advisory, so a finding that differs in severity, range, or
vulnerable instances can never be erased by its production twin. Installed
versions come from a structured lockfile parse that keeps every instance, since
one package can be installed at several paths at different versions.

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
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / ".github" / "dependency-audit-policy.json"
SUPPORTED_AUDIT_REPORT_VERSIONS = {2}
# 0 = audit ran, nothing found. 1 = audit ran, advisories found. Anything else
# is an operational failure, not a verdict.
COMPLETED_AUDIT_EXIT_CODES = {0, 1}


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


_SECRETISH = re.compile(
    r"(authorization|bearer|token|secret|password|passwd|api[-_]?key|cookie|set-cookie"
    r"|_auth|_authToken|npm_token|//[^/\s]+/:_)",
    re.I,
)


def sanitize_stderr(text: str, max_lines: int = 4, max_chars: int = 240) -> str:
    """A short, redacted stderr summary safe to print in a public CI log.

    npm writes registry URLs and, when misconfigured, auth material to stderr.
    Only a handful of lines are kept, any line that looks credential-bearing is
    replaced wholesale rather than partially masked, and the result is capped.
    """
    kept: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if _SECRETISH.search(line):
            kept.append("[redacted: credential-bearing line]")
        else:
            kept.append(line)
        if len(kept) >= max_lines:
            break
    summary = " | ".join(kept)
    if len(summary) > max_chars:
        summary = summary[:max_chars] + "…"
    return summary or "(no stderr)"


def run_npm_audit(npm_dir: pathlib.Path, production_only: bool) -> dict:
    """Run `npm audit --json` and validate both the process and the payload.

    npm exits 0 when nothing is found and 1 when advisories exist; both mean the
    audit completed and the policy decides. Every other exit code is an
    operational failure (network, auth, bad config, npm crash) and must be
    rejected even when stdout happens to contain valid-looking audit JSON —
    otherwise a failed run is indistinguishable from a clean tree.
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

    if proc.returncode not in COMPLETED_AUDIT_EXIT_CODES:
        raise AuditUnusable(
            f"{label}: npm exited {proc.returncode}, which does not represent a "
            f"completed audit (expected one of "
            f"{sorted(COMPLETED_AUDIT_EXIT_CODES)}); "
            f"stderr: {sanitize_stderr(proc.stderr)}"
        )

    if not proc.stdout.strip():
        raise AuditUnusable(
            f"{label}: produced no stdout (exit {proc.returncode}); "
            f"stderr: {sanitize_stderr(proc.stderr)}"
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AuditUnusable(
            f"{label}: stdout was not JSON (exit {proc.returncode}): {exc}; "
            f"stderr: {sanitize_stderr(proc.stderr)}"
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


def installed_instances(lock_path: pathlib.Path) -> dict[str, str]:
    """Map every lockfile path -> installed version.

    A package can be installed at several paths at different versions (a nested
    `node_modules/tool/node_modules/postcss` alongside a hoisted
    `node_modules/postcss`). Collapsing those to one version with `setdefault`
    silently picks an arbitrary winner and can validate an exception against a
    version that is not the vulnerable one, so every instance is kept.
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

    instances: dict[str, str] = {}
    for key, meta in packages.items():
        if not key or not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if "node_modules/" in key and isinstance(version, str):
            instances[key] = version
    return instances


def package_name_for(lock_key: str) -> str:
    marker = "node_modules/"
    idx = lock_key.rfind(marker)
    return lock_key[idx + len(marker) :] if idx != -1 else lock_key


def versions_for_package(instances: dict[str, str], name: str) -> dict[str, str]:
    """Every lockfile path of `name` -> its version."""
    return {k: v for k, v in instances.items() if package_name_for(k) == name}


def implicated_versions(
    instances: dict[str, str], name: str, node_paths: list[str]
) -> dict[str, str]:
    """Versions of the instances the advisory actually points at.

    npm reports vulnerable instances in `nodes` as lockfile-style paths. When
    those resolve, only they are considered; otherwise every installed instance
    of the package is, which is the conservative choice.
    """
    matched = {p: instances[p] for p in node_paths if p in instances}
    return matched or versions_for_package(instances, name)


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


# ── production / full-tree differencing ──────────────────────────────────────

# Facts that define WHICH advisory this is. Paths are deliberately excluded:
# the full tree legitimately contains extra dev instances of the same advisory.
SECURITY_IDENTITY_FIELDS = ("id", "advisory_package", "severity", "range", "node_range")


def security_identity(row: dict) -> tuple:
    return tuple(row[f] for f in SECURITY_IDENTITY_FIELDS)


def development_only(full_rows: list[dict], production_rows: list[dict]) -> list[dict]:
    """Full-tree rows that are not already accounted for by the production tree.

    Subtraction is by complete security identity, never by (id, package) alone.
    Three cases:

      * identical identity and identical vulnerable paths -> already covered by
        the production gate, subtract it;
      * identical identity but the full tree lists extra vulnerable instances ->
        those extra instances are dev-only, so the row is retained (with the
        extra paths) and evaluated by the development gate;
      * same (id, package) but different severity/range -> the two reports
        disagree about the advisory itself. Nothing can safely be subtracted, so
        fail closed rather than guess which report is right.
    """
    prod_by_identity: dict[tuple, dict] = {
        security_identity(r): r for r in production_rows
    }
    prod_by_key: dict[tuple, list[dict]] = {}
    for row in production_rows:
        prod_by_key.setdefault((row["id"], row["advisory_package"]), []).append(row)

    remaining: list[dict] = []
    for row in full_rows:
        identity = security_identity(row)
        twin = prod_by_identity.get(identity)
        if twin is None:
            conflicting = prod_by_key.get((row["id"], row["advisory_package"]))
            if conflicting:
                other = conflicting[0]
                differences = [
                    f"{field}: production={other[field]!r} full={row[field]!r}"
                    for field in SECURITY_IDENTITY_FIELDS
                    if other[field] != row[field]
                ]
                raise AuditUnusable(
                    "production and full audit reports disagree about "
                    f"{row['id']} ({row['advisory_package']}): "
                    + "; ".join(differences)
                    + ". Refusing to subtract one from the other."
                )
            remaining.append(row)  # genuinely dev-only
            continue

        extra_paths = [p for p in row["paths"] if p not in set(twin["paths"])]
        if extra_paths:
            # Same advisory, additional vulnerable instances that only exist in
            # the dev tree: keep it, scoped to just those instances.
            remaining.append({**row, "paths": extra_paths, "dev_only_instances": True})
    return remaining


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
    implicated = implicated_versions(versions, row["advisory_package"], row["paths"])
    observed = sorted(set(implicated.values()))
    if recorded_version is None:
        problems.append("installedVersion: not recorded in policy")
    elif not observed:
        problems.append(
            f"installedVersion: {row['advisory_package']} not present in package-lock.json"
        )
    elif len(observed) > 1:
        # Several vulnerable instances at different versions: one recorded
        # version cannot describe them all, so the exception must not apply.
        detail = ", ".join(f"{p}={v}" for p, v in sorted(implicated.items()))
        problems.append(
            f"installedVersion: policy records a single {recorded_version!r} but "
            f"{len(observed)} versions are installed ({detail})"
        )
    elif recorded_version != observed[0]:
        problems.append(
            f"installedVersion: policy={recorded_version!r} lockfile={observed[0]!r}"
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
        versions = installed_instances(lock_path)

        rows = advisories(evaluated)
        if args.scope == "development" and production is not None:
            rows = development_only(rows, advisories(production))
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
