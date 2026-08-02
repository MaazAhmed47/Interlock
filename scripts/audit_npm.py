#!/usr/bin/env python3
"""Policy-aware npm audit gate.

`npm audit --audit-level=...` cannot express "block everything except these
three advisories, and only until they expire". This wrapper can, without
resorting to a blanket suppression:

  * production and development advisories are reported separately;
  * anything at or above the policy severity threshold fails the build;
  * an advisory is tolerated only if `.github/dependency-audit-policy.json`
    lists its exact GHSA id with a future expiry date;
  * an expired exception fails;
  * an exception that no longer matches any advisory fails, so the policy file
    cannot accumulate dead entries that quietly widen over time.

`npm audit` exits non-zero whenever it finds anything, so shelling it into a
file needs `|| true` — exactly the exit-swallowing construct that made the old
job dishonest. This script runs npm audit itself instead: one command per scope
both records the JSON and decides pass/fail, with no shell escape hatch.

Usage:
    python scripts/audit_npm.py --scope production  --npm-dir interlock-web --write out.json
    python scripts/audit_npm.py --audit-json <file> --scope development   # fixtures/tests

Exit codes: 0 clean or fully excepted, 1 policy violation, 2 bad invocation.
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


def load_policy(path: pathlib.Path) -> dict:
    if not path.exists():
        sys.stderr.write(f"policy file missing: {path}\n")
        raise SystemExit(2)
    return json.loads(path.read_text(encoding="utf-8"))


def advisories(audit: dict) -> list[dict]:
    """Flatten `npm audit --json` into one row per (package, advisory)."""
    rows: list[dict] = []
    for name, node in (audit.get("vulnerabilities") or {}).items():
        for via in node.get("via") or []:
            if not isinstance(via, dict):
                continue  # a string `via` is an indirect edge, not an advisory
            url = via.get("url") or ""
            rows.append(
                {
                    "package": name,
                    "advisory_package": via.get("name") or name,
                    "id": url.rsplit("/", 1)[-1] if url else via.get("source", ""),
                    "severity": (
                        via.get("severity") or node.get("severity") or ""
                    ).lower(),
                    "title": via.get("title") or "",
                    "range": via.get("range") or node.get("range") or "",
                    "direct": bool(node.get("isDirect")),
                    "paths": node.get("nodes") or [],
                }
            )
    return rows


def at_or_above(severity: str, threshold: str, order: list[str]) -> bool:
    try:
        return order.index(severity) >= order.index(threshold)
    except ValueError:
        # Unknown severity: fail closed rather than silently passing.
        return True


def run_npm_audit(npm_dir: pathlib.Path, scope: str) -> dict:
    """Run `npm audit --json` directly.

    npm exits 1 when advisories exist, which is not an error for us: the policy
    decides. Only a missing/garbled payload is fatal, so a broken npm run can
    never be mistaken for a clean tree.
    """
    cmd = ["npm", "audit", "--json"]
    if scope == "production":
        cmd.insert(2, "--omit=dev")
    proc = subprocess.run(
        cmd,
        cwd=str(npm_dir),
        capture_output=True,
        text=True,
        shell=(sys.platform == "win32"),
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(
            f"npm audit produced no parsable JSON (exit {proc.returncode}).\n"
            f"stdout head: {proc.stdout[:400]}\nstderr head: {proc.stderr[:400]}\n"
        )
        raise SystemExit(2)


def main() -> int:
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--audit-json", help="pre-captured npm audit --json payload")
    src.add_argument("--npm-dir", help="run npm audit in this directory")
    ap.add_argument("--scope", required=True, choices=["production", "development"])
    ap.add_argument("--policy", default=str(POLICY_PATH))
    ap.add_argument("--write", default=None, help="persist the audit JSON here")
    ap.add_argument("--today", default=None, help="override date (testing only)")
    args = ap.parse_args()

    policy = load_policy(pathlib.Path(args.policy))
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

    if args.npm_dir:
        audit = run_npm_audit(pathlib.Path(args.npm_dir), args.scope)
    else:
        audit_path = pathlib.Path(args.audit_json)
        if not audit_path.exists():
            sys.stderr.write(f"audit json missing: {audit_path}\n")
            return 2
        audit = json.loads(audit_path.read_text(encoding="utf-8"))

    if args.write:
        out = pathlib.Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")

    rows = advisories(audit)

    by_id = {}
    for entry in policy.get("exceptions", []):
        by_id.setdefault(entry["id"], entry)

    print(f"== npm audit gate :: scope={args.scope} threshold={threshold} ==")
    if not rows:
        print("  no advisories reported")

    blocking, excepted, used = [], [], set()
    for row in sorted(rows, key=lambda r: (r["severity"], r["package"])):
        tag = "direct" if row["direct"] else "transitive"
        print(f"  {row['severity'].upper():8} {row['package']} ({tag}) {row['id']}")
        print(f"           {row['title']}")
        print(f"           vulnerable={row['range']} paths={','.join(row['paths'])}")
        if not at_or_above(row["severity"], threshold, order):
            print("           below threshold — informational")
            continue
        entry = by_id.get(row["id"])
        if entry is None:
            blocking.append(row)
            print("           NOT EXCEPTED -> blocking")
            continue
        used.add(row["id"])
        expires = _dt.date.fromisoformat(entry["expires"])
        if expires < today:
            blocking.append(row)
            print(f"           EXCEPTION EXPIRED {expires} (today {today}) -> blocking")
        else:
            excepted.append(row)
            print(
                f"           accepted until {expires} — {entry['compensatingControl']}"
            )

    stale = [i for i in by_id if i not in used]
    if stale:
        print(
            f"\n  stale policy entries no longer matching any advisory: {sorted(stale)}"
        )
        print("  remove them; a policy file must not accumulate dead exceptions")

    print(
        f"\n  summary: {len(rows)} advisories, {len(blocking)} blocking, "
        f"{len(excepted)} accepted, {len(stale)} stale"
    )
    # Stale entries only fail on the production pass so the same policy file is
    # not reported twice for one CI run.
    fail_stale = bool(stale) and args.scope == "production"
    if blocking or fail_stale:
        print("  RESULT: FAIL")
        return 1
    print("  RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
