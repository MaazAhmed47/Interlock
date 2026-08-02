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

A declared vulnerability must also survive the flattening. The verdict is
computed from advisory objects inside each node's `via`, while the report
declares vulnerabilities through `metadata` and per-node `severity` — fields the
flattening never reads. A report can therefore agree with itself on every count
and still produce zero advisory rows, which reads as "no advisories in this
scope" and passes. So the via graph is validated for completeness: every node
must reach a real advisory object, string edges must name nodes the report
actually contains, cycles must terminate in evidence, each advisory object must
carry the severity, range, package and identity the verdict is computed from,
the severity buckets must match the nodes one for one, and a summary declaring
vulnerable packages can never flatten to nothing.

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

    validate_metadata_counts(metadata["vulnerabilities"], vulns, source)
    for name, node in vulns.items():
        validate_vulnerability_node(name, node, source)
    # Only once every node is individually well-formed can the graph they form
    # and the severities they claim be checked against each other.
    validate_advisory_graph(vulns, source)
    validate_metadata_severities(metadata["vulnerabilities"], vulns, source)

    return payload


SEVERITY_BUCKETS = ("info", "low", "moderate", "high", "critical")


def _count(counts: dict, key: str, source: str) -> int:
    """A severity/total count that is genuinely a non-negative integer.

    `bool` is a subclass of `int` in Python, so `True` would otherwise pass as
    the number 1 and let a malformed report through.
    """
    if key not in counts:
        raise AuditUnusable(f"{source}: metadata.vulnerabilities.{key} is missing")
    value = counts[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuditUnusable(
            f"{source}: metadata.vulnerabilities.{key} must be an integer, "
            f"got {type(value).__name__} ({value!r})"
        )
    if value < 0:
        raise AuditUnusable(
            f"{source}: metadata.vulnerabilities.{key} is negative ({value})"
        )
    return value


def validate_metadata_counts(counts: dict, vulns: dict, source: str) -> None:
    """Cross-check npm's own summary against the report body.

    npm counts vulnerable *package nodes* in `metadata.vulnerabilities`, which
    is exactly `len(vulnerabilities)` — not the flattened advisory count, since
    one package node can carry several advisories. If the summary and the body
    disagree, the report is internally inconsistent and must not be trusted.
    """
    buckets = {name: _count(counts, name, source) for name in SEVERITY_BUCKETS}
    total = _count(counts, "total", source)

    bucket_sum = sum(buckets.values())
    if total != bucket_sum:
        raise AuditUnusable(
            f"{source}: metadata total {total} != sum of severity buckets "
            f"{bucket_sum} ({buckets})"
        )
    if total != len(vulns):
        raise AuditUnusable(
            f"{source}: metadata total {total} != {len(vulns)} vulnerable package "
            "nodes in the report body"
        )


def validate_metadata_severities(counts: dict, vulns: dict, source: str) -> None:
    """Compare every severity bucket against the severities actually declared.

    Matching totals are not agreement. A report can hold exactly as many
    vulnerable package nodes as `total` claims, with the buckets summing to that
    same total, and still describe a critical finding as moderate — which is
    precisely the drift the exception matcher exists to catch. Comparing the
    buckets one by one leaves no room for a severity to be restated on the way
    into the summary.
    """
    observed = {name: 0 for name in SEVERITY_BUCKETS}
    for node in vulns.values():
        # Node severities are validated before this runs, so an unknown bucket
        # is unreachable; counting only known ones keeps it that way rather than
        # raising a KeyError, and an uncounted node still shows up as a
        # difference below.
        bucket = str(node.get("severity", "")).lower()
        if bucket in observed:
            observed[bucket] += 1

    differences = [
        f"{name}: metadata={counts[name]} report body={observed[name]}"
        for name in SEVERITY_BUCKETS
        if counts[name] != observed[name]
    ]
    if differences:
        raise AuditUnusable(
            f"{source}: metadata.vulnerabilities severity buckets disagree with the "
            "severities declared by the vulnerable package nodes ("
            + "; ".join(differences)
            + ")"
        )


def validate_vulnerability_node(name: str, node: object, source: str) -> None:
    """Every vulnerability entry must be shaped as npm documents it."""
    where = f"{source}: vulnerabilities[{name!r}]"
    if not isinstance(node, dict):
        raise AuditUnusable(f"{where} is not an object")

    severity = node.get("severity")
    if not isinstance(severity, str) or severity.lower() not in SEVERITY_BUCKETS:
        raise AuditUnusable(f"{where}.severity is invalid ({severity!r})")

    via = node.get("via")
    if not isinstance(via, list):
        raise AuditUnusable(f"{where}.via must be a list")
    for index, item in enumerate(via):
        # npm mixes advisory objects with plain-string indirect edges.
        if isinstance(item, dict):
            validate_advisory_object(name, index, item, source)
        elif isinstance(item, str):
            if not item.strip():
                raise AuditUnusable(
                    f"{where}.via[{index}] is an empty package-name string"
                )
        else:
            raise AuditUnusable(
                f"{where}.via[{index}] is a {type(item).__name__}; "
                "expected an advisory object or a package-name string"
            )

    nodes = node.get("nodes")
    if not isinstance(nodes, list) or not all(
        isinstance(p, str) and p.strip() for p in nodes
    ):
        raise AuditUnusable(f"{where}.nodes must be a list of non-empty strings")

    vrange = node.get("range")
    if vrange is not None and not isinstance(vrange, str):
        raise AuditUnusable(f"{where}.range must be a string when present")


def advisory_identity(advisory: dict) -> str:
    """The advisory id the gate matches exceptions on.

    npm identifies an advisory twice over: a `url` ending in the GHSA id and a
    numeric `source`. The url is preferred because that is what a policy entry
    records; the source is the fallback that still names something specific.
    """
    url = advisory.get("url")
    if isinstance(url, str) and url.strip():
        return url.rsplit("/", 1)[-1]
    origin = advisory.get("source")
    return str(origin) if origin is not None else ""


def _require_text(value: object, field: str, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuditUnusable(
            f"{where}.{field} must be a non-empty string, got {value!r}"
        )
    return value


def validate_advisory_object(
    package: str, index: int, advisory: dict, source: str
) -> None:
    """An advisory object must carry every fact the verdict is computed from.

    `severity`, `range` and `name` are compared against the policy entry, and
    the identity derived from `url`/`source` is what an exception is keyed on.
    A missing one of these is not a harmless gap: the flattening turns it into
    an empty string, and an empty string is then compared as though it were an
    observed fact.
    """
    where = f"{source}: vulnerabilities[{package!r}].via[{index}]"

    name = _require_text(advisory.get("name"), "name", where)
    if name != package:
        raise AuditUnusable(
            f"{where}.name is {name!r} but the advisory is listed under "
            f"{package!r}; npm lists an advisory object under the package it "
            "affects, so the two must agree"
        )

    severity = advisory.get("severity")
    if not isinstance(severity, str) or severity.lower() not in SEVERITY_BUCKETS:
        raise AuditUnusable(f"{where}.severity is invalid ({severity!r})")

    _require_text(advisory.get("range"), "range", where)

    if advisory.get("url") is not None:
        _require_text(advisory.get("url"), "url", where)

    origin = advisory.get("source")
    if origin is not None and (
        isinstance(origin, bool) or not isinstance(origin, int) or origin < 0
    ):
        raise AuditUnusable(
            f"{where}.source must be a non-negative integer advisory id, "
            f"got {origin!r}"
        )

    if not advisory_identity(advisory):
        raise AuditUnusable(
            f"{where} carries neither a usable url nor a source, so the advisory "
            "cannot be identified and no exception could ever be matched to it"
        )


def _via_reaches_advisory(start: str, vulns: dict) -> tuple[bool, set[str]]:
    """Walk the via graph from `start`; report whether it reaches an advisory.

    The visited set makes the walk cycle-safe and doubles as the diagnostic:
    when nothing is reachable it names exactly which nodes were consulted.
    """
    seen: set[str] = set()
    stack = [start]
    while stack:
        package = stack.pop()
        if package in seen:
            continue
        seen.add(package)
        for item in vulns[package].get("via") or []:
            if isinstance(item, dict):
                return True, seen
            if isinstance(item, str):
                stack.append(item)
    return False, seen


def validate_advisory_graph(vulns: dict, source: str) -> None:
    """Every declared vulnerability must reach a real advisory object.

    npm states causation two ways inside `via`: an advisory object is direct
    evidence, and a bare string names another vulnerable package node that makes
    this one vulnerable. The gate's verdict is computed only from advisory
    objects, so a node whose via graph never reaches one declares a
    vulnerability that nothing downstream can see, count or block — it flattens
    away and the scope reads as clean.

    Three shapes are rejected: an empty `via`, an edge naming a package the
    report does not contain (the report is missing its own cause), and a cycle
    that never terminates in evidence.
    """
    for package, node in vulns.items():
        for index, item in enumerate(node.get("via") or []):
            if isinstance(item, str) and item not in vulns:
                raise AuditUnusable(
                    f"{source}: vulnerabilities[{package!r}].via[{index}] names "
                    f"{item!r}, which is not a vulnerable package node in this "
                    "report; the advisory graph is incomplete"
                )

    for package, node in vulns.items():
        reached, visited = _via_reaches_advisory(package, vulns)
        if reached:
            continue
        others = sorted(visited - {package})
        if not node.get("via"):
            detail = "it declares no via entries at all"
        elif others:
            detail = "its via graph only reaches " + ", ".join(repr(o) for o in others)
        else:
            detail = "its via graph only refers back to itself"
        raise AuditUnusable(
            f"{source}: vulnerabilities[{package!r}] declares severity "
            f"{node.get('severity')!r} but no advisory object is reachable from "
            f"it ({detail}); a declared vulnerability carrying no advisory "
            "flattens to zero rows and would be reported as a clean scope"
        )


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
    instances: dict[str, str], name: str, node_paths: object
) -> dict[str, str]:
    """Versions of the instances the advisory actually points at.

    npm reports vulnerable instances in `nodes` as lockfile-style paths. Partial
    resolution is refused: if npm names instances, EVERY one must resolve to an
    instance of the expected package in the lockfile. Dropping the ones that do
    not resolve would quietly shrink the evidence — and could leave a single
    surviving path whose version happens to match an exception.

    Only when npm supplies no paths at all does this fall back to considering
    every installed instance of the package, which is the conservative choice.
    """
    if node_paths is None:
        node_paths = []
    if not isinstance(node_paths, list) or not all(
        isinstance(p, str) and p.strip() for p in node_paths
    ):
        raise AuditUnusable(
            f"{name}: vulnerable 'nodes' must be a list of non-empty strings, "
            f"got {node_paths!r}"
        )

    if not node_paths:
        return versions_for_package(instances, name)

    resolved: dict[str, str] = {}
    unresolved: list[str] = []
    wrong_package: list[str] = []
    for path in node_paths:
        if path not in instances:
            unresolved.append(path)
        elif package_name_for(path) != name:
            wrong_package.append(f"{path} -> {package_name_for(path)}")
        else:
            resolved[path] = instances[path]

    if unresolved or wrong_package:
        problems = []
        if unresolved:
            problems.append(f"not found in package-lock.json: {sorted(unresolved)}")
        if wrong_package:
            problems.append(f"resolve to another package: {sorted(wrong_package)}")
        raise AuditUnusable(
            f"{name}: npm reported vulnerable instances that cannot be verified "
            "against the lockfile (" + "; ".join(problems) + ")"
        )
    return resolved


def advisories(report: dict, source: str = "audit report") -> list[dict]:
    """Flatten an npm audit report into one row per (package, advisory).

    The closing invariant lives here rather than in validation: whatever path a
    report took to get this far, a summary that declares vulnerable packages can
    never be turned into an empty advisory list. Zero rows is the one result the
    gate cannot distinguish from a clean tree, so it has to be earned.
    """
    rows: list[dict] = []
    for name, node in (report.get("vulnerabilities") or {}).items():
        if not isinstance(node, dict):
            continue
        for via in node.get("via") or []:
            if not isinstance(via, dict):
                continue  # a string `via` is an indirect edge, not an advisory
            rows.append(
                {
                    "package": name,
                    "advisory_package": via.get("name") or name,
                    "id": advisory_identity(via),
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

    counts = (report.get("metadata") or {}).get("vulnerabilities") or {}
    declared = counts.get("total")
    if isinstance(declared, int) and not isinstance(declared, bool):
        if declared > 0 and not rows:
            raise AuditUnusable(
                f"{source}: metadata declares {declared} vulnerable package "
                "node(s) but the report flattens to zero advisories; a declared "
                "vulnerability that produces no advisory row would be reported "
                "as a clean scope"
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


def _group_by_identity(rows: list[dict]) -> dict[tuple, dict]:
    """Group rows by security identity, unioning their vulnerable paths.

    npm can list the same advisory more than once for a package. Keying a plain
    dict by identity would let the last row overwrite the earlier one and drop
    its paths, so paths are accumulated instead of replaced.
    """
    grouped: dict[tuple, dict] = {}
    for row in rows:
        identity = security_identity(row)
        bucket = grouped.get(identity)
        if bucket is None:
            grouped[identity] = {**row, "paths": list(dict.fromkeys(row["paths"]))}
        else:
            merged = list(dict.fromkeys([*bucket["paths"], *row["paths"]]))
            bucket["paths"] = merged
    return grouped


def development_only(full_rows: list[dict], production_rows: list[dict]) -> list[dict]:
    """Full-tree rows not already accounted for by the production tree.

    The full tree is `npm audit` over every dependency; the production tree is
    the same audit with `--omit=dev`. The full tree must therefore be a superset
    of production. That invariant is checked in BOTH directions, because a
    one-way scan can only find extra dev findings — it cannot notice that a
    production finding went missing, which would mean the two runs did not
    describe the same dependency graph.

    Cases:
      * identity in both, identical paths -> covered by the production gate,
        subtract;
      * identity in both, full has extra paths -> those instances are dev-only,
        retain the row narrowed to them;
      * identity only in full -> genuinely dev-only, retain;
      * identity only in production, or a production path missing from full ->
        the superset invariant is broken: fail closed;
      * same (id, package) with different security fields -> the reports
        disagree about the advisory itself: fail closed.
    """
    prod_by_identity = _group_by_identity(production_rows)
    full_by_identity = _group_by_identity(full_rows)

    prod_by_key: dict[tuple, list[dict]] = {}
    for identity, row in prod_by_identity.items():
        prod_by_key.setdefault((row["id"], row["advisory_package"]), []).append(row)

    full_by_key: dict[tuple, list[dict]] = {}
    for identity, row in full_by_identity.items():
        full_by_key.setdefault((row["id"], row["advisory_package"]), []).append(row)

    # Direction 1: everything production saw must still be present in full.
    for identity, prod_row in prod_by_identity.items():
        full_row = full_by_identity.get(identity)
        if full_row is None:
            # Prefer the specific diagnosis: if the same advisory is present in
            # full but with different security facts, the reports disagree —
            # that is more informative than "it is missing".
            counterpart = full_by_key.get(
                (prod_row["id"], prod_row["advisory_package"])
            )
            if counterpart:
                other = counterpart[0]
                differences = [
                    f"{field}: production={prod_row[field]!r} full={other[field]!r}"
                    for field in SECURITY_IDENTITY_FIELDS
                    if prod_row[field] != other[field]
                ]
                raise AuditUnusable(
                    "production and full audit reports disagree about "
                    f"{prod_row['id']} ({prod_row['advisory_package']}): "
                    + "; ".join(differences)
                    + ". Refusing to subtract one from the other."
                )
            raise AuditUnusable(
                "production audit reported "
                f"{prod_row['id']} ({prod_row['advisory_package']}, "
                f"severity={prod_row['severity']}) but the full audit did not; "
                "the full tree must be a superset of the production tree"
            )
        missing_paths = [
            p for p in prod_row["paths"] if p not in set(full_row["paths"])
        ]
        if missing_paths:
            raise AuditUnusable(
                f"production audit reported vulnerable instances for "
                f"{prod_row['id']} ({prod_row['advisory_package']}) that the full "
                f"audit did not: {sorted(missing_paths)}"
            )

    # Direction 2: what the full tree adds is a development finding.
    remaining: list[dict] = []
    for identity, row in full_by_identity.items():
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
            remaining.append({**row, "paths": extra_paths, "dev_only_instances": True})
    return remaining


# ── policy loading ───────────────────────────────────────────────────────────

# Fields decide() reads without guarding. An entry missing one of them used to
# surface as a KeyError or ValueError traceback and exit 1 — the same exit code
# as "policy violation", making a broken policy file look like a blocked build.
EXCEPTION_REQUIRED_TEXT = ("id", "package", "scope", "severity", "compensatingControl")


def validate_exception(where: str, entry: object) -> None:
    if not isinstance(entry, dict):
        raise AuditUnusable(f"{where} is not an object")
    for field in EXCEPTION_REQUIRED_TEXT:
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            raise AuditUnusable(
                f"{where}.{field} must be a non-empty string, got {value!r}"
            )
    expires = entry.get("expires")
    if not isinstance(expires, str):
        raise AuditUnusable(
            f"{where}.expires must be an ISO date string, got {expires!r}"
        )
    try:
        _dt.date.fromisoformat(expires)
    except ValueError as exc:
        raise AuditUnusable(
            f"{where}.expires is not an ISO date (YYYY-MM-DD): {expires!r}"
        ) from exc


def load_policy(path: pathlib.Path) -> dict:
    """Read the policy, or explain why it cannot be trusted."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AuditUnusable(f"{path}: policy file is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise AuditUnusable(f"{path}: policy file could not be read ({exc})") from exc

    if not isinstance(payload, dict):
        raise AuditUnusable(f"{path}: policy must be a JSON object")
    entries = payload.get("exceptions", [])
    if not isinstance(entries, list):
        raise AuditUnusable(f"{path}: policy 'exceptions' must be a list")
    for index, entry in enumerate(entries):
        validate_exception(f"{path}: exceptions[{index}]", entry)
    return payload


def parse_today(raw: str | None) -> _dt.date:
    if raw is None:
        return _dt.datetime.now(_dt.timezone.utc).date()
    try:
        return _dt.date.fromisoformat(raw)
    except ValueError as exc:
        raise AuditUnusable(
            f"--today must be an ISO date (YYYY-MM-DD), got {raw!r}"
        ) from exc


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
        # Loaded inside the fail-closed boundary: an unreadable policy or an
        # unparsable date is an operational failure (exit 2), not a verdict.
        policy = load_policy(policy_path)
        order = [
            s.lower()
            for s in policy.get(
                "severityOrder", ["low", "moderate", "high", "critical"]
            )
        ]
        threshold = str(policy.get("failOnSeverity", "moderate")).lower()
        today = parse_today(args.today)

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

        rows = advisories(evaluated, f"{args.scope} audit report")
        if args.scope == "development" and production is not None:
            rows = development_only(rows, advisories(production, "production tree"))

        if args.write:
            out = pathlib.Path(args.write)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(written, indent=2, sort_keys=True), encoding="utf-8"
            )

        return decide(rows, versions, policy, args.scope, order, threshold, today)
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


def decide(
    rows: list[dict],
    versions: dict[str, str],
    policy: dict,
    scope: str,
    order: list[str],
    threshold: str,
    today: _dt.date,
) -> int:
    """Print the per-advisory verdict and return the gate's exit code.

    Kept inside the caller's AuditUnusable boundary: evidence problems found
    while matching an exception (an unverifiable vulnerable instance, say) must
    fail closed with the same clean diagnostic, not surface as a traceback.
    """
    # Exceptions are indexed by (id, package) and only apply in their own scope,
    # so a policy entry can never approve a different package on a shared id.
    scoped = [
        e
        for e in policy.get("exceptions", [])
        if str(e.get("scope", "")).lower() == scope
    ]
    by_key = {(e["id"], e.get("package")): e for e in scoped}

    print(f"== npm audit gate :: scope={scope} threshold={threshold} ==")
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

        drift = mismatches(row, entry, scope, versions)
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
        print(f"\n  stale {scope} policy entries matching no observed advisory:")
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
