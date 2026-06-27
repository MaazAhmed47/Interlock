#!/usr/bin/env python3
"""Local proof for destination-aware external reach drift.

This does not call a real MCP server. It exercises the same profile, classifier,
and evidence record code used by the gateway, with controls for clean and
internally scoped changes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.external_reach import (
    build_external_reach_drift_record,
    build_external_reach_profile,
    classify_external_reach_drift,
    compute_external_reach_drift_digest,
    external_reach_profile_hash,
)


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    print(f"{status} {name}{(': ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(1)


def main() -> None:
    approved = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/services/T/B/one"}
    )
    same_host = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/services/T/B/two"}
    )
    new_host = build_external_reach_profile(
        {"webhook_url": "https://evil.example/collect/secret"}
    )
    secret_host = build_external_reach_profile(
        {"webhook_url": "https://evil.example/collect", "include_secrets": True}
    )
    internal_a = build_external_reach_profile(
        {"webhook_url": "http://api.internal/hook"}
    )
    internal_b = build_external_reach_profile(
        {"webhook_url": "http://db.internal/hook"}
    )

    clean = classify_external_reach_drift(approved, same_host)
    check("same approved host stays clean", not clean["drift_detected"])

    high = classify_external_reach_drift(approved, new_host)
    check(
        "new external host denies",
        high["severity"] == "high" and high["action"] == "deny",
        json.dumps(high["types"]),
    )

    critical = classify_external_reach_drift(approved, secret_host)
    check(
        "new external host plus secret indicator quarantines",
        critical["severity"] == "critical" and critical["action"] == "quarantine",
        json.dumps(critical["types"]),
    )

    internal = classify_external_reach_drift(internal_a, internal_b)
    check(
        "internal-only destination change does not flag", not internal["drift_detected"]
    )

    record = build_external_reach_drift_record(
        server_id="demo-server",
        tool_name="publish_report",
        baseline_profile_hash=external_reach_profile_hash(approved),
        current_profile_hash=external_reach_profile_hash(new_host),
        finding_types=high["types"],
        severity=high["severity"],
        decision=high["action"],
    )
    digest = compute_external_reach_drift_digest(record)
    blob = json.dumps(record, sort_keys=True)
    check("receipt digest is sha256", digest.startswith("sha256:"), digest)
    check("record stores hashes, not raw URL path", "collect/secret" not in blob)


if __name__ == "__main__":
    main()
