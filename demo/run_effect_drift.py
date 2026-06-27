#!/usr/bin/env python3
"""Local proof for outcome/effect drift.

This exercises the same effect profile, classifier, and evidence record code used
by the gateway. It does not contact a real MCP server.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.effect_drift import (
    build_effect_drift_record,
    build_effect_profile,
    classify_effect_drift,
    compute_effect_drift_digest,
    effect_profile_hash,
)


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    print(f"{status} {name}{(': ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(1)


def main() -> None:
    dry_run = build_effect_profile({"result": {"dry_run": True, "would_change": 2}})
    dry_run_same = build_effect_profile(
        {"result": {"dry_run": True, "would_change": 7}}
    )
    applied = build_effect_profile({"result": {"applied": True, "updated": 2}})
    sent = build_effect_profile(
        {"result": {"sent": True, "message_id": "msg-secret-123"}}
    )
    deleted = build_effect_profile(
        {"result": {"deleted": True, "resource_id": "prod-secret"}}
    )
    unknown = build_effect_profile({"result": {"status": "unknown"}})

    clean = classify_effect_drift(dry_run, dry_run_same)
    check("same dry-run effect stays clean", not clean["drift_detected"])

    high = classify_effect_drift(dry_run, applied)
    check(
        "dry-run to applied mutation quarantines",
        high["severity"] == "high" and high["action"] == "quarantine",
        json.dumps(high["types"]),
    )

    critical_send = classify_effect_drift(dry_run, sent)
    check(
        "preview to external send is critical",
        critical_send["severity"] == "critical"
        and critical_send["action"] == "quarantine",
        json.dumps(critical_send["types"]),
    )

    critical_delete = classify_effect_drift(dry_run, deleted)
    check(
        "preview to delete is critical",
        critical_delete["severity"] == "critical"
        and critical_delete["action"] == "quarantine",
        json.dumps(critical_delete["types"]),
    )

    inconclusive = classify_effect_drift(dry_run, unknown)
    check("unknown effect does not false-positive", not inconclusive["drift_detected"])

    record = build_effect_drift_record(
        server_id="demo-server",
        tool_name="terraform_plan",
        baseline_profile_hash=effect_profile_hash(dry_run),
        current_profile_hash=effect_profile_hash(deleted),
        finding_types=critical_delete["types"],
        severity=critical_delete["severity"],
        decision=critical_delete["action"],
    )
    blob = json.dumps(record, sort_keys=True)
    digest = compute_effect_drift_digest(record)
    check("effect receipt digest is sha256", digest.startswith("sha256:"), digest)
    check(
        "effect record stores hashes, not raw resource ids", "prod-secret" not in blob
    )


if __name__ == "__main__":
    main()
