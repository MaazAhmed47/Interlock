#!/usr/bin/env python3
"""Local proof for response/data-exposure drift.

No network, no credentials, no real customer data. Demonstrates a response
profile baseline and three drift severities with evidence-safe records.
"""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.response_drift import (
    build_response_drift_record,
    build_response_exposure_profile,
    classify_response_exposure_drift,
    compute_response_drift_digest,
    response_profile_hash,
)


def profile(payload):
    return build_response_exposure_profile(json.dumps(payload))


def assert_case(
    name, baseline_payload, current_payload, expected_severity, expected_action
):
    baseline = profile(baseline_payload)
    current = profile(current_payload)
    decision = classify_response_exposure_drift(baseline, current)
    record = build_response_drift_record(
        server_id="response-demo",
        tool_name="search_contacts",
        baseline_profile_hash=response_profile_hash(baseline),
        current_profile_hash=response_profile_hash(current),
        finding_types=decision["types"],
        severity=decision["severity"],
        decision=decision["action"],
    )
    digest = compute_response_drift_digest(record)

    ok = (
        decision["severity"] == expected_severity
        and decision["action"] == expected_action
    )
    if not ok:
        raise AssertionError(
            f"{name}: expected {expected_severity}/{expected_action}, "
            f"got {decision['severity']}/{decision['action']}"
        )

    encoded_record = json.dumps(record)
    for forbidden in ("person@example.com", "sk-live-response-demo", "safe summary"):
        if forbidden in encoded_record:
            raise AssertionError(
                f"{name}: raw response value leaked into evidence record"
            )

    print(
        f"PASS {name}: severity={decision['severity']} action={decision['action']} "
        f"types={decision['types']} digest={digest}"
    )


def main():
    clean_summary = {"result": {"summary": "safe summary", "count": 3}}

    assert_case(
        "clean-summary-value-churn",
        clean_summary,
        {"result": {"summary": "different safe summary", "count": 5}},
        "none",
        "allow",
    )
    assert_case(
        "pii-added",
        clean_summary,
        {"result": [{"customer_id": "cust_1", "email": "person@example.com"}]},
        "high",
        "deny",
    )
    assert_case(
        "secret-added",
        clean_summary,
        {"result": {"api_key": "sk-live-response-demo", "status": "ok"}},
        "critical",
        "quarantine",
    )
    assert_case(
        "volume-expanded",
        {"result": [{"id": 1}]},
        {"result": [{"id": i} for i in range(650)]},
        "moderate",
        "monitor",
    )
    assert_case(
        "sensitive-removed-control",
        {"result": {"email": "person@example.com"}},
        clean_summary,
        "none",
        "allow",
    )


if __name__ == "__main__":
    main()
