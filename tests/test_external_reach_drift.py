"""Tests for destination-aware external reach drift.

Run: python3 -m pytest tests/test_external_reach_drift.py -q -s
"""

import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "interlock-web"
    / "public"
    / "schemas"
    / "external-reach-drift-record.v1.json"
)

from core.external_reach import (
    build_external_reach_drift_record,
    build_external_reach_profile,
    classify_external_reach_drift,
    compute_external_reach_drift_digest,
    external_reach_profile_hash,
)


def validate_schema(record):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = getattr(jsonschema, "Draft202012Validator", None)
    if validator is not None:
        validator.check_schema(schema)
        validator(schema).validate(record)
        return
    assert set(record) == set(schema["properties"])


def test_no_destination_profile_is_clean_and_contains_no_raw_values():
    profile = build_external_reach_profile({"query": "status report", "limit": 10})

    assert profile["external_destinations"] == []
    assert profile["internal_destinations"] == []
    assert profile["destination_kinds"] == []
    assert profile["profile_hash"].startswith("sha256:")
    assert "status report" not in json.dumps(profile)


def test_url_profile_records_public_host_not_full_url():
    profile = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/services/T000/B000/SECRET"}
    )

    assert "url_host:hooks.slack.com" in profile["external_destinations"]
    encoded = json.dumps(profile)
    assert "services/T000" not in encoded
    assert "SECRET" not in encoded


def test_email_profile_records_domain_not_local_part():
    profile = build_external_reach_profile(
        {"recipient_email": "alice@customer.example"}
    )

    assert "email_domain:customer.example" in profile["external_destinations"]
    encoded = json.dumps(profile)
    assert "alice@" not in encoded


def test_internal_loopback_destination_is_not_external_drift():
    baseline = build_external_reach_profile(
        {"webhook_url": "http://localhost:9000/hook"}
    )
    current = build_external_reach_profile(
        {"webhook_url": "http://127.0.0.1:9000/hook"}
    )

    decision = classify_external_reach_drift(baseline, current)

    assert decision["drift_detected"] is False
    assert decision["severity"] == "none"
    assert decision["action"] == "allow"


def test_same_external_destination_stays_clean_even_if_path_changes():
    baseline = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/services/T000/B000/one"}
    )
    current = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/services/T000/B000/two"}
    )

    decision = classify_external_reach_drift(baseline, current)

    assert decision["drift_detected"] is False
    assert decision["severity"] == "none"
    assert decision["action"] == "allow"


def test_new_external_url_after_internal_baseline_is_high_deny():
    baseline = build_external_reach_profile(
        {"webhook_url": "http://localhost:9000/hook"}
    )
    current = build_external_reach_profile({"webhook_url": "https://evil.example/hook"})

    decision = classify_external_reach_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "high"
    assert decision["action"] == "deny"
    assert "external_destination_added" in decision["types"]
    assert any("evil.example" in reason for reason in decision["reasons"])


def test_new_email_domain_after_approved_domain_is_high_deny():
    baseline = build_external_reach_profile(
        {"recipient_email": "alerts@company.example"}
    )
    current = build_external_reach_profile(
        {"recipient_email": "alerts@outside.example"}
    )

    decision = classify_external_reach_drift(baseline, current)

    assert decision["severity"] == "high"
    assert decision["action"] == "deny"
    assert "external_destination_added" in decision["types"]


def test_new_external_destination_with_secret_indicator_is_critical_quarantine():
    baseline = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/services/T000/B000/one"}
    )
    current = build_external_reach_profile(
        {
            "webhook_url": "https://evil.example/hook",
            "include_secrets": True,
        }
    )

    decision = classify_external_reach_drift(baseline, current)

    assert decision["severity"] == "critical"
    assert decision["action"] == "quarantine"
    assert "external_secret_destination_added" in decision["types"]


def test_channel_values_are_hashed_not_stored_raw():
    profile = build_external_reach_profile({"slack_channel": "#customer-escalations"})

    assert profile["hashed_destinations"]
    encoded = json.dumps(profile)
    assert "customer-escalations" not in encoded


def test_profile_hash_changes_only_on_material_destination_delta():
    baseline = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/a"}
    )
    same_host = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/b"}
    )
    new_host = build_external_reach_profile(
        {"webhook_url": "https://api.example.com/b"}
    )

    assert external_reach_profile_hash(baseline) == external_reach_profile_hash(
        same_host
    )
    assert external_reach_profile_hash(baseline) != external_reach_profile_hash(
        new_host
    )


def test_external_reach_record_is_schema_valid_and_no_raw_secret_path():
    baseline = build_external_reach_profile(
        {"webhook_url": "https://hooks.slack.com/a"}
    )
    current = build_external_reach_profile(
        {"webhook_url": "https://evil.example/secret/path"}
    )
    decision = classify_external_reach_drift(baseline, current)
    record = build_external_reach_drift_record(
        server_id="postfast",
        tool_name="publish_post",
        baseline_profile_hash=external_reach_profile_hash(baseline),
        current_profile_hash=external_reach_profile_hash(current),
        finding_types=decision["types"],
        severity=decision["severity"],
        decision=decision["action"],
    )

    validate_schema(record)
    assert record["record_type"] == "interlock.external-reach-drift-record"
    assert record["diff_classification"] == "external-reach"
    assert compute_external_reach_drift_digest(record).startswith("sha256:")
    assert "secret/path" not in json.dumps(record)
