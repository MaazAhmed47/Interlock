"""Tests for response/data-exposure drift profiling and evidence.

Run: python3 -m pytest tests/test_response_drift.py -q
"""

import json
import sys
from pathlib import Path

import pytest

try:
    import jsonschema
except ImportError:  # pragma: no cover - fallback for minimal envs
    jsonschema = None


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "interlock-web"
    / "public"
    / "schemas"
    / "response-drift-record.v1.json"
)

from core.response_drift import (
    build_response_drift_record,
    build_response_exposure_profile,
    classify_response_exposure_drift,
    compute_response_drift_digest,
    response_profile_hash,
)


def validate_against_response_drift_schema(record):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = getattr(jsonschema, "Draft202012Validator", None)
    if validator is not None:
        validator.check_schema(schema)
        validator(schema).validate(record)
        return

    assert set(record) == set(schema["properties"])
    assert record["record_type"] == "interlock.response-drift-record"
    assert record["schema_version"] == "1"
    assert record["diff_classification"] == "data-exposure"


def profile(payload):
    return build_response_exposure_profile(json.dumps(payload))


def test_clean_response_profile_has_no_sensitive_classes_or_raw_values():
    p = profile({"result": {"summary": "3 open tickets", "count": 3}})

    assert p["sensitive_classes"] == []
    assert p["redaction_labels"] == []
    assert p["byte_count"] > 0
    assert p["content_digest"].startswith("sha256:")
    encoded = json.dumps(p)
    assert "3 open tickets" not in encoded
    assert "summary" in p["field_names"]


def test_same_profile_stays_clean():
    baseline = profile({"result": {"summary": "3 open tickets", "count": 3}})
    current = profile({"result": {"summary": "5 open tickets", "count": 5}})

    decision = classify_response_exposure_drift(baseline, current)

    assert decision["drift_detected"] is False
    assert decision["severity"] == "none"
    assert decision["action"] == "allow"
    assert decision["types"] == []


def test_response_starts_returning_pii_is_high_data_exposure_drift():
    baseline = profile({"result": {"summary": "3 open tickets", "count": 3}})
    current = profile(
        {
            "result": [
                {
                    "customer": "A",
                    "email": "person@example.com",
                    "phone": "555-123-4567",
                }
            ]
        }
    )

    decision = classify_response_exposure_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "high"
    assert decision["action"] == "deny"
    assert "response_data_class_added" in decision["types"]
    assert any("pii.email" in reason for reason in decision["reasons"])


def test_response_starts_returning_secret_is_critical_data_exposure_drift():
    baseline = profile({"result": {"summary": "build ok"}})
    current = profile({"result": {"api_key": "sk-live-abc123xyz", "status": "ok"}})

    decision = classify_response_exposure_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "critical"
    assert decision["action"] == "quarantine"
    assert "response_secret_added" in decision["types"]


def test_response_volume_expansion_is_moderate_drift_not_quarantine():
    baseline = profile({"result": [{"id": 1, "title": "one"}]})
    current = profile(
        {"result": [{"id": i, "title": f"ticket-{i}"} for i in range(650)]}
    )

    decision = classify_response_exposure_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "moderate"
    assert decision["action"] == "monitor"
    assert "response_volume_expanded" in decision["types"]


def test_removed_sensitive_class_does_not_count_as_expansion():
    baseline = profile({"result": {"email": "person@example.com"}})
    current = profile({"result": {"summary": "no customer contact details"}})

    decision = classify_response_exposure_drift(baseline, current)

    assert decision["drift_detected"] is False
    assert decision["severity"] == "none"
    assert decision["action"] == "allow"


def test_response_profile_hash_is_stable_and_changes_on_material_profile_delta():
    first = profile({"result": {"summary": "a", "count": 1}})
    equivalent = profile({"result": {"summary": "b", "count": 2}})
    drifted = profile({"result": {"email": "person@example.com"}})

    assert response_profile_hash(first) == response_profile_hash(equivalent)
    assert response_profile_hash(first) != response_profile_hash(drifted)


def test_response_drift_record_is_digestible_and_contains_no_raw_response():
    baseline = profile({"result": {"summary": "safe summary"}})
    current = profile({"result": {"email": "person@example.com"}})
    decision = classify_response_exposure_drift(baseline, current)

    record = build_response_drift_record(
        server_id="crm",
        tool_name="search_contacts",
        baseline_profile_hash=response_profile_hash(baseline),
        current_profile_hash=response_profile_hash(current),
        finding_types=decision["types"],
        severity=decision["severity"],
        decision=decision["action"],
    )

    assert record["record_type"] == "interlock.response-drift-record"
    assert record["diff_classification"] == "data-exposure"
    assert record["severity"] == "high"
    assert record["decision"] == "deny"
    validate_against_response_drift_schema(record)
    assert compute_response_drift_digest(record).startswith("sha256:")
    assert "person@example.com" not in json.dumps(record)


def test_placeholder_example_email_is_not_treated_as_live_pii():
    p = profile({"result": {"docs": "Use user@example.com in examples."}})

    assert "pii.email" not in p["sensitive_classes"]
