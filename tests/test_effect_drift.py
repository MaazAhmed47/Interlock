"""Tests for outcome/effect drift profiling and evidence.

Run: python3 -m pytest tests/test_effect_drift.py -q -s
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
    / "effect-drift-record.v1.json"
)

from core.effect_drift import (
    build_effect_drift_record,
    build_effect_profile,
    classify_effect_drift,
    compute_effect_drift_digest,
    effect_profile_hash,
)


def validate_against_effect_drift_schema(record):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = getattr(jsonschema, "Draft202012Validator", None)
    if validator is not None:
        validator.check_schema(schema)
        validator(schema).validate(record)
        return

    assert set(schema["required"]).issubset(record)
    assert record["record_type"] == "interlock.effect-drift-record"
    assert record["schema_version"] == "1"
    assert record["diff_classification"] == "effect"


def profile(payload):
    return build_effect_profile(payload)


def test_dry_run_profile_is_evidence_safe_and_no_effect():
    p = profile(
        {
            "result": {
                "dry_run": True,
                "would_change": 2,
                "resource_id": "prod-vpc-secret-123",
            }
        }
    )

    assert "dry_run" in p["effect_classes"]
    assert "preview" in p["effect_classes"]
    assert p["effect_rank"] <= 1
    assert p["profile_hash"].startswith("sha256:")
    assert "prod-vpc-secret-123" not in json.dumps(p)


def test_same_dry_run_profile_stays_clean_with_value_changes():
    baseline = profile({"result": {"dry_run": True, "would_change": 2}})
    current = profile({"result": {"dry_run": True, "would_change": 5}})

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is False
    assert decision["severity"] == "none"
    assert decision["action"] == "allow"
    assert decision["types"] == []


def test_dry_run_to_applied_mutation_quarantines_future_use():
    baseline = profile({"result": {"dry_run": True, "would_change": 2}})
    current = profile({"result": {"applied": True, "updated": 2}})

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "high"
    assert decision["action"] == "quarantine"
    assert "effect_mutation_after_preview" in decision["types"]


def test_preview_to_external_send_is_critical_effect_drift():
    baseline = profile({"result": {"preview": True, "would_send": True}})
    current = profile({"result": {"sent": True, "message_id": "msg-secret-123"}})

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "critical"
    assert decision["action"] == "quarantine"
    assert "effect_external_send_after_preview" in decision["types"]


def test_plan_to_delete_deploy_or_money_movement_is_critical():
    baseline = profile({"result": {"plan": True, "changes": 3}})
    current = profile(
        {
            "result": {
                "deleted": True,
                "deployed": True,
                "charged_amount": 1000,
                "transaction_id": "txn-secret-123",
            }
        }
    )

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "critical"
    assert decision["action"] == "quarantine"
    assert "effect_destructive_after_preview" in decision["types"]
    assert "effect_money_movement_after_preview" in decision["types"]


def test_preview_to_scheduled_send_is_temporal_critical():
    baseline = profile({"result": {"preview": True, "would_send": True}})
    current = profile(
        {
            "result": {
                "scheduled": True,
                "send_at": "2026-07-01T12:00:00Z",
                "message_id": "msg-secret-123",
            }
        }
    )

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "critical"
    assert decision["action"] == "quarantine"
    assert "scheduled" in current["effect_classes"]
    assert "sent" in current["effect_classes"]
    assert "effect_temporal_external_after_preview" in decision["types"]
    assert "msg-secret-123" not in json.dumps(decision)


def test_plan_to_scheduled_delete_deploy_execute_and_money_are_temporal_critical():
    baseline = profile({"result": {"plan": True, "changes": 3}})
    current = profile(
        {
            "result": {
                "scheduled_for": "2026-07-02T08:30:00Z",
                "delete_at": "2026-07-02T08:30:00Z",
                "deploy_at": "2026-07-02T08:30:00Z",
                "execute_at": "2026-07-02T08:30:00Z",
                "charge_at": "2026-07-02T08:30:00Z",
                "resource_id": "prod-secret-123",
            }
        }
    )

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "critical"
    assert decision["action"] == "quarantine"
    assert "effect_temporal_destructive_after_preview" in decision["types"]
    assert "effect_temporal_deploy_after_preview" in decision["types"]
    assert "effect_temporal_execution_after_preview" in decision["types"]
    assert "effect_temporal_money_movement_after_preview" in decision["types"]
    assert "prod-secret-123" not in json.dumps(decision)


def test_preview_to_scheduled_unknown_future_action_is_high():
    baseline = profile({"result": {"dry_run": True}})
    current = profile(
        {
            "result": {
                "scheduled_for": "2026-07-03T10:00:00Z",
                "job_id": "job-secret-123",
            }
        }
    )

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "high"
    assert decision["action"] == "quarantine"
    assert "effect_temporal_action_after_preview" in decision["types"]
    assert "job-secret-123" not in json.dumps(decision)


def test_expected_mutating_tool_observing_no_effect_is_regression_monitor_only():
    baseline = profile({"result": {"applied": True, "updated": 2}})
    current = profile({"result": {"dry_run": True, "would_change": 2}})

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "moderate"
    assert decision["action"] == "monitor"
    assert "effect_regression" in decision["types"]


def test_unknown_or_inconclusive_effect_does_not_false_positive():
    baseline = profile({"result": {"dry_run": True}})
    current = profile(
        {"result": {"status": "unknown", "message": "upstream did not report effect"}}
    )

    decision = classify_effect_drift(baseline, current)

    assert decision["drift_detected"] is False
    assert decision["severity"] == "none"
    assert decision["action"] == "allow"


def test_effect_profile_hash_tracks_material_effect_not_raw_values():
    first = profile({"result": {"dry_run": True, "resource_id": "a-secret"}})
    equivalent = profile({"result": {"dry_run": True, "resource_id": "b-secret"}})
    drifted = profile({"result": {"applied": True, "resource_id": "b-secret"}})

    assert effect_profile_hash(first) == effect_profile_hash(equivalent)
    assert effect_profile_hash(first) != effect_profile_hash(drifted)


def test_effect_drift_record_is_schema_valid_and_contains_no_raw_observation():
    baseline = profile(
        {"result": {"dry_run": True, "resource_id": "prod-vpc-secret-123"}}
    )
    current = profile(
        {"result": {"deleted": True, "resource_id": "prod-vpc-secret-123"}}
    )
    decision = classify_effect_drift(baseline, current)

    record = build_effect_drift_record(
        server_id="terraform",
        tool_name="plan",
        baseline_profile_hash=effect_profile_hash(baseline),
        current_profile_hash=effect_profile_hash(current),
        finding_types=decision["types"],
        severity=decision["severity"],
        decision=decision["action"],
    )

    assert record["record_type"] == "interlock.effect-drift-record"
    assert record["diff_classification"] == "effect"
    assert record["severity"] == "critical"
    assert record["decision"] == "quarantine"
    validate_against_effect_drift_schema(record)
    assert compute_effect_drift_digest(record).startswith("sha256:")
    assert "prod-vpc-secret-123" not in json.dumps(record)
