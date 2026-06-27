"""Tests for provider readback / canary effect observation.

Run: python3 -m pytest tests/test_effect_readback.py -q
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

try:
    import jsonschema
except ImportError:  # pragma: no cover - fallback for minimal envs
    jsonschema = None

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.db as db
from core import receipt as receipt_builder

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "interlock-web"
    / "public"
    / "schemas"
    / "readback-effect-drift-record.v1.json"
)

from core.effect_readback import (
    build_readback_state_profile,
    classify_readback_effect_drift,
    compute_readback_effect_drift_digest,
)


def validate_against_readback_schema(record):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = getattr(jsonschema, "Draft202012Validator", None)
    if validator is not None:
        validator.check_schema(schema)
        validator(schema).validate(record)
        return

    assert set(schema["required"]).issubset(record)
    assert record["record_type"] == "interlock.readback-effect-drift-record"
    assert record["schema_version"] == "1"
    assert record["diff_classification"] == "effect"


def test_state_profile_hashes_raw_values_without_storing_them():
    profile = build_readback_state_profile(
        {
            "object_id": "secret-customer-123",
            "version": 1,
            "status": "draft",
            "nested": {"email": "person@example.com"},
        }
    )

    encoded = json.dumps(profile, sort_keys=True)
    assert profile["state_hash"].startswith("sha256:")
    assert profile["profile_hash"].startswith("sha256:")
    assert "secret-customer-123" not in encoded
    assert "person@example.com" not in encoded
    assert "object_id" in profile["field_names"]
    assert "nested.email" in profile["field_paths"]


def test_no_change_expected_with_same_readback_is_clean():
    before = build_readback_state_profile({"version": 1, "status": "draft"})
    after = build_readback_state_profile({"version": 1, "status": "draft"})
    target = {"dry_run": True, "would_update": 1}

    result = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response=target,
        expected_effect="no_change",
    )

    assert result["drift_detected"] is False
    assert result["severity"] == "none"
    assert result["action"] == "allow"
    assert result["types"] == []


def test_no_change_expected_with_changed_readback_is_silent_side_effect_drift():
    before = build_readback_state_profile({"version": 1, "status": "draft"})
    after = build_readback_state_profile({"version": 2, "status": "sent"})
    target = {"dry_run": True, "would_send": 1, "message_id": "secret-msg-123"}

    result = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response=target,
        expected_effect="no_change",
    )

    assert result["drift_detected"] is True
    assert result["severity"] == "critical"
    assert result["action"] == "quarantine"
    assert "readback_state_changed_after_no_effect_expected" in result["types"]
    assert "silent_side_effect_drift" in result["types"]
    assert "effect_response_contradicted_by_readback" in result["types"]
    assert result["before_state_hash"] != result["after_state_hash"]
    assert "secret-msg-123" not in json.dumps(result)


def test_expected_change_missing_monitors_instead_of_quarantining():
    before = build_readback_state_profile({"version": 1, "status": "draft"})
    after = build_readback_state_profile({"version": 1, "status": "draft"})
    target = {"sent": True}

    result = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response=target,
        expected_effect="change_allowed",
    )

    assert result["drift_detected"] is True
    assert result["severity"] == "moderate"
    assert result["action"] == "monitor"
    assert result["types"] == ["expected_provider_change_missing"]


def test_inconclusive_readback_does_not_false_positive():
    before = build_readback_state_profile({"version": 1, "status": "draft"})
    target = {"dry_run": True}

    result = classify_readback_effect_drift(
        before_profile=before,
        after_profile=None,
        target_response=target,
        expected_effect="no_change",
    )

    assert result["drift_detected"] is False
    assert result["severity"] == "none"
    assert result["action"] == "monitor"
    assert result["types"] == []
    assert "inconclusive" in result["reason"].lower()


def test_readback_receipt_uses_hashes_not_raw_provider_state():
    tmp_db = tempfile.mktemp(suffix="_readback_receipt_test.db")
    db.DB_PATH = tmp_db
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(tmp_db + suffix)
        except OSError:
            pass
    db.init_db()
    try:
        before = build_readback_state_profile({"version": 1, "token": "secret-before"})
        after = build_readback_state_profile({"version": 2, "token": "secret-after"})
        result = classify_readback_effect_drift(
            before_profile=before,
            after_profile=after,
            target_response={"dry_run": True},
            expected_effect="no_change",
        )
        row = db.log_mcp_audit_event(
            {
                "server_id": "readback-server",
                "tool_name": "preview_send",
                "role": "operator",
                "action": result["action"],
                "matched_rule": "effect_readback_observer",
                "reason": result["reason"],
                "verification_level": "manual_provider_readback",
                "argument_keys": [],
                "blocked_by": "effect_readback_observer",
                "probe_id": "readback-proof-1",
                "argument_hash": "sha256:" + "a" * 64,
                "drift_status": "readback_effect_drift",
                "drift_severity": result["severity"],
                "drift_action": result["action"],
                "drift_types": result["types"],
                "drift_reasons": result["reasons"],
                "drift_baseline_hash": result["before_state_hash"],
                "drift_current_hash": result["after_state_hash"],
            }
        )

        receipt = receipt_builder.build_receipt(row, chain_verified=True)
        evidence = receipt["drift_evidence"]
        encoded = json.dumps(evidence, sort_keys=True)

        assert (
            evidence["record"]["record_type"]
            == "interlock.readback-effect-drift-record"
        )
        assert evidence["record"]["diff_classification"] == "effect"
        assert evidence["evidence_ref"]["type"] == "readback-effect-drift"
        assert compute_readback_effect_drift_digest(evidence["record"]).startswith(
            "sha256:"
        )
        assert "secret-before" not in encoded
        assert "secret-after" not in encoded
    finally:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass
