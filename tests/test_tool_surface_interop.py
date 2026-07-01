"""
Tests for the strict Interlock tool-surface interop projection.

This adapter is intentionally stricter than Interlock's internal runtime
receipt: internal receipts may surface heuristic signals at monitor severity,
but the composition/replay record only says `drifted` when evidence is verified,
complete, and not based solely on inferred metadata.

Run: python -m pytest tests/test_tool_surface_interop.py -q
"""

import json
import os
import sys

import pytest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "interlock-web" / "public" / "schemas" / "tool-surface-interop.v0.json"
)
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"

from core import tool_surface_interop  # noqa: E402

APPROVED_HASH = "sha256:" + "a" * 64
OBSERVED_HASH = "sha256:" + "b" * 64
SAME_HASH = APPROVED_HASH


def make_record(**overrides):
    fields = dict(
        action_id="action-001",
        run_id="run-001",
        approved_tool_surface_hash=APPROVED_HASH,
        observed_tool_surface_hash=OBSERVED_HASH,
        coverage="complete",
        evidence_verified=True,
        finding_types=["required_field_added"],
    )
    fields.update(overrides)
    return tool_surface_interop.build_tool_surface_record(**fields)


def test_verified_equal_hashes_emit_unchanged():
    record = make_record(
        observed_tool_surface_hash=SAME_HASH,
        finding_types=[],
    )

    assert record["profile"] == "interlock.tool-surface.v0"
    assert record["verdict"] == "unchanged"
    assert record["finding"] == ""
    assert record["evidence"] == {"evidence_verified": True}


def test_verified_declared_surface_drift_emits_drifted():
    record = make_record(finding_types=["required_field_added", "schema_field_added"])

    assert record["verdict"] == "drifted"
    assert record["finding"] == "required_field_added"
    assert record["finding_types"] == ["required_field_added", "schema_field_added"]


def test_unverified_evidence_stays_not_verifiable_even_when_hashes_differ():
    record = make_record(evidence_verified=False)

    assert record["verdict"] == "not_verifiable"
    assert record["finding"] == ""
    assert record["finding_types"] == []


def test_partial_coverage_stays_not_verifiable_even_when_hashes_differ():
    record = make_record(coverage="partial")

    assert record["verdict"] == "not_verifiable"
    assert record["finding"] == ""
    assert record["finding_types"] == []


def test_missing_surface_hash_stays_not_verifiable():
    record = make_record(approved_tool_surface_hash="")

    assert record["verdict"] == "not_verifiable"
    assert record["finding"] == ""
    assert record["finding_types"] == []


def test_inferred_only_metadata_finding_stays_not_verifiable_for_interop():
    record = make_record(
        finding_types=["effect_escalated", "side_effect_escalated"],
        inferred_fields=["effects", "side_effect"],
    )

    assert record["verdict"] == "not_verifiable"
    assert record["finding"] == ""
    assert record["finding_types"] == []


def test_inferred_metadata_does_not_hide_independent_schema_drift():
    record = make_record(
        finding_types=["effect_escalated", "required_field_added"],
        inferred_fields=["effects"],
    )

    assert record["verdict"] == "drifted"
    assert record["finding"] == "required_field_added"
    assert record["finding_types"] == ["required_field_added"]


def test_record_digest_is_recomputable_and_tamper_evident():
    record = make_record()
    digest = tool_surface_interop.compute_tool_surface_digest(record)

    result = tool_surface_interop.verify_tool_surface_record(record, digest)
    assert result["verified"] is True
    assert result["reason"] == "verified"

    tampered = dict(record)
    tampered["verdict"] = "unchanged"
    result = tool_surface_interop.verify_tool_surface_record(tampered, digest)
    assert result["verified"] is False
    assert result["reason"] == "digest_mismatch"


def test_projection_from_interlock_drift_record_uses_strict_verdict_rules():
    drift_record = {
        "approved_surface_hash": APPROVED_HASH,
        "current_surface_hash": OBSERVED_HASH,
        "finding_types": ["externality_escalated"],
    }

    record = tool_surface_interop.project_drift_record(
        drift_record,
        action_id="action-from-receipt",
        run_id="run-from-receipt",
        coverage="complete",
        evidence_verified=True,
        inferred_fields=["externality"],
    )

    assert record["action_id"] == "action-from-receipt"
    assert record["run_id"] == "run-from-receipt"
    assert record["approved_tool_surface_hash"] == APPROVED_HASH
    assert record["observed_tool_surface_hash"] == OBSERVED_HASH
    assert record["verdict"] == "not_verifiable"


jsonschema = pytest.importorskip("jsonschema")


def test_public_schema_matches_emitter_and_validates_records():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)

    assert schema["$id"] == tool_surface_interop.SCHEMA_URL
    assert schema["properties"]["profile"]["const"] == tool_surface_interop.PROFILE

    validator = jsonschema.Draft202012Validator(schema)
    jsonschema.Draft202012Validator.check_schema(schema)
    validator.validate(make_record())
    validator.validate(
        make_record(observed_tool_surface_hash=SAME_HASH, finding_types=[])
    )
    validator.validate(make_record(evidence_verified=False))


def test_public_schema_rejects_overclaimed_or_malformed_records():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    validator = jsonschema.Draft202012Validator(schema)

    record = make_record()
    record["verdict"] = "safe"
    assert not validator.is_valid(record)

    record = make_record()
    record["evidence"]["evidence_verified"] = "true"
    assert not validator.is_valid(record)

    record = make_record()
    record["approved_tool_surface_hash"] = "sha256:nothex"
    assert not validator.is_valid(record)
