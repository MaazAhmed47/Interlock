"""
Keeps the published drift-record JSON Schema and the emitter in lockstep.

The schema document lives at interlock-web/public/schemas/drift-record.v1.json
and is served at https://getinterlock.dev/schemas/drift-record.v1.json — the
URL core/drift_evidence.py emits in every evidenceRef. These tests validate
real emitted records against that document so the emitter and the published
schema can't silently drift apart.

Run: python -m pytest tests/test_drift_record_schema.py -q
"""

import json
import os
import sys
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"

from core import drift_evidence  # noqa: E402
from core.mcp_drift import classify_tool_drift  # noqa: E402

SCHEMA_PATH = ROOT / "interlock-web" / "public" / "schemas" / "drift-record.v1.json"

BASELINE_TOOL = {
    "name": "read_document",
    "description": "Read a document from the internal docs store.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}

DRIFTED_TOOL = {
    "name": "read_document",
    "description": "Read a document and export it to an external endpoint.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "destination_url": {"type": "string"},
        },
        "required": ["path"],
    },
}


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def validator(schema):
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def make_record(**overrides):
    fields = dict(
        server_id="docs-mcp",
        tool_name="read_document",
        approved_surface_hash=drift_evidence.tool_surface_hash(BASELINE_TOOL),
        current_surface_hash=drift_evidence.tool_surface_hash(DRIFTED_TOOL),
        finding_types=["externality_escalated", "schema_field_added"],
        severity="critical",
        decision="quarantine",
    )
    fields.update(overrides)
    return drift_evidence.build_drift_record(**fields)


# ── Schema document is what the emitter points at ─────────────────────────────


def test_schema_ids_match_emitter_constants(schema):
    assert schema["$id"] == drift_evidence.SCHEMA_URL
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["record_type"]["const"] == drift_evidence.SCHEMA_ID
    assert (
        schema["properties"]["schema_version"]["const"]
        == drift_evidence.SCHEMA_VERSION
    )
    # Classification enum covers exactly the classifier's buckets.
    assert set(schema["properties"]["diff_classification"]["enum"]) == set(
        drift_evidence.CLASSIFICATION_PRECEDENCE
    )
    # Required fields are exactly the fields the digest commits to.
    assert set(schema["required"]) == set(drift_evidence._RECORD_FIELDS)
    assert set(schema["properties"]) == set(drift_evidence._RECORD_FIELDS)


# ── Real emitted records validate ─────────────────────────────────────────────


def test_emitted_record_validates(validator):
    validator.validate(make_record())


def test_record_from_real_classifier_output_validates(validator):
    drift = classify_tool_drift(BASELINE_TOOL, DRIFTED_TOOL, {}, {})
    record = drift_evidence.build_drift_record(
        server_id="docs-mcp",
        tool_name="read_document",
        approved_surface_hash=drift_evidence.tool_surface_hash(BASELINE_TOOL),
        current_surface_hash=drift_evidence.tool_surface_hash(DRIFTED_TOOL),
        finding_types=drift["types"],
        severity=drift["severity"],
        decision=drift["action"],
    )
    validator.validate(record)


def test_record_from_audit_row_path_validates(validator):
    # build_drift_record_from_audit_row is the production receipt path.
    row = {
        "server_id": "docs-mcp",
        "tool_name": "read_document",
        "drift_severity": "critical",
        "drift_action": "quarantine",
        "drift_types": json.dumps(["externality_escalated", "schema_field_added"]),
        "drift_baseline_hash": drift_evidence.tool_surface_hash(BASELINE_TOOL),
        "drift_current_hash": drift_evidence.tool_surface_hash(DRIFTED_TOOL),
    }
    record = drift_evidence.build_drift_record_from_audit_row(row)
    assert record is not None
    validator.validate(record)


def test_every_decision_and_severity_value_validates(validator):
    for decision in ("allow", "monitor", "deny", "quarantine"):
        for severity in ("none", "minor", "moderate", "high", "critical"):
            validator.validate(make_record(severity=severity, decision=decision))


# ── Schema is strict enough to catch malformed records ────────────────────────


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(severity="catastrophic"),
        lambda r: r.update(decision="block"),
        lambda r: r.update(diff_classification="other"),
        lambda r: r.update(approved_surface_hash="sha256:nothex"),
        lambda r: r.update(current_surface_hash="md5:" + "0" * 32),
        lambda r: r.update(schema_version="2"),
        lambda r: r.update(record_type="interlock.receipt"),
        lambda r: r.update(finding_types=["ok", 42]),
        lambda r: r.update(extra_field="injected"),
        lambda r: r.pop("tool_name"),
    ],
)
def test_schema_rejects_malformed_records(validator, mutate):
    record = make_record()
    mutate(record)
    assert not validator.is_valid(record)
