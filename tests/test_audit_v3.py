"""
Adversarial tests for v3 full-field audit hashing.

The security claim under test: a v3 row's integrity hash commits to EVERY
stored security-significant field of mcp_audit_log and admin_audit_log —
including nested JSON details, arrays, status codes, drift reasons, principal
identity, matched rule, blocked_by, and probe outcomes. Mutating any protected
database field must fail verification, closed.

Also pins the migration contract: v1 and v2 rows written under the historical
rules keep verifying unchanged next to v3 rows; legacy hashes are never
rewritten.

Run: python -m pytest tests/test_audit_v3.py -q
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_audit_v3_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    path = tempfile.mktemp(suffix="_audit_v3_test.db")
    db.DB_PATH = path
    db.init_db()
    yield
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def _log_rich_mcp_event(**overrides):
    event = {
        "server_id": "v3-server",
        "tool_name": "read_document",
        "principal_id": "lf-key-prefix",
        "role": "readonly_agent",
        "action": "quarantine",
        "matched_rule": "effective_permission_probe",
        "reason": "capability drift detected",
        "effects": ["read", "export"],
        "side_effect": "external",
        "data_classes": ["email"],
        "externality": "external",
        "verification_level": "verified",
        "confidence": 0.85,
        "warnings": ["pii detected"],
        "argument_keys": ["path", "recursive"],
        "blocked_by": "tool_quarantined",
        "probe_id": "probe-123",
        "argument_hash": "sha256:" + "a" * 64,
        "expected_outcome": "denied",
        "expected_status_code": 403,
        "observed_outcome": "allowed",
        "observed_status_code": 200,
        "observed_error_class": "PermissionError",
        "drift_status": "quarantined",
        "drift_severity": "critical",
        "drift_action": "quarantine",
        "drift_types": ["effect_escalated"],
        "drift_reasons": ["read-only tool gained export effect"],
        "drift_baseline_hash": "sha256:" + "b" * 64,
        "drift_current_hash": "sha256:" + "c" * 64,
        "scan_time_ms": 12.5,
    }
    event.update(overrides)
    return db.log_mcp_audit_event(event)


def _log_rich_admin_event(**overrides):
    event = {
        "actor_auth_type": "scoped_token",
        "actor_role": "operator",
        "actor_label": "ops-team",
        "actor_email": "ops@example.com",
        "actor_subject": "oidc-subject-1",
        "actor_token_prefix": "ia_abcdef",
        "action": "key_created",
        "target_type": "api_key",
        "target_id": "lf-target",
        "result": "success",
        "reason": "provisioning",
        "details": {"plan": "developer", "nested": {"scopes": ["mcp.call", 2]}},
    }
    event.update(overrides)
    return db.log_admin_audit_event(event)


def _set_column(table, column, value, row_id):
    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            f"UPDATE {table} SET {column} = ? WHERE id = ?",
            (value, row_id),
        )


def _get_column(table, column, row_id):
    with db.get_conn() as conn:
        row = conn.execute(
            f"SELECT {column} AS value FROM {table} WHERE id = ?", (row_id,)
        ).fetchone()
    return dict(row)["value"]


# ── new rows are v3 ───────────────────────────────────────────────────────────


def test_new_mcp_row_is_hash_v3_and_verifies():
    saved = _log_rich_mcp_event()
    row = db.get_mcp_audit_log(saved["id"])
    assert row["hash_v"] == 3
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert db.verify_audit_chain()["valid"] is True


def test_new_admin_row_is_hash_v3_and_verifies():
    saved = _log_rich_admin_event()
    assert saved["hash_v"] == 3
    assert _get_column("admin_audit_log", "hash_v", saved["id"]) == 3
    assert db.verify_audit_chain()["valid"] is True


# ── every protected MCP field fails closed when mutated ──────────────────────

MCP_MUTATIONS = [
    ("ts", "2000-01-01T00:00:00+00:00"),
    ("server_id", "attacker-server"),
    ("tool_name", "attacker_tool"),
    ("principal_id", "someone-else"),
    ("role", "admin_agent"),
    ("action", "allow"),
    ("matched_rule", "no_rule_matched"),
    ("reason", "nothing to see here"),
    ("effects", '["read"]'),
    ("side_effect", "read_only"),
    ("data_classes", "[]"),
    ("externality", "internal"),
    ("verification_level", "unknown"),
    ("confidence", 0.01),
    ("confidence", 0.8500001),  # sub-.6f-precision: aliased by the old encoding
    ("warnings", "[]"),
    ("argument_keys", '["other"]'),
    ("blocked_by", ""),
    ("probe_id", "different-probe"),
    ("argument_hash", "sha256:" + "f" * 64),
    ("expected_outcome", "allowed"),
    ("expected_status_code", 200),
    ("observed_outcome", "denied"),
    ("observed_status_code", 403),
    ("observed_error_class", ""),
    ("drift_status", "active"),
    ("drift_severity", "none"),
    ("drift_action", "allow"),
    ("drift_types", "[]"),
    ("drift_reasons", '["harmless rewording"]'),
    ("drift_baseline_hash", "sha256:" + "0" * 64),
    ("drift_current_hash", "sha256:" + "1" * 64),
    ("scan_time_ms", 999.75),
    ("scan_time_ms", 12.5000001),  # sub-.6f-precision: aliased by the old encoding
    ("call_id", "attacker-call-id"),
    ("prev_hash", "e" * 64),
    ("hash_v", 1),
    ("hash_v", 4),  # future version must not be reinterpreted as v3
]


@pytest.mark.parametrize("column,tampered", MCP_MUTATIONS)
def test_mutating_mcp_field_fails_closed(column, tampered):
    saved = _log_rich_mcp_event()
    original = _get_column("mcp_audit_log", column, saved["id"])
    assert str(original) != str(tampered), f"mutation for {column} must differ"

    _set_column("mcp_audit_log", column, tampered, saved["id"])
    record = db.verify_mcp_audit_record(saved["id"])
    chain = db.verify_audit_chain()
    assert record["chain_verified"] is False, f"tampered {column} must fail record"
    assert chain["valid"] is False, f"tampered {column} must fail chain walk"

    _set_column("mcp_audit_log", column, original, saved["id"])
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert db.verify_audit_chain()["valid"] is True


# ── float integrity: lossless encoding, fail-closed non-finite ───────────────


@pytest.mark.parametrize(
    "confidence,scan_time_ms",
    [
        (0.85, 12.5),
        (0.8500001, 12.5000001),
        (0.1 + 0.2, 12.3456789),  # 0.30000000000000004
        (5e-324, 1.7976931348623157e308),  # subnormal min / largest double
        (0.0, 0.0),
        (1.0, None),
    ],
)
def test_accepted_floats_round_trip_and_verify(confidence, scan_time_ms):
    """Every accepted numeric value must hash exactly what a verifier reads
    back from storage — full double precision, no truncation."""
    saved = _log_rich_mcp_event(confidence=confidence, scan_time_ms=scan_time_ms)
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert db.verify_audit_chain()["valid"] is True


@pytest.mark.parametrize(
    "field,bad",
    [
        ("confidence", float("nan")),
        ("confidence", float("inf")),
        ("scan_time_ms", float("-inf")),
        ("scan_time_ms", "not a number"),
    ],
)
def test_nonfinite_float_event_is_rejected_and_nothing_is_written(field, bad):
    """SQLite cannot faithfully store NaN (becomes NULL) so non-finite floats
    are rejected fail-closed before anything is hashed or inserted."""
    before = _get_count("mcp_audit_log")
    with pytest.raises(ValueError):
        _log_rich_mcp_event(**{field: bad})
    assert _get_count("mcp_audit_log") == before
    assert db.verify_audit_chain()["valid"] is True


def test_tampering_stored_float_to_nonfinite_fails_cleanly():
    """A stored float column rewritten to inf must fail verification with a
    clean verdict (never an exception)."""
    saved = _log_rich_mcp_event()
    _set_column("mcp_audit_log", "confidence", float("inf"), saved["id"])
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False
    assert db.verify_audit_chain()["valid"] is False


def _get_count(table):
    with db.get_conn() as conn:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
    return int(dict(row)["n"])


# ── every protected admin field fails closed when mutated ────────────────────

ADMIN_MUTATIONS = [
    ("ts", "2000-01-01T00:00:00+00:00"),
    ("actor_auth_type", "bootstrap"),
    ("actor_role", "owner"),
    ("actor_label", "someone-else"),
    ("actor_email", "attacker@example.com"),
    ("actor_subject", "other-subject"),
    ("actor_token_prefix", "ia_zzzzzz"),
    ("action", "key_deleted"),
    ("target_type", "mcp_server"),
    ("target_id", "other-target"),
    ("result", "failure"),
    ("reason", "rewritten reason"),
    ("details", '{"nested":{"scopes":["mcp.call",3]},"plan":"developer"}'),
    ("prev_hash", "e" * 64),
    ("hash_v", 1),
    ("hash_v", 2),  # admin chain never had a v2 rule; must not fall back to v1
    ("hash_v", 4),
]


@pytest.mark.parametrize("column,tampered", ADMIN_MUTATIONS)
def test_mutating_admin_field_fails_closed(column, tampered):
    saved = _log_rich_admin_event()
    original = _get_column("admin_audit_log", column, saved["id"])
    assert str(original) != str(tampered), f"mutation for {column} must differ"

    _set_column("admin_audit_log", column, tampered, saved["id"])
    chain = db.verify_audit_chain()
    assert chain["valid"] is False, f"tampered {column} must fail chain walk"
    assert chain["broken_at"]["table"] == "admin_audit_log"

    _set_column("admin_audit_log", column, original, saved["id"])
    assert db.verify_audit_chain()["valid"] is True


def test_deep_nested_admin_details_mutation_fails_closed():
    """A single value flipped deep inside the details JSON must be caught."""
    saved = _log_rich_admin_event(
        details={"outer": {"middle": {"inner": [1, {"leaf": "original"}]}}}
    )
    original = _get_column("admin_audit_log", "details", saved["id"])
    tampered = original.replace('"original"', '"tampered"')
    assert tampered != original

    _set_column("admin_audit_log", "details", tampered, saved["id"])
    assert db.verify_audit_chain()["valid"] is False

    _set_column("admin_audit_log", "details", original, saved["id"])
    assert db.verify_audit_chain()["valid"] is True


# ── typed storage: INT/FLOAT/JSON stored-form tampering fails closed ──────────
#
# SQLite affinity stores 200.9 as REAL and '' as TEXT even in INTEGER/REAL
# columns, so each of these is a real stored-value mutation.

MCP_JSON_LIST_COLUMNS = [
    "effects",
    "data_classes",
    "warnings",
    "argument_keys",
    "drift_types",
    "drift_reasons",
]


@pytest.mark.parametrize(
    "column,tampered",
    [("expected_status_code", 403.9), ("observed_status_code", 200.9)],
)
def test_nonintegral_status_code_tamper_fails_closed(column, tampered):
    """403 -> 403.9 aliased under int() coercion and verified after mutation."""
    saved = _log_rich_mcp_event()
    original = _get_column("mcp_audit_log", column, saved["id"])
    _set_column("mcp_audit_log", column, tampered, saved["id"])
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False
    assert db.verify_audit_chain()["valid"] is False
    _set_column("mcp_audit_log", column, original, saved["id"])
    assert db.verify_audit_chain()["valid"] is True


@pytest.mark.parametrize(
    "column", ["expected_status_code", "observed_status_code", "scan_time_ms"]
)
def test_null_optional_column_tampered_to_empty_text_fails_closed(column):
    """A legitimately-NULL optional column rewritten to empty text must not
    verify: NULL and '' are different stored values."""
    saved = _log_rich_mcp_event(
        expected_status_code=None, observed_status_code=None, scan_time_ms=None
    )
    assert _get_column("mcp_audit_log", column, saved["id"]) is None

    _set_column("mcp_audit_log", column, "", saved["id"])
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False
    assert db.verify_audit_chain()["valid"] is False

    _set_column("mcp_audit_log", column, None, saved["id"])
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert db.verify_audit_chain()["valid"] is True


@pytest.mark.parametrize("column", MCP_JSON_LIST_COLUMNS)
def test_empty_json_list_tampered_to_empty_text_fails_closed(column):
    """'[]' -> '' aliased under the default-JSON normalization."""
    saved = _log_rich_mcp_event(**{name: [] for name in MCP_JSON_LIST_COLUMNS})
    assert _get_column("mcp_audit_log", column, saved["id"]) == "[]"

    _set_column("mcp_audit_log", column, "", saved["id"])
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False
    assert db.verify_audit_chain()["valid"] is False

    _set_column("mcp_audit_log", column, "[]", saved["id"])
    assert db.verify_audit_chain()["valid"] is True


def test_empty_json_object_details_tampered_to_empty_text_fails_closed():
    """'{}' -> '' on the admin details JSON object column."""
    saved = _log_rich_admin_event(details={})
    assert _get_column("admin_audit_log", "details", saved["id"]) == "{}"

    _set_column("admin_audit_log", "details", "", saved["id"])
    assert db.verify_audit_chain()["valid"] is False

    _set_column("admin_audit_log", "details", "{}", saved["id"])
    assert db.verify_audit_chain()["valid"] is True


@pytest.mark.parametrize("field", ["expected_status_code", "observed_status_code"])
@pytest.mark.parametrize("bad", [403.9, True, "not-a-code", float("inf")])
def test_writer_rejects_invalid_status_code_inputs(field, bad):
    before = _get_count("mcp_audit_log")
    with pytest.raises(ValueError):
        _log_rich_mcp_event(**{field: bad})
    assert _get_count("mcp_audit_log") == before
    assert db.verify_audit_chain()["valid"] is True


def test_optional_null_status_codes_and_timing_still_supported():
    saved = _log_rich_mcp_event(
        expected_status_code=None, observed_status_code=None, scan_time_ms=None
    )
    row = db.get_mcp_audit_log(saved["id"])
    assert row["expected_status_code"] is None
    assert row["observed_status_code"] is None
    assert row["scan_time_ms"] is None
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert db.verify_audit_chain()["valid"] is True


def test_numeric_string_status_code_is_stored_as_integer_and_verifies():
    saved = _log_rich_mcp_event(expected_status_code="403")
    assert _get_column("mcp_audit_log", "expected_status_code", saved["id"]) == 403
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True


# ── exact hash-version enforcement ────────────────────────────────────────────

INVALID_MCP_HASH_VERSIONS = [0, -1, 5, 99, "not-a-version"]
INVALID_ADMIN_HASH_VERSIONS = [0, -1, 4, 99, "not-a-version"]


@pytest.mark.parametrize("bad_version", INVALID_MCP_HASH_VERSIONS)
def test_invalid_mcp_hash_version_fails_closed(bad_version):
    """A stored hash_v outside exactly {1, 2, 3, 4} must fail verification with
    a clean verdict — zero, negative, future, and malformed alike."""
    saved = _log_rich_mcp_event()
    _set_column("mcp_audit_log", "hash_v", bad_version, saved["id"])

    record = db.verify_mcp_audit_record(saved["id"])
    assert record["chain_verified"] is False, record
    chain = db.verify_audit_chain()
    assert chain["valid"] is False, chain
    assert chain["reason"] == "unsupported hash version"

    _set_column("mcp_audit_log", "hash_v", 3, saved["id"])
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert db.verify_audit_chain()["valid"] is True


@pytest.mark.parametrize("bad_version", INVALID_ADMIN_HASH_VERSIONS)
def test_invalid_admin_hash_version_fails_closed(bad_version):
    saved = _log_rich_admin_event()
    _set_column("admin_audit_log", "hash_v", bad_version, saved["id"])
    chain = db.verify_audit_chain()
    assert chain["valid"] is False, chain
    assert chain["reason"] == "unsupported hash version"

    _set_column("admin_audit_log", "hash_v", 3, saved["id"])
    assert db.verify_audit_chain()["valid"] is True


def test_missing_or_null_hash_version_fails_closed_at_recompute():
    """The columns are NOT NULL so a stored row always carries a version, but
    the recompute dispatch itself must reject a missing/None hash_v rather
    than defaulting to a legacy rule."""
    row = {"prev_hash": "GENESIS", "ts": "2026-01-01T00:00:00+00:00"}
    for variant in (row, {**row, "hash_v": None}):
        with pytest.raises(db.audit_envelope.UnsupportedHashVersionError):
            db._recompute_mcp_audit_hash(dict(variant))
        with pytest.raises(db.audit_envelope.UnsupportedHashVersionError):
            db._recompute_admin_audit_hash(dict(variant))


def test_admin_v2_is_not_a_supported_version():
    """The admin chain only ever wrote v1 and v3; hash_v=2 on an admin row
    must not silently fall back to the v1 rule."""
    with pytest.raises(db.audit_envelope.UnsupportedHashVersionError):
        db._recompute_admin_audit_hash({"hash_v": 2, "prev_hash": "GENESIS", "ts": "t"})


# ── v1/v2 rows keep verifying under their historical rules ────────────────────


def _insert_legacy_mcp_v1_row():
    ts = "2026-01-01T00:00:00+00:00"
    with db._db_lock, db.get_conn() as conn:
        prev = conn.execute(
            "SELECT integrity_hash FROM mcp_audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = (dict(prev).get("integrity_hash") if prev else None) or "GENESIS"
        integrity = db._compute_audit_hash(
            prev_hash, ts, "allow", "legacy_tool", "legacy_role", "legacy reason"
        )
        cursor = conn.execute(
            """
            INSERT INTO mcp_audit_log
              (ts, server_id, tool_name, role, action, reason,
               prev_hash, integrity_hash, hash_v)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                ts,
                "legacy-server",
                "legacy_tool",
                "legacy_role",
                "allow",
                "legacy reason",
                prev_hash,
                integrity,
            ),
        )
        return cursor.lastrowid


def _insert_legacy_mcp_v2_row():
    ts = "2026-02-01T00:00:00+00:00"
    with db._db_lock, db.get_conn() as conn:
        prev = conn.execute(
            "SELECT integrity_hash FROM mcp_audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = (dict(prev).get("integrity_hash") if prev else None) or "GENESIS"
        integrity = db._compute_audit_hash_v2(
            prev_hash,
            ts,
            "deny",
            "v2_tool",
            "v2_role",
            "v2 reason",
            "v2-server",
            "v2-call-id",
            "sha256:" + "d" * 64,
            "sha256:" + "b" * 64,
            "sha256:" + "c" * 64,
        )
        cursor = conn.execute(
            """
            INSERT INTO mcp_audit_log
              (ts, server_id, tool_name, role, action, reason, call_id,
               argument_hash, drift_baseline_hash, drift_current_hash,
               prev_hash, integrity_hash, hash_v)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
            """,
            (
                ts,
                "v2-server",
                "v2_tool",
                "v2_role",
                "deny",
                "v2 reason",
                "v2-call-id",
                "sha256:" + "d" * 64,
                "sha256:" + "b" * 64,
                "sha256:" + "c" * 64,
                prev_hash,
                integrity,
            ),
        )
        return cursor.lastrowid


def _insert_legacy_admin_v1_row():
    ts = "2026-01-01T00:00:00+00:00"
    with db._db_lock, db.get_conn() as conn:
        prev = conn.execute(
            "SELECT integrity_hash FROM admin_audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = (dict(prev).get("integrity_hash") if prev else None) or "GENESIS"
        integrity = db._compute_audit_hash(
            prev_hash, ts, "legacy_action", "legacy-target", "operator", "legacy"
        )
        cursor = conn.execute(
            """
            INSERT INTO admin_audit_log
              (ts, actor_auth_type, actor_role, action, target_type, target_id,
               reason, prev_hash, integrity_hash, hash_v)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                ts,
                "scoped_token",
                "operator",
                "legacy_action",
                "api_key",
                "legacy-target",
                "legacy",
                prev_hash,
                integrity,
            ),
        )
        return cursor.lastrowid


def test_mixed_v1_v2_v3_mcp_chain_verifies():
    v1_id = _insert_legacy_mcp_v1_row()
    v2_id = _insert_legacy_mcp_v2_row()
    v3 = _log_rich_mcp_event()

    assert db.verify_mcp_audit_record(v1_id)["chain_verified"] is True
    assert db.verify_mcp_audit_record(v2_id)["chain_verified"] is True
    assert db.verify_mcp_audit_record(v3["id"])["chain_verified"] is True
    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["mcp"]["total"] == 3


def test_mixed_v1_v3_admin_chain_verifies():
    _insert_legacy_admin_v1_row()
    _log_rich_admin_event()
    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["admin"]["total"] == 2


def test_legacy_hashes_are_not_rewritten():
    v1_id = _insert_legacy_mcp_v1_row()
    before = _get_column("mcp_audit_log", "integrity_hash", v1_id)
    _log_rich_mcp_event()
    db.verify_audit_chain()
    after = _get_column("mcp_audit_log", "integrity_hash", v1_id)
    assert before == after
    assert _get_column("mcp_audit_log", "hash_v", v1_id) == 1


def test_v2_field_not_covered_by_v2_hash_is_covered_on_v3_rows():
    """The exact v2 gap this change closes: principal_id, matched_rule,
    blocked_by, effects, and outcomes could change under a v2 hash without
    breaking it. On v2 legacy rows that stays true (historical rule); on v3
    rows every one of them is committed (asserted by the matrix above)."""
    v2_id = _insert_legacy_mcp_v2_row()
    _set_column("mcp_audit_log", "principal_id", "swapped-principal", v2_id)
    # Historical v2 rule: not committed, still verifies. Documented gap.
    assert db.verify_mcp_audit_record(v2_id)["chain_verified"] is True
    _set_column("mcp_audit_log", "principal_id", "", v2_id)
