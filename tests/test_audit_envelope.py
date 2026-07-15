"""
Unit tests for the v3 canonical audit envelope (core/audit_envelope.py).

These pin the determinism contract: one canonical serialization for SQLite
and Postgres, explicit field ordering, stable empty/null normalization,
stable nested-JSON ordering, and float/int representations that survive a
round trip through either backend. Any drift in these rules silently breaks
chain verification, so every rule gets its own test.

Run: python -m pytest tests/test_audit_envelope.py -q
"""

import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import audit_envelope as env  # noqa: E402


def _mcp_row(**overrides):
    row = {
        "ts": "2026-07-14T00:00:00+00:00",
        "server_id": "srv",
        "tool_name": "tool",
        "principal_id": "key-1",
        "role": "readonly_agent",
        "action": "allow",
        "matched_rule": "rule",
        "reason": "ok",
        "effects": '["read"]',
        "side_effect": "read_only",
        "data_classes": "[]",
        "externality": "internal",
        "verification_level": "verified",
        "confidence": 0.85,
        "warnings": "[]",
        "argument_keys": '["path"]',
        "blocked_by": "",
        "probe_id": "",
        "argument_hash": "sha256:" + "a" * 64,
        "expected_outcome": "denied",
        "expected_status_code": 403,
        "observed_outcome": "allowed",
        "observed_status_code": 200,
        "observed_error_class": "",
        "drift_status": "quarantined",
        "drift_severity": "critical",
        "drift_action": "quarantine",
        "drift_types": '["effect_escalated"]',
        "drift_reasons": '["read-only tool gained export"]',
        "drift_baseline_hash": "sha256:" + "b" * 64,
        "drift_current_hash": "sha256:" + "c" * 64,
        "scan_time_ms": 12.5,
        "call_id": "call-1",
    }
    row.update(overrides)
    return row


# ── determinism / equality under storage round-trips ─────────────────────────


def test_same_row_same_hash():
    a = env.compute_hash_v3("mcp_audit_log", _mcp_row(), "GENESIS")
    b = env.compute_hash_v3("mcp_audit_log", _mcp_row(), "GENESIS")
    assert a == b
    assert len(a) == 64


def test_none_and_empty_string_normalize_identically():
    a = env.compute_hash_v3("mcp_audit_log", _mcp_row(blocked_by=None), "GENESIS")
    b = env.compute_hash_v3("mcp_audit_log", _mcp_row(blocked_by=""), "GENESIS")
    assert a == b


def test_null_status_code_normalizes_like_missing():
    a = env.compute_hash_v3(
        "mcp_audit_log", _mcp_row(expected_status_code=None), "GENESIS"
    )
    row = _mcp_row()
    del row["expected_status_code"]
    b = env.compute_hash_v3("mcp_audit_log", row, "GENESIS")
    assert a == b


def test_int_column_accepts_int_or_numeric_string():
    a = env.compute_hash_v3(
        "mcp_audit_log", _mcp_row(observed_status_code=200), "GENESIS"
    )
    b = env.compute_hash_v3(
        "mcp_audit_log", _mcp_row(observed_status_code="200"), "GENESIS"
    )
    assert a == b


def test_float_column_accepts_float_int_or_numeric_string():
    a = env.compute_hash_v3("mcp_audit_log", _mcp_row(scan_time_ms=5), "GENESIS")
    b = env.compute_hash_v3("mcp_audit_log", _mcp_row(scan_time_ms=5.0), "GENESIS")
    c = env.compute_hash_v3("mcp_audit_log", _mcp_row(scan_time_ms="5.0"), "GENESIS")
    assert a == b == c


def test_float_canonical_form_is_lossless_hex():
    assert env._canonical_float(0.85) == (0.85).hex()
    assert env._canonical_float(12.3456789) == (12.3456789).hex()
    assert env._canonical_float(None) == ""
    # Full double-precision range survives, including subnormals and the
    # largest finite double.
    assert env._canonical_float(5e-324) == (5e-324).hex()
    assert (
        env._canonical_float(1.7976931348623157e308) == (1.7976931348623157e308).hex()
    )


def test_close_floats_produce_distinct_canonical_bytes_and_hashes():
    """The v1 defect this replaces: .6f aliased 0.85 and 0.8500001."""
    env_a = env.canonical_envelope(
        "mcp_audit_log", _mcp_row(confidence=0.85), "GENESIS"
    )
    env_b = env.canonical_envelope(
        "mcp_audit_log", _mcp_row(confidence=0.8500001), "GENESIS"
    )
    assert env_a != env_b
    a = env.compute_hash_v3("mcp_audit_log", _mcp_row(confidence=0.85), "GENESIS")
    b = env.compute_hash_v3("mcp_audit_log", _mcp_row(confidence=0.8500001), "GENESIS")
    assert a != b


def test_zero_negative_zero_and_none_are_distinct():
    forms = {
        env._canonical_float(None),
        env._canonical_float(0.0),
        env._canonical_float(-0.0),
    }
    assert len(forms) == 3, forms


def test_nonfinite_floats_fail_closed_on_write():
    for bad in (float("nan"), float("inf"), float("-inf")):
        try:
            env.compute_hash_v3("mcp_audit_log", _mcp_row(confidence=bad), "GENESIS")
        except ValueError:
            continue
        raise AssertionError(f"non-finite {bad!r} must be rejected fail-closed")


def test_nonfinite_and_unparseable_floats_are_tagged_distinctly_on_verify():
    """Verification recomputes stored rows and must never crash: non-finite
    or non-numeric storage gets a deterministic tagged form, distinct from
    empty, from every finite hex form, and from each other — so a tampered
    row cleanly fails instead of raising."""
    tagged = [
        env._canonical_float(float("nan"), strict=False),
        env._canonical_float(float("inf"), strict=False),
        env._canonical_float(float("-inf"), strict=False),
        env._canonical_float("not a number", strict=False),
    ]
    assert len(set(tagged)) == 4, tagged
    assert "" not in tagged
    assert env._canonical_float(0.0) not in tagged
    # deterministic
    assert tagged[0] == env._canonical_float(float("nan"), strict=False)
    assert tagged[3] == env._canonical_float("not a number", strict=False)


def test_unparseable_float_fails_closed_on_write():
    try:
        env.compute_hash_v3(
            "mcp_audit_log", _mcp_row(confidence="not a number"), "GENESIS"
        )
    except ValueError:
        return
    raise AssertionError("non-numeric float-column value must be rejected on write")


def test_normalize_stored_float_contract():
    """The insert-path sanitizer: accepted values must round-trip identically
    through SQLite REAL and Postgres double precision. SQLite cannot store
    -0.0 (reads back +0.0) or NaN (reads back NULL), so -0.0 normalizes to
    0.0 before hashing/storing and non-finite values are rejected."""
    assert env.normalize_stored_float(None) is None
    assert env.normalize_stored_float("") is None
    assert env.normalize_stored_float(None, 0.0) == 0.0
    assert env.normalize_stored_float(0.85) == 0.85
    assert env.normalize_stored_float("12.5") == 12.5
    assert env.normalize_stored_float(5) == 5.0
    normalized = env.normalize_stored_float(-0.0)
    assert normalized == 0.0 and math.copysign(1.0, normalized) == 1.0
    for bad in (float("nan"), float("inf"), float("-inf"), "junk"):
        try:
            env.normalize_stored_float(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} must be rejected")


def test_json_list_column_ignores_insignificant_whitespace():
    a = env.compute_hash_v3(
        "mcp_audit_log", _mcp_row(effects='["read", "export"]'), "GENESIS"
    )
    b = env.compute_hash_v3(
        "mcp_audit_log", _mcp_row(effects='["read","export"]'), "GENESIS"
    )
    assert a == b


def test_json_list_order_is_significant():
    a = env.compute_hash_v3(
        "mcp_audit_log", _mcp_row(effects='["read","export"]'), "GENESIS"
    )
    b = env.compute_hash_v3(
        "mcp_audit_log", _mcp_row(effects='["export","read"]'), "GENESIS"
    )
    assert a != b


def _admin_row(**overrides):
    row = {
        "ts": "2026-07-14T00:00:00+00:00",
        "actor_auth_type": "scoped_token",
        "actor_role": "operator",
        "actor_label": "ops",
        "actor_email": "",
        "actor_subject": "",
        "actor_token_prefix": "ia_abc",
        "action": "key_created",
        "target_type": "api_key",
        "target_id": "lf-x",
        "result": "success",
        "reason": "",
        "details": '{"plan":"free","nested":{"a":[1,2]}}',
    }
    row.update(overrides)
    return row


def test_nested_json_object_key_order_is_insignificant():
    a = env.compute_hash_v3(
        "admin_audit_log",
        _admin_row(details='{"plan":"free","nested":{"a":[1,2]}}'),
        "GENESIS",
    )
    b = env.compute_hash_v3(
        "admin_audit_log",
        _admin_row(details='{"nested": {"a": [1, 2]}, "plan": "free"}'),
        "GENESIS",
    )
    assert a == b


def test_nested_json_value_change_changes_hash():
    a = env.compute_hash_v3(
        "admin_audit_log",
        _admin_row(details='{"nested":{"a":[1,2]},"plan":"free"}'),
        "GENESIS",
    )
    b = env.compute_hash_v3(
        "admin_audit_log",
        _admin_row(details='{"nested":{"a":[1,3]},"plan":"free"}'),
        "GENESIS",
    )
    assert a != b


def test_unparseable_json_text_is_still_tamper_evident():
    a = env.compute_hash_v3(
        "admin_audit_log", _admin_row(details="not json {"), "GENESIS"
    )
    b = env.compute_hash_v3(
        "admin_audit_log", _admin_row(details="not json {x"), "GENESIS"
    )
    assert a != b
    # ... and deterministic for the same text.
    assert a == env.compute_hash_v3(
        "admin_audit_log", _admin_row(details="not json {"), "GENESIS"
    )


# ── every field is committed ──────────────────────────────────────────────────


def test_every_mcp_field_changes_the_hash():
    baseline = env.compute_hash_v3("mcp_audit_log", _mcp_row(), "GENESIS")
    mutations = {
        "str": "mutated-value",
        "int": 599,
        "float": 99999.125,
        "json_list": '["mutated"]',
        "json_object": '{"mutated":true}',
    }
    for name, kind in env.MCP_AUDIT_V3_FIELDS:
        mutated = env.compute_hash_v3(
            "mcp_audit_log", _mcp_row(**{name: mutations[kind]}), "GENESIS"
        )
        assert mutated != baseline, f"mutating {name} must change the v3 hash"


def test_every_admin_field_changes_the_hash():
    baseline = env.compute_hash_v3("admin_audit_log", _admin_row(), "GENESIS")
    mutations = {
        "str": "mutated-value",
        "int": 599,
        "float": 99999.125,
        "json_list": '["mutated"]',
        "json_object": '{"mutated":true}',
    }
    for name, kind in env.ADMIN_AUDIT_V3_FIELDS:
        mutated = env.compute_hash_v3(
            "admin_audit_log", _admin_row(**{name: mutations[kind]}), "GENESIS"
        )
        assert mutated != baseline, f"mutating {name} must change the v3 hash"


def test_prev_hash_is_committed():
    a = env.compute_hash_v3("mcp_audit_log", _mcp_row(), "GENESIS")
    b = env.compute_hash_v3("mcp_audit_log", _mcp_row(), "f" * 64)
    assert a != b


# ── typed storage forms: every materially different stored value differs ──────
#
# SQLite affinity happily stores 200.9 (REAL) or '' (TEXT) in an INTEGER
# column, so these are genuine stored-value tampering vectors, not just
# in-memory type quirks. Verification canonicals (strict=False) must give
# every distinct stored form distinct bytes.


def _verify_hash(**overrides):
    return env.compute_hash_v3(
        "mcp_audit_log", _mcp_row(**overrides), "GENESIS", strict=False
    )


def test_int_column_distinguishes_every_stored_scalar_form():
    forms = [
        _verify_hash(expected_status_code=403),
        _verify_hash(expected_status_code=403.9),
        _verify_hash(expected_status_code=None),
        _verify_hash(expected_status_code=""),
        _verify_hash(expected_status_code=True),
        _verify_hash(expected_status_code="not-a-code"),
        _verify_hash(expected_status_code=float("inf")),
    ]
    assert len(set(forms)) == len(forms), "stored int forms must never alias"
    # Intentional equivalence: both backends coerce numeric text to the
    # integer at write time, so "403" and 403 are the same stored value.
    assert _verify_hash(expected_status_code=403) == _verify_hash(
        expected_status_code="403"
    )


def test_float_column_distinguishes_null_from_empty_text():
    forms = [
        _verify_hash(scan_time_ms=None),
        _verify_hash(scan_time_ms=""),
        _verify_hash(scan_time_ms=12.5),
        _verify_hash(scan_time_ms="junk"),
        _verify_hash(scan_time_ms=float("inf")),
    ]
    assert len(set(forms)) == len(forms), "stored float forms must never alias"


def test_json_columns_distinguish_null_empty_and_default_values():
    list_forms = [
        _verify_hash(effects="[]"),
        _verify_hash(effects=""),
        _verify_hash(effects=None),
        _verify_hash(effects="not json {"),
    ]
    assert len(set(list_forms)) == len(list_forms)

    def admin_hash(**overrides):
        return env.compute_hash_v3(
            "admin_audit_log", _admin_row(**overrides), "GENESIS", strict=False
        )

    object_forms = [
        admin_hash(details="{}"),
        admin_hash(details=""),
        admin_hash(details=None),
        admin_hash(details="not json {"),
    ]
    assert len(set(object_forms)) == len(object_forms)


def test_int_verify_forms_are_deterministic():
    for value in (None, "", 403, 403.9, True, "not-a-code", float("inf")):
        a = env._canonical_int(value, strict=False)
        b = env._canonical_int(value, strict=False)
        assert a == b


def test_int_column_write_rejects_invalid_inputs():
    for bad in (403.9, True, "not-a-code", float("nan"), float("inf")):
        try:
            env.compute_hash_v3(
                "mcp_audit_log", _mcp_row(expected_status_code=bad), "GENESIS"
            )
        except ValueError:
            continue
        raise AssertionError(f"int-column input {bad!r} must be rejected on write")


def test_normalize_stored_int_contract():
    assert env.normalize_stored_int(None) is None
    assert env.normalize_stored_int("") is None
    assert env.normalize_stored_int(None, 0) == 0
    assert env.normalize_stored_int(403) == 403
    assert env.normalize_stored_int("403") == 403
    assert env.normalize_stored_int(403.0) == 403
    for bad in (403.9, True, "not-a-code", float("nan"), float("inf")):
        try:
            env.normalize_stored_int(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} must be rejected")


# ── exact hash-version enforcement ────────────────────────────────────────────


def test_require_hash_version_accepts_only_exact_supported_values():
    assert env.require_hash_version(1, (1, 2, 3)) == 1
    assert env.require_hash_version(2, (1, 2, 3)) == 2
    assert env.require_hash_version(3, (1, 2, 3)) == 3
    assert env.require_hash_version(3, (3,)) == 3


def test_require_hash_version_fails_closed_on_anything_else():
    """Unknown, missing, malformed, zero, negative, boolean, float, or future
    versions must never be reinterpreted as a supported version."""
    for bad in (None, 0, -1, 4, 99, "3", "three", 3.0, True, False, [3]):
        try:
            env.require_hash_version(bad, (1, 2, 3))
        except env.UnsupportedHashVersionError:
            continue
        raise AssertionError(f"hash_v {bad!r} must be rejected")
    # a supported number outside THIS chain's supported set is still rejected
    try:
        env.require_hash_version(2, (1, 3))
    except env.UnsupportedHashVersionError:
        pass
    else:
        raise AssertionError("version 2 must be rejected when only (1, 3) allowed")


# ── domain separation ─────────────────────────────────────────────────────────


def test_chain_kind_is_domain_separated():
    row = {name: None for name, _kind in env.MCP_AUDIT_V3_FIELDS}
    a = env.compute_hash_v3("mcp_audit_log", row, "GENESIS")
    b = env.compute_hash_v3("admin_audit_log", row, "GENESIS")
    assert a != b


def test_unknown_chain_kind_is_rejected():
    try:
        env.compute_hash_v3("not_a_chain", {}, "GENESIS")
    except KeyError:
        return
    raise AssertionError("unknown chain kind must raise")


# ── canonical envelope shape ──────────────────────────────────────────────────


def test_envelope_is_compact_ascii_json_with_explicit_order():
    canonical = env.canonical_envelope("mcp_audit_log", _mcp_row(), "GENESIS")
    parsed = json.loads(canonical)
    assert parsed[0] == ["hash_v", "3"]
    assert parsed[1] == ["chain", "mcp_audit_log"]
    assert parsed[2] == ["prev_hash", "GENESIS"]
    names = [pair[0] for pair in parsed[3:]]
    assert names == [name for name, _kind in env.MCP_AUDIT_V3_FIELDS]
    assert ": " not in canonical and ", " not in canonical
    assert canonical == canonical.encode("ascii", errors="strict").decode("ascii")
    assert all(isinstance(pair[1], str) for pair in parsed)
