"""
Deterministic canonical audit envelopes — hash version 3.

One serializer for both storage backends (SQLite and Postgres) and all three
hash-chained record kinds: ``mcp_audit_log`` rows, ``admin_audit_log`` rows,
and ``audit_chain_checkpoints`` rows. The v3 integrity hash commits to EVERY
stored security-significant field of a row, so mutating any protected column
— including nested JSON, arrays, status codes, principal identity, matched
rule, blocked_by, and probe outcomes — breaks chain verification. (v1/v2
hashes covered only selected fields; rows written under those rules keep
verifying under them — see core/db.py.)

Canonical form, stated exactly (unit-tested in tests/test_audit_envelope.py):

- The envelope is a JSON array of ``[name, value]`` string pairs in an
  explicit, versioned field order — never a dict walk, never database column
  order — prefixed by ``["hash_v","3"]``, ``["chain",<kind>]`` and
  ``["prev_hash",<prev>]`` so hashes are domain-separated across versions
  and chains and commit to their chain position.
- Every canonical value is a string:
  - str columns: None -> "", else str(value).
  - int columns: None -> ""; ints -> base-10 text; numeric text -> the same
    base-10 text (both backends coerce numeric text to the integer at write
    time, so it is the same stored value). Every OTHER stored form is
    distinct: SQLite affinity keeps 200.9 as REAL and '' as TEXT even in an
    INTEGER column, so non-integral floats canonicalize to their hex form,
    non-finite floats to "nonfinite:" tags, and empty/non-numeric text to
    "raw:" tags. Writes reject any non-integer input fail-closed
    (strict=True, the default); writers sanitize with normalize_stored_int()
    so legitimate optional NULLs are preserved.
  - float columns: None/"" -> "", else ``float.hex()`` — lossless for every
    finite double, so two distinct stored values can never share canonical
    bytes (0.85 vs 0.8500001, 0.0 vs -0.0). Hex round-trips bit-exactly on
    both backends (the audit float columns are double precision on Postgres —
    see _ensure_double_precision in core/db.py). Non-finite and non-numeric
    values are rejected fail-closed when hashing for a write (strict=True,
    the default); verification recomputes with strict=False, where they get
    deterministic tagged forms ("nonfinite:...", "raw:...") that no honest
    write can produce — a tampered row fails cleanly instead of raising.
    Writers must sanitize with normalize_stored_float() first: SQLite cannot
    store -0.0 (reads back +0.0) or NaN (reads back NULL), so -0.0 is
    normalized to 0.0 before hashing and non-finite values never reach
    storage. Every accepted value round-trips identically on both backends.
    Empty text ('' stored as TEXT in a REAL column) is tagged "raw:",
    distinct from NULL.
  - JSON columns: valid JSON text (and dict/list values) is re-dumped with
    sorted keys, compact separators, ASCII escaping, default=str — the ONLY
    intentional normalization (whitespace/key order). There is no default
    substitution: None -> "", empty text -> "raw:", malformed text ->
    "raw:" + text. '' and '[]'/'{}' are different stored values and never
    share canonical bytes; canonical dumps cannot begin with "raw:", so the
    tagged forms are unambiguous.
- The envelope itself is dumped compact + ensure_ascii and hashed as UTF-8
  SHA-256.

This is a hash chain, NOT a cryptographic signature: there is no signing
key, KMS, or HSM lifecycle here. It proves append order and detects mutation
of stored fields after the fact; it does not prove authorship, and an actor
with direct database write access can always rewrite the chain suffix from
any point. Describe records as "hash-chained" / "tamper-evident", never
"signed".
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping, Optional, Tuple

HASH_V3 = 3
HASH_V4 = 4

GENESIS = "GENESIS"


class UnsupportedHashVersionError(ValueError):
    """A stored hash_v is not an exactly supported version — fail closed."""


def require_hash_version(value: Any, supported: Tuple[int, ...]) -> int:
    """
    Validate a stored hash_v against a chain's exact supported version set.

    Only a plain int exactly in ``supported`` passes. Missing/None, zero,
    negative, future, boolean, float, and string values all raise: an
    unknown or future version must never be reinterpreted under this code's
    rules, or a mutated version field could still verify.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value not in supported:
        raise UnsupportedHashVersionError(
            f"unsupported hash_v {value!r}; supported versions: {supported}"
        )
    return value


# Field kinds — the second element of each (name, kind) pair below.
STR = "str"
INT = "int"
FLOAT = "float"
JSON_LIST = "json_list"
JSON_OBJECT = "json_object"
BOOL = "bool"

# Every stored security-significant column of mcp_audit_log, in explicit
# envelope order. Excluded on purpose: ``id`` (unknown before insert; row
# order is proven by prev_hash linkage), ``hash_v``/``prev_hash`` (committed
# via the envelope prefix), and ``integrity_hash`` (the hash itself).
MCP_AUDIT_V3_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("ts", STR),
    ("server_id", STR),
    ("tool_name", STR),
    ("principal_id", STR),
    ("role", STR),
    ("action", STR),
    ("matched_rule", STR),
    ("reason", STR),
    ("effects", JSON_LIST),
    ("side_effect", STR),
    ("data_classes", JSON_LIST),
    ("externality", STR),
    ("verification_level", STR),
    ("confidence", FLOAT),
    ("warnings", JSON_LIST),
    ("argument_keys", JSON_LIST),
    ("blocked_by", STR),
    ("probe_id", STR),
    ("argument_hash", STR),
    ("expected_outcome", STR),
    ("expected_status_code", INT),
    ("observed_outcome", STR),
    ("observed_status_code", INT),
    ("observed_error_class", STR),
    ("drift_status", STR),
    ("drift_severity", STR),
    ("drift_action", STR),
    ("drift_types", JSON_LIST),
    ("drift_reasons", JSON_LIST),
    ("drift_baseline_hash", STR),
    ("drift_current_hash", STR),
    ("scan_time_ms", FLOAT),
    ("call_id", STR),
)

# Authority-bearing rows use a separate envelope.  It commits to all legacy
# runtime evidence plus every explicit authority identity, algorithm/key ID,
# validation boundary, token-binding, and downstream-boundary field.
MCP_AUDIT_V4_AUTHORITY_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("transport", STR),
    ("mcp_resource_uri", STR),
    ("mcp_protocol_version", STR),
    ("mcp_method", STR),
    ("authority_mode", STR),
    ("authority_status", STR),
    ("authority_profile", STR),
    ("authority_artifact_type", STR),
    ("authority_signature_algorithm", STR),
    ("authority_token_type", STR),
    ("authority_validation_boundary", STR),
    ("authority_verified_at", INT),
    ("authority_issuer", STR),
    ("authority_audiences", JSON_LIST),
    ("authority_resource", STR),
    ("authority_scopes", JSON_LIST),
    ("authority_expires_at", INT),
    ("authority_not_before", INT),
    ("authority_issued_at", INT),
    ("oauth_client_binding", STR),
    ("oauth_client_binding_alg", STR),
    ("oauth_client_binding_key_id", STR),
    ("delegated_subject_binding", STR),
    ("delegated_subject_binding_alg", STR),
    ("delegated_subject_binding_key_id", STR),
    ("interlock_service_principal_id", STR),
    ("downstream_service_principal_id", STR),
    ("token_binding", STR),
    ("token_binding_alg", STR),
    ("token_binding_key_id", STR),
    ("downstream_auth_mode", STR),
    ("inbound_authority_forwarded", BOOL),
    ("downstream_authority_evaluated", BOOL),
    ("authority_failure_code", STR),
)
MCP_AUDIT_V4_FIELDS = MCP_AUDIT_V3_FIELDS + MCP_AUDIT_V4_AUTHORITY_FIELDS

# Every stored security-significant column of admin_audit_log.
ADMIN_AUDIT_V3_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("ts", STR),
    ("actor_auth_type", STR),
    ("actor_role", STR),
    ("actor_label", STR),
    ("actor_email", STR),
    ("actor_subject", STR),
    ("actor_token_prefix", STR),
    ("action", STR),
    ("target_type", STR),
    ("target_id", STR),
    ("result", STR),
    ("reason", STR),
    ("details", JSON_OBJECT),
)

# Retention checkpoint: binds the pruned boundary of one audit chain — chain
# name, last deleted row (id + hash), first retained row (id + its recorded
# prev hash), how many rows were removed, under which retention policy, when,
# and by which actor/context.
CHECKPOINT_V3_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("chain", STR),
    ("created_at", STR),
    ("last_deleted_id", INT),
    ("last_deleted_hash", STR),
    ("first_retained_id", INT),
    ("first_retained_prev_hash", STR),
    ("deleted_count", INT),
    ("retention_policy", JSON_OBJECT),
    ("actor", JSON_OBJECT),
)

CHAIN_FIELDS = {
    "mcp_audit_log": MCP_AUDIT_V3_FIELDS,
    "admin_audit_log": ADMIN_AUDIT_V3_FIELDS,
    "audit_chain_checkpoint": CHECKPOINT_V3_FIELDS,
}


def _canonical_str(value: Any) -> str:
    return "" if value is None else str(value)


def _canonical_int(value: Any, *, strict: bool = True) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        if strict:
            raise ValueError(f"boolean value in audit int column: {value!r}")
        return "raw:" + str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # SQLite INTEGER affinity keeps non-integral REALs as REAL: a stored
        # 200.9 is a different value than 200 and must hash differently.
        if strict:
            raise ValueError(f"non-integer value in audit int column: {value!r}")
        if not math.isfinite(value):
            return "nonfinite:" + repr(value)
        return value.hex()
    text = value if isinstance(value, str) else str(value)
    try:
        # Numeric text coerces to the integer at write time on both backends
        # (SQLite affinity, Postgres cast), so it IS the stored integer.
        return str(int(text, 10))
    except ValueError:
        if strict:
            raise ValueError(
                f"non-integer value in audit int column: {value!r}"
            ) from None
        return "raw:" + text


def _canonical_float(value: Any, *, strict: bool = True) -> str:
    if value is None:
        return ""
    if isinstance(value, str) and value == "":
        # '' stored as TEXT in a REAL column is a different stored value
        # than NULL; writers send None (normalize_stored_float), so this can
        # only be tampered or degenerate storage.
        if strict:
            raise ValueError("empty text in audit float column")
        return "raw:"
    try:
        number = float(value)
    except (TypeError, ValueError):
        if strict:
            raise ValueError(
                f"non-numeric value in audit float column: {value!r}"
            ) from None
        return "raw:" + str(value)
    if not math.isfinite(number):
        if strict:
            raise ValueError(f"non-finite value in audit float column: {value!r}")
        return "nonfinite:" + repr(number)
    return number.hex()


def _canonical_bool(value: Any, *, strict: bool = True) -> str:
    if value is None:
        return ""
    if value is True or value == 1:
        return "true"
    if value is False or value == 0:
        return "false"
    if strict:
        raise ValueError(f"non-boolean value in audit bool column: {value!r}")
    return "raw:" + str(value)


def normalize_stored_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    """
    Sanitize an integer destined for an audit column BEFORE hashing/storing.

    Returns exactly what both backends will hand back to a verifier:
    None/"" -> ``default`` (optional status codes stay NULL); ints pass;
    integral floats and numeric text collapse to the int storage would
    produce; booleans and non-integral/non-finite/non-numeric values raise
    ValueError fail-closed.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError(f"boolean audit int value: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise ValueError(f"non-integer audit int value: {value!r}")
        return int(value)
    text = str(value)
    if text == "":
        return default
    try:
        return int(text, 10)
    except ValueError:
        raise ValueError(f"non-integer audit int value: {value!r}") from None


def normalize_stored_float(
    value: Any, default: Optional[float] = None
) -> Optional[float]:
    """
    Sanitize a float destined for an audit column BEFORE hashing/storing it.

    Returns exactly the value both backends will hand back to a verifier:
    None/"" -> ``default``; -0.0 -> 0.0 (SQLite drops the sign bit); any
    non-finite or non-numeric value raises ValueError fail-closed (SQLite
    stores NaN as NULL, so it cannot be made tamper-evident).
    """
    if value is None or value == "":
        return default
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite audit float value: {value!r}")
    if number == 0.0:
        return 0.0
    return number


def _canonical_json_dump(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def _canonical_json(value: Any) -> str:
    # No default substitution: NULL, empty text, and '[]'/'{}' are three
    # different stored values. Only semantically-equivalent JSON (whitespace,
    # key order) is normalized. Canonical dumps can never begin with "raw:"
    # (they start with a JSON token), so the tagged forms are unambiguous.
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return _canonical_json_dump(value)
    text = value if isinstance(value, str) else str(value)
    if text == "":
        return "raw:"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return "raw:" + text
    return _canonical_json_dump(parsed)


def _canonical_value(kind: str, value: Any, *, strict: bool = True) -> str:
    if kind == STR:
        return _canonical_str(value)
    if kind == INT:
        return _canonical_int(value, strict=strict)
    if kind == FLOAT:
        return _canonical_float(value, strict=strict)
    if kind == BOOL:
        return _canonical_bool(value, strict=strict)
    return _canonical_json(value)


def canonical_envelope(
    chain: str, row: Mapping[str, Any], prev_hash: str, *, strict: bool = True
) -> str:
    """
    Serialize one record into its canonical v3 envelope string.

    strict=True (writes) rejects values storage cannot faithfully round-trip;
    strict=False (verification) never raises — see _canonical_float.
    """
    fields = CHAIN_FIELDS[chain]
    pairs = [
        ["hash_v", str(HASH_V3)],
        ["chain", chain],
        ["prev_hash", _canonical_str(prev_hash)],
    ]
    for name, kind in fields:
        pairs.append([name, _canonical_value(kind, row.get(name), strict=strict)])
    return json.dumps(pairs, separators=(",", ":"), ensure_ascii=True)


def compute_hash_v3(
    chain: str, row: Mapping[str, Any], prev_hash: str, *, strict: bool = True
) -> str:
    """SHA-256 over the canonical v3 envelope of one record."""
    envelope = canonical_envelope(chain, row, prev_hash, strict=strict)
    return hashlib.sha256(envelope.encode("utf-8")).hexdigest()


def canonical_mcp_envelope_v4(
    row: Mapping[str, Any], prev_hash: str, *, strict: bool = True
) -> str:
    pairs = [
        ["hash_v", str(HASH_V4)],
        ["chain", "mcp_audit_log"],
        ["prev_hash", _canonical_str(prev_hash)],
    ]
    for name, kind in MCP_AUDIT_V4_FIELDS:
        pairs.append([name, _canonical_value(kind, row.get(name), strict=strict)])
    return json.dumps(pairs, separators=(",", ":"), ensure_ascii=True)


def compute_mcp_hash_v4(
    row: Mapping[str, Any], prev_hash: str, *, strict: bool = True
) -> str:
    envelope = canonical_mcp_envelope_v4(row, prev_hash, strict=strict)
    return hashlib.sha256(envelope.encode("utf-8")).hexdigest()
