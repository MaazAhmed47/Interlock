"""
Tests for deterministic argument constraint checking (GAP 2).

Covers _check_param_bounds() directly, which is the pure-function core of
the constraint enforcement step in proxy_mcp_tool_call().

Test matrix:
- Numeric max exceeded  → denied
- Numeric at exact max  → allowed
- Numeric at zero       → allowed (when min=0)
- Numeric below min     → denied
- String max_length exceeded → denied
- String at exact max_length → allowed
- Enum not in allowed_values → denied
- Enum in allowed_values     → allowed
- Unconstrained / absent params do not affect valid calls
- Empty param_bounds dict → always allowed
- Constraints on absent param → silently skipped (no error)
"""

import pytest
from core.mcp_gateway import _check_param_bounds

REFUND_RULES = {
    "param_bounds": {
        "amount": {"min": 0, "max": 500},
        "currency": {"allowed_values": ["USD", "EUR"]},
        "reason": {"max_length": 200},
    }
}


# ── Numeric bounds ────────────────────────────────────────────────────────────

def test_numeric_max_exceeded_denied():
    result = _check_param_bounds(
        {"amount": 99999, "currency": "USD", "reason": "test"},
        REFUND_RULES,
    )
    assert result is not None
    assert "amount=99999" in result
    assert "max=500" in result
    assert "Numeric bound violation" in result


def test_numeric_at_exact_max_allowed():
    result = _check_param_bounds(
        {"amount": 500, "currency": "USD", "reason": "test"},
        REFUND_RULES,
    )
    assert result is None


def test_numeric_at_zero_allowed():
    result = _check_param_bounds(
        {"amount": 0, "currency": "USD", "reason": "test"},
        REFUND_RULES,
    )
    assert result is None


def test_numeric_below_min_denied():
    rules = {"param_bounds": {"amount": {"min": 1, "max": 500}}}
    result = _check_param_bounds({"amount": -5}, rules)
    assert result is not None
    assert "below min=1" in result
    assert "Numeric bound violation" in result


def test_numeric_float_exceeds_max():
    result = _check_param_bounds({"amount": 500.01}, REFUND_RULES)
    assert result is not None
    assert "Numeric bound violation" in result


def test_numeric_float_at_max_allowed():
    result = _check_param_bounds({"amount": 500.0}, REFUND_RULES)
    assert result is None


# ── String max_length ─────────────────────────────────────────────────────────

def test_string_max_length_exceeded_denied():
    long_reason = "x" * 201
    result = _check_param_bounds(
        {"amount": 10, "currency": "USD", "reason": long_reason},
        REFUND_RULES,
    )
    assert result is not None
    assert "reason" in result
    assert "max_length=200" in result
    assert "String length violation" in result


def test_string_at_exact_max_length_allowed():
    exact_reason = "x" * 200
    result = _check_param_bounds(
        {"amount": 10, "currency": "USD", "reason": exact_reason},
        REFUND_RULES,
    )
    assert result is None


def test_string_empty_allowed():
    result = _check_param_bounds(
        {"amount": 10, "currency": "USD", "reason": ""},
        REFUND_RULES,
    )
    assert result is None


# ── Enum allowed_values ───────────────────────────────────────────────────────

def test_enum_not_in_allowed_values_denied():
    result = _check_param_bounds(
        {"amount": 10, "currency": "BTC", "reason": "test"},
        REFUND_RULES,
    )
    assert result is not None
    assert "currency=BTC" in result
    assert "allowed_values" in result
    assert "Enum violation" in result


def test_enum_in_allowed_values_allowed():
    for currency in ("USD", "EUR"):
        result = _check_param_bounds(
            {"amount": 10, "currency": currency, "reason": "ok"},
            REFUND_RULES,
        )
        assert result is None, f"Expected None for currency={currency}"


# ── Missing / unconstrained params ───────────────────────────────────────────

def test_missing_constrained_param_skipped():
    """Absent params are skipped — they do not trigger a violation."""
    result = _check_param_bounds({}, REFUND_RULES)
    assert result is None


def test_unconstrained_params_ignored():
    """Extra params not in param_bounds are always ignored."""
    rules = {"param_bounds": {"amount": {"max": 500}}}
    result = _check_param_bounds(
        {"amount": 100, "extra_field": "anything", "another": 9999},
        rules,
    )
    assert result is None


def test_empty_param_bounds_always_allowed():
    result = _check_param_bounds(
        {"amount": 99999, "currency": "XMR"},
        {"param_bounds": {}},
    )
    assert result is None


def test_no_param_bounds_key_allowed():
    result = _check_param_bounds({"amount": 99999}, {})
    assert result is None


# ── Denial reason format ──────────────────────────────────────────────────────

def test_numeric_denial_reason_format():
    """Verify the denial reason follows the expected format exactly."""
    result = _check_param_bounds({"amount": 999}, REFUND_RULES)
    assert result == "Numeric bound violation: amount=999 exceeds max=500"


def test_string_denial_reason_format():
    long_reason = "y" * 201
    result = _check_param_bounds(
        {"amount": 1, "currency": "USD", "reason": long_reason},
        REFUND_RULES,
    )
    assert result == f"String length violation: reason length=201 exceeds max_length=200"


def test_enum_denial_reason_format():
    result = _check_param_bounds(
        {"amount": 1, "currency": "GBP", "reason": "ok"},
        REFUND_RULES,
    )
    assert result == "Enum violation: currency=GBP not in allowed_values"
