import pytest

from core import rate_limit


def setup_function():
    rate_limit.reset_memory_state()


def test_memory_rate_limit_allows_until_limit():
    first = rate_limit.check_rate("lf_test_key", 2)
    second = rate_limit.check_rate("lf_test_key", 2)

    assert first["backend"] == "memory"
    assert first["remaining"] == 1
    assert second["remaining"] == 0


def test_memory_rate_limit_blocks_over_limit():
    rate_limit.check_rate("lf_test_key", 1)

    with pytest.raises(rate_limit.RateLimitExceeded):
        rate_limit.check_rate("lf_test_key", 1)


def test_zero_or_negative_limit_disables_rate_limit():
    result = rate_limit.check_rate("lf_test_key", 0)

    assert result["remaining"] is None
    assert result["limit"] == 0
