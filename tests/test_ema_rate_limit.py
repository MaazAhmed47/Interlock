"""Adversarial bounds for the experimental per-process EMA limiters."""

from __future__ import annotations

import asyncio

from core.ema_rate_limit import BoundedWindowLimiter


def test_same_key_concurrency_cannot_exceed_the_fixed_window_budget():
    limiter = BoundedWindowLimiter(
        limit=4,
        window_seconds=60,
        max_keys=16,
    )

    async def exercise():
        return await asyncio.gather(*(limiter.allow("one-host") for _ in range(40)))

    admitted = asyncio.run(exercise())
    assert admitted.count(True) == 4
    assert admitted.count(False) == 36
    assert limiter.safe_keys() == ("one-host",)


def test_key_cardinality_is_bounded_and_new_keys_fail_closed():
    limiter = BoundedWindowLimiter(
        limit=10,
        window_seconds=60,
        max_keys=2,
    )
    assert asyncio.run(limiter.allow("host-one")) is True
    assert asyncio.run(limiter.allow("host-two")) is True
    assert asyncio.run(limiter.allow("host-three")) is False
    assert limiter.safe_keys() == ("host-one", "host-two")

    asyncio.run(limiter.refund("host-one"))
    assert asyncio.run(limiter.allow("host-three")) is True
    assert limiter.safe_keys() == ("host-two", "host-three")


def test_expired_windows_are_removed_before_cardinality_admission():
    now = [100.0]
    limiter = BoundedWindowLimiter(
        limit=1,
        window_seconds=10,
        max_keys=1,
        monotonic=lambda: now[0],
    )
    assert asyncio.run(limiter.allow("old-host")) is True
    assert asyncio.run(limiter.allow("new-host")) is False
    now[0] = 111.0
    assert asyncio.run(limiter.allow("new-host")) is True
    assert limiter.safe_keys() == ("new-host",)
