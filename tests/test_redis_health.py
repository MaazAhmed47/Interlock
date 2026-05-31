"""Active Redis connection probing for the /health endpoint.

``rate_limit._redis_available`` starts as ``None`` and was only mutated as a
side effect of an actual rate-limit check (lazy client init). So ``/health``
reported ``redis_available: null`` whenever no Redis-backed rate check had run
yet -- you could not tell a configured-but-unreachable Redis apart from one
that simply had not been touched. ``ping_redis()`` actively PINGs Redis,
records a real true/false verdict, and logs failures clearly instead of
leaving the stale ``None``.
"""

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import rate_limit


@pytest.fixture(autouse=True)
def _reset_redis_state(monkeypatch):
    # Each test starts from the real cold-start state: nothing tried yet.
    monkeypatch.setattr(rate_limit, "_redis_client", None)
    monkeypatch.setattr(rate_limit, "_redis_available", None)
    monkeypatch.setattr(rate_limit, "_warned_redis_failure", False)


class _FakeRedis:
    def __init__(self, ping_error=None):
        self._ping_error = ping_error
        self.pings = 0

    def ping(self):
        self.pings += 1
        if self._ping_error is not None:
            raise self._ping_error
        return True


def test_ping_redis_returns_none_when_not_configured(monkeypatch):
    monkeypatch.setattr(rate_limit, "REDIS_URL", "")

    assert rate_limit.ping_redis() is None
    # Not configured stays None (N/A); redis_configured already says false.
    assert rate_limit._redis_available is None
    assert rate_limit.status()["redis_available"] is None


def test_ping_redis_true_when_reachable(monkeypatch):
    monkeypatch.setattr(rate_limit, "REDIS_URL", "redis://localhost:6379/0")
    fake = _FakeRedis()
    monkeypatch.setattr(rate_limit, "_get_redis_client", lambda: fake)

    assert rate_limit.ping_redis() is True
    assert rate_limit._redis_available is True
    assert rate_limit.status()["redis_available"] is True
    assert fake.pings >= 1, "ping_redis must actually issue a PING"


def test_ping_redis_false_and_logs_when_ping_fails(monkeypatch, caplog):
    monkeypatch.setattr(rate_limit, "REDIS_URL", "redis://localhost:6379/0")
    fake = _FakeRedis(ping_error=ConnectionError("Connection refused"))
    monkeypatch.setattr(rate_limit, "_get_redis_client", lambda: fake)

    with caplog.at_level(logging.WARNING, logger="interlock.rate_limit"):
        result = rate_limit.ping_redis()

    assert result is False
    assert rate_limit._redis_available is False
    assert rate_limit.status()["redis_available"] is False
    # Failure is surfaced clearly, not swallowed: a log record with the error.
    assert any("redis" in r.getMessage().lower() for r in caplog.records)
    assert any(r.exc_info for r in caplog.records)


def test_ping_redis_false_when_client_cannot_connect(monkeypatch, caplog):
    monkeypatch.setattr(rate_limit, "REDIS_URL", "redis://localhost:6379/0")

    def _boom():
        raise rate_limit.RateLimitUnavailable("cannot connect to redis")

    monkeypatch.setattr(rate_limit, "_get_redis_client", _boom)

    with caplog.at_level(logging.WARNING, logger="interlock.rate_limit"):
        result = rate_limit.ping_redis()

    assert result is False
    assert rate_limit._redis_available is False
    assert any(r.exc_info for r in caplog.records)


def test_ping_redis_never_raises(monkeypatch):
    monkeypatch.setattr(rate_limit, "REDIS_URL", "redis://localhost:6379/0")

    def _boom():
        raise RuntimeError("unexpected explosion")

    monkeypatch.setattr(rate_limit, "_get_redis_client", _boom)

    # Must degrade gracefully so /health cannot 500 on a Redis problem.
    assert rate_limit.ping_redis() is False
