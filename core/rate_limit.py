"""Rate limiting backends for Interlock.

Default local mode uses an in-memory sliding window. Production deployments can set
REDIS_URL to share rate-limit state across workers or replicas.
"""

import hashlib
import logging
import os
import time
from collections import defaultdict
from typing import Optional

logger = logging.getLogger("interlock.rate_limit")

REDIS_URL = os.getenv("REDIS_URL", "").strip()
RATE_LIMIT_NAMESPACE = os.getenv("RATE_LIMIT_NAMESPACE", "interlock").strip() or "interlock"
RATE_LIMIT_REDIS_TIMEOUT = float(os.getenv("RATE_LIMIT_REDIS_TIMEOUT", "1.5"))

_memory_windows = defaultdict(list)
_redis_client = None
_redis_available: Optional[bool] = None
_warned_redis_failure = False


class RateLimitExceeded(Exception):
    """Raised when the caller exceeds its configured request rate."""


class RateLimitUnavailable(Exception):
    """Raised when a required external rate-limit backend is unavailable."""


def _key_id(raw_key: str) -> str:
    return hashlib.sha256((raw_key or "").encode("utf-8")).hexdigest()


def _memory_check(raw_key: str, rate_per_min: int) -> dict:
    now = time.time()
    key = _key_id(raw_key)
    _memory_windows[key] = [t for t in _memory_windows[key] if now - t < 60]
    used = len(_memory_windows[key])
    if used >= rate_per_min:
        raise RateLimitExceeded("Rate limit exceeded.")
    _memory_windows[key].append(now)
    return {
        "backend": "memory",
        "limit": rate_per_min,
        "remaining": max(0, rate_per_min - used - 1),
        "window_seconds": 60,
    }


def _get_redis_client():
    global _redis_client, _redis_available
    if not REDIS_URL:
        return None
    if _redis_client is not None:
        return _redis_client
    try:
        import redis

        _redis_client = redis.Redis.from_url(
            REDIS_URL,
            socket_connect_timeout=RATE_LIMIT_REDIS_TIMEOUT,
            socket_timeout=RATE_LIMIT_REDIS_TIMEOUT,
            decode_responses=True,
        )
        _redis_client.ping()
        _redis_available = True
        logger.info("Redis rate limiter enabled")
        return _redis_client
    except Exception as exc:
        _redis_available = False
        raise RateLimitUnavailable(str(exc)) from exc


def _redis_check(raw_key: str, rate_per_min: int) -> dict:
    client = _get_redis_client()
    if client is None:
        return _memory_check(raw_key, rate_per_min)

    now_ms = int(time.time() * 1000)
    window_ms = 60_000
    member = f"{now_ms}:{os.getpid()}:{time.perf_counter_ns()}"
    key = f"{RATE_LIMIT_NAMESPACE}:rate:{_key_id(raw_key)}"

    try:
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, 0, now_ms - window_ms)
        pipe.zadd(key, {member: now_ms})
        pipe.zcard(key)
        pipe.expire(key, 120)
        _, _, count, _ = pipe.execute()
    except Exception as exc:
        global _redis_available
        _redis_available = False
        raise RateLimitUnavailable(str(exc)) from exc

    if int(count) > rate_per_min:
        try:
            client.zrem(key, member)
        except Exception:
            logger.debug("Failed to remove over-limit rate member", exc_info=True)
        raise RateLimitExceeded("Rate limit exceeded.")

    return {
        "backend": "redis",
        "limit": rate_per_min,
        "remaining": max(0, rate_per_min - int(count)),
        "window_seconds": 60,
    }


def check_rate(raw_key: str, rate_per_min: int) -> dict:
    """Enforce a per-key per-minute request limit.

    If REDIS_URL is set, Redis is treated as the preferred production backend. If
    Redis is unavailable we fall back to the in-memory limiter so local demos do
    not fail closed from missing infrastructure. Health/readiness exposes the
    active backend so production can alert on this condition.
    """
    if rate_per_min <= 0:
        return {"backend": backend_name(), "limit": rate_per_min, "remaining": None, "window_seconds": 60}

    if REDIS_URL:
        try:
            return _redis_check(raw_key, rate_per_min)
        except RateLimitExceeded:
            raise
        except RateLimitUnavailable:
            global _warned_redis_failure
            if not _warned_redis_failure:
                logger.exception("Redis rate limiter unavailable; falling back to in-memory limiter")
                _warned_redis_failure = True
            return _memory_check(raw_key, rate_per_min)

    return _memory_check(raw_key, rate_per_min)


def backend_name() -> str:
    if REDIS_URL and _redis_available is True:
        return "redis"
    if REDIS_URL and _redis_available is False:
        return "memory_fallback"
    if REDIS_URL:
        return "redis_configured"
    return "memory"


def status() -> dict:
    return {
        "backend": backend_name(),
        "redis_configured": bool(REDIS_URL),
        "redis_available": _redis_available,
    }


def reset_memory_state() -> None:
    _memory_windows.clear()
