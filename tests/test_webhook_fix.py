"""
Tests for webhook async behavior (core/webhook.py).

Tests:
1. trigger_webhook doesn't crash when called from sync context (no event loop)
2. trigger_webhook schedules as a task (fire-and-forget) in an async route
3. fire_webhook skips silently for SAFE / LOW / MEDIUM threats
4. fire_webhook skips silently when the key has no webhook URL configured

Run: python tests/test_webhook_fix.py
"""
import sys, os, tempfile, asyncio
from pathlib import Path
from unittest.mock import MagicMock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_tmp_db = tempfile.mktemp(suffix="_webhook_test.db")
import core.db as db
db.DB_PATH = _tmp_db
db.init_db()

import httpx as _httpx
from core.webhook import trigger_webhook, fire_webhook
from models.schemas import ScanResult, ThreatLevel


# ── Fixtures ──────────────────────────────────────────────────────────────────

k_with = db.generate_key("free", label="webhook-key")
db.update_key(k_with["key_prefix"], webhook_url="http://hooks.example.test/alerts")
RAW_WITH = k_with["raw_key"]

k_without = db.generate_key("free", label="no-webhook-key")
RAW_WITHOUT = k_without["raw_key"]


def make_result(level: ThreatLevel) -> ScanResult:
    return ScanResult(
        is_threat=level != ThreatLevel.SAFE,
        threat_level=level,
        reason="test reason",
        original_prompt="test prompt",
        safe_to_proceed=(level == ThreatLevel.SAFE),
    )


# Shared HTTP mock — replaces httpx.AsyncClient for the duration of each test.
# Tracks all URL arguments passed to post() so tests can assert call counts.
_http_calls: list = []


class _MockHTTP:
    """Async context manager that records HTTP POST calls instead of making them."""
    def __init__(self, **kwargs): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def post(self, url, **kwargs):
        _http_calls.append(url)
        return MagicMock(status_code=200)


# ── Test 1: sync context — no crash ──────────────────────────────────────────

print("Test 1: trigger_webhook doesn't crash when called from sync context (no event loop) ...")
_http_calls.clear()
_orig = _httpx.AsyncClient
_httpx.AsyncClient = _MockHTTP
try:
    trigger_webhook(RAW_WITH, make_result(ThreatLevel.HIGH))
finally:
    _httpx.AsyncClient = _orig
# Reaching this line proves no exception escaped
print("  OK — returned without raising")


# ── Test 2: async context — task is scheduled, fires after yield ──────────────

print("Test 2: trigger_webhook schedules on the running loop and fires after yield ...")

async def _test_async():
    _http_calls.clear()
    _orig2 = _httpx.AsyncClient
    _httpx.AsyncClient = _MockHTTP
    try:
        trigger_webhook(RAW_WITH, make_result(ThreatLevel.HIGH))
        # Task is scheduled but the event loop hasn't run it yet
        assert len(_http_calls) == 0, \
            f"Webhook must not fire synchronously in async context — got {len(_http_calls)} call(s)"
        await asyncio.sleep(0)  # yield control so the scheduled task can run
        assert len(_http_calls) == 1, \
            f"Expected 1 HTTP POST after event loop yield, got {len(_http_calls)}"
    finally:
        _httpx.AsyncClient = _orig2

asyncio.run(_test_async())
print("  OK — task scheduled (not blocking), fired exactly once after yield")


# ── Test 3: low-severity threats never trigger HTTP ──────────────────────────

print("Test 3: fire_webhook skips silently for SAFE / LOW / MEDIUM threats ...")

async def _test_low_severity():
    _http_calls.clear()
    _orig3 = _httpx.AsyncClient
    _httpx.AsyncClient = _MockHTTP
    try:
        for level in (ThreatLevel.SAFE, ThreatLevel.LOW, ThreatLevel.MEDIUM):
            await fire_webhook(RAW_WITH, make_result(level))
    finally:
        _httpx.AsyncClient = _orig3

asyncio.run(_test_low_severity())
assert len(_http_calls) == 0, \
    f"Expected 0 HTTP calls for SAFE/LOW/MEDIUM threats, got {_http_calls}"
print("  OK — no HTTP calls for sub-HIGH threat levels")


# ── Test 4: no webhook URL — skips silently ───────────────────────────────────

print("Test 4: fire_webhook skips silently when key has no webhook URL ...")

async def _test_no_url():
    _http_calls.clear()
    _orig4 = _httpx.AsyncClient
    _httpx.AsyncClient = _MockHTTP
    try:
        await fire_webhook(RAW_WITHOUT, make_result(ThreatLevel.CRITICAL))
    finally:
        _httpx.AsyncClient = _orig4

asyncio.run(_test_no_url())
assert len(_http_calls) == 0, \
    f"Expected 0 HTTP calls for key with no webhook URL, got {_http_calls}"
print("  OK — no HTTP calls when webhook URL is not configured")


# ── Cleanup ────────────────────────────────────────────────────────────────────

for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
    try:
        os.unlink(path)
    except OSError:
        pass

print("\nAll webhook tests passed. (4/4)")
