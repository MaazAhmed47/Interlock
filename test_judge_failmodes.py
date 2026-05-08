"""
Tests for LLM Judge fail-modes and circuit breaker (core/llm_judge.py).

Tests:
1. fail_closed blocks when Groq is unavailable
2. fail_open allows when Groq is unavailable
3. fail_open_safe allows on Groq failure when prior layers were safe
4. fail_open_safe blocks on Groq failure when prior layers flagged risk
5. Circuit breaker trips after CIRCUIT_BREAKER_THRESHOLD consecutive failures
6. Circuit breaker skips Groq entirely while open
7. Circuit breaker allows requests through after cooldown expires

Run: python test_judge_failmodes.py
"""
import sys, os, time, tempfile
from unittest.mock import MagicMock
sys.path.insert(0, ".")

# Provide a dummy key so the Groq client constructs without error at import time
os.environ.setdefault("GROQ_API_KEY", "gsk_test_dummy_key_for_unit_tests")

_tmp_db = tempfile.mktemp(suffix="_judge_test.db")
import core.db as db
db.DB_PATH = _tmp_db
db.init_db()

import core.llm_judge as judge
from core.llm_judge import (
    llm_judge_scan,
    _breaker,
    CIRCUIT_BREAKER_THRESHOLD,
    CIRCUIT_BREAKER_COOLDOWN_S,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_key(fail_mode: str) -> str:
    """Generate a key with the given fail_mode; return the raw key."""
    result = db.generate_key("free", label=f"test-{fail_mode}", fail_mode=fail_mode)
    return result["raw_key"]


def reset_breaker() -> None:
    """Reset circuit breaker to clean state between tests."""
    with _breaker._lock:
        _breaker._consecutive_failures = 0
        _breaker._opened_at = None


def raising_client() -> MagicMock:
    """Mock Groq client whose API call always raises."""
    m = MagicMock()
    m.chat.completions.create.side_effect = Exception("Groq service unavailable")
    return m


def safe_client() -> MagicMock:
    """Mock Groq client that returns a SAFE verdict."""
    m = MagicMock()
    resp = MagicMock()
    resp.choices[0].message.content = (
        "VERDICT: SAFE\nLEVEL: SAFE\nTYPE: NONE\nREASON: No threats detected"
    )
    m.chat.completions.create.return_value = resp
    return m


# ── Provision keys ────────────────────────────────────────────────────────────

RAW_CLOSED = make_key("fail_closed")
RAW_OPEN   = make_key("fail_open")
RAW_SAFE   = make_key("fail_open_safe")


# ── Test 1: fail_closed blocks on Groq failure ────────────────────────────────

print("Test 1: fail_closed blocks when Groq is unavailable ...")
reset_breaker()
judge.client = raising_client()

result = llm_judge_scan("test prompt", api_key=RAW_CLOSED, prior_layers_safe=True)
assert result.is_threat is True, \
    f"fail_closed must block on outage — is_threat={result.is_threat}"
assert result.safe_to_proceed is False, \
    f"fail_closed must block — safe_to_proceed={result.safe_to_proceed}"
assert "fail_closed" in (result.layer_caught or "").lower() \
    or "fail_closed" in result.reason.lower(), \
    f"fail_closed policy not reflected in result: layer={result.layer_caught!r} reason={result.reason!r}"
print("  OK")


# ── Test 2: fail_open allows on Groq failure ──────────────────────────────────

print("Test 2: fail_open allows when Groq is unavailable ...")
reset_breaker()
judge.client = raising_client()

result = llm_judge_scan("test prompt", api_key=RAW_OPEN, prior_layers_safe=True)
assert result.is_threat is False, \
    f"fail_open must allow on outage — is_threat={result.is_threat}"
assert result.safe_to_proceed is True, \
    f"fail_open must allow — safe_to_proceed={result.safe_to_proceed}"
print("  OK")


# ── Test 3: fail_open_safe allows when prior layers were safe ─────────────────

print("Test 3: fail_open_safe allows on Groq failure when prior layers were safe ...")
reset_breaker()
judge.client = raising_client()

result = llm_judge_scan("test prompt", api_key=RAW_SAFE, prior_layers_safe=True)
assert result.is_threat is False, \
    f"fail_open_safe with clean priors must allow: is_threat={result.is_threat}"
assert result.safe_to_proceed is True, \
    f"fail_open_safe with clean priors must allow: safe_to_proceed={result.safe_to_proceed}"
print("  OK")


# ── Test 4: fail_open_safe blocks when prior layers flagged risk ──────────────

print("Test 4: fail_open_safe blocks on Groq failure when prior layers flagged risk ...")
reset_breaker()
judge.client = raising_client()

result = llm_judge_scan("test prompt", api_key=RAW_SAFE, prior_layers_safe=False)
assert result.is_threat is True, \
    f"fail_open_safe with risky priors must block: is_threat={result.is_threat}"
assert result.safe_to_proceed is False, \
    f"fail_open_safe with risky priors must block: safe_to_proceed={result.safe_to_proceed}"
print("  OK")


# ── Test 5: circuit breaker trips after N consecutive failures ────────────────

print(f"Test 5: circuit breaker trips after {CIRCUIT_BREAKER_THRESHOLD} consecutive failures ...")
reset_breaker()
judge.client = raising_client()

for i in range(CIRCUIT_BREAKER_THRESHOLD):
    assert not _breaker.status()["open"], \
        f"Breaker opened too early before failure #{i + 1}"
    llm_judge_scan("test prompt", api_key=RAW_OPEN, prior_layers_safe=True)

status = _breaker.status()
assert status["open"] is True, \
    f"Breaker must be open after {CIRCUIT_BREAKER_THRESHOLD} failures"
assert status["consecutive_failures"] == CIRCUIT_BREAKER_THRESHOLD, \
    f"Expected {CIRCUIT_BREAKER_THRESHOLD} recorded failures, got {status['consecutive_failures']}"
print("  OK")


# ── Test 6: Groq is skipped while circuit breaker is open ────────────────────

print("Test 6: circuit breaker skips Groq entirely while open ...")
# Breaker is still open from Test 5 (cooldown has not elapsed)
sentinel = MagicMock()
judge.client = sentinel

llm_judge_scan("test prompt", api_key=RAW_OPEN, prior_layers_safe=True)
assert sentinel.chat.completions.create.call_count == 0, \
    f"Groq must not be called while circuit breaker is open — " \
    f"got {sentinel.chat.completions.create.call_count} call(s)"
print("  OK")


# ── Test 7: circuit breaker recovers after cooldown expires ──────────────────

print("Test 7: circuit breaker allows requests through after cooldown expires ...")
# Simulate cooldown already elapsed by backdating opened_at
with _breaker._lock:
    _breaker._consecutive_failures = CIRCUIT_BREAKER_THRESHOLD
    _breaker._opened_at = time.time() - CIRCUIT_BREAKER_COOLDOWN_S - 1

assert _breaker.is_open() is False, \
    "is_open() must return False once cooldown elapses — it should auto-reset state"

good_mock = safe_client()
judge.client = good_mock

result = llm_judge_scan("safe prompt", api_key=RAW_SAFE, prior_layers_safe=True)
assert good_mock.chat.completions.create.call_count >= 1, \
    "Groq must be called after circuit breaker recovers"
assert result.is_threat is False, \
    f"Expected SAFE result after recovery, got is_threat={result.is_threat}"
print("  OK")


# ── Cleanup ────────────────────────────────────────────────────────────────────

for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
    try:
        os.unlink(path)
    except OSError:
        pass

print("\nAll judge fail-mode tests passed. (7/7)")
