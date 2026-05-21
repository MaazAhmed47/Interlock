"""
Tests for policy_scan() DB-first behaviour (core/policy.py).

(a) Key with DB custom_policy  → DB policy enforced
(b) Key with no DB policy      → CUSTOM_POLICIES dict used as fallback
(c) Key in neither source      → None returned
(d) Key in both                → DB policy wins; dict policy ignored

Run: python tests/test_policy_db.py
"""
import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Isolate to a temp DB
_tmp_db = tempfile.mktemp(suffix="_policy_test.db")
import core.db as db
db.DB_PATH = _tmp_db
db.init_db()

from core.policy import policy_scan, CUSTOM_POLICIES

# ── Provision test keys in the temp DB ────────────────────────────────────────

# (a)/(d): key whose DB row has custom_policy set
k_db = db.generate_key("free", label="db-policy-key")
RAW_DB = k_db["raw_key"]
db.update_key(k_db["key_prefix"], custom_policy={
    "blocked_keywords": ["db_forbidden"],
    "max_prompt_length": 500,
})

# (b): key whose DB row has NO custom_policy — falls back to dict
k_dict = db.generate_key("free", label="dict-policy-key")
RAW_DICT = k_dict["raw_key"]
# intentionally not calling update_key with custom_policy

# (c): key with nothing anywhere
k_none = db.generate_key("free", label="no-policy-key")
RAW_NONE = k_none["raw_key"]

# Inject entries into the module-level CUSTOM_POLICIES for test isolation
CUSTOM_POLICIES[RAW_DICT] = {
    "blocked_keywords": ["dict_forbidden"],
    "max_prompt_length": 1000,
}
# Also add an entry for RAW_DB — DB policy must shadow this
CUSTOM_POLICIES[RAW_DB] = {
    "blocked_keywords": ["dict_word_that_must_be_ignored"],
    "max_prompt_length": 9999,
}

try:
    # ── (a) DB custom_policy is used ──────────────────────────────────────────

    print("Test 1: key with DB custom_policy — blocked keyword caught ...")
    result = policy_scan("this contains db_forbidden in the text", RAW_DB)
    assert result is not None, "Expected a block, got None"
    assert result.is_threat is True
    assert result.threat_type == "CUSTOM_POLICY_VIOLATION"
    assert "db_forbidden" in result.reason, f"Unexpected reason: {result.reason}"
    print(f"  OK — {result.reason}")

    print("Test 2: key with DB custom_policy — clean prompt passes through ...")
    result = policy_scan("this is a perfectly normal question", RAW_DB)
    assert result is None, f"Expected None for clean prompt, got {result}"
    print("  OK — None for clean prompt")

    print("Test 3: key with DB custom_policy — prompt over DB length limit blocked ...")
    long_prompt = "x" * 501  # DB limit is 500
    result = policy_scan(long_prompt, RAW_DB)
    assert result is not None, f"Expected block for 501-char prompt (DB limit=500)"
    assert result.threat_type == "CUSTOM_POLICY_VIOLATION"
    assert "500" in result.reason, f"Expected DB limit in reason: {result.reason}"
    print(f"  OK — {result.reason}")

    # ── (b) CUSTOM_POLICIES dict used as fallback ──────────────────────────────

    print("Test 4: key with no DB policy falls back to CUSTOM_POLICIES dict ...")
    result = policy_scan("this contains dict_forbidden in the text", RAW_DICT)
    assert result is not None, "Expected block from dict fallback, got None"
    assert result.is_threat is True
    assert "dict_forbidden" in result.reason, f"Unexpected reason: {result.reason}"
    print(f"  OK — {result.reason}")

    # ── (c) Neither source — returns None ────────────────────────────────────

    print("Test 5: key with no policy in DB or dict returns None ...")
    result = policy_scan(
        "prompt containing db_forbidden and dict_forbidden and dict_word_that_must_be_ignored",
        RAW_NONE,
    )
    assert result is None, f"Expected None for key with no policy, got {result}"
    print("  OK — None returned")

    # ── (d) DB policy takes precedence over dict ──────────────────────────────

    print("Test 6: DB policy wins — dict word not blocked, DB word is blocked ...")
    # RAW_DB has both a DB policy (blocks 'db_forbidden') and a dict entry
    # (blocks 'dict_word_that_must_be_ignored'). DB must win entirely.
    result_dict_word = policy_scan("this has dict_word_that_must_be_ignored in it", RAW_DB)
    assert result_dict_word is None, (
        f"Dict-only word must not be blocked when DB policy is present; got {result_dict_word}"
    )
    result_db_word = policy_scan("this has db_forbidden in it", RAW_DB)
    assert result_db_word is not None and result_db_word.is_threat is True, (
        f"DB-policy word must be blocked; got {result_db_word}"
    )
    print("  OK — DB word blocked, dict word not blocked")

finally:
    # Restore CUSTOM_POLICIES to avoid polluting other test runs in same process
    CUSTOM_POLICIES.pop(RAW_DICT, None)
    CUSTOM_POLICIES.pop(RAW_DB, None)

    for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass

print("\nAll policy DB tests passed. (6/6)")
