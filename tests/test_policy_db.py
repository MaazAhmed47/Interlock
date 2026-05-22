"""
Tests for policy_scan() DB-first behaviour (core/policy.py).

(a) Key with DB custom_policy  -> DB policy enforced
(b) Key with no DB policy      -> None returned
(c) Seeded legacy keys         -> policies are stored in the DB

Run: python tests/test_policy_db.py
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Isolate to a temp DB
_tmp_db = tempfile.mktemp(suffix="_policy_test.db")
import core.db as db

db.DB_PATH = _tmp_db
db.init_db()

from core.policy import policy_scan

# ── Provision test keys in the temp DB ────────────────────────────────────────

k_db = db.generate_key("free", label="db-policy-key")
RAW_DB = k_db["raw_key"]
db.update_key(k_db["key_prefix"], custom_policy={
    "blocked_keywords": ["db_forbidden"],
    "max_prompt_length": 500,
})

k_none = db.generate_key("free", label="no-policy-key")
RAW_NONE = k_none["raw_key"]

try:
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
    assert result is not None, "Expected block for 501-char prompt (DB limit=500)"
    assert result.threat_type == "CUSTOM_POLICY_VIOLATION"
    assert "500" in result.reason, f"Expected DB limit in reason: {result.reason}"
    print(f"  OK — {result.reason}")

    print("Test 4: key with no DB policy returns None ...")
    result = policy_scan("prompt containing db_forbidden", RAW_NONE)
    assert result is None, f"Expected None for key with no DB policy, got {result}"
    print("  OK — None returned")

    print("Test 5: seeded legacy keys store custom policies in the DB ...")
    db.seed_legacy_keys()
    legacy = db.lookup_key("lf-dev-key-456")
    assert legacy is not None, "Expected seeded developer legacy key"
    assert legacy.get("custom_policy"), "Expected legacy custom_policy to live in DB"
    result = policy_scan("this mentions confidential roadmap details", "lf-dev-key-456")
    assert result is not None, "Expected DB-seeded legacy policy to block confidential"
    assert "confidential" in result.reason
    print(f"  OK — {result.reason}")

finally:
    for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass

print("\nAll policy DB tests passed. (5/5)")
