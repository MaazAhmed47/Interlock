"""
Tests for the SQLite-backed API key store (core/db.py).

Covers: init_db, generate_key, lookup_key, revoke_key, update_key, list_keys,
        log_usage, usage_this_month, seed_legacy_keys idempotency, and the
        invariant that raw keys are never stored (only sha256 hashes).

Run: python test_db.py
"""
import sys, os, tempfile, hashlib
sys.path.insert(0, ".")

_tmp_db = tempfile.mktemp(suffix="_api_key_test.db")
import core.db as db
db.DB_PATH = _tmp_db
db.init_db()


# ── init_db ────────────────────────────────────────────────────────────────────

print("Test 1: init_db creates the api_keys and usage_log tables ...")
with db.get_conn() as conn:
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
assert "api_keys"  in tables, f"api_keys table missing after init_db: {tables}"
assert "usage_log" in tables, f"usage_log table missing after init_db: {tables}"
print("  OK")

print("Test 2: init_db is idempotent — calling twice preserves existing rows ...")
k_early = db.generate_key("free", label="pre-reinit")
db.init_db()
assert db.lookup_key(k_early["raw_key"]) is not None, \
    "Row created before re-init disappeared — CREATE TABLE IF NOT EXISTS must not wipe data"
print("  OK")


# ── generate_key ───────────────────────────────────────────────────────────────

print("Test 3: generate_key returns raw_key and key_prefix with correct plan defaults ...")
result = db.generate_key("free", label="test-free")
assert "raw_key" in result and result["raw_key"].startswith("lf_free_"), \
    f"Unexpected raw_key: {result.get('raw_key')}"
assert "key_prefix" in result and result["key_prefix"] == result["raw_key"][:12], \
    f"key_prefix must be first 12 chars: {result.get('key_prefix')}"
assert result["plan"] == "free"
RAW_FREE    = result["raw_key"]
FREE_PREFIX = result["key_prefix"]
print(f"  OK — {FREE_PREFIX}")

print("Test 4: generate_key stores plan-correct limits and fail_mode (developer plan) ...")
dev = db.generate_key("developer", label="test-dev")
rec = db.lookup_key(dev["raw_key"])
assert rec["monthly_limit"] == 50_000,          f"Wrong monthly_limit: {rec['monthly_limit']}"
assert rec["rate_per_min"]  == 60,              f"Wrong rate_per_min: {rec['rate_per_min']}"
assert rec["fail_mode"]     == "fail_open_safe", f"Wrong fail_mode: {rec['fail_mode']}"
print("  OK")

print("Test 5: generate_key raises ValueError for an unknown plan ...")
try:
    db.generate_key("gold_tier")
    assert False, "Expected ValueError"
except ValueError as exc:
    assert "gold_tier" in str(exc), f"Error message should name the bad plan: {exc}"
print("  OK")


# ── lookup_key ─────────────────────────────────────────────────────────────────

print("Test 6: lookup_key finds an active key by raw value ...")
rec = db.lookup_key(RAW_FREE)
assert rec is not None,          "lookup_key returned None for a known active key"
assert rec["label"]     == "test-free"
assert rec["plan"]      == "free"
assert rec["is_active"] == 1
print("  OK")

print("Test 7: lookup_key returns None for an unknown raw key ...")
assert db.lookup_key("lf_free_totally_unknown_xxxxxxxxxxx") is None
print("  OK")

print("Test 8: lookup_key returns None for empty or None input ...")
assert db.lookup_key("") is None
assert db.lookup_key(None) is None
print("  OK")


# ── revoke_key ─────────────────────────────────────────────────────────────────

print("Test 9: revoke_key deactivates the key; subsequent lookup returns None ...")
k = db.generate_key("free", label="to-revoke")
assert db.lookup_key(k["raw_key"]) is not None, "Key should be active before revoke"
ok = db.revoke_key(k["key_prefix"])
assert ok is True,                          f"revoke_key returned {ok}"
assert db.lookup_key(k["raw_key"]) is None, "lookup_key must return None after revoke"
print("  OK")

print("Test 10: revoke_key returns False for an already-revoked key ...")
assert db.revoke_key(k["key_prefix"]) is False
print("  OK")

print("Test 11: revoke_key returns False for an unknown prefix ...")
assert db.revoke_key("lf_free_no_such") is False
print("  OK")


# ── update_key ─────────────────────────────────────────────────────────────────

print("Test 12: update_key modifies editable scalar fields ...")
k2 = db.generate_key("free", label="to-update")
ok = db.update_key(k2["key_prefix"], label="new-label", webhook_url="https://hooks.example.com")
assert ok is True, f"update_key returned {ok}"
rec = db.lookup_key(k2["raw_key"])
assert rec["label"]       == "new-label",                 f"label not updated: {rec['label']}"
assert rec["webhook_url"] == "https://hooks.example.com", f"webhook_url not updated: {rec}"
print("  OK")

print("Test 13: update_key serialises custom_policy as JSON and round-trips correctly ...")
policy = {"blocked_keywords": ["forbidden", "secret"], "max_prompt_length": 512}
db.update_key(k2["key_prefix"], custom_policy=policy)
rec = db.lookup_key(k2["raw_key"])
assert rec["custom_policy"] == policy, f"custom_policy round-trip failed: {rec['custom_policy']}"
print("  OK")

print("Test 14: update_key returns False when only non-editable fields are passed ...")
result_bool = db.update_key(k2["key_prefix"], key_hash="not_allowed", id=999)
assert result_bool is False, f"Expected False when only non-editable fields given, got {result_bool}"
print("  OK")


# ── list_keys ──────────────────────────────────────────────────────────────────

print("Test 15: list_keys excludes revoked keys by default ...")
k_active  = db.generate_key("startup", label="stays-active")
k_revoked = db.generate_key("free",    label="gets-revoked")
db.revoke_key(k_revoked["key_prefix"])
active_prefixes = {r["key_prefix"] for r in db.list_keys()}
assert k_active["key_prefix"]  in active_prefixes, "Active key missing from default list"
assert k_revoked["key_prefix"] not in active_prefixes, "Revoked key must not appear in default list"
print("  OK")

print("Test 16: list_keys with include_inactive=True surfaces revoked keys ...")
all_prefixes = {r["key_prefix"] for r in db.list_keys(include_inactive=True)}
assert k_revoked["key_prefix"] in all_prefixes, "Revoked key must appear when include_inactive=True"
print("  OK")

print("Test 17: list_keys never exposes key_hash in any row ...")
for rec in db.list_keys(include_inactive=True):
    assert "key_hash" not in rec, f"key_hash leaked via list_keys: {list(rec.keys())}"
print("  OK")


# ── log_usage / usage_this_month ────────────────────────────────────────────────

print("Test 18: log_usage increments usage_this_month ...")
k3  = db.generate_key("free", label="usage-test")
rec3 = db.lookup_key(k3["raw_key"])
kid  = rec3["id"]
assert db.usage_this_month(kid) == 0, "Fresh key must start with 0 usage"
db.log_usage(kid, "/scan")
db.log_usage(kid, "/scan")
db.log_usage(kid, "/inspect/tool-call", threat_blocked=True)
assert db.usage_this_month(kid) == 3, \
    f"Expected 3 usage entries, got {db.usage_this_month(kid)}"
print("  OK")

print("Test 19: usage_this_month returns 0 for a key_id with no log entries ...")
assert db.usage_this_month(999_999) == 0
print("  OK")


# ── seed_legacy_keys ───────────────────────────────────────────────────────────

print("Test 20: seed_legacy_keys inserts the three hard-coded legacy keys ...")
db.seed_legacy_keys()
for raw in ("lf-free-demo-key-123", "lf-dev-key-456", "lf-startup-key-789"):
    assert db.lookup_key(raw) is not None, f"Legacy key {raw[:12]}... not found after seed"
print("  OK")

print("Test 21: seed_legacy_keys is idempotent — calling twice keeps exactly 3 legacy rows ...")
db.seed_legacy_keys()
legacy_rows = [
    r for r in db.list_keys(include_inactive=True)
    if r["label"] in ("Legacy free demo", "Legacy developer", "Legacy startup")
]
assert len(legacy_rows) == 3, \
    f"Expected exactly 3 legacy rows, got {len(legacy_rows)}: {[r['label'] for r in legacy_rows]}"
print("  OK")


# ── Key hashing ────────────────────────────────────────────────────────────────

print("Test 22: raw key is never stored — DB holds only the sha256 hash ...")
k4 = db.generate_key("free", label="hash-check")
raw4 = k4["raw_key"]
expected_hash = hashlib.sha256(raw4.encode()).hexdigest()
with db.get_conn() as conn:
    row = conn.execute(
        "SELECT * FROM api_keys WHERE key_prefix = ?", (k4["key_prefix"],)
    ).fetchone()
assert row is not None, "Key row not found via direct SQL query"
stored_hash = row["key_hash"]
assert stored_hash == expected_hash, \
    f"Hash mismatch: stored={stored_hash[:16]}… expected={expected_hash[:16]}…"
for col in row.keys():
    val = row[col]
    assert val != raw4, f"Raw key found verbatim in column '{col}' — must never store raw keys"
print("  OK — only sha256 hash stored, raw key absent from every column")


# ── Cleanup ────────────────────────────────────────────────────────────────────

for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
    try:
        os.unlink(path)
    except OSError:
        pass

print("\nAll DB tests passed. (22/22)")
