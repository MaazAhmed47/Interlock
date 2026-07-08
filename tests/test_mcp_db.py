"""
Tests for SQLite-backed MCP server registry (mcp_servers table in db.py).
Covers: seeding, idempotency, CRUD, verify flag, persistence across restarts.

Run: python tests/test_mcp_db.py
"""
import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Isolate to a temp DB — must be set before any db functions run
_tmp_db = tempfile.mktemp(suffix="_mcp_test.db")
import core.db as db
db.DB_PATH = _tmp_db

db.init_db()
db.seed_mcp_servers()

# ── Seeding ────────────────────────────────────────────────────────────────────

print("Test 1: seeded servers appear after init ...")
fs = db.lookup_mcp_server("trusted-filesystem")
assert fs is not None, "trusted-filesystem not found after seed"
assert fs["verified"] is True, f"Expected verified=True, got {fs['verified']}"
assert "read_file" in fs["allowed_tools"], f"Expected read_file in allowed_tools: {fs}"
assert "write_file" in fs["blocked_tools"], f"Expected write_file in blocked_tools: {fs}"

srch = db.lookup_mcp_server("trusted-search")
assert srch is not None, "trusted-search not found after seed"
assert srch["verified"] is True, f"Expected verified=True, got {srch['verified']}"
assert "search" in srch["allowed_tools"], f"Expected search in allowed_tools: {srch}"
print("  OK")

print("Test 2: seed_mcp_servers is idempotent (safe to call twice) ...")
db.seed_mcp_servers()
all_seeds = [s for s in db.list_mcp_servers()
             if s["server_id"] in ("trusted-filesystem", "trusted-search")]
assert len(all_seeds) == 2, f"Expected exactly 2 seed servers, got {[s['server_id'] for s in all_seeds]}"
print("  OK")

# ── Register / lookup ──────────────────────────────────────────────────────────

print("Test 3: register new server, look it up, config matches ...")
ok = db.register_mcp_server("my-tools", {
    "url": "http://localhost:4000/mcp",
    "description": "Custom tool server",
    "allowed_tools": ["tool_a", "tool_b"],
    "blocked_tools": ["danger_tool"],
    "rate_limit": 120,
})
assert ok is True, f"register_mcp_server returned {ok} for new server"

rec = db.lookup_mcp_server("my-tools")
assert rec is not None, "lookup returned None for just-registered server"
assert rec["url"] == "http://localhost:4000/mcp"
assert rec["description"] == "Custom tool server"
assert rec["allowed_tools"] == ["tool_a", "tool_b"]
assert rec["blocked_tools"] == ["danger_tool"]
assert rec["rate_limit"] == 120
assert rec["verified"] is False, f"New servers must default to unverified, got {rec['verified']}"
print(f"  OK — {rec['server_id']}")

print("Test 4: duplicate server_id returns False ...")
ok2 = db.register_mcp_server("my-tools", {"url": "http://other.example.com/mcp"})
assert ok2 is False, f"Expected False for duplicate server_id, got {ok2}"
# Original record must be unchanged
rec2 = db.lookup_mcp_server("my-tools")
assert rec2["url"] == "http://localhost:4000/mcp", "Duplicate insert must not overwrite"
print("  OK")

# ── list_mcp_servers ───────────────────────────────────────────────────────────

print("Test 5: list_mcp_servers includes all registered servers ...")
all_servers = db.list_mcp_servers()
ids = {s["server_id"] for s in all_servers}
assert "trusted-filesystem" in ids, f"trusted-filesystem missing from list: {ids}"
assert "trusted-search" in ids, f"trusted-search missing from list: {ids}"
assert "my-tools" in ids, f"my-tools missing from list: {ids}"
print(f"  OK — {len(all_servers)} servers total")

# ── verify_mcp_server ──────────────────────────────────────────────────────────

print("Test 6: verify_mcp_server sets verified=True ...")
result = db.verify_mcp_server("my-tools")
assert result is True, f"verify_mcp_server returned {result}"
rec = db.lookup_mcp_server("my-tools")
assert rec["verified"] is True, f"Expected verified=True after verify, got {rec['verified']}"
print("  OK")

print("Test 7: verify non-existent server returns False ...")
result = db.verify_mcp_server("does-not-exist")
assert result is False, f"Expected False for non-existent server, got {result}"
print("  OK")

# ── unregister_mcp_server ──────────────────────────────────────────────────────

print("Test 8: unregister removes the server ...")
removed = db.unregister_mcp_server("my-tools")
assert removed is True, f"Expected True from unregister, got {removed}"
gone = db.lookup_mcp_server("my-tools")
assert gone is None, f"Expected None after unregister, got {gone}"
print("  OK")

print("Test 9: unregister non-existent server returns False ...")
removed2 = db.unregister_mcp_server("does-not-exist")
assert removed2 is False, f"Expected False for missing server, got {removed2}"
print("  OK")

# ── Persistence across simulated restart ──────────────────────────────────────

print("Test 10: data persists across simulated restart (init_db must not wipe rows) ...")
db.register_mcp_server("persistent-server", {
    "url": "http://localhost:5000/mcp",
    "description": "Persistence test",
    "allowed_tools": ["ping"],
    "blocked_tools": [],
    "rate_limit": 10,
})
# Simulate restart: re-run init_db on the same file
db.init_db()
rec = db.lookup_mcp_server("persistent-server")
assert rec is not None, "Server was lost after simulated restart — CREATE TABLE IF NOT EXISTS must not drop data"
assert rec["url"] == "http://localhost:5000/mcp"
print("  OK — data survived restart")

print("Test 11: registry classification hides disposable and unapproved demo servers ...")
db.register_mcp_server("m14", {
    "url": "http://localhost:8787/mcp",
    "description": "Drift matrix fixture",
    "allowed_tools": ["payments"],
    "blocked_tools": [],
    "rate_limit": 10,
})
db.register_mcp_server("asmi-demo", {
    "url": "https://broen.tech/api/asmi/mcp",
    "description": "Third-party hosted server",
    "allowed_tools": ["read_document"],
    "blocked_tools": [],
    "rate_limit": 10,
})
fixture = db.lookup_mcp_server("m14")
external = db.lookup_mcp_server("asmi-demo")
assert fixture["registry_class"] == "disposable_fixture"
assert fixture["demo_visible"] is False
assert external["registry_class"] == "external_unapproved"
assert external["demo_visible"] is False
visible_ids = {s["server_id"] for s in db.list_mcp_servers(demo_visible_only=True)}
assert "m14" not in visible_ids
assert "asmi-demo" not in visible_ids
print("  OK")

# ── Cleanup ────────────────────────────────────────────────────────────────────

for path in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
    try:
        os.unlink(path)
    except OSError:
        pass

print("\nAll MCP DB tests passed. (11/11)")
