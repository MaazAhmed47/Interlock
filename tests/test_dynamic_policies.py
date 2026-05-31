"""
Tests for dynamic DB-backed policies (GAP 1).

Covers:
- policies table creation
- seed_default_policies: inserts defaults, never overwrites existing DB policies
- CRUD helpers: upsert_policy, get_policy, get_policy_by_name, list_policies, delete_policy
- rbac_scan fallback: hardcoded defaults used when DB policy is absent
- rbac_scan DB-first: DB policy used when present
"""

import json
import os
import sqlite3
import tempfile
import pytest

# Point at an in-memory / temp DB so tests don't touch the dev DB.
_TMP_DB = tempfile.mktemp(suffix=".db")
os.environ.setdefault("FIREWALL_DB_PATH", _TMP_DB)

from core import db  # noqa: E402  (env must be set first)
from core.policy import ROLE_POLICIES, rbac_scan  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    """Each test gets its own isolated SQLite DB."""
    db_path = str(tmp_path / "test.db")
    original = os.environ.get("FIREWALL_DB_PATH")
    os.environ["FIREWALL_DB_PATH"] = db_path
    db.DB_PATH = db_path
    db._pg_pool = None  # ensure no stale pool reference
    db.init_db()
    yield
    if original is not None:
        os.environ["FIREWALL_DB_PATH"] = original
    else:
        os.environ.pop("FIREWALL_DB_PATH", None)


# ── Table creation ────────────────────────────────────────────────────────────

def test_policies_table_exists():
    """The policies table must be created by init_db."""
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='policies'"
        ).fetchall()
    assert rows, "policies table was not created"


def test_policies_table_has_expected_columns():
    expected = {
        "id", "policy_type", "name", "server_id", "rules_json",
        "is_active", "created_at", "updated_at", "updated_by",
    }
    cols = set(db.table_columns("policies"))
    assert expected.issubset(cols), f"Missing columns: {expected - cols}"


# ── seed_default_policies ─────────────────────────────────────────────────────

def test_seed_inserts_defaults():
    defaults = {
        "support_agent": {"allowed_tools": ["read_crm"], "blocked_tools": ["delete"]},
        "finance_agent": {"allowed_tools": ["read_ledger"], "blocked_tools": ["execute_sql"]},
    }
    db.seed_default_policies(defaults, policy_type="role")
    policies = db.list_policies("role")
    names = {p["name"] for p in policies}
    assert "support_agent" in names
    assert "finance_agent" in names


def test_seed_does_not_overwrite_existing():
    """If a policy row already exists, seed must not touch it."""
    custom_rules = {"allowed_tools": ["custom_tool"], "blocked_tools": []}
    db.upsert_policy("role", "support_agent", json.dumps(custom_rules), updated_by="test")

    defaults = {"support_agent": {"allowed_tools": ["read_crm"], "blocked_tools": ["delete"]}}
    db.seed_default_policies(defaults, policy_type="role")

    row = db.get_policy_by_name("role", "support_agent")
    assert row is not None
    assert row["rules"]["allowed_tools"] == ["custom_tool"], (
        "seed_default_policies must not overwrite existing DB policies"
    )


def test_seed_idempotent():
    """Calling seed twice must not raise and must not duplicate rows."""
    defaults = {"readonly_agent": {"allowed_tools": ["read"], "blocked_tools": []}}
    db.seed_default_policies(defaults, policy_type="role")
    db.seed_default_policies(defaults, policy_type="role")
    policies = [p for p in db.list_policies("role") if p["name"] == "readonly_agent"]
    assert len(policies) == 1


# ── CRUD helpers ──────────────────────────────────────────────────────────────

def test_upsert_creates_policy():
    rules = {"allowed_tools": ["fetch"], "blocked_tools": []}
    saved = db.upsert_policy("role", "data_analyst", json.dumps(rules), updated_by="admin")
    assert saved is not None
    assert saved["name"] == "data_analyst"
    assert saved["rules"]["allowed_tools"] == ["fetch"]


def test_upsert_updates_existing_policy():
    rules_v1 = {"allowed_tools": ["fetch"]}
    db.upsert_policy("role", "data_analyst", json.dumps(rules_v1), updated_by="admin")

    rules_v2 = {"allowed_tools": ["fetch", "query"]}
    db.upsert_policy("role", "data_analyst", json.dumps(rules_v2), updated_by="admin")

    row = db.get_policy_by_name("role", "data_analyst")
    assert row is not None
    assert "query" in row["rules"]["allowed_tools"]


def test_get_policy_by_id():
    rules = {"blocked_tools": ["delete"]}
    saved = db.upsert_policy("tool", "refund_user", json.dumps(rules))
    assert saved is not None
    fetched = db.get_policy(saved["id"])
    assert fetched is not None
    assert fetched["name"] == "refund_user"
    assert fetched["policy_type"] == "tool"


def test_get_policy_by_id_missing():
    assert db.get_policy(99999) is None


def test_get_policy_by_name_not_found():
    assert db.get_policy_by_name("role", "nonexistent_role") is None


def test_get_policy_by_name_server_id_fallback():
    """Server-scoped lookup falls back to the unscoped policy."""
    rules = {"allowed_tools": ["search"]}
    db.upsert_policy("tool", "search_tool", json.dumps(rules), server_id="")

    row = db.get_policy_by_name("tool", "search_tool", server_id="my-server")
    assert row is not None
    assert row["rules"]["allowed_tools"] == ["search"]


def test_get_policy_by_name_server_id_exact_wins():
    """Exact server_id match takes priority over the unscoped fallback."""
    generic = {"allowed_tools": ["generic"]}
    scoped = {"allowed_tools": ["scoped"]}
    db.upsert_policy("tool", "my_tool", json.dumps(generic), server_id="")
    db.upsert_policy("tool", "my_tool", json.dumps(scoped), server_id="my-server")

    row = db.get_policy_by_name("tool", "my_tool", server_id="my-server")
    assert row is not None
    assert row["rules"]["allowed_tools"] == ["scoped"]


def test_list_policies_all():
    db.upsert_policy("role", "role_a", json.dumps({}))
    db.upsert_policy("tool", "tool_a", json.dumps({}))
    all_policies = db.list_policies()
    types = {p["policy_type"] for p in all_policies}
    assert "role" in types
    assert "tool" in types


def test_list_policies_filtered_by_type():
    db.upsert_policy("role", "role_a", json.dumps({}))
    db.upsert_policy("tool", "tool_a", json.dumps({}))
    role_policies = db.list_policies("role")
    assert all(p["policy_type"] == "role" for p in role_policies)


def test_delete_policy_soft_deletes():
    saved = db.upsert_policy("role", "temp_role", json.dumps({"allowed_tools": []}))
    assert saved is not None
    ok = db.delete_policy(saved["id"])
    assert ok
    row = db.get_policy_by_name("role", "temp_role")
    assert row is None, "Soft-deleted policy must not be returned by get_policy_by_name"


def test_delete_policy_missing_returns_false():
    assert db.delete_policy(99999) is False


# ── rbac_scan DB-first lookup ─────────────────────────────────────────────────

def test_rbac_scan_falls_back_to_hardcoded_when_no_db_policy():
    """When no DB policy exists, rbac_scan must use the hardcoded ROLE_POLICIES."""
    # Don't seed anything — the DB is empty.
    result = rbac_scan("read some data", "read_file", "readonly_agent")
    # readonly_agent allows read_file — should pass
    assert result is None


def test_rbac_scan_uses_db_policy_when_present():
    """When a DB policy exists for a role, rbac_scan must use it instead of the hardcoded one."""
    # Create a DB policy for support_agent that blocks 'read_crm' (opposite of default)
    custom_rules = {
        "allowed_tools": ["only_this_tool"],
        "blocked_tools": ["read_crm"],
        "blocked_keywords": [],
        "max_prompt_length": 9999,
        "description": "custom test policy",
    }
    db.upsert_policy("role", "support_agent", json.dumps(custom_rules), updated_by="test")

    # read_crm is in the default allowed list, but our DB policy blocks it
    result = rbac_scan("help customer", "read_crm", "support_agent")
    assert result is not None
    assert result.is_threat
    assert "RBAC_VIOLATION" in result.threat_type


def test_rbac_scan_unknown_role_still_blocked():
    """Unknown roles are denied regardless of DB state."""
    result = rbac_scan("some prompt", "some_tool", "ghost_role")
    assert result is not None
    assert result.is_threat
    assert "UNKNOWN_ROLE" in result.threat_type
