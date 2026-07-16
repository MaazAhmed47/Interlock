"""
Atomic CAS rebaseline on real Postgres (not SQLite alone).

What only Postgres can prove: the promote transaction's per-server
advisory-lock serialization across connections that do NOT share the
process-local ``_db_lock`` (like N replicas), true transactional rollback of
the multi-statement promote, and psycopg2 type/parameter behavior for the
new candidate/version tables. These tests run against a disposable Postgres:

  docker run -d --name interlock-v3-pg -e POSTGRES_PASSWORD=v3pw \
      -p 54333:5432 postgres:16
  INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:v3pw@127.0.0.1:54333/postgres \
      python -m pytest tests/test_postgres_rebaseline_cas.py

Skipped when the env var is absent (same convention as the other PG suites).
"""

import asyncio
import importlib
import json
import os
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DB_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
DB_URL = os.getenv(DB_URL_ENV)

pytestmark = pytest.mark.skipif(
    not DB_URL,
    reason=f"{DB_URL_ENV} not set; rebaseline CAS tests need a disposable Postgres",
)

SERVER_ID = "_pg_rebaseline_cas_server"

TOOL_A = {
    "name": "list_avatars",
    "description": "List avatars.",
    "inputSchema": {"type": "object", "properties": {}},
}
TOOL_B = {
    "name": "read_document",
    "description": "Read one document.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}
TOOL_C = {
    "name": "send_summary",
    "description": "Send a summary email to the requesting user.",
    "inputSchema": {
        "type": "object",
        "properties": {"summary": {"type": "string"}},
        "required": ["summary"],
    },
}
TOOL_CONTENT_C = {
    "name": "read_document",
    "description": "Read one document.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
    "annotations": {
        "readOnlyHint": True,
        "destructiveHint": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
}
TOOL_CONTENT_ANNOTATIONS_D = {
    **TOOL_CONTENT_C,
    "annotations": {
        "readOnlyHint": False,
        "destructiveHint": True,
        "openWorldHint": True,
    },
}
TOOL_CONTENT_OUTPUT_D = {
    **TOOL_CONTENT_C,
    "outputSchema": {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "external_url": {"type": "string"},
        },
        "required": ["text", "external_url"],
    },
}
CONTENT_METADATA_C = {
    "side_effect": "read_only",
    "data_classes": ["internal"],
    "custom": {"alpha": 1, "beta": 2},
}
CONTENT_METADATA_D = {
    **CONTENT_METADATA_C,
    "side_effect": "destructive",
}

ACTOR = {"reviewer": "ops (key:lf-pg)", "principal_id": "lf-pg"}


def _content_entry(tool=TOOL_CONTENT_C, metadata=CONTENT_METADATA_C):
    return {"tool": tool, "normalized_metadata": metadata}


@pytest.fixture(scope="module")
def pg_db():
    """Reset rebaseline state, then re-import core.db on Postgres."""
    import psycopg2

    raw = psycopg2.connect(DB_URL)
    raw.autocommit = True
    with raw.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS mcp_rebaseline_candidates CASCADE")
        cur.execute("DROP TABLE IF EXISTS mcp_baseline_versions CASCADE")
    raw.close()

    os.environ["DATABASE_URL"] = DB_URL
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"

    import core.db as db

    db = importlib.reload(db)
    assert db.USE_POSTGRES, "test must exercise the Postgres path"
    db.init_db()
    yield db

    os.environ.pop("DATABASE_URL", None)
    importlib.reload(db)


@pytest.fixture(autouse=True)
def clean_state(pg_db):
    with pg_db.get_conn() as conn:
        conn.execute("DELETE FROM mcp_rebaseline_candidates")
        conn.execute("DELETE FROM mcp_baseline_versions")
        conn.execute("DELETE FROM mcp_tool_metadata")
        conn.execute("DELETE FROM mcp_audit_log")
        conn.execute("DELETE FROM audit_chain_checkpoints")
        conn.execute(
            "DELETE FROM mcp_servers WHERE server_id = ?",
            (SERVER_ID,),
        )
    pg_db.register_mcp_server(
        SERVER_ID,
        {
            "url": "http://localhost:9781/mcp",
            "description": "PG rebaseline CAS test server",
            "allowed_tools": [],
            "blocked_tools": [],
            "rate_limit": 10,
        },
    )
    pg_db.verify_mcp_server(SERVER_ID)
    yield
    pg_db.unregister_mcp_server(SERVER_ID)


def _validated(pg_db, tools):
    from core.mcp_gateway import validate_mcp_tool_definition

    out = []
    for tool in tools:
        validation = validate_mcp_tool_definition(tool)
        assert not validation.is_threat
        out.append(
            {"tool": tool, "normalized_metadata": validation.tool_metadata or {}}
        )
    return out


def _seed_baseline(pg_db, tools):
    for entry in _validated(pg_db, tools):
        pg_db.upsert_mcp_tool_metadata(
            SERVER_ID, entry["tool"], entry["normalized_metadata"]
        )
    return pg_db.get_active_baseline(SERVER_ID)


def _server_state_counts(pg_db):
    with pg_db.get_conn() as conn:
        tables = (
            "mcp_servers",
            "mcp_tool_metadata",
            "mcp_rebaseline_candidates",
            "mcp_baseline_versions",
        )
        counts = {
            table: int(
                dict(
                    conn.execute(
                        f"SELECT COUNT(*) AS n FROM {table} WHERE server_id = ?",
                        (SERVER_ID,),
                    ).fetchone()
                )["n"]
            )
            for table in tables
        }
        counts["rebaseline_audit"] = int(
            dict(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM mcp_audit_log "
                    "WHERE server_id = ? AND action = 'rebaseline'",
                    (SERVER_ID,),
                ).fetchone()
            )["n"]
        )
    return counts


def test_migration_creates_rebaseline_tables(pg_db):
    with pg_db.get_conn() as conn:
        for table in ("mcp_rebaseline_candidates", "mcp_baseline_versions"):
            row = conn.execute(
                """
                SELECT COUNT(*) AS n FROM information_schema.tables
                 WHERE table_schema = current_schema() AND table_name = ?
                """,
                (table,),
            ).fetchone()
            assert dict(row)["n"] == 1, f"{table} must exist"


@pytest.mark.parametrize(
    ("changed_entry", "mutation"),
    [
        (_content_entry(TOOL_CONTENT_ANNOTATIONS_D), "annotation_only"),
        (_content_entry(TOOL_CONTENT_OUTPUT_D), "output_schema_only"),
        (_content_entry(metadata=CONTENT_METADATA_D), "normalized_metadata_only"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_rebaseline_candidate_hash_covers_complete_content_on_postgres(
    pg_db, changed_entry, mutation
):
    first = pg_db.save_rebaseline_candidate(
        SERVER_ID, [_content_entry()], f"ops-{mutation}-c"
    )
    second = pg_db.save_rebaseline_candidate(
        SERVER_ID, [changed_entry], f"ops-{mutation}-d"
    )
    assert (
        first["candidate_surface_hash"] != second["candidate_surface_hash"]
    ), f"{mutation} candidate content must not alias on Postgres"


def test_rebaseline_content_canonical_order_is_stable_on_postgres(pg_db):
    reordered_tool = {
        "outputSchema": {
            "required": ["text"],
            "properties": {"text": {"type": "string"}},
            "type": "object",
        },
        "annotations": {"destructiveHint": False, "readOnlyHint": True},
        "inputSchema": {
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
            "type": "object",
        },
        "description": "Read one document.",
        "name": "read_document",
    }
    reordered_metadata = {
        "custom": {"beta": 2, "alpha": 1},
        "data_classes": ["internal"],
        "side_effect": "read_only",
    }
    first = pg_db.save_rebaseline_candidate(
        SERVER_ID,
        [_content_entry(), _content_entry(TOOL_A, {"z": 3, "a": 1})],
        "ops",
    )
    second = pg_db.save_rebaseline_candidate(
        SERVER_ID,
        [
            _content_entry(TOOL_A, {"a": 1, "z": 3}),
            _content_entry(reordered_tool, reordered_metadata),
        ],
        "ops",
    )
    assert first["candidate_surface_hash"] == second["candidate_surface_hash"]
    assert first["canonical_surface"] == second["canonical_surface"]


@pytest.mark.parametrize(
    ("newer_tool", "mutation"),
    [
        (TOOL_CONTENT_ANNOTATIONS_D, "annotation_only"),
        (TOOL_CONTENT_OUTPUT_D, "output_schema_only"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_route_exact_candidate_hash_returns_409_on_postgres(
    pg_db, newer_tool, mutation
):
    import proxy

    active = _seed_baseline(pg_db, [TOOL_A])
    candidate_c = pg_db.save_rebaseline_candidate(
        SERVER_ID, [_content_entry()], f"ops-{mutation}-c"
    )
    candidate_d = pg_db.save_rebaseline_candidate(
        SERVER_ID, [_content_entry(newer_tool)], f"ops-{mutation}-d"
    )
    assert (
        candidate_c["candidate_surface_hash"] != candidate_d["candidate_surface_hash"]
    )

    with patch(
        "routes.mcp.proxy.require_scope",
        return_value=({"key_prefix": "lf-pg", "label": "ops"}, None),
    ):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                proxy.mcp_rebaseline_server(
                    SERVER_ID,
                    request=proxy.MCPRebaselineRequest(
                        confirm_rebaseline=True,
                        expected_current_hash=active["surface_hash"],
                        expected_candidate_hash=candidate_c["candidate_surface_hash"],
                    ),
                    x_api_key="test",
                )
            )
    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "stale_rebaseline_state"
    assert (
        pg_db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        == candidate_d["candidate_surface_hash"]
    )


@pytest.mark.parametrize(
    ("changed_tool", "changed_metadata", "mutation"),
    [
        (TOOL_CONTENT_ANNOTATIONS_D, CONTENT_METADATA_C, "annotation_only"),
        (TOOL_CONTENT_OUTPUT_D, CONTENT_METADATA_C, "output_schema_only"),
        (TOOL_CONTENT_C, CONTENT_METADATA_D, "normalized_metadata_only"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_active_content_change_invalidates_expected_current_hash_on_postgres(
    pg_db, changed_tool, changed_metadata, mutation
):
    pg_db.upsert_mcp_tool_metadata(SERVER_ID, TOOL_CONTENT_C, CONTENT_METADATA_C)
    reviewed_active = pg_db.get_active_baseline(SERVER_ID)
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_C]), "ops"
    )

    pg_db.upsert_mcp_tool_metadata(SERVER_ID, changed_tool, changed_metadata)
    current_active = pg_db.get_active_baseline(SERVER_ID)
    assert (
        reviewed_active["surface_hash"] != current_active["surface_hash"]
    ), f"{mutation} active content must invalidate Postgres expected_current_hash"

    result = pg_db.promote_rebaseline_candidate(
        SERVER_ID,
        reviewed_active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert result["ok"] is False, result
    assert result["error"] == "stale_rebaseline_state"
    assert (
        pg_db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        == candidate["candidate_surface_hash"]
    )


def test_cas_promote_succeeds_and_preserves_history_on_postgres(pg_db):
    active = _seed_baseline(pg_db, [TOOL_A, TOOL_B])
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_A, TOOL_C]), "ops"
    )

    result = pg_db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert result["ok"] is True, result

    new_active = pg_db.get_active_baseline(SERVER_ID)
    assert new_active["surface_hash"] == candidate["candidate_surface_hash"]
    assert pg_db.get_rebaseline_candidate(SERVER_ID) is None

    versions = pg_db.list_baseline_versions(SERVER_ID)
    assert len(versions) == 2
    assert versions[0]["surface_hash"] == active["surface_hash"]
    assert versions[0]["replaced_at"] is not None
    assert versions[1]["surface_hash"] == candidate["candidate_surface_hash"]
    assert versions[1]["replaced_at"] is None
    assert versions[1]["approval_audit_id"] == result["audit"]["audit_id"]

    assert (
        pg_db.verify_mcp_audit_record(result["audit"]["audit_id"])["chain_verified"]
        is True
    )
    assert pg_db.verify_audit_chain()["valid"] is True


def test_promote_history_and_audit_commit_full_content_on_postgres(pg_db):
    pg_db.upsert_mcp_tool_metadata(SERVER_ID, TOOL_CONTENT_C, CONTENT_METADATA_C)
    active = pg_db.get_active_baseline(SERVER_ID)
    candidate_tool = {
        **TOOL_CONTENT_OUTPUT_D,
        "annotations": TOOL_CONTENT_ANNOTATIONS_D["annotations"],
    }
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID,
        [_content_entry(candidate_tool, CONTENT_METADATA_D)],
        "ops",
    )

    result = pg_db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert result["ok"] is True, result

    versions = pg_db.list_baseline_versions(SERVER_ID)
    assert versions[0]["surface_hash"] == active["surface_hash"]
    assert versions[0]["canonical_surface"] == active["canonical_surface"]
    assert versions[1]["surface_hash"] == candidate["candidate_surface_hash"]
    assert versions[1]["canonical_surface"] == candidate["canonical_surface"]

    canonical = json.loads(versions[1]["canonical_surface"])
    assert canonical[0]["tool"] == candidate_tool
    assert canonical[0]["normalized_metadata"] == CONTENT_METADATA_D

    audit = pg_db.get_mcp_audit_log(result["audit"]["audit_id"])
    assert audit["drift_baseline_hash"] == active["surface_hash"]
    assert audit["drift_current_hash"] == candidate["candidate_surface_hash"]
    assert pg_db.verify_mcp_audit_record(audit["id"])["chain_verified"] is True


def test_stale_hashes_are_rejected_on_postgres(pg_db):
    active = _seed_baseline(pg_db, [TOOL_A])
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_B]), "ops"
    )

    stale_current = pg_db.promote_rebaseline_candidate(
        SERVER_ID,
        "sha256:" + "f" * 64,
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert stale_current["ok"] is False
    assert stale_current["error"] == "stale_rebaseline_state"

    # a newer discovery invalidates the reviewed candidate
    pg_db.save_rebaseline_candidate(SERVER_ID, _validated(pg_db, [TOOL_C]), "ops")
    stale_candidate = pg_db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert stale_candidate["ok"] is False
    assert stale_candidate["error"] == "stale_rebaseline_state"

    assert (
        pg_db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]
    )
    assert pg_db.list_baseline_versions(SERVER_ID) == []


class _NoOpLock:
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _advisory_waiters(pg_db) -> int:
    """How many sessions are currently WAITING on an advisory lock."""
    with pg_db.get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM pg_locks "
            "WHERE locktype = 'advisory' AND NOT granted"
        ).fetchone()
    return int(dict(row)["n"])


def _wait_for(predicate, timeout=10.0, interval=0.05):
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_discovery_wins_first_old_approval_is_stale_on_postgres(pg_db, monkeypatch):
    """Interleaving (a): a newer discovery stages D before the approval of C
    lands. The approval must be rejected stale (the route maps this to 409)
    and D must remain staged."""
    monkeypatch.setattr(pg_db, "_db_lock", _NoOpLock())
    active = _seed_baseline(pg_db, [TOOL_A])
    candidate_c = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_B]), "ops"
    )
    candidate_d = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_C]), "ops"
    )

    result = pg_db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate_c["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert result["ok"] is False, result
    assert result["error"] == "stale_rebaseline_state"
    assert result["candidate_surface_hash"] == candidate_d["candidate_surface_hash"]

    # D staged, baseline unchanged, no partial history/audit state
    staged = pg_db.get_rebaseline_candidate(SERVER_ID)
    assert staged["candidate_surface_hash"] == candidate_d["candidate_surface_hash"]
    assert (
        pg_db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]
    )
    assert pg_db.list_baseline_versions(SERVER_ID) == []
    assert pg_db.verify_audit_chain()["valid"] is True


def _run_writer_blocked_during_promote(pg_db, monkeypatch, writer):
    """Drive interleaving (b) deterministically: a promote holds the
    per-server lock mid-transaction (at the replace seam) on one pool
    connection; ``writer`` runs on another connection with no shared process
    lock and must WAIT on the advisory lock (observed via pg_locks), then
    apply AFTER the promote commits. Returns the promote result."""
    monkeypatch.setattr(pg_db, "_db_lock", _NoOpLock())
    active = _seed_baseline(pg_db, [TOOL_A])
    candidate_c = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_B]), "ops"
    )

    promote_at_seam = threading.Event()
    release_promote = threading.Event()
    writer_done = threading.Event()
    real_replace = pg_db._replace_tool_metadata_from_candidate

    def holding_replace(conn, server_id, candidate_row):
        promote_at_seam.set()
        assert release_promote.wait(timeout=15), "test deadlock: never released"
        return real_replace(conn, server_id, candidate_row)

    monkeypatch.setattr(pg_db, "_replace_tool_metadata_from_candidate", holding_replace)

    outcome = {}

    def promote():
        outcome["promote"] = pg_db.promote_rebaseline_candidate(
            SERVER_ID,
            active["surface_hash"],
            candidate_c["candidate_surface_hash"],
            actor=ACTOR,
        )

    def run_writer():
        writer()
        writer_done.set()

    promote_thread = threading.Thread(target=promote)
    promote_thread.start()
    assert promote_at_seam.wait(timeout=15), "promote never reached the seam"

    writer_thread = threading.Thread(target=run_writer)
    writer_thread.start()

    # Deterministic blocking proof: the writer must show up as an ungranted
    # advisory-lock waiter and must NOT complete while the promote holds the
    # per-server lock.
    assert _wait_for(
        lambda: _advisory_waiters(pg_db) > 0
    ), "writer never blocked on the rebaseline advisory lock"
    assert not writer_done.is_set(), "writer ran during an in-flight promotion"

    release_promote.set()
    promote_thread.join(timeout=30)
    assert _wait_for(writer_done.is_set), "writer never completed after promote"
    writer_thread.join(timeout=30)
    monkeypatch.undo()

    assert outcome["promote"]["ok"] is True, outcome["promote"]
    return active, candidate_c


def test_promotion_wins_first_new_discovery_waits_and_is_not_lost_on_postgres(
    pg_db, monkeypatch
):
    """Interleaving (b) for candidate staging: discovery D arrives while the
    approval of C is mid-transaction. D must wait for the lock and stage
    AFTER the promotion — never be consumed by it."""
    validated_d = _validated(pg_db, [TOOL_C])
    staged_result = {}

    def stage_d():
        staged_result.update(
            pg_db.save_rebaseline_candidate(SERVER_ID, validated_d, "ops")
        )

    active, candidate_c = _run_writer_blocked_during_promote(
        pg_db, monkeypatch, stage_d
    )

    # C was promoted; D was staged afterwards and is NOT lost
    assert (
        pg_db.get_active_baseline(SERVER_ID)["surface_hash"]
        == candidate_c["candidate_surface_hash"]
    )
    staged = pg_db.get_rebaseline_candidate(SERVER_ID)
    assert staged is not None, "candidate D was silently lost"
    from core import drift_evidence

    assert staged["candidate_surface_hash"] == drift_evidence.rebaseline_content_hash(
        _validated(pg_db, [TOOL_C])
    )
    assert staged_result["active_surface_hash"] == candidate_c["candidate_surface_hash"]
    versions = pg_db.list_baseline_versions(SERVER_ID)
    assert len(versions) == 2
    assert versions[1]["replaced_at"] is None
    assert pg_db.verify_audit_chain()["valid"] is True


def test_review_snapshot_waits_for_promote_and_is_coherent_on_postgres(
    pg_db, monkeypatch
):
    captured = {}

    def read_snapshot():
        captured.update(pg_db.get_rebaseline_review_snapshot(SERVER_ID))

    _active, candidate = _run_writer_blocked_during_promote(
        pg_db, monkeypatch, read_snapshot
    )

    assert captured["ok"] is True
    assert captured["active"]["surface_hash"] == candidate["candidate_surface_hash"]
    assert captured["candidate"] is None
    assert len(captured["versions"]) == 2
    assert (
        captured["versions"][-1]["surface_hash"] == candidate["candidate_surface_hash"]
    )
    assert captured["versions"][-1]["replaced_at"] is None


def test_ordinary_discovery_upsert_waits_for_promote_and_applies_after(
    pg_db, monkeypatch
):
    """Interleaving (b) for the active surface: an ordinary discovery upsert
    arrives mid-promotion. It must wait on the same per-server lock and then
    apply ON TOP of the new baseline — never interleave inside the promote
    where the replace step would silently clobber it."""
    changed_tool_c = {
        **TOOL_C,
        "inputSchema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "recipient": {"type": "string"},
            },
            "required": ["summary", "recipient"],
        },
    }
    validated = _validated(pg_db, [changed_tool_c])[0]

    def upsert_changed():
        pg_db.upsert_mcp_tool_metadata(
            SERVER_ID, validated["tool"], validated["normalized_metadata"]
        )

    _active, candidate_c = _run_writer_blocked_during_promote(
        pg_db, monkeypatch, upsert_changed
    )

    # candidate_c contained TOOL_B only; the upsert added changed TOOL_C after
    # the promote, so the row must exist with the UPSERT's definition — not
    # have vanished under the replace.
    import json as _json

    with pg_db.get_conn() as conn:
        row = conn.execute(
            "SELECT raw_tool_definition FROM mcp_tool_metadata "
            "WHERE server_id = ? AND tool_name = ?",
            (SERVER_ID, "send_summary"),
        ).fetchone()
    assert row is not None, "post-promote upsert was silently lost"
    assert dict(row)["raw_tool_definition"] == _json.dumps(changed_tool_c)
    assert pg_db.verify_audit_chain()["valid"] is True


def test_quarantine_waits_for_promote_and_is_not_silently_lost_on_postgres(
    pg_db, monkeypatch
):
    """A status writer that updates the old row while promotion is paused
    before its delete/reinsert can report success and then be wiped. Prove
    the server advisory lock, not the process-local lock, prevents that."""
    changed_tool_a = {**TOOL_A, "description": "List approved avatars."}
    active = _seed_baseline(pg_db, [TOOL_A])
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [changed_tool_a]), "ops"
    )
    monkeypatch.setattr(pg_db, "_db_lock", _NoOpLock())
    monkeypatch.setattr(pg_db, "log_mcp_audit_event", lambda _event: {})

    promote_at_seam = threading.Event()
    release_promote = threading.Event()
    quarantine_done = threading.Event()
    real_replace = pg_db._replace_tool_metadata_from_candidate
    results = {}
    errors = []

    def holding_replace(conn, server_id, candidate_row):
        promote_at_seam.set()
        if not release_promote.wait(timeout=15):
            raise RuntimeError("test deadlock: promotion was not released")
        return real_replace(conn, server_id, candidate_row)

    monkeypatch.setattr(pg_db, "_replace_tool_metadata_from_candidate", holding_replace)

    def promote():
        try:
            results["promote"] = pg_db.promote_rebaseline_candidate(
                SERVER_ID,
                active["surface_hash"],
                candidate["candidate_surface_hash"],
                actor=ACTOR,
            )
        except BaseException as exc:
            errors.append(exc)

    def quarantine():
        try:
            results["quarantine"] = pg_db.quarantine_mcp_tool(
                SERVER_ID, TOOL_A["name"], reviewer="ops"
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            quarantine_done.set()

    promote_thread = threading.Thread(target=promote)
    quarantine_thread = threading.Thread(target=quarantine)
    promote_thread.start()
    assert promote_at_seam.wait(timeout=15), "promotion never reached replace seam"
    quarantine_thread.start()
    try:
        quarantine_finished_inside_promote = quarantine_done.wait(timeout=2)
    finally:
        release_promote.set()
        promote_thread.join(timeout=30)
        quarantine_thread.join(timeout=30)

    assert (
        not quarantine_finished_inside_promote
    ), "quarantine updated the old row inside promotion and can be overwritten"
    assert not promote_thread.is_alive() and not quarantine_thread.is_alive()
    assert errors == []
    assert results["promote"]["ok"] is True
    assert results["quarantine"]["ok"] is True
    stored = pg_db.lookup_mcp_tool_metadata(SERVER_ID, TOOL_A["name"])
    assert stored["status"] == "quarantined"
    assert "operator_quarantine" in stored["drift_types"]


def test_metadata_rederivation_waits_for_promote_and_reads_promoted_row_on_postgres(
    pg_db, monkeypatch
):
    from core.tool_metadata import normalize_tool_metadata

    active = _seed_baseline(pg_db, [TOOL_CONTENT_C])
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID,
        [{"tool": TOOL_CONTENT_ANNOTATIONS_D, "normalized_metadata": {}}],
        "ops",
    )
    monkeypatch.setattr(pg_db, "_db_lock", _NoOpLock())

    promote_at_seam = threading.Event()
    release_promote = threading.Event()
    rederive_done = threading.Event()
    real_replace = pg_db._replace_tool_metadata_from_candidate
    results = {}
    errors = []

    def holding_replace(conn, server_id, candidate_row):
        promote_at_seam.set()
        if not release_promote.wait(timeout=15):
            raise RuntimeError("test deadlock: promotion was not released")
        return real_replace(conn, server_id, candidate_row)

    monkeypatch.setattr(pg_db, "_replace_tool_metadata_from_candidate", holding_replace)

    def promote():
        try:
            results["promote"] = pg_db.promote_rebaseline_candidate(
                SERVER_ID,
                active["surface_hash"],
                candidate["candidate_surface_hash"],
                actor=ACTOR,
            )
        except BaseException as exc:
            errors.append(exc)

    def rederive():
        try:
            results["rederive"] = pg_db.rederive_mcp_tool_metadata(
                SERVER_ID, TOOL_CONTENT_ANNOTATIONS_D["name"]
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            rederive_done.set()

    promote_thread = threading.Thread(target=promote)
    rederive_thread = threading.Thread(target=rederive)
    promote_thread.start()
    assert promote_at_seam.wait(timeout=15), "promotion never reached replace seam"
    rederive_thread.start()
    try:
        rederive_waited = _wait_for(lambda: _advisory_waiters(pg_db) > 0)
        rederive_finished_early = rederive_done.is_set()
    finally:
        release_promote.set()
        promote_thread.join(timeout=30)
        rederive_thread.join(timeout=30)

    assert rederive_waited, "metadata rederivation never waited on the server lock"
    assert not rederive_finished_early, "metadata rederivation read the old row"
    assert not promote_thread.is_alive() and not rederive_thread.is_alive()
    assert errors == []
    assert results["promote"]["ok"] is True
    assert results["rederive"]["outcome"] == "changed"
    expected_metadata = normalize_tool_metadata(TOOL_CONTENT_ANNOTATIONS_D)
    assert results["rederive"]["new_metadata"] == expected_metadata
    stored = pg_db.lookup_mcp_tool_metadata(
        SERVER_ID, TOOL_CONTENT_ANNOTATIONS_D["name"]
    )
    assert stored["raw_tool_definition"] == TOOL_CONTENT_ANNOTATIONS_D
    assert stored["normalized_metadata"] == expected_metadata


def test_promotion_wins_then_unregister_waits_and_cascades_on_postgres(
    pg_db, monkeypatch
):
    """No process lock: promotion owns the server advisory lock, unregister
    must wait, then delete the fully committed server state without a raw FK
    or transaction error. The immutable rebaseline audit row remains."""
    active = _seed_baseline(pg_db, [TOOL_A])
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_B]), "ops"
    )
    monkeypatch.setattr(pg_db, "_db_lock", _NoOpLock())

    promote_at_seam = threading.Event()
    release_promote = threading.Event()
    unregister_done = threading.Event()
    real_replace = pg_db._replace_tool_metadata_from_candidate
    results = {}
    errors = []

    def holding_replace(conn, server_id, candidate_row):
        promote_at_seam.set()
        if not release_promote.wait(timeout=15):
            raise RuntimeError("test deadlock: promotion was not released")
        return real_replace(conn, server_id, candidate_row)

    monkeypatch.setattr(pg_db, "_replace_tool_metadata_from_candidate", holding_replace)

    def promote():
        try:
            results["promote"] = pg_db.promote_rebaseline_candidate(
                SERVER_ID,
                active["surface_hash"],
                candidate["candidate_surface_hash"],
                actor=ACTOR,
            )
        except BaseException as exc:
            errors.append(exc)

    def unregister():
        try:
            results["unregister"] = pg_db.unregister_mcp_server(SERVER_ID)
        except BaseException as exc:
            errors.append(exc)
        finally:
            unregister_done.set()

    promote_thread = threading.Thread(target=promote)
    unregister_thread = threading.Thread(target=unregister)
    promote_thread.start()
    assert promote_at_seam.wait(timeout=15), "promotion never reached replace seam"
    unregister_thread.start()
    try:
        unregister_waited = _wait_for(lambda: _advisory_waiters(pg_db) > 0)
        unregister_finished_early = unregister_done.is_set()
    finally:
        release_promote.set()
        promote_thread.join(timeout=30)
        unregister_thread.join(timeout=30)

    assert unregister_waited, "unregister never waited on the rebaseline advisory lock"
    assert not unregister_finished_early, "unregister ran inside promotion"
    assert not promote_thread.is_alive() and not unregister_thread.is_alive()
    assert errors == []
    assert results["promote"]["ok"] is True
    assert results["unregister"] is True
    assert _server_state_counts(pg_db) == {
        "mcp_servers": 0,
        "mcp_tool_metadata": 0,
        "mcp_rebaseline_candidates": 0,
        "mcp_baseline_versions": 0,
        "rebaseline_audit": 1,
    }
    assert (
        pg_db.verify_mcp_audit_record(results["promote"]["audit"]["audit_id"])[
            "chain_verified"
        ]
        is True
    )
    assert pg_db.verify_audit_chain()["valid"] is True


def test_unregister_wins_then_promote_is_clean_not_found_on_postgres(
    pg_db, monkeypatch
):
    """Queue unregister before promotion on the server advisory lock. With
    no process lock, unregister must win cleanly and promotion must return a
    typed not-found verdict rather than leaking an FK/transaction exception."""
    active = _seed_baseline(pg_db, [TOOL_A])
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_B]), "ops"
    )
    monkeypatch.setattr(pg_db, "_db_lock", _NoOpLock())
    results = {}
    errors = []
    unregister_done = threading.Event()
    promote_done = threading.Event()

    def unregister():
        try:
            results["unregister"] = pg_db.unregister_mcp_server(SERVER_ID)
        except BaseException as exc:
            errors.append(exc)
        finally:
            unregister_done.set()

    def promote():
        try:
            results["promote"] = pg_db.promote_rebaseline_candidate(
                SERVER_ID,
                active["surface_hash"],
                candidate["candidate_surface_hash"],
                actor=ACTOR,
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            promote_done.set()

    with pg_db.get_conn() as blocker:
        blocker.execute("BEGIN")
        blocker.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (pg_db._rebaseline_lock_key(SERVER_ID),),
        )
        unregister_thread = threading.Thread(target=unregister)
        promote_thread = threading.Thread(target=promote)
        unregister_thread.start()
        unregister_waited = _wait_for(lambda: _advisory_waiters(pg_db) >= 1)
        promote_thread.start()
        both_waited = _wait_for(lambda: _advisory_waiters(pg_db) >= 2)
        finished_while_blocked = unregister_done.is_set() or promote_done.is_set()
        blocker.execute("COMMIT")

    unregister_thread.join(timeout=30)
    promote_thread.join(timeout=30)

    assert unregister_waited, "unregister did not join the server-lock queue"
    assert both_waited, "both operations were not serialized on the server lock"
    assert not finished_while_blocked
    assert not unregister_thread.is_alive() and not promote_thread.is_alive()
    assert errors == []
    assert results["unregister"] is True
    assert results["promote"]["ok"] is False
    assert results["promote"]["error"] == "server_not_found"
    assert _server_state_counts(pg_db) == {
        "mcp_servers": 0,
        "mcp_tool_metadata": 0,
        "mcp_rebaseline_candidates": 0,
        "mcp_baseline_versions": 0,
        "rebaseline_audit": 0,
    }
    assert pg_db.verify_audit_chain()["valid"] is True


def test_unregister_wins_then_candidate_staging_is_clean_not_found_on_postgres(
    pg_db, monkeypatch
):
    """A completed upstream discovery can queue behind unregister. The
    server lock must order both writers and staging must return a typed
    not-found result rather than a child-row FK/transaction exception."""
    monkeypatch.setattr(pg_db, "_db_lock", _NoOpLock())
    validated = _validated(pg_db, [TOOL_B])
    results = {}
    errors = []
    unregister_done = threading.Event()
    staging_done = threading.Event()

    def unregister():
        try:
            results["unregister"] = pg_db.unregister_mcp_server(SERVER_ID)
        except BaseException as exc:
            errors.append(exc)
        finally:
            unregister_done.set()

    def stage():
        try:
            results["stage"] = pg_db.save_rebaseline_candidate(
                SERVER_ID, validated, "ops"
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            staging_done.set()

    with pg_db.get_conn() as blocker:
        blocker.execute("BEGIN")
        blocker.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (pg_db._rebaseline_lock_key(SERVER_ID),),
        )
        unregister_thread = threading.Thread(target=unregister)
        staging_thread = threading.Thread(target=stage)
        unregister_thread.start()
        unregister_waited = _wait_for(lambda: _advisory_waiters(pg_db) >= 1)
        staging_thread.start()
        both_waited = _wait_for(lambda: _advisory_waiters(pg_db) >= 2)
        finished_while_blocked = unregister_done.is_set() or staging_done.is_set()
        blocker.execute("COMMIT")

    unregister_thread.join(timeout=30)
    staging_thread.join(timeout=30)

    assert unregister_waited and both_waited
    assert not finished_while_blocked
    assert not unregister_thread.is_alive() and not staging_thread.is_alive()
    assert errors == []
    assert results["unregister"] is True
    assert results["stage"] == {
        "ok": False,
        "error": "server_not_found",
        "server_id": SERVER_ID,
    }
    assert _server_state_counts(pg_db) == {
        "mcp_servers": 0,
        "mcp_tool_metadata": 0,
        "mcp_rebaseline_candidates": 0,
        "mcp_baseline_versions": 0,
        "rebaseline_audit": 0,
    }


def test_active_surface_upsert_after_unregister_is_clean_not_found_on_postgres(pg_db):
    validated = _validated(pg_db, [TOOL_B])[0]
    assert pg_db.unregister_mcp_server(SERVER_ID) is True

    result = pg_db.upsert_mcp_tool_metadata(
        SERVER_ID, validated["tool"], validated["normalized_metadata"]
    )

    assert result == {
        "ok": False,
        "error": "server_not_found",
        "server_id": SERVER_ID,
        "tool_name": TOOL_B["name"],
    }


def test_concurrent_promotes_exactly_one_succeeds_on_postgres(pg_db, monkeypatch):
    """Two workers with NO shared process lock (like two replicas) race the
    same promote; the per-server advisory xact lock must let exactly one
    win, and the loser must see the moved state, not a torn one."""
    active = _seed_baseline(pg_db, [TOOL_A, TOOL_B])
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_C]), "ops"
    )
    monkeypatch.setattr(pg_db, "_db_lock", _NoOpLock())

    results = []
    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        results.append(
            pg_db.promote_rebaseline_candidate(
                SERVER_ID,
                active["surface_hash"],
                candidate["candidate_surface_hash"],
                actor=ACTOR,
            )
        )

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(r["ok"] for r in results) == [False, True], results
    loser = next(r for r in results if not r["ok"])
    assert loser["error"] in ("stale_rebaseline_state", "no_candidate")

    assert (
        pg_db.get_active_baseline(SERVER_ID)["surface_hash"]
        == candidate["candidate_surface_hash"]
    )
    assert len(pg_db.list_baseline_versions(SERVER_ID)) == 2
    assert pg_db.verify_audit_chain()["valid"] is True


def test_injected_failure_rolls_back_transactionally_on_postgres(pg_db, monkeypatch):
    active = _seed_baseline(pg_db, [TOOL_A, TOOL_B])
    candidate = pg_db.save_rebaseline_candidate(
        SERVER_ID, _validated(pg_db, [TOOL_C]), "ops"
    )

    def boom(conn, server_id, candidate_row):
        raise RuntimeError("injected pg promote failure")

    monkeypatch.setattr(pg_db, "_replace_tool_metadata_from_candidate", boom)
    with pytest.raises(RuntimeError, match="injected pg promote failure"):
        pg_db.promote_rebaseline_candidate(
            SERVER_ID,
            active["surface_hash"],
            candidate["candidate_surface_hash"],
            actor=ACTOR,
        )
    monkeypatch.undo()

    assert (
        pg_db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]
    )
    assert (
        pg_db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        == candidate["candidate_surface_hash"]
    )
    assert pg_db.list_baseline_versions(SERVER_ID) == []
    assert pg_db.verify_audit_chain()["valid"] is True

    retry = pg_db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert retry["ok"] is True
    assert pg_db.verify_audit_chain()["valid"] is True
