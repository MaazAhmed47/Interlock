"""
Atomic, compare-and-swap-safe MCP rebaseline.

The claims under test:

- Discovery creates a CANDIDATE and never mutates the active baseline: on
  timeout, malformed responses, or validation failure the active baseline
  and any existing candidate stay byte-for-byte unchanged, with a clear
  failure reason.
- Approval is compare-and-swap safe: it requires the exact active-baseline
  hash the reviewer saw AND the exact candidate hash they reviewed, re-read
  inside the final transaction; either being stale rejects with the current
  hashes (HTTP 409 at the route). A newer discovery invalidates approval of
  an older candidate.
- Replacement is atomic: history snapshot + promotion + audit evidence in
  one transaction; an injected failure before commit leaves no partial
  state. Concurrent approvals: exactly one succeeds.
- Every prior active baseline is preserved in immutable version history.

Run: python -m pytest tests/test_rebaseline_cas.py -q
"""

import asyncio
import ast
import json
import os
import re
import sys
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

_tmp_db = tempfile.mktemp(suffix="_rebaseline_cas_test.db")
os.environ.setdefault("FIREWALL_DB_PATH", _tmp_db)

import core.db as db  # noqa: E402
from core import drift_evidence  # noqa: E402
from core.tool_metadata import normalize_tool_metadata  # noqa: E402

# ── deterministic server surface hashing ─────────────────────────────────────

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


def test_server_surface_hash_is_deterministic_and_order_insensitive():
    a = drift_evidence.server_surface_hash([TOOL_A, TOOL_B])
    b = drift_evidence.server_surface_hash([TOOL_B, TOOL_A])
    assert a == b
    assert a.startswith("sha256:")
    assert a == drift_evidence.server_surface_hash([dict(TOOL_A), dict(TOOL_B)])


def test_server_surface_hash_commits_to_every_tool_surface_field():
    baseline = drift_evidence.server_surface_hash([TOOL_A, TOOL_B])
    renamed = {**TOOL_A, "name": "list_avatars_v2"}
    described = {**TOOL_A, "description": "List ALL avatars."}
    reschema = {
        **TOOL_A,
        "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
    }
    for mutated in (renamed, described, reschema):
        assert drift_evidence.server_surface_hash([mutated, TOOL_B]) != baseline
    # tool set membership is committed too
    assert drift_evidence.server_surface_hash([TOOL_A]) != baseline
    assert drift_evidence.server_surface_hash([]) != baseline


def test_server_surface_canonical_json_round_trips_the_hash():
    canonical = drift_evidence.server_surface_canonical_json([TOOL_B, TOOL_A])
    recomputed = drift_evidence._digest_bytes(canonical.encode("utf-8"))
    assert recomputed == drift_evidence.server_surface_hash([TOOL_A, TOOL_B])


# ── db layer: candidate staging, CAS promote, version history ────────────────

from core.mcp_gateway import validate_mcp_tool_definition  # noqa: E402

SERVER_ID = "_rebaseline_cas_server"

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


def _content_entry(tool=TOOL_CONTENT_C, metadata=CONTENT_METADATA_C):
    return {"tool": tool, "normalized_metadata": metadata}


@pytest.fixture(autouse=True)
def fresh_db():
    path = tempfile.mktemp(suffix="_rebaseline_cas_test.db")
    db.DB_PATH = path
    db.init_db()
    db.register_mcp_server(
        SERVER_ID,
        {
            "url": "http://localhost:9781/mcp",
            "description": "Rebaseline CAS test server",
            "allowed_tools": [],
            "blocked_tools": [],
            "rate_limit": 10,
        },
    )
    db.verify_mcp_server(SERVER_ID)
    yield
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def _validated(tools):
    out = []
    for tool in tools:
        validation = validate_mcp_tool_definition(tool)
        assert not validation.is_threat, f"fixture tool must be safe: {tool['name']}"
        out.append(
            {"tool": tool, "normalized_metadata": validation.tool_metadata or {}}
        )
    return out


def _seed_baseline(tools):
    for entry in _validated(tools):
        db.upsert_mcp_tool_metadata(
            SERVER_ID, entry["tool"], entry["normalized_metadata"]
        )
    return db.get_active_baseline(SERVER_ID)


def _snapshot_tool_rows():
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM mcp_tool_metadata WHERE server_id = ? ORDER BY tool_name",
            (SERVER_ID,),
        ).fetchall()
    return [dict(r) for r in rows]


def _server_state_counts():
    with db.get_conn() as conn:
        tables = (
            "mcp_servers",
            "mcp_tool_metadata",
            "mcp_rebaseline_candidates",
            "mcp_baseline_versions",
        )
        counts = {
            table: int(
                conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE server_id = ?",
                    (SERVER_ID,),
                ).fetchone()["n"]
            )
            for table in tables
        }
        counts["rebaseline_audit"] = int(
            conn.execute(
                "SELECT COUNT(*) AS n FROM mcp_audit_log "
                "WHERE server_id = ? AND action = 'rebaseline'",
                (SERVER_ID,),
            ).fetchone()["n"]
        )
    return counts


ACTOR = {"reviewer": "ops (key:lf-test)", "principal_id": "lf-test"}


def test_live_reset_script_has_no_direct_protected_table_writes():
    source_path = Path(__file__).resolve().parents[1] / "scripts" / "reset_live_demo.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    protected_write = re.compile(
        r"\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM)\s+"
        r"(?:mcp_servers|mcp_tool_metadata)\b",
        re.IGNORECASE,
    )
    offenders = [
        " ".join(node.value.split())
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and protected_write.search(node.value)
    ]
    assert offenders == [], (
        "reset_live_demo.py must route protected writes through locked core.db "
        f"helpers, found: {offenders}"
    )


def test_locked_metadata_rederivation_returns_changed_then_unchanged():
    _seed_baseline([TOOL_A])
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE mcp_tool_metadata SET normalized_metadata = '{}' "
            "WHERE server_id = ? AND tool_name = ?",
            (SERVER_ID, TOOL_A["name"]),
        )

    preview = db.rederive_mcp_tool_metadata(SERVER_ID, TOOL_A["name"], dry_run=True)
    assert preview["outcome"] == "changed"
    assert preview["changed"] is True
    assert preview["applied"] is False
    assert (
        db.lookup_mcp_tool_metadata(SERVER_ID, TOOL_A["name"])["normalized_metadata"]
        == {}
    )

    changed = db.rederive_mcp_tool_metadata(SERVER_ID, TOOL_A["name"])
    assert changed["ok"] is True
    assert changed["outcome"] == "changed"
    assert changed["changed"] is True
    assert changed["applied"] is True
    assert changed["new_metadata"] == normalize_tool_metadata(TOOL_A)

    unchanged = db.rederive_mcp_tool_metadata(SERVER_ID, TOOL_A["name"])
    assert unchanged["ok"] is True
    assert unchanged["outcome"] == "unchanged"
    assert unchanged["changed"] is False
    assert unchanged["applied"] is False


@pytest.mark.parametrize(
    ("column", "bad_value", "expected_error"),
    [
        ("raw_tool_definition", "{bad-json", "corrupt_raw_tool_definition"),
        ("normalized_metadata", "[not-an-object]", "corrupt_normalized_metadata"),
    ],
)
def test_locked_metadata_rederivation_returns_typed_corrupt_result(
    column, bad_value, expected_error
):
    _seed_baseline([TOOL_A])
    with db.get_conn() as conn:
        conn.execute(
            f"UPDATE mcp_tool_metadata SET {column} = ? "
            "WHERE server_id = ? AND tool_name = ?",
            (bad_value, SERVER_ID, TOOL_A["name"]),
        )

    result = db.rederive_mcp_tool_metadata(SERVER_ID, TOOL_A["name"])
    assert result == {
        "ok": False,
        "outcome": "corrupt",
        "error": expected_error,
        "server_id": SERVER_ID,
        "tool_name": TOOL_A["name"],
    }


def test_locked_metadata_rederivation_returns_typed_not_found_results():
    missing_tool = db.rederive_mcp_tool_metadata(SERVER_ID, "missing_tool")
    assert missing_tool["ok"] is False
    assert missing_tool["outcome"] == "not_found"
    assert missing_tool["error"] == "tool_not_found"

    assert db.unregister_mcp_server(SERVER_ID) is True
    missing_server = db.rederive_mcp_tool_metadata(SERVER_ID, TOOL_A["name"])
    assert missing_server["ok"] is False
    assert missing_server["outcome"] == "not_found"
    assert missing_server["error"] == "server_not_found"


def test_active_baseline_reflects_stored_tool_metadata():
    empty = db.get_active_baseline(SERVER_ID)
    assert empty["tool_count"] == 0
    assert empty["surface_hash"] == drift_evidence.rebaseline_content_hash([])

    active = _seed_baseline([TOOL_A, TOOL_B])
    validated = _validated([TOOL_A, TOOL_B])
    assert active["tool_count"] == 2
    assert active["surface_hash"] == drift_evidence.rebaseline_content_hash(validated)
    assert active[
        "canonical_surface"
    ] == drift_evidence.rebaseline_content_canonical_json(validated)


def test_drift_surface_hash_keeps_formal_projection_semantics():
    baseline = drift_evidence.server_surface_hash([TOOL_CONTENT_C])
    assert drift_evidence.server_surface_hash([TOOL_CONTENT_ANNOTATIONS_D]) == baseline
    assert drift_evidence.server_surface_hash([TOOL_CONTENT_OUTPUT_D]) == baseline


@pytest.mark.parametrize(
    ("changed_entry", "mutation"),
    [
        (_content_entry(TOOL_CONTENT_ANNOTATIONS_D), "annotation_only"),
        (_content_entry(TOOL_CONTENT_OUTPUT_D), "output_schema_only"),
        (_content_entry(metadata=CONTENT_METADATA_D), "normalized_metadata_only"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_rebaseline_candidate_hash_covers_complete_persisted_content(
    changed_entry, mutation
):
    first = db.save_rebaseline_candidate(
        SERVER_ID, [_content_entry()], f"ops-{mutation}-c"
    )
    second = db.save_rebaseline_candidate(
        SERVER_ID, [changed_entry], f"ops-{mutation}-d"
    )
    assert (
        first["candidate_surface_hash"] != second["candidate_surface_hash"]
    ), f"{mutation} candidate content must not alias the reviewed hash"


def test_rebaseline_content_canonical_order_is_stable():
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
    first = db.save_rebaseline_candidate(
        SERVER_ID,
        [_content_entry(), _content_entry(TOOL_A, {"z": 3, "a": 1})],
        "ops",
    )
    second = db.save_rebaseline_candidate(
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
    ("changed_tool", "changed_metadata", "mutation"),
    [
        (TOOL_CONTENT_ANNOTATIONS_D, CONTENT_METADATA_C, "annotation_only"),
        (TOOL_CONTENT_OUTPUT_D, CONTENT_METADATA_C, "output_schema_only"),
        (TOOL_CONTENT_C, CONTENT_METADATA_D, "normalized_metadata_only"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_active_content_change_invalidates_expected_current_hash(
    changed_tool, changed_metadata, mutation
):
    db.upsert_mcp_tool_metadata(SERVER_ID, TOOL_CONTENT_C, CONTENT_METADATA_C)
    reviewed_active = db.get_active_baseline(SERVER_ID)
    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")

    db.upsert_mcp_tool_metadata(SERVER_ID, changed_tool, changed_metadata)
    current_active = db.get_active_baseline(SERVER_ID)
    assert (
        reviewed_active["surface_hash"] != current_active["surface_hash"]
    ), f"{mutation} active content must invalidate expected_current_hash"

    result = db.promote_rebaseline_candidate(
        SERVER_ID,
        reviewed_active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert result["ok"] is False, result
    assert result["error"] == "stale_rebaseline_state"
    assert (
        db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        == candidate["candidate_surface_hash"]
    )


def test_save_candidate_replaces_prior_candidate():
    first_validated = _validated([TOOL_A])
    first = db.save_rebaseline_candidate(SERVER_ID, first_validated, "ops")
    assert first["candidate_surface_hash"] == drift_evidence.rebaseline_content_hash(
        first_validated
    )
    assert first["tool_count"] == 1

    second_validated = _validated([TOOL_A, TOOL_C])
    second = db.save_rebaseline_candidate(SERVER_ID, second_validated, "ops")
    assert second["candidate_surface_hash"] == drift_evidence.rebaseline_content_hash(
        second_validated
    )
    stored = db.get_rebaseline_candidate(SERVER_ID)
    assert stored["candidate_surface_hash"] == second["candidate_surface_hash"]
    assert stored["tool_count"] == 2
    # exactly one candidate row per server
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM mcp_rebaseline_candidates WHERE server_id = ?",
            (SERVER_ID,),
        ).fetchone()
    assert dict(row)["n"] == 1


def test_promote_rejects_stale_or_missing_state():
    active = _seed_baseline([TOOL_A, TOOL_B])

    # no candidate at all
    result = db.promote_rebaseline_candidate(
        SERVER_ID, active["surface_hash"], "sha256:" + "0" * 64, actor=ACTOR
    )
    assert result["ok"] is False
    assert result["error"] == "no_candidate"

    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")

    # stale current hash
    result = db.promote_rebaseline_candidate(
        SERVER_ID,
        "sha256:" + "f" * 64,
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert result["ok"] is False
    assert result["error"] == "stale_rebaseline_state"
    assert result["active_surface_hash"] == active["surface_hash"]
    assert result["candidate_surface_hash"] == candidate["candidate_surface_hash"]

    # stale candidate hash
    result = db.promote_rebaseline_candidate(
        SERVER_ID, active["surface_hash"], "sha256:" + "f" * 64, actor=ACTOR
    )
    assert result["ok"] is False
    assert result["error"] == "stale_rebaseline_state"

    # nothing was mutated by the rejections
    assert db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]
    assert (
        db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        == candidate["candidate_surface_hash"]
    )
    assert db.list_baseline_versions(SERVER_ID) == []


def test_promote_atomically_replaces_baseline_and_preserves_history():
    active = _seed_baseline([TOOL_A, TOOL_B])
    candidate = db.save_rebaseline_candidate(
        SERVER_ID, _validated([TOOL_A, TOOL_C]), "ops"
    )

    result = db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert result["ok"] is True, result
    assert result["new_surface_hash"] == candidate["candidate_surface_hash"]
    assert result["old_surface_hash"] == active["surface_hash"]

    # active metadata is exactly the candidate, statuses reset
    new_active = db.get_active_baseline(SERVER_ID)
    assert new_active["surface_hash"] == candidate["candidate_surface_hash"]
    assert new_active["tool_count"] == 2
    names = {row["tool_name"] for row in _snapshot_tool_rows()}
    assert names == {"list_avatars", "send_summary"}
    for row in _snapshot_tool_rows():
        assert row["status"] == "active"
        assert row["drift_severity"] == "none"

    # candidate is consumed
    assert db.get_rebaseline_candidate(SERVER_ID) is None

    # immutable history: old baseline preserved, new baseline active
    versions = db.list_baseline_versions(SERVER_ID)
    assert len(versions) == 2
    old, new = versions
    assert old["surface_hash"] == active["surface_hash"]
    assert old["canonical_surface"] == active["canonical_surface"]
    assert old["replaced_at"] is not None
    assert new["surface_hash"] == candidate["candidate_surface_hash"]
    assert new["replaced_at"] is None
    assert new["version"] == old["version"] + 1

    # approval/audit evidence recorded and chain-valid
    assert result["audit"]["audit_id"]
    assert new["approval_audit_id"] == result["audit"]["audit_id"]
    assert (
        db.verify_mcp_audit_record(result["audit"]["audit_id"])["chain_verified"]
        is True
    )
    assert db.verify_audit_chain()["valid"] is True


def test_promote_history_and_audit_commit_full_rebaseline_content():
    db.upsert_mcp_tool_metadata(SERVER_ID, TOOL_CONTENT_C, CONTENT_METADATA_C)
    active = db.get_active_baseline(SERVER_ID)
    candidate_tool = {
        **TOOL_CONTENT_OUTPUT_D,
        "annotations": TOOL_CONTENT_ANNOTATIONS_D["annotations"],
    }
    candidate = db.save_rebaseline_candidate(
        SERVER_ID,
        [_content_entry(candidate_tool, CONTENT_METADATA_D)],
        "ops",
    )

    result = db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert result["ok"] is True, result

    versions = db.list_baseline_versions(SERVER_ID)
    assert versions[0]["surface_hash"] == active["surface_hash"]
    assert versions[0]["canonical_surface"] == active["canonical_surface"]
    assert versions[1]["surface_hash"] == candidate["candidate_surface_hash"]
    assert versions[1]["canonical_surface"] == candidate["canonical_surface"]

    canonical = json.loads(versions[1]["canonical_surface"])
    assert canonical[0]["tool"] == candidate_tool
    assert canonical[0]["normalized_metadata"] == CONTENT_METADATA_D

    audit = db.get_mcp_audit_log(result["audit"]["audit_id"])
    assert audit["drift_baseline_hash"] == active["surface_hash"]
    assert audit["drift_current_hash"] == candidate["candidate_surface_hash"]
    assert db.verify_mcp_audit_record(audit["id"])["chain_verified"] is True


def test_second_promote_extends_history_without_rewriting_it():
    active = _seed_baseline([TOOL_A])
    c1 = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    r1 = db.promote_rebaseline_candidate(
        SERVER_ID, active["surface_hash"], c1["candidate_surface_hash"], actor=ACTOR
    )
    assert r1["ok"] is True

    first_history = db.list_baseline_versions(SERVER_ID)
    c2 = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")
    r2 = db.promote_rebaseline_candidate(
        SERVER_ID, r1["new_surface_hash"], c2["candidate_surface_hash"], actor=ACTOR
    )
    assert r2["ok"] is True

    versions = db.list_baseline_versions(SERVER_ID)
    assert len(versions) == 3
    # prior rows are immutable apart from the replaced_at closing stamp
    for before in first_history:
        after = next(v for v in versions if v["id"] == before["id"])
        for field in ("version", "surface_hash", "canonical_surface", "promoted_at"):
            assert after[field] == before[field]
    assert [v["replaced_at"] is None for v in versions] == [False, False, True]


def test_newer_discovery_invalidates_older_candidate_approval():
    active = _seed_baseline([TOOL_A])
    older = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")

    result = db.promote_rebaseline_candidate(
        SERVER_ID, active["surface_hash"], older["candidate_surface_hash"], actor=ACTOR
    )
    assert result["ok"] is False
    assert result["error"] == "stale_rebaseline_state"
    assert db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]


def test_concurrent_promotes_exactly_one_succeeds():
    active = _seed_baseline([TOOL_A, TOOL_B])
    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")

    results = []
    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        results.append(
            db.promote_rebaseline_candidate(
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

    outcomes = sorted(r["ok"] for r in results)
    assert outcomes == [False, True], results
    loser = next(r for r in results if not r["ok"])
    assert loser["error"] in ("stale_rebaseline_state", "no_candidate")
    assert (
        db.get_active_baseline(SERVER_ID)["surface_hash"]
        == candidate["candidate_surface_hash"]
    )
    assert len(db.list_baseline_versions(SERVER_ID)) == 2
    assert db.verify_audit_chain()["valid"] is True


def test_injected_failure_before_commit_leaves_no_partial_state(monkeypatch):
    active = _seed_baseline([TOOL_A, TOOL_B])
    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")
    before_rows = _snapshot_tool_rows()

    def boom(conn, server_id, candidate_row):
        raise RuntimeError("injected promote failure")

    monkeypatch.setattr(db, "_replace_tool_metadata_from_candidate", boom)
    with pytest.raises(RuntimeError, match="injected promote failure"):
        db.promote_rebaseline_candidate(
            SERVER_ID,
            active["surface_hash"],
            candidate["candidate_surface_hash"],
            actor=ACTOR,
        )
    monkeypatch.undo()

    # nothing changed: baseline rows, candidate, history, audit chain
    assert _snapshot_tool_rows() == before_rows
    assert db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]
    assert (
        db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        == candidate["candidate_surface_hash"]
    )
    assert db.list_baseline_versions(SERVER_ID) == []
    assert db.verify_audit_chain()["valid"] is True

    # and a retry succeeds cleanly
    retry = db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert retry["ok"] is True
    assert db.verify_audit_chain()["valid"] is True


# ── staging/promotion share ONE serialization domain ─────────────────────────
#
# The CAS invariant requires every candidate writer and every active-surface
# writer to serialize with promotion on the SAME per-server lock. Without it,
# a discovery can stage candidate D while a promoter (holding stale reads of
# candidate C) consumes the candidate row — silently destroying D.


def test_promote_consumes_exactly_the_reviewed_candidate_row(monkeypatch):
    """Cross-replica interleave at the read seam: the promoter validated
    candidate C, but the stored row was already replaced by D. Consuming the
    candidate must key on server_id AND candidate hash, require exactly one
    affected row, and otherwise roll back and report stale with the CURRENT
    hashes — never delete D and promote C."""
    active = _seed_baseline([TOOL_A])
    candidate_c = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    forged_read = db.get_rebaseline_candidate(SERVER_ID)  # C, as the promoter saw it
    candidate_d = db.save_rebaseline_candidate(
        SERVER_ID, _validated([TOOL_C]), "ops"
    )  # newer discovery replaces C with D

    monkeypatch.setattr(
        db,
        "_rebaseline_candidate_from_conn",
        lambda conn, sid: dict(forged_read),
    )
    result = db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate_c["candidate_surface_hash"],
        actor=ACTOR,
    )
    monkeypatch.undo()

    assert result["ok"] is False, result
    assert result["error"] == "stale_rebaseline_state"
    assert result["active_surface_hash"] == active["surface_hash"]
    assert (
        result["candidate_surface_hash"] == candidate_d["candidate_surface_hash"]
    ), "stale rejection must report the CURRENT candidate hash"

    # D is intact, nothing was promoted, no partial history/audit state
    assert (
        db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        == candidate_d["candidate_surface_hash"]
    )
    assert db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]
    assert db.list_baseline_versions(SERVER_ID) == []
    assert db.verify_audit_chain()["valid"] is True


def test_racing_save_and_promote_never_lose_the_new_candidate():
    """Whatever order a save(D) and a promote(C) land in, D must survive:
    either the promote was first (D staged after it) or the promote sees the
    replaced candidate and rejects stale. D never silently disappears."""
    active = _seed_baseline([TOOL_A])
    candidate_c = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    validated_d = _validated([TOOL_C])
    hash_d = drift_evidence.rebaseline_content_hash(validated_d)

    outcomes = {}
    barrier = threading.Barrier(2)

    def stage_d():
        barrier.wait()
        outcomes["save"] = db.save_rebaseline_candidate(SERVER_ID, validated_d, "ops")

    def promote_c():
        barrier.wait()
        outcomes["promote"] = db.promote_rebaseline_candidate(
            SERVER_ID,
            active["surface_hash"],
            candidate_c["candidate_surface_hash"],
            actor=ACTOR,
        )

    threads = [threading.Thread(target=stage_d), threading.Thread(target=promote_c)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    staged = db.get_rebaseline_candidate(SERVER_ID)
    assert staged is not None, "candidate D must never be silently lost"
    assert staged["candidate_surface_hash"] == hash_d

    if outcomes["promote"]["ok"]:
        assert (
            db.get_active_baseline(SERVER_ID)["surface_hash"]
            == candidate_c["candidate_surface_hash"]
        )
        assert len(db.list_baseline_versions(SERVER_ID)) == 2
    else:
        assert outcomes["promote"]["error"] == "stale_rebaseline_state"
        assert (
            db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]
        )
        assert db.list_baseline_versions(SERVER_ID) == []
    assert db.verify_audit_chain()["valid"] is True


def test_candidate_staged_after_promotion_is_preserved():
    """Promotion-first ordering: a discovery landing after an approval stages
    its candidate on top of the NEW baseline; nothing is lost."""
    active = _seed_baseline([TOOL_A])
    candidate_c = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    promoted = db.promote_rebaseline_candidate(
        SERVER_ID,
        active["surface_hash"],
        candidate_c["candidate_surface_hash"],
        actor=ACTOR,
    )
    assert promoted["ok"] is True

    candidate_d = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")
    staged = db.get_rebaseline_candidate(SERVER_ID)
    assert staged["candidate_surface_hash"] == candidate_d["candidate_surface_hash"]
    assert (
        db.get_active_baseline(SERVER_ID)["surface_hash"]
        == candidate_c["candidate_surface_hash"]
    )
    assert len(db.list_baseline_versions(SERVER_ID)) == 2


# ── unregister/promotion share the server lifecycle serialization domain ─────


def test_review_snapshot_waits_for_promote_and_returns_wholly_after_state(
    monkeypatch, admin_key
):
    active = _seed_baseline([TOOL_A])
    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    before = db.get_rebaseline_review_snapshot(SERVER_ID)
    assert before["active"]["surface_hash"] == active["surface_hash"]
    assert (
        before["candidate"]["candidate_surface_hash"]
        == candidate["candidate_surface_hash"]
    )
    assert before["versions"] == []

    promote_at_seam = threading.Event()
    release_promote = threading.Event()
    snapshot_done = threading.Event()
    real_replace = db._replace_tool_metadata_from_candidate
    results = {}

    def holding_replace(conn, server_id, candidate_row):
        promote_at_seam.set()
        assert release_promote.wait(timeout=10), "promotion was never released"
        return real_replace(conn, server_id, candidate_row)

    monkeypatch.setattr(db, "_replace_tool_metadata_from_candidate", holding_replace)

    def promote():
        results["promote"] = db.promote_rebaseline_candidate(
            SERVER_ID,
            active["surface_hash"],
            candidate["candidate_surface_hash"],
            actor=ACTOR,
        )

    def read_snapshot():
        results["snapshot"] = asyncio.run(
            proxy.mcp_rebaseline_status(SERVER_ID, x_api_key=admin_key)
        )
        snapshot_done.set()

    promote_thread = threading.Thread(target=promote)
    snapshot_thread = threading.Thread(target=read_snapshot)
    promote_thread.start()
    assert promote_at_seam.wait(timeout=10), "promotion never reached replace seam"
    snapshot_thread.start()
    assert not snapshot_done.wait(timeout=0.2), "snapshot read a mixed in-flight state"
    release_promote.set()
    promote_thread.join(timeout=15)
    snapshot_thread.join(timeout=15)

    assert not promote_thread.is_alive() and not snapshot_thread.is_alive()
    assert results["promote"]["ok"] is True
    after = results["snapshot"]
    assert after["active"]["surface_hash"] == candidate["candidate_surface_hash"]
    assert after["candidate"] is None
    assert len(after["versions"]) == 2
    assert after["versions"][-1]["surface_hash"] == candidate["candidate_surface_hash"]
    assert after["versions"][-1]["replaced_at"] is None


def test_promotion_wins_then_unregister_cascades_state_cleanly_on_sqlite(
    monkeypatch,
):
    active = _seed_baseline([TOOL_A])
    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    promote_at_seam = threading.Event()
    release_promote = threading.Event()
    unregister_done = threading.Event()
    real_replace = db._replace_tool_metadata_from_candidate
    results = {}
    errors = []

    def holding_replace(conn, server_id, candidate_row):
        promote_at_seam.set()
        if not release_promote.wait(timeout=10):
            raise RuntimeError("test deadlock: promotion was not released")
        return real_replace(conn, server_id, candidate_row)

    monkeypatch.setattr(db, "_replace_tool_metadata_from_candidate", holding_replace)

    def promote():
        try:
            results["promote"] = db.promote_rebaseline_candidate(
                SERVER_ID,
                active["surface_hash"],
                candidate["candidate_surface_hash"],
                actor=ACTOR,
            )
        except BaseException as exc:  # surfaced in the parent test thread
            errors.append(exc)

    def unregister():
        try:
            results["unregister"] = db.unregister_mcp_server(SERVER_ID)
        except BaseException as exc:  # surfaced in the parent test thread
            errors.append(exc)
        finally:
            unregister_done.set()

    promote_thread = threading.Thread(target=promote)
    unregister_thread = threading.Thread(target=unregister)
    promote_thread.start()
    assert promote_at_seam.wait(timeout=10), "promotion never reached replace seam"
    unregister_thread.start()
    assert not unregister_done.wait(
        timeout=0.2
    ), "unregister must wait while promotion owns the serialization domain"
    release_promote.set()
    promote_thread.join(timeout=15)
    unregister_thread.join(timeout=15)

    assert not promote_thread.is_alive() and not unregister_thread.is_alive()
    assert errors == []
    assert results["promote"]["ok"] is True
    assert results["unregister"] is True
    assert _server_state_counts() == {
        "mcp_servers": 0,
        "mcp_tool_metadata": 0,
        "mcp_rebaseline_candidates": 0,
        "mcp_baseline_versions": 0,
        "rebaseline_audit": 1,
    }
    assert (
        db.verify_mcp_audit_record(results["promote"]["audit"]["audit_id"])[
            "chain_verified"
        ]
        is True
    )
    assert db.verify_audit_chain()["valid"] is True


def test_unregister_wins_then_promote_returns_not_found_on_sqlite(monkeypatch):
    active = _seed_baseline([TOOL_A])
    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    unregister_holds_transaction = threading.Event()
    release_unregister = threading.Event()
    promote_done = threading.Event()
    real_transaction = db._rebaseline_transaction
    results = {}
    errors = []

    @contextmanager
    def holding_unregister_transaction(conn, server_id):
        with real_transaction(conn, server_id):
            if threading.current_thread().name == "unregister-winner":
                unregister_holds_transaction.set()
                if not release_unregister.wait(timeout=10):
                    raise RuntimeError("test deadlock: unregister was not released")
            yield

    monkeypatch.setattr(db, "_rebaseline_transaction", holding_unregister_transaction)

    def unregister():
        try:
            results["unregister"] = db.unregister_mcp_server(SERVER_ID)
        except BaseException as exc:
            errors.append(exc)

    def promote():
        try:
            results["promote"] = db.promote_rebaseline_candidate(
                SERVER_ID,
                active["surface_hash"],
                candidate["candidate_surface_hash"],
                actor=ACTOR,
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            promote_done.set()

    unregister_thread = threading.Thread(target=unregister, name="unregister-winner")
    promote_thread = threading.Thread(target=promote, name="promote-loser")
    unregister_thread.start()
    assert unregister_holds_transaction.wait(
        timeout=5
    ), "unregister did not enter the shared rebaseline transaction"
    promote_thread.start()
    assert not promote_done.wait(
        timeout=0.2
    ), "promotion must wait while unregister owns the serialization domain"
    release_unregister.set()
    unregister_thread.join(timeout=15)
    promote_thread.join(timeout=15)

    assert not unregister_thread.is_alive() and not promote_thread.is_alive()
    assert errors == []
    assert results["unregister"] is True
    assert results["promote"]["ok"] is False
    assert results["promote"]["error"] == "server_not_found"
    assert _server_state_counts() == {
        "mcp_servers": 0,
        "mcp_tool_metadata": 0,
        "mcp_rebaseline_candidates": 0,
        "mcp_baseline_versions": 0,
        "rebaseline_audit": 0,
    }
    assert db.verify_audit_chain()["valid"] is True


def test_candidate_staging_after_unregister_is_clean_not_found():
    """A discovery that fetched before unregister but stages afterwards must
    not leak a raw child-row foreign-key exception."""
    assert db.unregister_mcp_server(SERVER_ID) is True

    result = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")

    assert result == {
        "ok": False,
        "error": "server_not_found",
        "server_id": SERVER_ID,
    }


def test_active_surface_upsert_after_unregister_is_clean_not_found():
    """The other child-row insert in the serialization domain must use the
    same clean lifecycle failure contract."""
    validated = _validated([TOOL_B])[0]
    assert db.unregister_mcp_server(SERVER_ID) is True

    result = db.upsert_mcp_tool_metadata(
        SERVER_ID, validated["tool"], validated["normalized_metadata"]
    )

    assert result == {
        "ok": False,
        "error": "server_not_found",
        "server_id": SERVER_ID,
        "tool_name": TOOL_B["name"],
    }


# ── Postgres transaction shape: every CAS writer takes the server lock ───────
#
# Mirrors tests/test_audit_chain_concurrency.py: a recording fake connection
# asserts the statement sequence without needing a live Postgres.


class _RecordingCursor:
    rowcount = 0

    def __init__(self, raw):
        self.raw = raw
        self.last_sql = ""

    def execute(self, sql, params=()):
        self.last_sql = sql
        self.raw.statements.append((sql, params))
        return self

    def fetchone(self):
        if "FROM mcp_servers" in self.last_sql:
            return {"server_id": SERVER_ID}
        return self.raw.fetchone_result

    def fetchall(self):
        return []


class _RecordingRaw:
    def __init__(self, fetchone_result=None):
        self.statements = []
        self.fetchone_result = fetchone_result

    def cursor(self):
        return _RecordingCursor(self)

    def close(self):
        pass


def _shape_of(monkeypatch, call, *, fetchone_result=None):
    raw = _RecordingRaw(fetchone_result)
    conn = db._PostgresConn(raw)

    class _FakeConnManager:
        def __enter__(self):
            return conn

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(db, "get_conn", lambda: _FakeConnManager())
    call()
    return [sql for sql, _params in raw.statements]


def _assert_rebaseline_locked_shape(sqls, mutation_fragment):
    assert sqls and sqls[0] == "BEGIN", f"writer must open a transaction: {sqls}"
    assert sqls[-1] == "COMMIT", f"writer must commit: {sqls}"
    lock_index = next(
        (i for i, sql in enumerate(sqls) if "pg_advisory_xact_lock" in sql), None
    )
    assert lock_index is not None, f"writer must take the rebaseline lock: {sqls}"
    mutation_index = next(
        (i for i, sql in enumerate(sqls) if mutation_fragment in sql), None
    )
    assert mutation_index is not None, f"expected {mutation_fragment!r} in: {sqls}"
    assert lock_index < mutation_index, "lock must precede the mutation"


def test_save_candidate_takes_the_rebaseline_lock_on_postgres(monkeypatch):
    sqls = _shape_of(
        monkeypatch,
        lambda: db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_A]), "ops"),
    )
    _assert_rebaseline_locked_shape(sqls, "INSERT INTO mcp_rebaseline_candidates")


def test_upsert_tool_metadata_takes_the_rebaseline_lock_on_postgres(monkeypatch):
    validation = validate_mcp_tool_definition(TOOL_A)
    sqls = _shape_of(
        monkeypatch,
        lambda: db.upsert_mcp_tool_metadata(
            SERVER_ID, TOOL_A, validation.tool_metadata or {}
        ),
    )
    _assert_rebaseline_locked_shape(sqls, "INSERT INTO mcp_tool_metadata")


def test_clear_tool_metadata_takes_the_rebaseline_lock_on_postgres(monkeypatch):
    sqls = _shape_of(monkeypatch, lambda: db.clear_mcp_tool_metadata(SERVER_ID))
    _assert_rebaseline_locked_shape(sqls, "DELETE FROM mcp_tool_metadata")


def test_unregister_takes_the_rebaseline_lock_on_postgres(monkeypatch):
    sqls = _shape_of(monkeypatch, lambda: db.unregister_mcp_server(SERVER_ID))
    _assert_rebaseline_locked_shape(sqls, "DELETE FROM mcp_servers")


def test_status_writers_take_the_rebaseline_lock_on_postgres(monkeypatch):
    """Status changes do not move the CAS hash, but promotion deletes and
    reinserts these rows. They must serialize or a successful quarantine /
    approval can be silently overwritten by an in-flight promotion."""
    monkeypatch.setattr(
        db,
        "_mcp_tool_metadata_row_to_dict",
        lambda _row: {
            "normalized_metadata": {},
            "drift_types": [],
            "drift_reasons": [],
        },
    )
    monkeypatch.setattr(db, "lookup_mcp_tool_metadata", lambda *_args: {})
    monkeypatch.setattr(db, "log_mcp_audit_event", lambda _event: {})
    calls = [
        lambda: db.mark_mcp_tool_removed(SERVER_ID, "tool"),
        lambda: db.mark_mcp_tool_added_drift(SERVER_ID, "tool"),
        lambda: db.mark_mcp_tool_effective_permission_drift(SERVER_ID, "tool"),
        lambda: db.approve_mcp_tool_baseline(SERVER_ID, "tool"),
        lambda: db.quarantine_mcp_tool(SERVER_ID, "tool"),
        lambda: db.mark_mcp_tool_external_reach_drift(
            SERVER_ID, "tool", ["external_reach_expansion"]
        ),
        lambda: db.mark_mcp_tool_effect_drift(
            SERVER_ID, "tool", ["effect_destructive_added"]
        ),
        lambda: db.mark_mcp_tool_response_drift(
            SERVER_ID, "tool", ["response_sensitive_data_added"]
        ),
    ]
    for call in calls:
        sqls = _shape_of(monkeypatch, call, fetchone_result={"tool_name": "tool"})
        _assert_rebaseline_locked_shape(sqls, "UPDATE mcp_tool_metadata")


# ── candidate discovery: fetch + validate, zero persistence ──────────────────

from core.mcp_gateway import fetch_candidate_tool_surface  # noqa: E402


def _mock_upstream(json_value=None, exc=None):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = json_value
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    if exc is not None:
        client.post = AsyncMock(side_effect=exc)
    else:
        client.post = AsyncMock(return_value=resp)
    return client


def _fetch(client):
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        return asyncio.run(
            fetch_candidate_tool_surface(
                "http://localhost:9781/mcp", server_id=SERVER_ID
            )
        )


def _full_state_snapshot():
    return (
        _snapshot_tool_rows(),
        db.get_active_baseline(SERVER_ID)["surface_hash"],
        db.get_rebaseline_candidate(SERVER_ID),
    )


def test_candidate_discovery_timeout_touches_nothing():
    _seed_baseline([TOOL_A, TOOL_B])
    db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")
    before = _full_state_snapshot()

    result = _fetch(_mock_upstream(exc=httpx.TimeoutException("timed out")))
    assert result["ok"] is False
    assert result["error"] == "MCP server timeout"

    assert _full_state_snapshot() == before


@pytest.mark.parametrize(
    "payload,expected_error",
    [
        (["not", "an", "object"], "mcp_discovery_error"),
        ({"error": {"code": -32000, "message": "boom"}}, "mcp_discovery_error"),
        ({"result": {"tools": "not-a-list"}}, "mcp_discovery_error"),
        (
            {"result": {"tools": [TOOL_A, dict(TOOL_A)]}},
            "duplicate_tool_names",
        ),
    ],
)
def test_candidate_discovery_malformed_response_touches_nothing(
    payload, expected_error
):
    _seed_baseline([TOOL_A, TOOL_B])
    db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")
    before = _full_state_snapshot()

    result = _fetch(_mock_upstream(json_value=payload))
    assert result["ok"] is False
    assert result["error"] == expected_error

    assert _full_state_snapshot() == before


def test_candidate_validation_failure_rejects_whole_candidate():
    """One bad tool poisons the whole candidate — fail-closed, and the
    active baseline plus any prior candidate stay untouched."""
    _seed_baseline([TOOL_A])
    before = _full_state_snapshot()

    bad_tool = {"name": "bash", "description": "Run shell.", "inputSchema": {}}
    result = _fetch(
        _mock_upstream(json_value={"result": {"tools": [TOOL_B, bad_tool]}})
    )
    assert result["ok"] is False
    assert result["error"] == "candidate_validation_failed"
    assert any(b["tool_name"] == "bash" for b in result["blocked"])
    assert _full_state_snapshot() == before


def test_candidate_discovery_malformed_tool_entry_rejects_candidate():
    _seed_baseline([TOOL_A])
    before = _full_state_snapshot()
    result = _fetch(
        _mock_upstream(json_value={"result": {"tools": [TOOL_B, "not-a-tool"]}})
    )
    assert result["ok"] is False
    assert result["error"] == "candidate_validation_failed"
    assert _full_state_snapshot() == before


def test_candidate_discovery_success_is_pure_and_hashes_the_surface():
    _seed_baseline([TOOL_A])
    before = _full_state_snapshot()

    result = _fetch(_mock_upstream(json_value={"result": {"tools": [TOOL_B, TOOL_C]}}))
    assert result["ok"] is True, result
    assert result["tool_count"] == 2
    assert result["candidate_surface_hash"] == drift_evidence.rebaseline_content_hash(
        result["validated_tools"]
    )
    assert [e["tool"]["name"] for e in result["validated_tools"]] == [
        "read_document",
        "send_summary",
    ]
    for entry in result["validated_tools"]:
        assert isinstance(entry["normalized_metadata"], dict)

    # pure fetch: NOTHING was persisted — no upserts, no candidate row
    assert _full_state_snapshot() == before


# ── routes: discover → review hashes → CAS approve ───────────────────────────

import proxy  # noqa: E402
from fastapi import HTTPException  # noqa: E402


@pytest.fixture()
def admin_key():
    return db.generate_key("free", label="rebaseline-ops", scopes=["admin"])["raw_key"]


def _route_discover(client, api_key):
    with patch("core.mcp_gateway.httpx.AsyncClient", return_value=client):
        return asyncio.run(proxy.mcp_rebaseline_discover(SERVER_ID, x_api_key=api_key))


def _route_approve(api_key, current_hash, candidate_hash, confirm=True):
    return asyncio.run(
        proxy.mcp_rebaseline_server(
            SERVER_ID,
            request=proxy.MCPRebaselineRequest(
                confirm_rebaseline=confirm,
                expected_current_hash=current_hash,
                expected_candidate_hash=candidate_hash,
            ),
            x_api_key=api_key,
        )
    )


def test_route_discover_creates_candidate_and_reports_both_hashes(admin_key):
    active = _seed_baseline([TOOL_A])
    result = _route_discover(
        _mock_upstream(json_value={"result": {"tools": [TOOL_B, TOOL_C]}}), admin_key
    )
    assert result["ok"] is True, result
    assert result["candidate_surface_hash"] == drift_evidence.rebaseline_content_hash(
        _validated([TOOL_B, TOOL_C])
    )
    assert result["active_surface_hash"] == active["surface_hash"]
    assert result["tool_count"] == 2

    stored = db.get_rebaseline_candidate(SERVER_ID)
    assert stored["candidate_surface_hash"] == result["candidate_surface_hash"]
    # the active baseline was NOT touched by discovery
    assert db.get_active_baseline(SERVER_ID)["surface_hash"] == active["surface_hash"]


def test_route_discover_waits_for_promote_and_returns_one_after_state(
    admin_key, monkeypatch
):
    active = _seed_baseline([TOOL_A])
    candidate_c = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops-c")
    validated_d = _validated([TOOL_C])
    fetched = threading.Event()
    discover_done = threading.Event()
    promote_at_seam = threading.Event()
    release_promote = threading.Event()
    real_replace = db._replace_tool_metadata_from_candidate
    results = {}

    def holding_replace(conn, server_id, candidate_row):
        promote_at_seam.set()
        assert release_promote.wait(timeout=10), "promotion was never released"
        return real_replace(conn, server_id, candidate_row)

    async def fetched_candidate(*_args, **_kwargs):
        fetched.set()
        return {"ok": True, "validated_tools": validated_d}

    monkeypatch.setattr(db, "_replace_tool_metadata_from_candidate", holding_replace)
    monkeypatch.setattr("routes.mcp.fetch_candidate_tool_surface", fetched_candidate)

    def promote():
        results["promote"] = db.promote_rebaseline_candidate(
            SERVER_ID,
            active["surface_hash"],
            candidate_c["candidate_surface_hash"],
            actor=ACTOR,
        )

    def discover():
        results["discover"] = asyncio.run(
            proxy.mcp_rebaseline_discover(SERVER_ID, x_api_key=admin_key)
        )
        discover_done.set()

    promote_thread = threading.Thread(target=promote)
    discover_thread = threading.Thread(target=discover)
    promote_thread.start()
    assert promote_at_seam.wait(timeout=10), "promotion never reached replace seam"
    discover_thread.start()
    assert fetched.wait(timeout=5), "discovery never completed its pure fetch"
    assert not discover_done.wait(timeout=0.2), "candidate staged inside promotion"
    release_promote.set()
    promote_thread.join(timeout=15)
    discover_thread.join(timeout=15)

    assert not promote_thread.is_alive() and not discover_thread.is_alive()
    assert results["promote"]["ok"] is True
    discover_result = results["discover"]
    assert (
        discover_result["active_surface_hash"] == candidate_c["candidate_surface_hash"]
    )
    assert discover_result[
        "candidate_surface_hash"
    ] == drift_evidence.rebaseline_content_hash(validated_d)
    snapshot = db.get_rebaseline_review_snapshot(SERVER_ID)
    assert snapshot["active"]["surface_hash"] == discover_result["active_surface_hash"]
    assert (
        snapshot["candidate"]["candidate_surface_hash"]
        == discover_result["candidate_surface_hash"]
    )
    assert (
        snapshot["versions"][-1]["surface_hash"]
        == discover_result["active_surface_hash"]
    )


def test_route_discover_failure_reports_reason_and_touches_nothing(admin_key):
    _seed_baseline([TOOL_A])
    db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_C]), "ops")
    before = _full_state_snapshot()

    result = _route_discover(
        _mock_upstream(exc=httpx.TimeoutException("timed out")), admin_key
    )
    assert result["ok"] is False
    assert result["error"] == "MCP server timeout"
    assert _full_state_snapshot() == before


def test_failed_route_discovery_uses_one_coherent_after_snapshot(
    admin_key, monkeypatch
):
    active = _seed_baseline([TOOL_A])
    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    fetched = threading.Event()
    failure_done = threading.Event()
    promote_at_seam = threading.Event()
    release_promote = threading.Event()
    real_replace = db._replace_tool_metadata_from_candidate
    results = {}

    def holding_replace(conn, server_id, candidate_row):
        promote_at_seam.set()
        assert release_promote.wait(timeout=10), "promotion was never released"
        return real_replace(conn, server_id, candidate_row)

    async def failed_fetch(*_args, **_kwargs):
        fetched.set()
        return {"ok": False, "error": "MCP server timeout"}

    monkeypatch.setattr(db, "_replace_tool_metadata_from_candidate", holding_replace)
    monkeypatch.setattr("routes.mcp.fetch_candidate_tool_surface", failed_fetch)

    def promote():
        results["promote"] = db.promote_rebaseline_candidate(
            SERVER_ID,
            active["surface_hash"],
            candidate["candidate_surface_hash"],
            actor=ACTOR,
        )

    def discover_failure():
        results["failure"] = asyncio.run(
            proxy.mcp_rebaseline_discover(SERVER_ID, x_api_key=admin_key)
        )
        failure_done.set()

    promote_thread = threading.Thread(target=promote)
    failure_thread = threading.Thread(target=discover_failure)
    promote_thread.start()
    assert promote_at_seam.wait(timeout=10), "promotion never reached replace seam"
    failure_thread.start()
    assert fetched.wait(timeout=5), "failed discovery never completed its pure fetch"
    assert not failure_done.wait(timeout=0.2), "failure response read mixed state"
    release_promote.set()
    promote_thread.join(timeout=15)
    failure_thread.join(timeout=15)

    assert not promote_thread.is_alive() and not failure_thread.is_alive()
    assert results["promote"]["ok"] is True
    failure = results["failure"]
    assert failure["ok"] is False
    assert failure["active_surface_hash"] == candidate["candidate_surface_hash"]
    assert failure["candidate"] is None


def test_route_status_reports_active_candidate_and_history(admin_key):
    active = _seed_baseline([TOOL_A])
    candidate = db.save_rebaseline_candidate(SERVER_ID, _validated([TOOL_B]), "ops")
    status = asyncio.run(proxy.mcp_rebaseline_status(SERVER_ID, x_api_key=admin_key))
    assert status["active"]["surface_hash"] == active["surface_hash"]
    assert (
        status["candidate"]["candidate_surface_hash"]
        == candidate["candidate_surface_hash"]
    )
    assert status["versions"] == []


def test_route_approve_full_flow_and_drift_detection_still_works(admin_key):
    active = _seed_baseline([TOOL_A])
    discover = _route_discover(
        _mock_upstream(json_value={"result": {"tools": [TOOL_B]}}), admin_key
    )
    result = _route_approve(
        admin_key, discover["active_surface_hash"], discover["candidate_surface_hash"]
    )
    assert result["ok"] is True, result
    assert result["new_surface_hash"] == discover["candidate_surface_hash"]
    assert db.get_active_baseline(SERVER_ID)["surface_hash"] != active["surface_hash"]

    # capability drift on the NEW baseline still works unchanged: an ordinary
    # discovery seeing an escalated read_document must classify drift.
    escalated = {
        **TOOL_B,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "recursive": {"type": "boolean"},
            },
            "required": ["path", "recursive"],
        },
    }
    from core.mcp_gateway import discover_mcp_tools

    with patch(
        "core.mcp_gateway.httpx.AsyncClient",
        return_value=_mock_upstream(json_value={"result": {"tools": [escalated]}}),
    ):
        rediscovered = asyncio.run(
            discover_mcp_tools("http://localhost:9781/mcp", server_id=SERVER_ID)
        )
    assert rediscovered["ok"] is True
    drifted = db.lookup_mcp_tool_metadata(SERVER_ID, "read_document")
    assert drifted["drift_severity"] == "high"
    assert drifted["drift_action"] == "deny"


def test_route_approve_stale_current_hash_is_409(admin_key):
    _seed_baseline([TOOL_A])
    discover = _route_discover(
        _mock_upstream(json_value={"result": {"tools": [TOOL_B]}}), admin_key
    )
    # the baseline moves after review (ordinary drift discovery)
    changed = {**TOOL_A, "description": "List avatars, now with filters."}
    validation = validate_mcp_tool_definition(changed)
    db.upsert_mcp_tool_metadata(SERVER_ID, changed, validation.tool_metadata)

    with pytest.raises(HTTPException) as exc:
        _route_approve(
            admin_key,
            discover["active_surface_hash"],
            discover["candidate_surface_hash"],
        )
    assert exc.value.status_code == 409
    detail = exc.value.detail
    assert detail["error"] == "stale_rebaseline_state"
    assert (
        detail["active_surface_hash"]
        == db.get_active_baseline(SERVER_ID)["surface_hash"]
    )
    assert detail["candidate_surface_hash"] == discover["candidate_surface_hash"]


def test_route_approve_stale_candidate_after_newer_discovery_is_409(admin_key):
    _seed_baseline([TOOL_A])
    older = _route_discover(
        _mock_upstream(json_value={"result": {"tools": [TOOL_B]}}), admin_key
    )
    newer = _route_discover(
        _mock_upstream(json_value={"result": {"tools": [TOOL_C]}}), admin_key
    )
    assert newer["candidate_surface_hash"] != older["candidate_surface_hash"]

    with pytest.raises(HTTPException) as exc:
        _route_approve(
            admin_key, older["active_surface_hash"], older["candidate_surface_hash"]
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["candidate_surface_hash"] == newer["candidate_surface_hash"]


@pytest.mark.parametrize(
    ("newer_tool", "mutation"),
    [
        (TOOL_CONTENT_ANNOTATIONS_D, "annotation_only"),
        (TOOL_CONTENT_OUTPUT_D, "output_schema_only"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_route_exact_candidate_hash_rejects_aliased_newer_candidate(
    admin_key, newer_tool, mutation
):
    active = _seed_baseline([TOOL_A])
    candidate_c = db.save_rebaseline_candidate(
        SERVER_ID, [_content_entry()], f"ops-{mutation}-c"
    )
    candidate_d = db.save_rebaseline_candidate(
        SERVER_ID,
        [_content_entry(newer_tool)],
        f"ops-{mutation}-d",
    )
    assert (
        candidate_c["candidate_surface_hash"] != candidate_d["candidate_surface_hash"]
    ), f"{mutation} candidates C and D must have distinct review tokens"

    with pytest.raises(HTTPException) as exc:
        _route_approve(
            admin_key,
            active["surface_hash"],
            candidate_c["candidate_surface_hash"],
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "stale_rebaseline_state"
    assert (
        exc.value.detail["candidate_surface_hash"]
        == candidate_d["candidate_surface_hash"]
    )
    assert (
        db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        == candidate_d["candidate_surface_hash"]
    ), "newer candidate D must remain staged after stale approval of C"


def test_route_approve_guards(admin_key):
    active = _seed_baseline([TOOL_A])

    # confirm_rebaseline required
    with pytest.raises(HTTPException) as exc:
        _route_approve(admin_key, active["surface_hash"], "sha256:x", confirm=False)
    assert exc.value.status_code == 400

    # both expected hashes required
    with pytest.raises(HTTPException) as exc:
        _route_approve(admin_key, "", "")
    assert exc.value.status_code == 400

    # unknown server is 404
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            proxy.mcp_rebaseline_server(
                "_no_such_server",
                request=proxy.MCPRebaselineRequest(
                    confirm_rebaseline=True,
                    expected_current_hash="sha256:x",
                    expected_candidate_hash="sha256:y",
                ),
                x_api_key=admin_key,
            )
        )
    assert exc.value.status_code == 404

    # no candidate staged is 409
    with pytest.raises(HTTPException) as exc:
        _route_approve(admin_key, active["surface_hash"], "sha256:" + "0" * 64)
    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "no_candidate"
