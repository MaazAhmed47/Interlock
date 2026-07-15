"""
Retention-safe chain checkpoint tests.

The claims under test:

- prune_retention() deletes only the contiguous id-prefix of each audit
  chain that is older than the cutoff, and writes a durable checkpoint —
  chain name, last deleted row (id + hash), first retained row (id + prev
  hash), deleted count, retention policy, deletion timestamp, deletion
  actor/context — BEFORE deleting, atomically: a failed prune leaves
  neither the deletion nor the checkpoint.
- verification anchors a pruned chain at the newest verified checkpoint
  instead of assuming GENESIS, and requires the first retained row's prev
  hash to equal the checkpoint's recorded boundary hash.
- tampering with a checkpoint or a retained row fails closed.
- no-row, all-row, and repeated (idempotent) retention behave sanely.

Run: python -m pytest tests/test_retention_checkpoints.py -q
"""

import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_retention_checkpoint_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db  # noqa: E402

POLICY = {
    "scan_history_days": 30,
    "mcp_audit_days": 30,
    "admin_audit_days": 30,
    "usage_log_days": 30,
}

ACTOR = {"actor_auth_type": "scoped_token", "actor_role": "operator"}


@pytest.fixture(autouse=True)
def fresh_db():
    path = tempfile.mktemp(suffix="_retention_checkpoint_test.db")
    db.DB_PATH = path
    db.init_db()
    yield
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def _ts(days_ago: int, seq: int = 0) -> str:
    moment = (
        datetime.now(timezone.utc) - timedelta(days=days_ago) + timedelta(seconds=seq)
    )
    return moment.isoformat()


def _seed_mcp(days_ago: int, seq: int = 0, **overrides):
    event = {
        "server_id": "ret-server",
        "tool_name": f"tool_{days_ago}_{seq}",
        "role": "readonly_agent",
        "action": "allow",
        "reason": f"seed {days_ago}d ago #{seq}",
        "ts": _ts(days_ago, seq),
    }
    event.update(overrides)
    return db.log_mcp_audit_event(event)


def _seed_admin(days_ago: int, seq: int = 0, **overrides):
    event = {
        "actor_auth_type": "scoped_token",
        "actor_role": "operator",
        "action": f"seed_action_{days_ago}_{seq}",
        "target_type": "api_key",
        "target_id": f"target-{days_ago}-{seq}",
        "ts": _ts(days_ago, seq),
    }
    event.update(overrides)
    return db.log_admin_audit_event(event)


def _checkpoints(chain: str):
    with db.get_conn() as conn:
        return db._list_chain_checkpoints(conn, chain)


def _count(table: str) -> int:
    with db.get_conn() as conn:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
    return int(dict(row)["n"])


def _set_checkpoint_column(column, value, checkpoint_id):
    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            f"UPDATE audit_chain_checkpoints SET {column} = ? WHERE id = ?",
            (value, checkpoint_id),
        )


# ── happy path: valid before, checkpointed, valid after ──────────────────────


def test_chain_valid_before_pruning():
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    _seed_admin(40, 0)
    _seed_admin(1, 0)
    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain


def test_prune_creates_bound_checkpoint_and_keeps_chain_valid():
    old_a = _seed_mcp(40, 0)
    old_b = _seed_mcp(40, 1)
    kept = _seed_mcp(1, 0)
    admin_old = _seed_admin(40, 0)
    admin_kept = _seed_admin(1, 0)

    old_b_hash = db.get_mcp_audit_log(old_b["id"])["integrity_hash"]

    result = db.prune_retention(POLICY, actor=ACTOR)

    assert result["mcp_audit_deleted"] == 2
    assert result["admin_audit_deleted"] == 1
    assert result["mcp_audit_checkpoint_id"] is not None
    assert result["admin_audit_checkpoint_id"] is not None

    # deleted rows are gone, retained rows are present
    assert db.get_mcp_audit_log(old_a["id"]) is None
    assert db.get_mcp_audit_log(old_b["id"]) is None
    assert db.get_mcp_audit_log(kept["id"]) is not None

    checkpoints = _checkpoints("mcp_audit_log")
    assert len(checkpoints) == 1
    checkpoint = checkpoints[0]
    assert checkpoint["chain"] == "mcp_audit_log"
    assert checkpoint["last_deleted_id"] == old_b["id"]
    assert checkpoint["last_deleted_hash"] == old_b_hash
    assert checkpoint["first_retained_id"] == kept["id"]
    assert checkpoint["first_retained_prev_hash"] == old_b_hash
    assert checkpoint["deleted_count"] == 2
    assert checkpoint["created_at"]
    assert '"mcp_audit_days":30' in checkpoint["retention_policy"].replace(" ", "")
    assert "scoped_token" in checkpoint["actor"]
    assert checkpoint["hash_v"] == 3
    assert len(checkpoint["integrity_hash"]) == 64

    admin_checkpoints = _checkpoints("admin_audit_log")
    assert len(admin_checkpoints) == 1
    assert admin_checkpoints[0]["last_deleted_id"] == admin_old["id"]
    assert admin_checkpoints[0]["first_retained_id"] == admin_kept["id"]

    # chain valid after pruning, anchored at the checkpoint (not GENESIS)
    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["mcp"]["total"] == 1
    assert chain["mcp"]["checkpoints"] == 1
    assert chain["mcp"]["anchor"] == old_b_hash
    assert chain["admin"]["total"] == 1
    assert chain["admin"]["checkpoints"] == 1

    # single-record verification of the first retained row links to the anchor
    verdict = db.verify_mcp_audit_record(kept["id"])
    assert verdict["chain_verified"] is True, verdict


def test_first_retained_row_prev_hash_equals_checkpoint_boundary():
    old = _seed_mcp(40, 0)
    kept = _seed_mcp(1, 0)
    boundary = db.get_mcp_audit_log(old["id"])["integrity_hash"]
    db.prune_retention(POLICY, actor=ACTOR)

    row = db.get_mcp_audit_log(kept["id"])
    checkpoint = _checkpoints("mcp_audit_log")[0]
    assert row["prev_hash"] == checkpoint["last_deleted_hash"] == boundary


# ── atomicity: checkpoint before deletion, rollback on failure ────────────────


def test_failed_prune_rolls_back_checkpoint_and_deletion(monkeypatch):
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    before_rows = _count("mcp_audit_log")

    def boom(conn, table, boundary_id):
        raise RuntimeError("injected deletion failure")

    monkeypatch.setattr(db, "_delete_chain_prefix", boom)
    with pytest.raises(RuntimeError, match="injected deletion failure"):
        db.prune_retention(POLICY, actor=ACTOR)

    # neither the deletion nor its checkpoint survives
    assert _count("mcp_audit_log") == before_rows
    assert _checkpoints("mcp_audit_log") == []
    assert db.verify_audit_chain()["valid"] is True


def test_prune_succeeds_after_a_failed_attempt(monkeypatch):
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)

    def boom(conn, table, boundary_id):
        raise RuntimeError("injected deletion failure")

    monkeypatch.setattr(db, "_delete_chain_prefix", boom)
    with pytest.raises(RuntimeError):
        db.prune_retention(POLICY, actor=ACTOR)
    monkeypatch.undo()

    result = db.prune_retention(POLICY, actor=ACTOR)
    assert result["mcp_audit_deleted"] == 1
    assert len(_checkpoints("mcp_audit_log")) == 1
    assert db.verify_audit_chain()["valid"] is True


# ── tampering fails closed ────────────────────────────────────────────────────

CHECKPOINT_MUTATIONS = [
    ("created_at", "2000-01-01T00:00:00+00:00"),
    ("last_deleted_id", 999999),
    # non-integral forms that int() coercion aliased with the honest value
    # (the seeded prune stores last_deleted_id=1, first_retained_id=2,
    # deleted_count=1; SQLite stores x.9 as REAL in the INTEGER column):
    ("last_deleted_id", 1.9),
    ("last_deleted_hash", "f" * 64),
    ("first_retained_id", 999999),
    ("first_retained_id", 2.9),
    ("first_retained_prev_hash", "f" * 64),
    ("deleted_count", 0),
    ("deleted_count", 1.9),
    ("retention_policy", '{"mcp_audit_days":1}'),
    ("retention_policy", ""),
    ("actor", '{"actor_auth_type":"attacker"}'),
    ("prev_hash", "f" * 64),
    ("integrity_hash", "f" * 64),
]


@pytest.mark.parametrize("column,tampered", CHECKPOINT_MUTATIONS)
def test_checkpoint_tampering_fails_closed(column, tampered):
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)
    checkpoint = _checkpoints("mcp_audit_log")[0]
    assert str(checkpoint[column]) != str(tampered)

    _set_checkpoint_column(column, tampered, checkpoint["id"])
    chain = db.verify_audit_chain()
    assert chain["valid"] is False, f"tampered checkpoint {column} must fail"

    _set_checkpoint_column(column, checkpoint[column], checkpoint["id"])
    assert db.verify_audit_chain()["valid"] is True


@pytest.mark.parametrize("bad_version", [0, -1, 2, 4, 99, "not-a-version"])
def test_checkpoint_hash_version_must_be_exactly_3(bad_version):
    """A retention checkpoint's stored hash_v is not part of its envelope
    (the envelope prefix pins the constant "3"), so version enforcement must
    reject anything but exactly 3 — including a future 4."""
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)
    checkpoint = _checkpoints("mcp_audit_log")[0]

    _set_checkpoint_column("hash_v", bad_version, checkpoint["id"])
    chain = db.verify_audit_chain()
    assert chain["valid"] is False, f"checkpoint hash_v={bad_version!r} must fail"
    assert chain["reason"] == "unsupported checkpoint hash version"

    _set_checkpoint_column("hash_v", 3, checkpoint["id"])
    assert db.verify_audit_chain()["valid"] is True


def test_empty_checkpoint_actor_tampered_to_empty_text_fails_closed():
    """An actor-less prune stores '{}'; rewriting it to '' must not verify —
    the default-JSON normalization aliased them."""
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    db.prune_retention(POLICY)  # no actor -> stored actor is '{}'
    checkpoint = _checkpoints("mcp_audit_log")[0]
    assert checkpoint["actor"] == "{}"

    _set_checkpoint_column("actor", "", checkpoint["id"])
    assert db.verify_audit_chain()["valid"] is False

    _set_checkpoint_column("actor", "{}", checkpoint["id"])
    assert db.verify_audit_chain()["valid"] is True


def test_checkpoint_chain_reassignment_fails_closed():
    """Re-pointing a checkpoint at the other chain must not verify."""
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)
    checkpoint = _checkpoints("mcp_audit_log")[0]

    _set_checkpoint_column("chain", "admin_audit_log", checkpoint["id"])
    assert db.verify_audit_chain()["valid"] is False

    _set_checkpoint_column("chain", "mcp_audit_log", checkpoint["id"])
    assert db.verify_audit_chain()["valid"] is True


def test_tampered_checkpoint_fails_single_record_verification():
    _seed_mcp(40, 0)
    kept = _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)
    checkpoint = _checkpoints("mcp_audit_log")[0]

    _set_checkpoint_column("last_deleted_hash", "f" * 64, checkpoint["id"])
    verdict = db.verify_mcp_audit_record(kept["id"])
    assert verdict["chain_verified"] is False, verdict


def test_retained_row_tampering_after_prune_fails_closed():
    _seed_mcp(40, 0)
    kept = _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)

    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            "UPDATE mcp_audit_log SET reason = 'rewritten after prune' WHERE id = ?",
            (kept["id"],),
        )
    assert db.verify_mcp_audit_record(kept["id"])["chain_verified"] is False
    assert db.verify_audit_chain()["valid"] is False


def test_out_of_band_deletion_of_first_retained_row_is_detected():
    """Rows removed without a checkpoint (not via retention) must not verify."""
    _seed_mcp(40, 0)
    kept_a = _seed_mcp(1, 0)
    _seed_mcp(1, 1)
    db.prune_retention(POLICY, actor=ACTOR)

    with db._db_lock, db.get_conn() as conn:
        conn.execute("DELETE FROM mcp_audit_log WHERE id = ?", (kept_a["id"],))
    chain = db.verify_audit_chain()
    assert chain["valid"] is False
    assert chain["reason"] == "first retained row does not match checkpoint"


# ── boundary binding: deleted prefix ↔ retained chain ─────────────────────────
#
# The checkpoint hash chain is not a signature: an actor with database write
# access can rewrite checkpoint fields AND recompute the checkpoint hashes.
# What they cannot forge consistently is the three-way boundary agreement:
#   checkpoint.last_deleted_hash
#     == checkpoint.first_retained_prev_hash
#     == first retained row's stored prev_hash.
# These tests forge each leg independently, with recomputed hashes, and
# require verification to fail every time.


def _forge_checkpoints(chain, mutate):
    """Rewrite checkpoint fields like an attacker who also recomputes the
    checkpoint hash chain under the v3 envelope rules."""
    with db._db_lock, db.get_conn() as conn:
        checkpoints = db._list_chain_checkpoints(conn, chain)
        prev = "GENESIS"
        for cp in checkpoints:
            mutate(cp)
            cp["prev_hash"] = prev
            cp["integrity_hash"] = db.audit_envelope.compute_hash_v3(
                "audit_chain_checkpoint", cp, prev
            )
            conn.execute(
                "UPDATE audit_chain_checkpoints SET created_at = ?,"
                " last_deleted_id = ?, last_deleted_hash = ?,"
                " first_retained_id = ?, first_retained_prev_hash = ?,"
                " deleted_count = ?, retention_policy = ?, actor = ?,"
                " hash_v = ?, prev_hash = ?, integrity_hash = ? WHERE id = ?",
                (
                    cp["created_at"],
                    cp["last_deleted_id"],
                    cp["last_deleted_hash"],
                    cp["first_retained_id"],
                    cp["first_retained_prev_hash"],
                    cp["deleted_count"],
                    cp["retention_policy"],
                    cp["actor"],
                    cp["hash_v"],
                    cp["prev_hash"],
                    cp["integrity_hash"],
                    cp["id"],
                ),
            )
            prev = cp["integrity_hash"]


def test_honest_boundary_values_agree_three_ways_and_verify():
    _seed_mcp(40, 0)
    kept = _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)

    checkpoint = _checkpoints("mcp_audit_log")[0]
    row = db.get_mcp_audit_log(kept["id"])
    assert (
        checkpoint["last_deleted_hash"]
        == checkpoint["first_retained_prev_hash"]
        == row["prev_hash"]
    )
    assert db.verify_audit_chain()["valid"] is True
    assert db.verify_mcp_audit_record(kept["id"])["chain_verified"] is True


def test_forged_first_retained_prev_hash_fails_despite_valid_checkpoint_hash():
    """The defect this pins: nothing compared first_retained_prev_hash to the
    boundary, so a checkpoint could bind the retained chain to one hash while
    claiming a different first-retained prev hash."""
    _seed_mcp(40, 0)
    kept = _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)

    def mutate(cp):
        cp["first_retained_prev_hash"] = "f" * 64

    _forge_checkpoints("mcp_audit_log", mutate)
    assert db.verify_audit_chain()["valid"] is False
    assert db.verify_mcp_audit_record(kept["id"])["chain_verified"] is False


def test_forged_last_deleted_hash_fails_despite_valid_checkpoint_hash():
    _seed_mcp(40, 0)
    kept = _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)

    def mutate(cp):
        cp["last_deleted_hash"] = "f" * 64

    _forge_checkpoints("mcp_audit_log", mutate)
    assert db.verify_audit_chain()["valid"] is False
    assert db.verify_mcp_audit_record(kept["id"])["chain_verified"] is False


def test_tampered_retained_row_prev_hash_fails_despite_recomputed_row_hash():
    """Third leg: rewrite the first retained row's prev_hash and recompute its
    content hash; the row is self-consistent but detached from the boundary."""
    _seed_mcp(40, 0)
    kept = _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)

    with db._db_lock, db.get_conn() as conn:
        row = dict(
            conn.execute(
                "SELECT * FROM mcp_audit_log WHERE id = ?", (kept["id"],)
            ).fetchone()
        )
        row["prev_hash"] = "f" * 64
        forged = db.audit_envelope.compute_hash_v3(
            "mcp_audit_log", row, row["prev_hash"]
        )
        conn.execute(
            "UPDATE mcp_audit_log SET prev_hash = ?, integrity_hash = ?"
            " WHERE id = ?",
            (row["prev_hash"], forged, kept["id"]),
        )
    assert db.verify_audit_chain()["valid"] is False
    assert db.verify_mcp_audit_record(kept["id"])["chain_verified"] is False


def test_single_record_verification_binds_to_checkpoint_first_retained_id():
    """Delete the first retained row out of band and re-point the next row at
    the checkpoint anchor with a recomputed content hash. The row is fully
    self-consistent — only the checkpoint's first_retained_id exposes it."""
    _seed_mcp(40, 0)
    kept_a = _seed_mcp(1, 0)
    kept_b = _seed_mcp(1, 1)
    db.prune_retention(POLICY, actor=ACTOR)
    anchor = _checkpoints("mcp_audit_log")[0]["last_deleted_hash"]

    with db._db_lock, db.get_conn() as conn:
        conn.execute("DELETE FROM mcp_audit_log WHERE id = ?", (kept_a["id"],))
        row = dict(
            conn.execute(
                "SELECT * FROM mcp_audit_log WHERE id = ?", (kept_b["id"],)
            ).fetchone()
        )
        row["prev_hash"] = anchor
        forged = db.audit_envelope.compute_hash_v3("mcp_audit_log", row, anchor)
        conn.execute(
            "UPDATE mcp_audit_log SET prev_hash = ?, integrity_hash = ?"
            " WHERE id = ?",
            (anchor, forged, kept_b["id"]),
        )

    assert db.verify_mcp_audit_record(kept_b["id"])["chain_verified"] is False
    assert db.verify_audit_chain()["valid"] is False


def test_forged_boundary_ids_out_of_order_fail():
    """last_deleted_id must sit strictly below first_retained_id."""
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    db.prune_retention(POLICY, actor=ACTOR)

    def mutate(cp):
        cp["last_deleted_id"] = int(cp["first_retained_id"]) + 7

    _forge_checkpoints("mcp_audit_log", mutate)
    chain = db.verify_audit_chain()
    assert chain["valid"] is False
    assert chain["reason"] == "checkpoint boundary ids out of order"


def test_forged_nonmonotonic_checkpoint_ranges_fail():
    """Successive checkpoints must record strictly advancing deleted ranges."""
    _seed_mcp(60, 0)
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    db.prune_retention({**POLICY, "mcp_audit_days": 50}, actor=ACTOR)
    db.prune_retention(POLICY, actor=ACTOR)
    checkpoints = _checkpoints("mcp_audit_log")
    assert len(checkpoints) == 2
    first_boundary_id = int(checkpoints[0]["last_deleted_id"])

    def mutate(cp):
        if cp["id"] == checkpoints[1]["id"]:
            cp["last_deleted_id"] = first_boundary_id

    _forge_checkpoints("mcp_audit_log", mutate)
    chain = db.verify_audit_chain()
    assert chain["valid"] is False
    assert chain["reason"] == "checkpoint ranges not monotonic"


def test_forged_all_row_checkpoint_with_boundary_prev_hash_fails():
    """An all-row prune retains nothing: first_retained_prev_hash must be
    empty, not a claim about a row that does not exist."""
    _seed_mcp(40, 0)
    db.prune_retention(POLICY, actor=ACTOR)
    assert _count("mcp_audit_log") == 0

    def mutate(cp):
        cp["first_retained_prev_hash"] = "f" * 64

    _forge_checkpoints("mcp_audit_log", mutate)
    assert db.verify_audit_chain()["valid"] is False


# ── no-row / all-row / idempotency ────────────────────────────────────────────


def test_no_row_retention_creates_no_checkpoint():
    _seed_mcp(1, 0)
    _seed_admin(1, 0)
    result = db.prune_retention(POLICY, actor=ACTOR)

    assert result["mcp_audit_deleted"] == 0
    assert result["admin_audit_deleted"] == 0
    assert result["mcp_audit_checkpoint_id"] is None
    assert result["admin_audit_checkpoint_id"] is None
    assert _checkpoints("mcp_audit_log") == []
    assert _checkpoints("admin_audit_log") == []
    assert db.verify_audit_chain()["valid"] is True


def test_all_row_retention_then_new_appends_continue_the_chain():
    old_a = _seed_mcp(40, 0)
    old_b = _seed_mcp(40, 1)
    boundary = db.get_mcp_audit_log(old_b["id"])["integrity_hash"]

    result = db.prune_retention(POLICY, actor=ACTOR)
    assert result["mcp_audit_deleted"] == 2
    assert db.get_mcp_audit_log(old_a["id"]) is None
    assert _count("mcp_audit_log") == 0

    checkpoint = _checkpoints("mcp_audit_log")[0]
    assert checkpoint["first_retained_id"] is None
    assert checkpoint["first_retained_prev_hash"] == ""
    assert checkpoint["last_deleted_hash"] == boundary

    # empty-but-checkpointed chain verifies
    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["mcp"]["total"] == 0
    assert chain["mcp"]["anchor"] == boundary

    # a new append continues from the checkpoint boundary, not GENESIS
    fresh = _seed_mcp(0, 0)
    row = db.get_mcp_audit_log(fresh["id"])
    assert row["prev_hash"] == boundary
    assert db.verify_mcp_audit_record(fresh["id"])["chain_verified"] is True
    assert db.verify_audit_chain()["valid"] is True


def test_idempotent_retention_second_prune_is_a_noop():
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    first = db.prune_retention(POLICY, actor=ACTOR)
    assert first["mcp_audit_deleted"] == 1

    second = db.prune_retention(POLICY, actor=ACTOR)
    assert second["mcp_audit_deleted"] == 0
    assert second["mcp_audit_checkpoint_id"] is None
    assert len(_checkpoints("mcp_audit_log")) == 1
    assert db.verify_audit_chain()["valid"] is True


def test_successive_prunes_chain_their_checkpoints():
    _seed_mcp(60, 0)
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)

    first = db.prune_retention({**POLICY, "mcp_audit_days": 50}, actor=ACTOR)
    assert first["mcp_audit_deleted"] == 1
    second = db.prune_retention(POLICY, actor=ACTOR)
    assert second["mcp_audit_deleted"] == 1

    checkpoints = _checkpoints("mcp_audit_log")
    assert len(checkpoints) == 2
    assert checkpoints[0]["prev_hash"] == "GENESIS"
    assert checkpoints[1]["prev_hash"] == checkpoints[0]["integrity_hash"]

    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["mcp"]["checkpoints"] == 2
    assert chain["mcp"]["anchor"] == checkpoints[1]["last_deleted_hash"]


def test_backdated_row_behind_retained_rows_is_kept_not_orphaned():
    """Prefix semantics: a backdated old row that sits after a retained row in
    chain order is retained (chain stays verifiable) instead of being cut out
    of the middle of the chain."""
    _seed_mcp(40, 0)
    _seed_mcp(1, 0)
    backdated = _seed_mcp(40, 1)  # old ts, but appended after the fresh row

    result = db.prune_retention(POLICY, actor=ACTOR)
    assert result["mcp_audit_deleted"] == 1  # only the true prefix
    assert db.get_mcp_audit_log(backdated["id"]) is not None
    assert db.verify_audit_chain()["valid"] is True


def test_scan_history_and_usage_log_pruning_unchanged():
    old_ts = _ts(40)
    new_ts = _ts(1)
    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_history (key_hash, ts, is_threat, threat_level, reason)"
            " VALUES (?, ?, ?, ?, ?)",
            ("kh", old_ts, 0, "SAFE", "old scan"),
        )
        conn.execute(
            "INSERT INTO scan_history (key_hash, ts, is_threat, threat_level, reason)"
            " VALUES (?, ?, ?, ?, ?)",
            ("kh", new_ts, 0, "SAFE", "new scan"),
        )
    result = db.prune_retention(POLICY, actor=ACTOR)
    assert result["scan_history_deleted"] == 1
    assert _count("scan_history") == 1
