"""Audit-chain append serialization tests.

The mcp_audit_log and admin_audit_log hash chains are each globally scoped:
one chain per table, tip = the row with the highest id. The process-local
``_db_lock`` cannot serialize appends across application replicas sharing one
Postgres: two replicas can read the same tip and both insert a row committing
to it, forking the chain. The append must therefore be atomic at the database
level — on Postgres a transaction-scoped advisory lock keyed per chain wraps
the read-tip + insert in one transaction; on SQLite the single-writer database
plus ``_db_lock`` already serialize appends and the guard stays a no-op.

Two layers of coverage:

1. Transaction-shape tests (run everywhere, no Postgres needed): on Postgres
   the append must emit BEGIN -> pg_advisory_xact_lock(chain key) -> read tip
   -> INSERT -> COMMIT on one connection, and ROLLBACK on failure.
2. An adversarial multi-process race test against a real, disposable Postgres
   (gated behind INTERLOCK_TEST_DATABASE_URL): N worker processes — each with
   its own process-local ``_db_lock``, like N replicas — hammer the same
   chain concurrently. Asserts no fork, contiguous ids, full-chain
   verification, and rows == append calls.

Run the adversarial test against a disposable Docker Postgres:

    docker run -d --name interlock-race-pg -e POSTGRES_PASSWORD=racepw \
        -p 54329:5432 postgres:16
    INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:racepw@127.0.0.1:54329/postgres \
        python -m pytest tests/test_audit_chain_concurrency.py -q

INTERLOCK_CHAIN_TEST_WRITERS / INTERLOCK_CHAIN_TEST_APPENDS scale the load.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import db  # noqa: E402

DB_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
WRITERS = int(os.getenv("INTERLOCK_CHAIN_TEST_WRITERS", "8"))
APPENDS = int(os.getenv("INTERLOCK_CHAIN_TEST_APPENDS", "25"))


# ── Transaction-shape tests (no real Postgres required) ──────────────────────


class RecordingCursor:
    def __init__(self, raw):
        self.raw = raw
        self.sql = ""

    def execute(self, sql, params=()):
        self.sql = sql
        self.raw.statements.append((sql, params))
        if self.raw.fail_on and self.raw.fail_on in sql:
            raise RuntimeError(f"injected failure on: {self.raw.fail_on}")
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []


class RecordingRaw:
    def __init__(self, fail_on=""):
        self.statements = []
        self.fail_on = fail_on
        self.closed = False

    def cursor(self):
        return RecordingCursor(self)

    def close(self):
        self.closed = True


class FakeSqliteConn:
    """Not a _PostgresConn — the guard must never touch it."""

    def __init__(self):
        self.statements = []

    def execute(self, sql, params=()):
        self.statements.append((sql, params))
        return self


def _patched_pg_conn(monkeypatch, fail_on=""):
    raw = RecordingRaw(fail_on=fail_on)
    conn = db._PostgresConn(raw)

    class FakeConnManager:
        def __enter__(self):
            return conn

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(db, "get_conn", lambda: FakeConnManager())
    return raw


def _assert_serialized_append_shape(raw, table):
    sqls = [sql for sql, _params in raw.statements]
    assert sqls[0] == "BEGIN", f"append must open a transaction, got: {sqls}"
    assert "pg_advisory_xact_lock" in sqls[1], (
        f"append must take the chain advisory lock before reading the tip, "
        f"got: {sqls}"
    )
    assert raw.statements[1][1] == (db._audit_chain_lock_key(table),)
    assert f"SELECT integrity_hash FROM {table}" in sqls[2]
    assert f"INSERT INTO {table}" in sqls[3]
    assert "RETURNING id" in sqls[3]
    assert sqls[4] == "COMMIT", f"append must commit the transaction, got: {sqls}"
    assert len(sqls) == 5


def test_postgres_mcp_append_locks_chain_inside_one_transaction(monkeypatch):
    raw = _patched_pg_conn(monkeypatch)

    db.log_mcp_audit_event(
        {
            "server_id": "tx-shape",
            "tool_name": "read_file",
            "role": "readonly_agent",
            "action": "allow",
            "matched_rule": "role_allows",
            "reason": "transaction shape test",
        }
    )

    _assert_serialized_append_shape(raw, "mcp_audit_log")


def test_postgres_admin_append_locks_chain_inside_one_transaction(monkeypatch):
    raw = _patched_pg_conn(monkeypatch)

    db.log_admin_audit_event(
        {
            "actor_auth_type": "token",
            "actor_role": "admin",
            "action": "key.created",
            "target_type": "api_key",
            "target_id": "tx-shape",
            "reason": "transaction shape test",
        }
    )

    _assert_serialized_append_shape(raw, "admin_audit_log")


def test_postgres_append_rolls_back_on_insert_failure(monkeypatch):
    raw = _patched_pg_conn(monkeypatch, fail_on="INSERT INTO mcp_audit_log")

    with pytest.raises(RuntimeError, match="injected failure"):
        db.log_mcp_audit_event(
            {
                "server_id": "tx-shape",
                "tool_name": "read_file",
                "action": "allow",
                "reason": "rollback test",
            }
        )

    sqls = [sql for sql, _params in raw.statements]
    assert sqls[-1] == "ROLLBACK", (
        f"a failed append must not leave the transaction (and advisory lock) "
        f"open, got: {sqls}"
    )
    assert "COMMIT" not in sqls


def test_chain_lock_keys_are_stable_distinct_signed_64bit():
    mcp_key = db._audit_chain_lock_key("mcp_audit_log")
    admin_key = db._audit_chain_lock_key("admin_audit_log")

    assert mcp_key != admin_key, "the two chains must not serialize each other"
    for key in (mcp_key, admin_key):
        assert isinstance(key, int)
        assert -(2**63) <= key < 2**63, "must fit Postgres advisory lock bigint"
    # Stable across processes/replicas: derived from the chain name only.
    assert mcp_key == db._audit_chain_lock_key("mcp_audit_log")


def test_guard_is_a_noop_on_sqlite():
    fake = FakeSqliteConn()

    with db._serialized_chain_append(fake, "mcp_audit_log"):
        pass

    assert fake.statements == [], (
        "on SQLite the guard must not emit transaction or lock statements; "
        "_db_lock plus the single-writer database already serialize appends"
    )


# ── Adversarial multi-process race test (real Postgres, opt-in) ──────────────

_WORKER_SRC = """
import os, sys, time, pathlib

url, table, n_appends, sync_dir, worker_id = sys.argv[1:6]
os.environ["DATABASE_URL"] = url
sys.path.insert(0, os.getcwd())

from core import db

assert db.USE_POSTGRES, "worker must run against Postgres"

sync = pathlib.Path(sync_dir)
(sync / ("ready-" + worker_id)).touch()
deadline = time.time() + 60
while not (sync / "go").exists():
    if time.time() > deadline:
        raise SystemExit("timed out waiting for go signal")
    time.sleep(0.005)

for i in range(int(n_appends)):
    if table == "mcp":
        db.log_mcp_audit_event(
            {
                "server_id": "race-server",
                "tool_name": "tool-%s-%d" % (worker_id, i),
                "role": "readonly_agent",
                "action": "allow",
                "matched_rule": "race_test",
                "reason": "writer %s append %d" % (worker_id, i),
            }
        )
    else:
        db.log_admin_audit_event(
            {
                "actor_auth_type": "token",
                "actor_role": "admin",
                "action": "race_test",
                "target_type": "test",
                "target_id": "%s-%d" % (worker_id, i),
                "reason": "writer %s append %d" % (worker_id, i),
            }
        )
print("WORKER_DONE", worker_id)
"""

_RESET_SRC = """
import os, sys

os.environ["DATABASE_URL"] = sys.argv[1]
sys.path.insert(0, os.getcwd())

from core import db

assert db.USE_POSTGRES, "reset must run against Postgres"
db.init_db()
with db.get_conn() as conn:
    conn.execute("TRUNCATE mcp_audit_log, admin_audit_log RESTART IDENTITY")
print("RESET_OK")
"""

_VERIFIER_SRC = """
import os, sys, json

os.environ["DATABASE_URL"] = sys.argv[1]
sys.path.insert(0, os.getcwd())

from core import db

table = "mcp_audit_log" if sys.argv[2] == "mcp" else "admin_audit_log"
with db.get_conn() as conn:
    rows = [
        dict(r)
        for r in conn.execute(
            "SELECT id, prev_hash, integrity_hash FROM " + table + " ORDER BY id ASC"
        ).fetchall()
    ]
print(
    json.dumps(
        {
            "chain": db.verify_audit_chain(),
            "count": len(rows),
            "ids": [r["id"] for r in rows],
            "prev_hashes": [r["prev_hash"] for r in rows],
            "integrity_hashes": [r["integrity_hash"] for r in rows],
        }
    )
)
"""


def _race_db_url():
    url = (os.getenv(DB_URL_ENV) or "").strip()
    if not url:
        pytest.skip(
            f"{DB_URL_ENV} not set; the adversarial race test needs a "
            f"disposable Postgres (see module docstring)"
        )
    if db.is_production_database_url(url):
        pytest.skip(
            "refusing to run the destructive race test against a "
            "production-like database"
        )
    return url


def _run_snippet(src, args, timeout=120):
    proc = subprocess.run(
        [sys.executable, "-c", src, *args],
        cwd=str(ROOT),
        env={**os.environ, "PYTHON_DOTENV_DISABLED": "1"},
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert proc.returncode == 0, (
        f"subprocess failed (rc={proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    return proc.stdout


@pytest.mark.parametrize("table", ["mcp", "admin"])
def test_concurrent_replica_appends_cannot_fork_the_chain(table, tmp_path):
    url = _race_db_url()
    _run_snippet(_RESET_SRC, [url])

    sync_dir = tmp_path / f"sync-{table}"
    sync_dir.mkdir()
    env = {**os.environ, "PYTHON_DOTENV_DISABLED": "1"}
    workers = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _WORKER_SRC,
                url,
                table,
                str(APPENDS),
                str(sync_dir),
                str(wid),
            ],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for wid in range(WRITERS)
    ]

    try:
        # Wait for every replica to finish importing before firing the gun,
        # so the appends genuinely overlap.
        import time

        deadline = time.time() + 90
        while len(list(sync_dir.glob("ready-*"))) < WRITERS:
            if time.time() > deadline:
                raise AssertionError("workers never became ready")
            time.sleep(0.05)
        (sync_dir / "go").touch()

        failures = []
        for wid, proc in enumerate(workers):
            out, err = proc.communicate(timeout=180)
            if proc.returncode != 0:
                failures.append(f"worker {wid} rc={proc.returncode}\n{err}")
        assert not failures, "\n".join(failures)
    finally:
        for proc in workers:
            if proc.poll() is None:
                proc.kill()

    data = json.loads(
        _run_snippet(_VERIFIER_SRC, [url, table]).strip().splitlines()[-1]
    )
    total = WRITERS * APPENDS

    # Every append call must have produced exactly one row.
    assert data["count"] == total

    # Sequence numbers (ids) must be contiguous: no aborted/ghost inserts.
    ids = data["ids"]
    assert ids == list(range(ids[0], ids[0] + total)), "ids must be contiguous"

    # No fork: no two rows may commit to the same previous hash, and each row
    # must extend exactly the row before it.
    prev_hashes = data["prev_hashes"]
    integrity_hashes = data["integrity_hashes"]
    assert prev_hashes[0] == "GENESIS"
    assert (
        len(set(prev_hashes)) == total
    ), "chain forked: multiple rows committed to the same previous hash"
    assert (
        prev_hashes[1:] == integrity_hashes[:-1]
    ), "chain must be a single linked line, in id order"
    assert len(set(integrity_hashes)) == total

    # The production verifier must agree over the full result.
    assert data["chain"]["valid"] is True, data["chain"]
    assert data["chain"][table]["total"] == total
