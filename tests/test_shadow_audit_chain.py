"""Shadow-scan audit writes must go through the hash-chained writer.

core/shadow_scanner.py (``shadow_discovered``) and core/admin.py
``review_shadow_server`` (``shadow_reviewed``) used to INSERT INTO
mcp_audit_log directly, without prev_hash/integrity_hash. Any such row
poisons the chain: verify_audit_chain() fails with "pre-integrity records
found". Both paths must route through db.log_mcp_audit_event — the single
chained writer — and no other production code may insert audit rows directly.
"""

import asyncio
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_shadow_audit_chain_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import admin  # noqa: E402
from core import db  # noqa: E402
from core.shadow_scanner import run_shadow_scan  # noqa: E402

ROOT_TOKEN = "root-shadow-chain-token"


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    old_db_path = db.DB_PATH
    old_admin_token = admin.ADMIN_TOKEN
    db.DB_PATH = TEST_DB
    admin.ADMIN_TOKEN = ROOT_TOKEN
    db.init_db()
    yield
    db.DB_PATH = old_db_path
    admin.ADMIN_TOKEN = old_admin_token
    for path in (TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


def _mock_client(json_body):
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=json_body)
    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    return client


def test_shadow_discovery_audit_row_is_chain_valid():
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO shadow_scan_targets (url, added_at) VALUES (?, ?)",
            ("http://shadow-chain:9000", "2026-01-01"),
        )
        client = _mock_client({"tools": []})
        findings = asyncio.run(run_shadow_scan(conn, client=client))
    assert len(findings) == 1

    rows = db.list_mcp_audit_logs(limit=10)
    row = next(r for r in rows if r["action"] == "shadow_discovered")
    assert "http://shadow-chain:9000" in row["reason"]
    assert row["matched_rule"] == "shadow_scanner"
    assert row["role"] == "system"
    # No established Interlock server ID exists at discovery time.
    assert row["server_id"] == ""
    assert row["prev_hash"], "shadow_discovered row must be chained (prev_hash)"
    assert row["integrity_hash"], (
        "shadow_discovered row must carry an integrity hash — a bare INSERT "
        "poisons the chain"
    )

    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain


def test_shadow_review_audit_row_is_chain_valid():
    now = "2026-07-13T00:00:00+00:00"
    with db.get_conn() as conn:
        cursor = conn.execute(
            "INSERT INTO shadow_mcp_servers (url, first_seen, last_seen) "
            "VALUES (?, ?, ?)",
            ("https://shadow-review.example.com/mcp", now, now),
        )
        server_id = cursor.lastrowid

    admin.review_shadow_server(
        server_id,
        admin.ShadowServerReviewRequest(
            status="quarantined", notes="chain regression test"
        ),
        x_admin_token=ROOT_TOKEN,
    )

    rows = db.list_mcp_audit_logs(limit=10)
    row = next(r for r in rows if r["action"] == "shadow_reviewed")
    assert row["server_id"] == str(server_id)
    assert row["reason"] == "chain regression test"
    assert row["matched_rule"] == "operator_action"
    assert row["prev_hash"], "shadow_reviewed row must be chained (prev_hash)"
    assert row["integrity_hash"], (
        "shadow_reviewed row must carry an integrity hash — a bare INSERT "
        "poisons the chain"
    )

    # Both shadow paths have now written; the full chain must still verify.
    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain


# ── No unchained audit-write paths anywhere in production code ────────────────

_AUDIT_INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+(?:mcp_audit_log|admin_audit_log)\b", re.IGNORECASE
)

# Directories holding tracked production Python code. tests/ is excluded on
# purpose: fixtures may insert raw rows to simulate legacy or tampered data.
_PRODUCTION_DIRS = ("core", "routes", "models", "demo", "examples", "scripts")


def _production_python_files():
    yield from ROOT.glob("*.py")
    for dirname in _PRODUCTION_DIRS:
        yield from (ROOT / dirname).rglob("*.py")


def test_no_direct_audit_inserts_outside_chained_writers():
    """Hard guarantee: nothing writes an audit row outside the chained writers.

    The only allowed INSERTs into mcp_audit_log / admin_audit_log live in
    core/db.py, inside log_mcp_audit_event / log_admin_audit_event. Exactly
    two statements are expected there; anything else — anywhere — is an
    unchained bypass that would poison the hash chain.
    """
    offenders = []
    db_py_matches = 0
    for path in _production_python_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        matches = _AUDIT_INSERT_RE.findall(text)
        if not matches:
            continue
        if path == ROOT / "core" / "db.py":
            db_py_matches = len(matches)
            continue
        offenders.append(f"{path.relative_to(ROOT)}: {len(matches)} insert(s)")

    assert not offenders, (
        "direct audit-log INSERTs outside core/db.py chained writers "
        f"(route them through db.log_mcp_audit_event / "
        f"db.log_admin_audit_event): {offenders}"
    )
    assert db_py_matches == 2, (
        "core/db.py must contain exactly the two chained INSERT statements "
        f"(log_mcp_audit_event + log_admin_audit_event), found {db_py_matches}"
    )
