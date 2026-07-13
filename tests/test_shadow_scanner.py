import sys
import sqlite3
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_shadow_scanner_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

import pytest  # noqa: E402
import asyncio  # noqa: E402
from unittest.mock import AsyncMock, MagicMock  # noqa: E402
from httpx import TimeoutException, ConnectError, Request  # noqa: E402

from core import db as _db  # noqa: E402
from core.shadow_scanner import (  # noqa: E402
    probe_target,
    run_shadow_scan,
    ProbeResult,
    _calculate_risk_score,
)


@pytest.fixture(scope="module", autouse=True)
def _isolated_global_db():
    """Discovery audit rows go through db.log_mcp_audit_event (the chained
    writer), which targets the global DB — point it at a disposable file."""
    old_db_path = _db.DB_PATH
    _db.DB_PATH = TEST_DB
    _db.init_db()
    yield
    _db.DB_PATH = old_db_path
    for path in (TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


def run(coro):
    return asyncio.run(coro)


def _mock_client(status_code=200, json_body=None, text_body=None, raise_exc=None):
    resp = MagicMock()
    resp.status_code = status_code
    if json_body is not None:
        resp.json = MagicMock(return_value=json_body)
    elif text_body is not None:
        resp.json = MagicMock(side_effect=Exception("not json"))
    client = AsyncMock()
    if raise_exc:
        client.get = AsyncMock(side_effect=raise_exc)
    else:
        client.get = AsyncMock(return_value=resp)
    return client


def _in_memory_db():
    from core import db as _db

    conn = sqlite3.connect(":memory:")
    conn.executescript(_db.SCHEMA)
    return conn


def test_probe_mcp_endpoint_detected():
    client = _mock_client(json_body={"tools": [{"name": "read_file"}]})
    result = run(probe_target("http://localhost:3000", client=client))
    assert result.looks_like_mcp is True
    assert result.tool_listing_available is True
    assert result.auth_required is False
    assert result.responded is True


def test_probe_auth_required_flagged():
    client = _mock_client(status_code=401)
    result = run(probe_target("http://localhost:3000", client=client))
    assert result.auth_required is True
    assert result.looks_like_mcp is True
    assert result.tool_listing_available is False


def test_probe_non_mcp_endpoint_not_flagged():
    client = _mock_client(text_body="<html>hello</html>")
    result = run(probe_target("http://localhost:3000", client=client))
    assert result.looks_like_mcp is False
    assert result.responded is True


def test_probe_timeout_not_flagged():
    req = Request("GET", "http://localhost:3000/tools/list")
    client = _mock_client(raise_exc=TimeoutException("timed out", request=req))
    result = run(probe_target("http://localhost:3000", client=client))
    assert result.responded is False
    assert result.looks_like_mcp is False


def test_probe_connection_error_not_flagged():
    req = Request("GET", "http://localhost:3000/tools/list")
    client = _mock_client(raise_exc=ConnectError("refused", request=req))
    result = run(probe_target("http://localhost:3000", client=client))
    assert result.responded is False


def test_scan_unregistered_endpoint_is_shadow():
    conn = _in_memory_db()
    conn.execute(
        "INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
        ("http://shadow:9000", "2026-01-01"),
    )
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    findings = run(run_shadow_scan(conn, client=client))
    assert len(findings) == 1
    assert findings[0].url == "http://shadow:9000"
    assert findings[0].is_registered is False


def test_scan_registered_endpoint_not_shadow():
    conn = _in_memory_db()
    conn.execute(
        "INSERT INTO mcp_servers (server_id, url, registered_at) VALUES (?,?,?)",
        ("srv1", "http://registered:9000", "2026-01-01"),
    )
    conn.execute(
        "INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
        ("http://registered:9000", "2026-01-01"),
    )
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    findings = run(run_shadow_scan(conn, client=client))
    assert len(findings) == 0


def test_scan_non_responding_target_not_shadow():
    conn = _in_memory_db()
    conn.execute(
        "INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
        ("http://dead:9000", "2026-01-01"),
    )
    conn.commit()
    req = Request("GET", "http://dead:9000/tools/list")
    client = _mock_client(raise_exc=ConnectError("refused", request=req))
    findings = run(run_shadow_scan(conn, client=client))
    assert len(findings) == 0


def test_risk_score_unauthenticated_tool_listing():
    probe = ProbeResult(
        url="http://x",
        responded=True,
        looks_like_mcp=True,
        auth_required=False,
        tool_listing_available=True,
        status_code=200,
    )
    assert _calculate_risk_score(probe) >= 80


def test_risk_score_auth_required():
    probe = ProbeResult(
        url="http://x",
        responded=True,
        looks_like_mcp=True,
        auth_required=True,
        tool_listing_available=False,
        status_code=401,
    )
    assert _calculate_risk_score(probe) < 50


def test_audit_log_written_on_discovery():
    conn = _in_memory_db()
    conn.execute(
        "INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
        ("http://shadow-audit:9000", "2026-01-01"),
    )
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    run(run_shadow_scan(conn, client=client))
    rows = [
        r
        for r in _db.list_mcp_audit_logs(limit=20)
        if r["action"] == "shadow_discovered"
        and "http://shadow-audit:9000" in r["reason"]
    ]
    assert len(rows) >= 1


def test_upsert_updates_last_seen():
    conn = _in_memory_db()
    conn.execute(
        "INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
        ("http://shadow:9000", "2026-01-01"),
    )
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    run(run_shadow_scan(conn, client=client))
    run(run_shadow_scan(conn, client=client))
    rows = conn.execute(
        "SELECT COUNT(*) FROM shadow_mcp_servers WHERE url='http://shadow:9000'"
    ).fetchone()
    assert rows[0] == 1


class _NoCommitConn:
    """Mimics db._PostgresConn: an autocommit wrapper with no commit() method."""

    def __init__(self, inner):
        self._inner = inner

    def execute(self, sql, params=()):
        return self._inner.execute(sql, params)


def test_scan_works_on_autocommit_conn_without_commit_method():
    raw = _in_memory_db()
    raw.isolation_level = None  # autocommit, like every db.get_conn() connection
    conn = _NoCommitConn(raw)
    conn.execute(
        "INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
        ("http://shadow-nocommit:9000", "2026-01-01"),
    )
    client = _mock_client(json_body={"tools": []})
    findings = run(run_shadow_scan(conn, client=client))
    assert len(findings) == 1


def test_disabled_target_not_probed():
    conn = _in_memory_db()
    conn.execute(
        "INSERT INTO shadow_scan_targets (url, enabled, added_at) VALUES (?,?,?)",
        ("http://disabled:9000", 0, "2026-01-01"),
    )
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    run(run_shadow_scan(conn, client=client))
    client.get.assert_not_called()
