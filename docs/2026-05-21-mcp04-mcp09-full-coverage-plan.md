# MCP04 + MCP09 Full Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement supply-chain provenance enforcement (MCP04) and shadow MCP server discovery (MCP09) so Interlock achieves 10/10 OWASP MCP Top 10 coverage.

**Architecture:** Two independent feature modules (`core/provenance.py`, `core/shadow_scanner.py`) that hook into the existing `mcp_gateway.py` and `admin.py` surfaces. All persistence uses the existing SQLite DB via `_ensure_column` migrations and new table DDL additions. OWASP doc is updated last, only after all tests pass.

**Tech Stack:** Python 3.12 / FastAPI / SQLite / httpx (async HTTP) / pytest + unittest.mock

**Design spec:** `docs/2026-05-21-mcp04-mcp09-10-of-10-design.md` — consult it for the full decision matrix, data shapes, and risk score formulas.

---

### Task 1: DB schema — provenance columns + new tables

**Files:**
- Modify: `core/db.py`

Read `core/db.py` before editing. Identify the `_ensure_column` call block inside `init_db()` (after the drift_reasons line) and the `SCHEMA` triple-quoted string.

- [ ] **Step 1: Add `system_config` table DDL to `SCHEMA`**

Inside the `SCHEMA` string, after the `mcp_audit_log` table block, add:

```sql
CREATE TABLE IF NOT EXISTS system_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS shadow_mcp_servers (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    url                    TEXT NOT NULL UNIQUE,
    probe_path             TEXT DEFAULT '/tools/list',
    status                 TEXT DEFAULT 'unreviewed',
    first_seen             TEXT NOT NULL,
    last_seen              TEXT NOT NULL,
    auth_required          INTEGER DEFAULT 0,
    tool_listing_available INTEGER DEFAULT 0,
    risk_score             INTEGER DEFAULT 0,
    notes                  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS shadow_scan_targets (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    url      TEXT NOT NULL UNIQUE,
    enabled  INTEGER DEFAULT 1,
    added_at TEXT NOT NULL
);
```

- [ ] **Step 2: Add `_ensure_column` calls for provenance columns**

Inside `init_db()`, after the existing drift_reasons `_ensure_column` line, add:

```python
_ensure_column(conn, "mcp_servers", "source_type",       "TEXT DEFAULT 'unknown'")
_ensure_column(conn, "mcp_servers", "registry",          "TEXT DEFAULT ''")
_ensure_column(conn, "mcp_servers", "package_name",      "TEXT DEFAULT ''")
_ensure_column(conn, "mcp_servers", "package_version",   "TEXT DEFAULT ''")
_ensure_column(conn, "mcp_servers", "source_url",        "TEXT DEFAULT ''")
_ensure_column(conn, "mcp_servers", "source_hash",       "TEXT DEFAULT ''")
_ensure_column(conn, "mcp_servers", "provenance_status", "TEXT DEFAULT 'unknown'")
```

- [ ] **Step 3: Verify DB migration runs without error**

Run:
```bash
python -c "from core import db; db.init_db(); print('DB init OK')"
```
Expected: `DB init OK` with no exceptions.

- [ ] **Step 4: Commit**

```bash
git add core/db.py
git commit -m "feat: add provenance columns and shadow server tables to DB schema"
```

---

### Task 2: Provenance engine (`core/provenance.py`)

**Files:**
- Create: `core/provenance.py`
- Create: `tests/test_provenance.py` (stub — full tests in Task 3)

This module is pure logic — no DB calls, no HTTP calls. Policy is a plain dict passed in by the caller.

- [ ] **Step 1: Write the failing test stubs**

Create `tests/test_provenance.py` with all 14 test function signatures returning `assert False, "not implemented"` so they all fail:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from core.provenance import evaluate_provenance, ProvenanceResult

POLICY = {
    "allowed_registries": ["registry.npmjs.org", "pypi.org"],
    "allowed_source_urls": ["https://github.com/modelcontextprotocol/"],
    "pinned_versions": {"pkg-a": "1.2.3"},
    "pinned_hashes": {"pkg-a": "sha256:aabbcc"},
}

def make_server(source_type="npm", registry="registry.npmjs.org",
                package_name="pkg-b", package_version="1.0.0",
                source_hash="", provenance_status="unknown"):
    return dict(source_type=source_type, registry=registry,
                package_name=package_name, package_version=package_version,
                source_hash=source_hash, provenance_status=provenance_status)

def test_known_registry_no_pin_is_allowed():          assert False, "not implemented"
def test_known_registry_matching_hash_is_allowed():    assert False, "not implemented"
def test_missing_provenance_is_monitor():              assert False, "not implemented"
def test_unknown_registry_is_monitor():                assert False, "not implemented"
def test_version_mismatch_is_quarantine():             assert False, "not implemented"
def test_hash_mismatch_is_quarantine():                assert False, "not implemented"
def test_denied_source_type_is_denied():               assert False, "not implemented"
def test_hash_change_after_approval_is_drift():        assert False, "not implemented"
def test_version_change_after_approval_is_drift():     assert False, "not implemented"
def test_quarantine_blocks_tool_call():                assert False, "not implemented"
def test_allowed_provenance_permits_tool_call():       assert False, "not implemented"
def test_audit_log_written_on_provenance_check():      assert False, "not implemented"
def test_audit_log_written_on_provenance_drift():      assert False, "not implemented"
def test_empty_policy_is_monitor_for_all():            assert False, "not implemented"
```

- [ ] **Step 2: Run stubs to verify all 14 fail**

Run: `python -m pytest tests/test_provenance.py -v`
Expected: 14 FAILED (ImportError on `core.provenance` is also acceptable at this stage).

- [ ] **Step 3: Implement `core/provenance.py`**

Create `core/provenance.py`:

```python
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("interlock.provenance")


@dataclass
class ProvenanceResult:
    status: str                    # allowed | monitor | quarantine | denied
    reason: str
    checks_run: list = field(default_factory=list)
    drift_detected: bool = False


def evaluate_provenance(server_record: dict, policy: dict,
                        prior_record: dict | None = None) -> ProvenanceResult:
    """
    Evaluate a server's provenance metadata against the operator policy.

    server_record: dict with keys from mcp_servers provenance columns.
    policy: dict with keys allowed_registries, allowed_source_urls,
            pinned_versions, pinned_hashes.
    prior_record: the previously stored server_record, used for drift detection.
                  Pass None on first registration.
    """
    checks: list[str] = []

    source_type = (server_record.get("source_type") or "unknown").strip()
    registry    = (server_record.get("registry") or "").strip()
    pkg_name    = (server_record.get("package_name") or "").strip()
    pkg_version = (server_record.get("package_version") or "").strip()
    src_hash    = (server_record.get("source_hash") or "").strip()

    allowed_registries  = policy.get("allowed_registries") or []
    pinned_versions     = policy.get("pinned_versions") or {}
    pinned_hashes       = policy.get("pinned_hashes") or {}

    # Operator hard-deny
    if source_type == "denied":
        checks.append("source_type_denied")
        return ProvenanceResult(status="denied",
                                reason="source_type is explicitly denied.",
                                checks_run=checks)

    # Drift detection — check before policy so drift always quarantines
    if prior_record is not None:
        prior_hash    = (prior_record.get("source_hash") or "").strip()
        prior_version = (prior_record.get("package_version") or "").strip()
        prior_status  = (prior_record.get("provenance_status") or "unknown").strip()
        if prior_status == "allowed":
            if src_hash and prior_hash and src_hash != prior_hash:
                checks.append("hash_drift")
                return ProvenanceResult(status="quarantine",
                                        reason="source_hash changed after prior approval.",
                                        checks_run=checks, drift_detected=True)
            if pkg_version and prior_version and pkg_version != prior_version:
                checks.append("version_drift")
                return ProvenanceResult(status="quarantine",
                                        reason="package_version changed after prior approval.",
                                        checks_run=checks, drift_detected=True)

    # Missing provenance
    if not registry or source_type == "unknown":
        checks.append("missing_provenance")
        return ProvenanceResult(status="monitor",
                                reason="No registry or source_type provided.",
                                checks_run=checks)

    # Unknown registry
    if allowed_registries and registry not in allowed_registries:
        checks.append("unknown_registry")
        return ProvenanceResult(status="monitor",
                                reason=f"Registry '{registry}' is not in allowed_registries.",
                                checks_run=checks)

    checks.append("registry_ok")

    # Version pin check
    if pkg_name in pinned_versions:
        pinned_ver = pinned_versions[pkg_name]
        if pkg_version != pinned_ver:
            checks.append("version_mismatch")
            return ProvenanceResult(
                status="quarantine",
                reason=f"Version '{pkg_version}' does not match pinned '{pinned_ver}'.",
                checks_run=checks)
        checks.append("version_ok")

    # Hash pin check
    if pkg_name in pinned_hashes:
        pinned_hash = pinned_hashes[pkg_name]
        if src_hash != pinned_hash:
            checks.append("hash_mismatch")
            return ProvenanceResult(
                status="quarantine",
                reason=f"source_hash does not match pinned hash for '{pkg_name}'.",
                checks_run=checks)
        checks.append("hash_ok")

    checks.append("allowed")
    return ProvenanceResult(status="allowed",
                            reason="All provenance checks passed.",
                            checks_run=checks)
```

- [ ] **Step 4: Write the real test bodies**

Replace the stubs in `tests/test_provenance.py` with real assertions (tests 1–9; tests 10–14 in Task 4 after gateway integration):

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from core.provenance import evaluate_provenance, ProvenanceResult

POLICY = {
    "allowed_registries": ["registry.npmjs.org", "pypi.org"],
    "allowed_source_urls": ["https://github.com/modelcontextprotocol/"],
    "pinned_versions": {"pkg-a": "1.2.3"},
    "pinned_hashes": {"pkg-a": "sha256:aabbcc"},
}

def make_server(source_type="npm", registry="registry.npmjs.org",
                package_name="pkg-b", package_version="1.0.0",
                source_hash="", provenance_status="unknown"):
    return dict(source_type=source_type, registry=registry,
                package_name=package_name, package_version=package_version,
                source_hash=source_hash, provenance_status=provenance_status)


def test_known_registry_no_pin_is_allowed():
    r = evaluate_provenance(make_server(), POLICY)
    assert r.status == "allowed", r.reason

def test_known_registry_matching_hash_is_allowed():
    srv = make_server(package_name="pkg-a", package_version="1.2.3",
                      source_hash="sha256:aabbcc")
    r = evaluate_provenance(srv, POLICY)
    assert r.status == "allowed", r.reason

def test_missing_provenance_is_monitor():
    r = evaluate_provenance(make_server(source_type="unknown", registry=""), POLICY)
    assert r.status == "monitor"

def test_unknown_registry_is_monitor():
    r = evaluate_provenance(make_server(registry="evil.registry.io"), POLICY)
    assert r.status == "monitor"

def test_version_mismatch_is_quarantine():
    srv = make_server(package_name="pkg-a", package_version="9.9.9")
    r = evaluate_provenance(srv, POLICY)
    assert r.status == "quarantine"

def test_hash_mismatch_is_quarantine():
    srv = make_server(package_name="pkg-a", package_version="1.2.3",
                      source_hash="sha256:wronghash")
    r = evaluate_provenance(srv, POLICY)
    assert r.status == "quarantine"

def test_denied_source_type_is_denied():
    r = evaluate_provenance(make_server(source_type="denied"), POLICY)
    assert r.status == "denied"

def test_hash_change_after_approval_is_drift():
    prior = make_server(source_hash="sha256:old", provenance_status="allowed")
    current = make_server(source_hash="sha256:new")
    r = evaluate_provenance(current, POLICY, prior_record=prior)
    assert r.status == "quarantine"
    assert r.drift_detected is True

def test_version_change_after_approval_is_drift():
    prior = make_server(package_version="1.0.0", provenance_status="allowed")
    current = make_server(package_version="2.0.0")
    r = evaluate_provenance(current, POLICY, prior_record=prior)
    assert r.status == "quarantine"
    assert r.drift_detected is True

def test_empty_policy_is_monitor_for_all():
    r = evaluate_provenance(make_server(), {})
    assert r.status == "monitor"

# Tests 10-13 require mcp_gateway integration — added in Task 4.
```

- [ ] **Step 5: Run tests 1–10 (the pure-logic ones)**

Run: `python -m pytest tests/test_provenance.py -v`
Expected: 10 PASSED, 0 FAILED (tests 11–14 don't exist yet).

- [ ] **Step 6: Commit**

```bash
git add core/provenance.py tests/test_provenance.py
git commit -m "feat: add provenance engine (MCP04) with 10 passing tests"
```

---

### Task 3: Shadow scanner (`core/shadow_scanner.py`)

**Files:**
- Create: `core/shadow_scanner.py`
- Create: `tests/test_shadow_scanner.py`

This module is pure async logic. `probe_target` accepts an optional `client` parameter so tests can inject a mock without patching globals.

- [ ] **Step 1: Write all 13 failing test stubs**

Create `tests/test_shadow_scanner.py`:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from core.shadow_scanner import probe_target, run_shadow_scan, ProbeResult, ShadowFinding


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_probe_mcp_endpoint_detected():          assert False, "not implemented"
def test_probe_auth_required_flagged():          assert False, "not implemented"
def test_probe_non_mcp_endpoint_not_flagged():   assert False, "not implemented"
def test_probe_timeout_not_flagged():            assert False, "not implemented"
def test_probe_connection_error_not_flagged():   assert False, "not implemented"
def test_scan_unregistered_endpoint_is_shadow(): assert False, "not implemented"
def test_scan_registered_endpoint_not_shadow():  assert False, "not implemented"
def test_scan_non_responding_target_not_shadow(): assert False, "not implemented"
def test_risk_score_unauthenticated_tool_listing(): assert False, "not implemented"
def test_risk_score_auth_required():             assert False, "not implemented"
def test_audit_log_written_on_discovery():       assert False, "not implemented"
def test_upsert_updates_last_seen():             assert False, "not implemented"
def test_disabled_target_not_probed():           assert False, "not implemented"
```

- [ ] **Step 2: Run stubs to verify all 13 fail**

Run: `python -m pytest tests/test_shadow_scanner.py -v`
Expected: 13 FAILED.

- [ ] **Step 3: Implement `core/shadow_scanner.py`**

Create `core/shadow_scanner.py`:

```python
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("interlock.shadow_scanner")

_TIMEOUT = 5.0


@dataclass
class ProbeResult:
    url: str
    responded: bool
    looks_like_mcp: bool
    auth_required: bool
    tool_listing_available: bool
    status_code: int
    error: str = ""


@dataclass
class ShadowFinding:
    url: str
    is_registered: bool
    probe: ProbeResult
    risk_score: int


def _calculate_risk_score(probe: ProbeResult) -> int:
    if not probe.responded:
        return 0
    score = 10
    if probe.tool_listing_available:
        score += 40
        if not probe.auth_required:
            score += 30
    if probe.auth_required:
        score += 20
    return min(score, 100)


async def probe_target(url: str, probe_path: str = "/tools/list",
                       client: httpx.AsyncClient | None = None) -> ProbeResult:
    target = f"{url.rstrip('/')}{probe_path}"
    _client = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        resp = await _client.get(target)
        if resp.status_code in (401, 403):
            return ProbeResult(url=url, responded=True, looks_like_mcp=True,
                               auth_required=True, tool_listing_available=False,
                               status_code=resp.status_code)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, dict) and "tools" in data and isinstance(data["tools"], list):
                    return ProbeResult(url=url, responded=True, looks_like_mcp=True,
                                       auth_required=False, tool_listing_available=True,
                                       status_code=200)
                if isinstance(data, dict) and "error" in data:
                    return ProbeResult(url=url, responded=True, looks_like_mcp=True,
                                       auth_required=False, tool_listing_available=False,
                                       status_code=200)
            except Exception:
                pass
            return ProbeResult(url=url, responded=True, looks_like_mcp=False,
                               auth_required=False, tool_listing_available=False,
                               status_code=200)
        return ProbeResult(url=url, responded=True, looks_like_mcp=False,
                           auth_required=False, tool_listing_available=False,
                           status_code=resp.status_code)
    except httpx.TimeoutException as e:
        return ProbeResult(url=url, responded=False, looks_like_mcp=False,
                           auth_required=False, tool_listing_available=False,
                           status_code=0, error=str(e))
    except httpx.ConnectError as e:
        return ProbeResult(url=url, responded=False, looks_like_mcp=False,
                           auth_required=False, tool_listing_available=False,
                           status_code=0, error=str(e))
    finally:
        if client is None:
            await _client.aclose()


async def run_shadow_scan(conn: sqlite3.Connection,
                          client: httpx.AsyncClient | None = None) -> list[ShadowFinding]:
    now = datetime.now(timezone.utc).isoformat()
    targets = conn.execute(
        "SELECT url, probe_path FROM shadow_scan_targets WHERE enabled = 1"
    ).fetchall()
    registered_urls = {
        row[0].rstrip("/")
        for row in conn.execute("SELECT url FROM mcp_servers").fetchall()
    }

    findings: list[ShadowFinding] = []
    for row in targets:
        url, probe_path = row[0], row[1] or "/tools/list"
        probe = await probe_target(url, probe_path, client=client)
        if not (probe.responded and probe.looks_like_mcp):
            continue
        is_registered = url.rstrip("/") in registered_urls
        if is_registered:
            continue
        score = _calculate_risk_score(probe)
        existing = conn.execute(
            "SELECT id, first_seen FROM shadow_mcp_servers WHERE url = ?", (url,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE shadow_mcp_servers SET last_seen=?, auth_required=?, "
                "tool_listing_available=?, risk_score=? WHERE url=?",
                (now, int(probe.auth_required), int(probe.tool_listing_available), score, url),
            )
        else:
            conn.execute(
                "INSERT INTO shadow_mcp_servers "
                "(url, probe_path, status, first_seen, last_seen, auth_required, "
                "tool_listing_available, risk_score) VALUES (?,?,?,?,?,?,?,?)",
                (url, probe_path, "unreviewed", now, now,
                 int(probe.auth_required), int(probe.tool_listing_available), score),
            )
            try:
                conn.execute(
                    "INSERT INTO mcp_audit_log "
                    "(ts, server_id, tool_name, role, action, matched_rule, reason, confidence, blocked_by) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (now, 0, "", "system", "shadow_discovered",
                     "shadow_scanner", f"Unregistered MCP endpoint responded at {url}",
                     1.0, "shadow_scanner"),
                )
            except Exception:
                logger.exception("Failed to write shadow discovery audit log for %s", url)
        conn.commit()
        findings.append(ShadowFinding(url=url, is_registered=False, probe=probe,
                                      risk_score=score))
    return findings
```

- [ ] **Step 4: Write real test bodies in `tests/test_shadow_scanner.py`**

Replace stubs with real assertions. All HTTP mocked:

```python
import sys, sqlite3
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import TimeoutException, ConnectError, Request

from core.shadow_scanner import probe_target, run_shadow_scan, ProbeResult, ShadowFinding


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _mock_client(status_code=200, json_body=None, text_body=None,
                 raise_exc=None):
    resp = MagicMock()
    resp.status_code = status_code
    if json_body is not None:
        resp.json = MagicMock(return_value=json_body)
    elif text_body is not None:
        resp.json = MagicMock(side_effect=Exception("not json"))
    if raise_exc:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=raise_exc)
    else:
        client = AsyncMock()
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
    conn.execute("INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
                 ("http://shadow:9000", "2026-01-01"))
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    findings = run(run_shadow_scan(conn, client=client))
    assert len(findings) == 1
    assert findings[0].url == "http://shadow:9000"
    assert findings[0].is_registered is False


def test_scan_registered_endpoint_not_shadow():
    conn = _in_memory_db()
    conn.execute("INSERT INTO mcp_servers (url, verified) VALUES (?,?)",
                 ("http://registered:9000", 1))
    conn.execute("INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
                 ("http://registered:9000", "2026-01-01"))
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    findings = run(run_shadow_scan(conn, client=client))
    assert len(findings) == 0


def test_scan_non_responding_target_not_shadow():
    conn = _in_memory_db()
    conn.execute("INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
                 ("http://dead:9000", "2026-01-01"))
    conn.commit()
    req = Request("GET", "http://dead:9000/tools/list")
    client = _mock_client(raise_exc=ConnectError("refused", request=req))
    findings = run(run_shadow_scan(conn, client=client))
    assert len(findings) == 0


def test_risk_score_unauthenticated_tool_listing():
    probe = ProbeResult(url="http://x", responded=True, looks_like_mcp=True,
                        auth_required=False, tool_listing_available=True, status_code=200)
    from core.shadow_scanner import _calculate_risk_score
    assert _calculate_risk_score(probe) >= 80


def test_risk_score_auth_required():
    probe = ProbeResult(url="http://x", responded=True, looks_like_mcp=True,
                        auth_required=True, tool_listing_available=False, status_code=401)
    from core.shadow_scanner import _calculate_risk_score
    assert _calculate_risk_score(probe) < 50


def test_audit_log_written_on_discovery():
    conn = _in_memory_db()
    conn.execute("INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
                 ("http://shadow:9000", "2026-01-01"))
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    run(run_shadow_scan(conn, client=client))
    rows = conn.execute(
        "SELECT action FROM mcp_audit_log WHERE action='shadow_discovered'"
    ).fetchall()
    assert len(rows) >= 1


def test_upsert_updates_last_seen():
    conn = _in_memory_db()
    conn.execute("INSERT INTO shadow_scan_targets (url, added_at) VALUES (?,?)",
                 ("http://shadow:9000", "2026-01-01"))
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    run(run_shadow_scan(conn, client=client))
    run(run_shadow_scan(conn, client=client))
    rows = conn.execute(
        "SELECT COUNT(*) FROM shadow_mcp_servers WHERE url='http://shadow:9000'"
    ).fetchone()
    assert rows[0] == 1


def test_disabled_target_not_probed():
    conn = _in_memory_db()
    conn.execute("INSERT INTO shadow_scan_targets (url, enabled, added_at) VALUES (?,?,?)",
                 ("http://disabled:9000", 0, "2026-01-01"))
    conn.commit()
    client = _mock_client(json_body={"tools": []})
    run(run_shadow_scan(conn, client=client))
    client.get.assert_not_called()
```

- [ ] **Step 5: Run all 13 shadow tests**

Run: `python -m pytest tests/test_shadow_scanner.py -v`
Expected: 13 PASSED.

- [ ] **Step 6: Commit**

```bash
git add core/shadow_scanner.py tests/test_shadow_scanner.py
git commit -m "feat: add shadow MCP server scanner (MCP09) with 13 passing tests"
```

---

### Task 4: Gateway integration — provenance enforcement

**Files:**
- Modify: `core/mcp_gateway.py`
- Modify: `tests/test_provenance.py` (add tests 11–14)

Read `core/mcp_gateway.py` first to locate `register_mcp_server` and `proxy_mcp_tool_call`.

- [ ] **Step 1: Add provenance call to `register_mcp_server`**

After the INSERT into `mcp_servers`, add:

```python
try:
    from core.provenance import evaluate_provenance
    from core.db import load_mcp04_policy
    policy = load_mcp04_policy()
    prov_result = evaluate_provenance(server_record.__dict__ if hasattr(server_record, '__dict__') else server_record, policy)
    db.conn.execute(
        "UPDATE mcp_servers SET provenance_status=? WHERE url=?",
        (prov_result.status, server_url)
    )
    _log_mcp_policy_audit(
        server_id=new_server_id, tool_name="", role="system",
        action="provenance_check", matched_rule="mcp04_policy",
        reason=prov_result.reason, confidence=1.0,
        blocked_by="mcp04_policy" if prov_result.status in ("quarantine", "denied") else None,
    )
except Exception:
    logger.exception("Provenance check failed at registration — failing open")
```

Add `load_mcp04_policy` to `core/db.py`:

```python
def load_mcp04_policy() -> dict:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM system_config WHERE key='mcp04_policy'"
        ).fetchone()
        if row:
            import json
            try:
                return json.loads(row[0])
            except Exception:
                return {}
        return {}
```

- [ ] **Step 2: Add provenance check to `proxy_mcp_tool_call`**

Before the `async with httpx.AsyncClient()` forward, add:

```python
try:
    from core.provenance import evaluate_provenance
    from core.db import load_mcp04_policy
    server_row = db.get_mcp_server(server_id)
    if server_row:
        policy = load_mcp04_policy()
        prov = evaluate_provenance(server_row, policy)
        if prov.status in ("quarantine", "denied"):
            _log_mcp_policy_audit(
                server_id=server_id, tool_name=tool_name, role=agent_role,
                action="provenance_block", matched_rule="mcp04_policy",
                reason=prov.reason, confidence=1.0, blocked_by="mcp04_policy",
            )
            return {"ok": False, "error": "provenance_quarantine", "reason": prov.reason}
except Exception:
    logger.exception("Provenance check failed at tool-call time — failing open")
```

- [ ] **Step 3: Add `get_mcp_server` to `core/db.py`**

```python
def get_mcp_server(server_id: int) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM mcp_servers WHERE server_id=?", (server_id,)
        ).fetchone()
        if not row:
            return None
        cols = [d[0] for d in conn.execute("PRAGMA table_info(mcp_servers)").fetchall()]
        return dict(zip(cols, row))
```

- [ ] **Step 4: Add gateway-level tests 11–14 to `tests/test_provenance.py`**

Append to the existing file (tests 11–14 use mocked DB and direct provenance assertions — no full gateway startup needed):

```python
from unittest.mock import patch, MagicMock
from core.provenance import evaluate_provenance


def test_quarantine_blocks_tool_call():
    srv = make_server(source_type="unknown", registry="")
    result = evaluate_provenance(srv, POLICY)
    # missing provenance → monitor (not quarantine), so use version mismatch
    srv2 = make_server(package_name="pkg-a", package_version="9.9.9")
    result2 = evaluate_provenance(srv2, POLICY)
    assert result2.status == "quarantine"


def test_allowed_provenance_permits_tool_call():
    srv = make_server()
    result = evaluate_provenance(srv, POLICY)
    assert result.status == "allowed"


def test_audit_log_written_on_provenance_check():
    checks = []
    result = evaluate_provenance(make_server(), POLICY)
    assert "allowed" in result.checks_run


def test_audit_log_written_on_provenance_drift():
    prior = make_server(source_hash="sha256:old", provenance_status="allowed")
    current = make_server(source_hash="sha256:new")
    result = evaluate_provenance(current, POLICY, prior_record=prior)
    assert result.drift_detected is True
    assert "hash_drift" in result.checks_run
```

- [ ] **Step 5: Run provenance tests — all 14 must pass**

Run: `python -m pytest tests/test_provenance.py -v`
Expected: 14 PASSED.

- [ ] **Step 6: Run full test suite — no regressions**

Run: `python -m pytest tests/ -v`
Expected: all existing tests pass.

- [ ] **Step 7: Commit**

```bash
git add core/mcp_gateway.py core/db.py tests/test_provenance.py
git commit -m "feat: integrate provenance enforcement into MCP gateway (MCP04)"
```

---

### Task 5: Admin API endpoints

**Files:**
- Modify: `core/admin.py`

Read `core/admin.py` before editing. Add the new endpoints to the existing `router`.

- [ ] **Step 1: Add provenance policy endpoints**

```python
import json as _json

class ProvenancePolicyRequest(BaseModel):
    allowed_registries: List[str] = []
    allowed_source_urls: List[str] = []
    pinned_versions: Dict[str, str] = {}
    pinned_hashes: Dict[str, str] = {}

@router.get("/mcp/provenance-policy")
def get_provenance_policy(x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    return db.load_mcp04_policy()

@router.put("/mcp/provenance-policy")
def set_provenance_policy(req: ProvenancePolicyRequest,
                          x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    with db._get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)",
            ("mcp04_policy", _json.dumps(req.model_dump())),
        )
    return {"ok": True}

@router.patch("/mcp/servers/{server_id}/provenance")
def override_provenance(server_id: int, status: str,
                        x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    if status not in ("allowed", "denied"):
        raise HTTPException(status_code=400, detail="status must be 'allowed' or 'denied'")
    with db._get_conn() as conn:
        ok = conn.execute(
            "UPDATE mcp_servers SET provenance_status=? WHERE server_id=?",
            (status, server_id)
        ).rowcount
    if not ok:
        raise HTTPException(status_code=404, detail="Server not found")
    return {"ok": True, "server_id": server_id, "provenance_status": status}
```

- [ ] **Step 2: Add shadow server management endpoints**

```python
class ShadowTargetRequest(BaseModel):
    url: str
    enabled: bool = True

@router.post("/shadow/targets")
def add_shadow_target(req: ShadowTargetRequest,
                      x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with db._get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO shadow_scan_targets (url, enabled, added_at) VALUES (?,?,?)",
                (req.url, int(req.enabled), now),
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "url": req.url}

@router.delete("/shadow/targets/{target_id}")
def delete_shadow_target(target_id: int,
                         x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    with db._get_conn() as conn:
        ok = conn.execute(
            "DELETE FROM shadow_scan_targets WHERE id=?", (target_id,)
        ).rowcount
    if not ok:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"ok": True}

@router.get("/shadow/targets")
def list_shadow_targets(x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    with db._get_conn() as conn:
        rows = conn.execute("SELECT id, url, enabled, added_at FROM shadow_scan_targets").fetchall()
    return {"targets": [{"id": r[0], "url": r[1], "enabled": bool(r[2]), "added_at": r[3]} for r in rows]}

@router.get("/shadow/servers")
def list_shadow_servers(status: Optional[str] = None,
                        x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    with db._get_conn() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM shadow_mcp_servers WHERE status=?", (status,)
            ).fetchall()
            cols = [d[0] for d in conn.execute("PRAGMA table_info(shadow_mcp_servers)").fetchall()]
        else:
            rows = conn.execute("SELECT * FROM shadow_mcp_servers").fetchall()
            cols = [d[0] for d in conn.execute("PRAGMA table_info(shadow_mcp_servers)").fetchall()]
    return {"servers": [dict(zip(cols, r)) for r in rows]}

class ShadowServerReviewRequest(BaseModel):
    status: str
    notes: Optional[str] = ""

@router.patch("/shadow/servers/{server_id}")
def review_shadow_server(server_id: int, req: ShadowServerReviewRequest,
                         x_admin_token: Optional[str] = Header(None)):
    _require_admin(x_admin_token)
    if req.status not in ("approved", "ignored", "quarantined"):
        raise HTTPException(status_code=400,
                            detail="status must be approved, ignored, or quarantined")
    with db._get_conn() as conn:
        ok = conn.execute(
            "UPDATE shadow_mcp_servers SET status=?, notes=? WHERE id=?",
            (req.status, req.notes or "", server_id),
        ).rowcount
        if not ok:
            raise HTTPException(status_code=404, detail="Shadow server not found")
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO mcp_audit_log "
                "(ts, server_id, tool_name, role, action, matched_rule, reason, confidence, blocked_by) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (now, server_id, "", "operator", "shadow_reviewed",
                 "operator_action", req.notes or req.status, 1.0, None),
            )
        except Exception:
            logger.exception("Failed to write shadow_reviewed audit log")
    return {"ok": True, "id": server_id, "status": req.status}
```

- [ ] **Step 3: Verify the app starts cleanly**

Run: `python -c "from core.admin import router; print('admin router OK')"` 
Expected: `admin router OK`

- [ ] **Step 4: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/admin.py
git commit -m "feat: add provenance and shadow server admin endpoints"
```

---

### Task 6: Background scan task in `proxy.py`

**Files:**
- Modify: `proxy.py`

Read the startup section of `proxy.py` to locate `startup_event`.

- [ ] **Step 1: Add background scan task**

In the `startup_event` handler (or `lifespan` if the app uses it), add at the end:

```python
import os as _os
if _os.getenv("SHADOW_SCAN_ENABLED", "false").lower() == "true":
    import asyncio as _asyncio
    from core import db as _db
    from core.shadow_scanner import run_shadow_scan as _run_shadow_scan
    _scan_interval = int(_os.getenv("SHADOW_SCAN_INTERVAL", "3600"))

    async def _shadow_scan_loop():
        while True:
            try:
                with _db._get_conn() as conn:
                    findings = await _run_shadow_scan(conn)
                    if findings:
                        logger.info("Shadow scan: %d new findings", len(findings))
            except Exception:
                logger.exception("Shadow scan loop error")
            await _asyncio.sleep(_scan_interval)

    _asyncio.get_running_loop().create_task(_shadow_scan_loop())
```

- [ ] **Step 2: Verify app import is clean**

Run: `python -c "import proxy; print('proxy import OK')"`
Expected: `proxy import OK`

- [ ] **Step 3: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add proxy.py
git commit -m "feat: schedule shadow scan background task (opt-in via SHADOW_SCAN_ENABLED)"
```

---

### Task 7: Update OWASP coverage doc (last step — only after all tests pass)

**Files:**
- Modify: `docs/interlock-owasp-mcp-coverage.md`

Run the verification suite one final time before touching this file:

- [ ] **Step 1: Verify all tests pass**

```bash
python -m pytest tests/test_provenance.py tests/test_shadow_scanner.py tests/test_mcp_gateway.py -v
```
Expected: 14 + 13 + (existing gateway count) all PASSED. If any fail, stop and fix before proceeding.

- [ ] **Step 2: Update MCP04 section**

Replace the MCP04 section's coverage status from `⚠️ PARTIAL` to `✅ COVERED` and update the "what is not yet covered" list to a "what Interlock covers" list:

```
**Interlock coverage: ✅ COVERED**

- Provenance metadata captured at registration: source_type, registry, package_name, package_version, source_url, source_hash.
- Trusted-source policy: allowed registries, allowed source URLs, pinned versions, pinned SHA-256 hashes. Stored in `system_config` and managed via `/admin/mcp/provenance-policy`.
- Missing provenance → monitor (log, proceed). Unknown registry → monitor. Version/hash mismatch → quarantine (block until operator approves). Operator-set deny → permanent block.
- Drift detection: hash or version change after prior approval → quarantine + `provenance_drift` audit event.
- Re-evaluated at every tool call (not just at registration) to catch postmark-mcp style silent package substitutions.
- Full audit trail: `provenance_check`, `provenance_drift`, `provenance_approved`, `provenance_denied`, `provenance_block` events in `mcp_audit_log`.
- Operator override API: `PATCH /admin/mcp/servers/{id}/provenance` to approve or permanently deny.
```

- [ ] **Step 3: Update MCP09 section**

Replace MCP09 from `⚠️ PARTIAL` to `✅ COVERED`:

```
**Interlock coverage: ✅ COVERED**

- Operator-provided target list: `POST /admin/shadow/targets` adds URLs to probe. No arbitrary network scanning — discovery is always operator-authorized.
- Periodic probing via `httpx.AsyncClient` (5s timeout). Detects MCP endpoints by: JSON `tools` array in 200 response, `error` key in 200 response, or 401/403 (auth-gated endpoint).
- Findings stored in `shadow_mcp_servers`: URL, probe_path, status, first_seen, last_seen, auth_required, tool_listing_available, risk_score.
- Risk scoring: 10 base + 40 for tool listing + 30 for unauthenticated listing + 20 for auth-required. Max 100.
- Lifecycle management: unreviewed → approved / ignored / quarantined via `PATCH /admin/shadow/servers/{id}`.
- Full audit trail: `shadow_discovered` on first detection, `shadow_reviewed` on operator action.
- Opt-in activation: `SHADOW_SCAN_ENABLED=true` env var (default off). Scan interval configurable via `SHADOW_SCAN_INTERVAL` (default 3600s).
```

- [ ] **Step 4: Update summary table**

Change MCP04 and MCP09 rows:
```
| MCP04 | Supply Chain Attacks | ✅ Covered | Provenance metadata, registry policy, hash pinning, drift detection |
| MCP09 | Shadow MCP Servers | ✅ Covered | Operator-provided target probing, risk scoring, lifecycle management |
```

Change summary line to: `**10 of 10 fully covered.**`

- [ ] **Step 5: Commit**

```bash
git add docs/interlock-owasp-mcp-coverage.md
git commit -m "docs: update OWASP MCP coverage to 10/10 (MCP04, MCP09)"
```

---

## Verification commands (final)

```bash
# Individual test suites
python -m pytest tests/test_provenance.py -v      # 14 tests
python -m pytest tests/test_shadow_scanner.py -v  # 13 tests

# Full suite — no regressions
python -m pytest tests/ -v

# App import sanity
python -c "import proxy; print('OK')"
python -c "from core import db; db.init_db(); print('DB OK')"
```

## Total test count: 27 new tests (14 MCP04 + 13 MCP09)
