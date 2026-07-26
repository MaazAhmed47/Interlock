"""
CI boundary-review gate against a real Postgres deployment (not SQLite alone).

What only Postgres can prove for this feature: the review's audit append lands
in the Postgres hash chain (advisory-lock serialized, `RETURNING id`) and still
verifies; the surface-snapshot, baseline, and drift-queue reads round-trip
through psycopg2 types; and the new `mcp.review` scope survives the Postgres
`scopes` column. The gate itself is exercised as a real subprocess against a
live uvicorn-served app, exactly as in the SQLite suite.

  docker run -d --name interlock-cigate-pg -e POSTGRES_PASSWORD=cigatepw \
      -p 54345:5432 postgres:16
  INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:cigatepw@127.0.0.1:54345/postgres \
      python -m pytest tests/test_postgres_ci_boundary_review_gate.py

Skipped when the env var is absent (same convention as the other PG suites).
"""

from __future__ import annotations

import copy
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DB_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
DB_URL = os.getenv(DB_URL_ENV)

pytestmark = pytest.mark.skipif(
    not DB_URL,
    reason=f"{DB_URL_ENV} not set; the CI gate PG suite needs a disposable Postgres",
)

from tests.test_ci_boundary_review_gate import (  # noqa: E402
    BASE_TOOLS,
    CI_FORBIDDEN_ROUTES,
    DRIFTED_READ_DOCUMENT,
    GATE_SCRIPT,
    LIST_DOCUMENTS,
    _serve,
)

SERVER_ID = "_test_pg_ci_gate_server"
QUARANTINE_SERVER_ID = "_test_pg_ci_gate_quarantined"
PG_SERVER_IDS = (SERVER_ID, QUARANTINE_SERVER_ID)
PG_GATE_TRUNCATE_TABLES = (
    "ci_review_idempotency",
    "tool_surface_snapshots",
    "mcp_rebaseline_candidates",
    "mcp_baseline_versions",
    "mcp_response_profiles",
    "mcp_external_reach_profiles",
    "mcp_effect_profiles",
    "mcp_permission_probes",
    "mcp_tool_metadata",
    "mcp_audit_log",
    "audit_chain_checkpoints",
    "mcp_servers",
    "api_keys",
    "usage_log",
)


def _reset_postgres_gate_fixture(pg_db):
    with pg_db.get_conn() as conn:
        conn.execute(
            "TRUNCATE "
            + ", ".join(PG_GATE_TRUNCATE_TABLES)
            + " RESTART IDENTITY CASCADE"
        )


def _postgres_persistence_counts(pg_db):
    with pg_db.get_conn() as conn:
        return tuple(
            int(
                pg_db.row_value(
                    conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone(),
                    "n",
                    0,
                )
            )
            for table in (
                "mcp_audit_log",
                "tool_surface_snapshots",
                "ci_review_idempotency",
                "audit_chain_checkpoints",
            )
        )


def _postgres_unique_drift_surface(marker):
    tool = copy.deepcopy(DRIFTED_READ_DOCUMENT)
    tool["description"] = f"Unique Postgres atomicity drift {marker}"
    tool["inputSchema"]["properties"][f"atomicity_{marker}"] = {"type": "string"}
    return [tool, copy.deepcopy(LIST_DOCUMENTS)]


@pytest.fixture(scope="module")
def pg_db():
    os.environ["DATABASE_URL"] = str(DB_URL)
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"

    import core.db as db

    db = importlib.reload(db)
    assert db.USE_POSTGRES, "test must exercise the Postgres path"
    db.init_db()
    yield db

    os.environ.pop("DATABASE_URL", None)
    importlib.reload(db)


@pytest.fixture
def pg_gate(pg_db, tmp_path):
    import proxy
    from core.tool_metadata import normalize_tool_metadata

    _reset_postgres_gate_fixture(pg_db)
    proxy._key_record_cache.clear()
    proxy._usage_cache.clear()

    state = {"tools": copy.deepcopy(BASE_TOOLS), "mode": "ok"}
    upstream = FastAPI()

    @upstream.post("/mcp")
    async def upstream_mcp(request: Request):
        message = await request.json()
        if state["mode"] == "http_500":
            return JSONResponse({"detail": "upstream failure"}, status_code=500)
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {"tools": state["tools"]},
            }
        )

    with _serve(upstream) as upstream_url:
        for server_id in PG_SERVER_IDS:
            pg_db.register_mcp_server(
                server_id,
                {
                    "url": f"{upstream_url}/mcp",
                    "description": "PG CI boundary review fixture",
                    "allowed_tools": ["read_document", "list_documents"],
                    "blocked_tools": [],
                    "environment": "non_production",
                },
            )
            pg_db.verify_mcp_server(server_id)
            for tool in BASE_TOOLS:
                pg_db.upsert_mcp_tool_metadata(
                    server_id, tool, normalize_tool_metadata(tool)
                )
        pg_db.quarantine_mcp_tool(
            QUARANTINE_SERVER_ID,
            "read_document",
            reviewer="fixture",
            reason="fixture quarantine",
        )
        ci_key = pg_db.generate_key(
            "developer",
            label="pg-ci-boundary-gate",
            scopes=["mcp.review"],
            role="readonly_agent",
        )["raw_key"]

        with _serve(proxy.app) as base_url:
            yield {
                "base_url": base_url,
                "state": state,
                "ci_key": ci_key,
                "db": pg_db,
            }

    _reset_postgres_gate_fixture(pg_db)
    proxy._key_record_cache.clear()
    proxy._usage_cache.clear()


def run_gate(live, output_dir: Path, server_id: str = SERVER_ID, *extra: str):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["INTERLOCK_BASE_URL"] = live["base_url"]
    env["INTERLOCK_CI_API_KEY"] = live["ci_key"]
    return subprocess.run(
        [
            sys.executable,
            str(GATE_SCRIPT),
            "--server-id",
            server_id,
            "--output-dir",
            str(output_dir),
            *extra,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


def load_artifact(output_dir: Path):
    path = output_dir / "interlock-boundary-review.json"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert (output_dir / "interlock-boundary-review.md").is_file()
    return json.loads(text), text


def registry_state(pg_db):
    return {
        server_id: {
            "baseline": pg_db.get_active_baseline(server_id)["surface_hash"],
            "tools": sorted(
                (t["tool_name"], t["status"], t["drift_severity"], t["drift_action"])
                for t in pg_db.list_mcp_tool_metadata(server_id)
            ),
        }
        for server_id in PG_SERVER_IDS
    }


def assert_postgres_audit_fidelity(pg_gate, artifact, before, outcome, action):
    rows = pg_gate["db"].list_mcp_audit_logs(5000)
    assert len(rows) == before + 1
    row = rows[0]
    assert row["hash_v"] == 5
    receipt = artifact["evidence"]["receipt"]
    assert row["id"] == receipt["audit_id"]
    assert row["observed_outcome"] == artifact["gate"]["outcome"] == outcome
    assert row["observed_status_code"] == artifact["gate"]["exit_code"]
    assert row["expected_outcome"] == ""
    assert row["expected_outcome"] not in ("material", "any-finding", "quarantine-only")
    assert row["action"] == row["drift_action"] == action
    assert f"outcome={outcome}" in row["reason"]
    assert "fail_policy=" not in row["reason"]
    assert receipt["hash_chained"] is True
    assert receipt["chain_verified"] is True
    assert receipt["receipt_verification_state"] == "verified"
    assert artifact["gate"]["boundary_review_semantic_outcome"] == outcome
    assert artifact["gate"]["boundary_review_final_outcome"] == outcome
    assert (
        artifact["gate"]["boundary_review_final_exit_code"]
        == artifact["gate"]["exit_code"]
    )
    assert row["boundary_review_metadata"] == {
        "boundary_review_semantic_outcome": outcome,
        "boundary_review_final_outcome": outcome,
        "boundary_review_final_exit_code": artifact["gate"]["exit_code"],
        "fail_policy": artifact["gate"]["fail_policy"],
        "receipt_verification_state": "verified",
    }
    metadata_text = json.dumps(row["boundary_review_metadata"], sort_keys=True)
    assert pg_gate["ci_key"] not in metadata_text
    assert "authorization" not in metadata_text.lower()
    assert "x-api-key" not in metadata_text.lower()
    assert "inputschema" not in metadata_text.lower()
    assert pg_gate["db"].verify_mcp_audit_record(row["id"])["chain_verified"] is True


@pytest.mark.parametrize("verification_mode", ["false", "exception"])
def test_postgres_receipt_verification_failure_rolls_back_final_row(
    pg_gate, tmp_path, monkeypatch, verification_mode
):
    pg_db = pg_gate["db"]
    before = len(pg_db.list_mcp_audit_logs(5000))

    if verification_mode == "false":

        def verifier(*args, **kwargs):
            return {"chain_verified": False, "reason": "forced"}

    else:

        def verifier(*args, **kwargs):
            raise RuntimeError("forced verifier exception")

    monkeypatch.setattr(pg_db, "_verify_mcp_audit_record_on_conn", verifier)
    result = run_gate(pg_gate, tmp_path)
    artifact, text = load_artifact(tmp_path)
    receipt = artifact["evidence"]["receipt"]

    assert result.returncode == 22, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["gate"]["boundary_review_semantic_outcome"] == "clean"
    assert artifact["gate"]["boundary_review_final_outcome"] == "inconclusive"
    assert artifact["gate"]["boundary_review_final_exit_code"] == 22
    assert receipt["audit_id"] is None
    assert receipt["hash_chained"] is False
    assert receipt["chain_verified"] is False
    assert receipt["receipt_verification_state"] == "failed"
    assert len(pg_db.list_mcp_audit_logs(5000)) == before
    assert SERVER_ID not in text + result.stdout + result.stderr
    assert pg_gate["ci_key"] not in text + result.stdout + result.stderr


def test_postgres_append_failure_leaves_zero_rows_and_inconclusive_artifact(
    pg_gate, tmp_path, monkeypatch
):
    pg_db = pg_gate["db"]
    before = len(pg_db.list_mcp_audit_logs(5000))

    def fail_append(*args, **kwargs):
        raise RuntimeError("forced append failure")

    monkeypatch.setattr(pg_db, "log_verified_mcp_audit_event", fail_append)
    result = run_gate(pg_gate, tmp_path)
    artifact, text = load_artifact(tmp_path)
    receipt = artifact["evidence"]["receipt"]

    assert result.returncode == 22, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["gate"]["boundary_review_semantic_outcome"] == "clean"
    assert artifact["gate"]["boundary_review_final_outcome"] == "inconclusive"
    assert artifact["gate"]["boundary_review_final_exit_code"] == 22
    assert receipt["audit_id"] is None
    assert receipt["hash_chained"] is False
    assert receipt["chain_verified"] is False
    assert receipt["receipt_verification_state"] == "append_failed"
    assert len(pg_db.list_mcp_audit_logs(5000)) == before
    assert SERVER_ID not in text + result.stdout + result.stderr
    assert pg_gate["ci_key"] not in text + result.stdout + result.stderr


@pytest.mark.parametrize(
    "failure_mode,idempotency_key",
    [
        ("verifier_false", "pv" * 24),
        ("verifier_exception", "pe" * 24),
        ("append_failure", "pa" * 24),
        ("commit_failure", "pc" * 24),
    ],
)
def test_postgres_atomic_failure_writes_nothing_and_same_key_retries(
    pg_gate, monkeypatch, failure_mode, idempotency_key
):
    import httpx

    pg_db = pg_gate["db"]
    pg_gate["state"]["tools"] = _postgres_unique_drift_surface(failure_mode)
    headers = {
        "x-api-key": pg_gate["ci_key"],
        "idempotency-key": idempotency_key,
    }
    url = f"{pg_gate['base_url']}/mcp/servers/{SERVER_ID}/boundary-review"
    before = _postgres_persistence_counts(pg_db)
    assert before == (1, 0, 0, 0)

    with monkeypatch.context() as injected:
        if failure_mode == "verifier_false":
            injected.setattr(
                pg_db,
                "_verify_mcp_audit_record_on_conn",
                lambda *args, **kwargs: {
                    "chain_verified": False,
                    "reason": "forced",
                },
            )
        elif failure_mode == "verifier_exception":

            def fail_verifier(*args, **kwargs):
                raise RuntimeError("forced verifier exception")

            injected.setattr(pg_db, "_verify_mcp_audit_record_on_conn", fail_verifier)
        elif failure_mode == "append_failure":

            def fail_append(*args, **kwargs):
                raise RuntimeError("forced append failure")

            injected.setattr(pg_db, "_append_mcp_audit_event", fail_append)
        else:

            def fail_commit(*args, **kwargs):
                raise RuntimeError("forced commit failure")

            injected.setattr(
                pg_db, "_commit_verified_mcp_audit_transaction", fail_commit
            )

        failed = httpx.post(url, headers=headers, timeout=90)

    assert failed.status_code == 200
    failed_artifact = failed.json()
    assert failed.headers.get("idempotent-replay") is None
    assert failed_artifact["gate"]["outcome"] == "inconclusive"
    assert failed_artifact["gate"]["exit_code"] == 22
    assert failed_artifact["evidence"]["receipt"]["audit_id"] is None
    assert _postgres_persistence_counts(pg_db) == before

    retry = httpx.post(url, headers=headers, timeout=90)
    assert retry.status_code == 200
    assert retry.headers.get("idempotent-replay") is None
    retry_artifact = retry.json()
    assert retry_artifact["evidence"]["receipt"]["chain_verified"] is True
    after_retry = _postgres_persistence_counts(pg_db)
    assert after_retry == (2, 2, 1, 0)

    replay = httpx.post(url, headers=headers, timeout=90)
    assert replay.headers.get("idempotent-replay") == "true"
    assert replay.json() == retry_artifact
    assert _postgres_persistence_counts(pg_db) == after_retry


def test_clean_review_on_postgres_exits_zero_with_a_verified_chain(pg_gate, tmp_path):
    before = len(pg_gate["db"].list_mcp_audit_logs(5000))
    result = run_gate(pg_gate, tmp_path)
    artifact, _ = load_artifact(tmp_path)

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "clean"
    assert artifact["boundary"]["matches_approved_surface"] is True
    assert artifact["evidence"]["receipt"]["chain_verified"] is True

    audit_id = int(artifact["evidence"]["receipt"]["audit_id"])
    row = pg_gate["db"].get_mcp_audit_log(audit_id)
    assert row["matched_rule"] == "ci_boundary_review"
    assert pg_gate["db"].verify_mcp_audit_record(audit_id)["chain_verified"] is True
    assert pg_gate["db"].verify_audit_chain()["valid"] is True
    assert_postgres_audit_fidelity(pg_gate, artifact, before, "clean", "allow")


def test_material_drift_on_postgres_exits_twenty_and_mutates_no_state(
    pg_gate, tmp_path
):
    pg_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
    before = registry_state(pg_gate["db"])
    audits_before = len(pg_gate["db"].list_mcp_audit_logs(5000))

    result = run_gate(pg_gate, tmp_path)
    artifact, text = load_artifact(tmp_path)
    assert SERVER_ID not in text + result.stdout + result.stderr

    assert result.returncode == 20, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "review_required"
    assert artifact["findings"][0]["severity"] == "high"
    assert artifact["evidence"]["evidence_ref"]["digest"].startswith("sha256:")
    assert pg_gate["ci_key"] not in text

    assert registry_state(pg_gate["db"]) == before
    assert pg_gate["db"].verify_audit_chain()["valid"] is True
    assert_postgres_audit_fidelity(
        pg_gate, artifact, audits_before, "review_required", "deny"
    )


def test_quarantined_server_on_postgres_exits_twenty_one(pg_gate, tmp_path):
    before = len(pg_gate["db"].list_mcp_audit_logs(5000))
    result = run_gate(pg_gate, tmp_path, QUARANTINE_SERVER_ID)
    artifact, _ = load_artifact(tmp_path)

    assert result.returncode == 21, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "quarantined"
    assert any(entry["status"] == "quarantined" for entry in artifact["review_queue"])
    assert_postgres_audit_fidelity(
        pg_gate, artifact, before, "quarantined", "quarantine"
    )


def test_inconclusive_upstream_failure_has_matching_postgres_audit(pg_gate, tmp_path):
    pg_gate["state"]["mode"] = "http_500"
    before = len(pg_gate["db"].list_mcp_audit_logs(5000))
    result = run_gate(pg_gate, tmp_path)
    artifact, text = load_artifact(tmp_path)

    assert result.returncode == 22, (result.stdout, result.stderr)
    assert artifact["observation"]["status"] == "unavailable"
    assert SERVER_ID not in text + result.stdout + result.stderr
    assert_postgres_audit_fidelity(pg_gate, artifact, before, "inconclusive", "monitor")


def test_review_scope_round_trips_through_the_postgres_scopes_column(pg_gate):
    record = pg_gate["db"].lookup_key(pg_gate["ci_key"])
    assert record["scopes"] == ["mcp.review"]
    assert "mcp.review" not in pg_gate["db"].DEFAULT_API_KEY_SCOPES


def test_surface_snapshots_written_by_a_review_resolve_on_postgres(pg_gate, tmp_path):
    pg_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
    assert run_gate(pg_gate, tmp_path).returncode == 20
    artifact, _ = load_artifact(tmp_path)

    finding = artifact["findings"][0]
    for surface_hash in (
        finding["approved_tool_surface_hash"],
        finding["observed_tool_surface_hash"],
    ):
        snapshot = pg_gate["db"].get_tool_surface_snapshot(surface_hash)
        assert snapshot, f"surface {surface_hash} must be resolvable"
        assert snapshot["canonical_json"]


# ── Idempotency, retention, and races on the real backend ────────────────────
IDEMPOTENCY_KEY = "p" * 48
OTHER_KEY = "q" * 48


def _post(live, server_id=SERVER_ID, key=None, idempotency=None):
    import httpx

    headers = {"x-api-key": key or live["ci_key"]}
    if idempotency:
        headers["idempotency-key"] = idempotency
    return httpx.post(
        f"{live['base_url']}/mcp/servers/{server_id}/boundary-review",
        headers=headers,
        timeout=90,
    )


def _counts(pg_db):
    with pg_db.get_conn() as conn:
        audits = pg_db.row_value(
            conn.execute("SELECT COUNT(*) AS n FROM mcp_audit_log").fetchone(), "n", 0
        )
        snaps = pg_db.row_value(
            conn.execute("SELECT COUNT(*) AS n FROM tool_surface_snapshots").fetchone(),
            "n",
            0,
        )
    return int(audits), int(snaps)


def test_postgres_idempotent_replay_appends_no_new_evidence(pg_gate):
    pg_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
    audits_before, _ = _counts(pg_gate["db"])

    first = _post(pg_gate, idempotency=IDEMPOTENCY_KEY)
    after_first = _counts(pg_gate["db"])
    second = _post(pg_gate, idempotency=IDEMPOTENCY_KEY)
    third = _post(pg_gate, idempotency=IDEMPOTENCY_KEY)

    assert first.status_code == 200
    assert second.json() == first.json() == third.json()
    assert second.headers.get("idempotent-replay") == "true"
    assert third.headers.get("idempotent-replay") == "true"
    assert after_first[0] == audits_before + 1
    assert (
        _counts(pg_gate["db"]) == after_first
    ), "a replay must append no audit row and no surface snapshot"


def test_postgres_verified_upstream_inconclusive_is_replayable(pg_gate):
    pg_gate["state"]["mode"] = "http_500"
    idempotency_key = "pu" * 24
    assert _postgres_persistence_counts(pg_gate["db"]) == (1, 0, 0, 0)

    first = _post(pg_gate, idempotency=idempotency_key)
    assert first.status_code == 200
    artifact = first.json()
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["evidence"]["receipt"]["chain_verified"] is True
    assert _postgres_persistence_counts(pg_gate["db"]) == (2, 0, 1, 0)

    replay = _post(pg_gate, idempotency=idempotency_key)
    assert replay.headers.get("idempotent-replay") == "true"
    assert replay.json() == artifact
    assert _postgres_persistence_counts(pg_gate["db"]) == (2, 0, 1, 0)


def test_postgres_idempotency_binding_is_enforced(pg_gate):
    other = pg_gate["db"].generate_key(
        "developer", label="pg-other-ci", scopes=["mcp.review"]
    )["raw_key"]
    assert _post(pg_gate, idempotency=OTHER_KEY).status_code == 200

    conflict_identity = _post(pg_gate, key=other, idempotency=OTHER_KEY)
    conflict_server = _post(
        pg_gate, server_id=QUARANTINE_SERVER_ID, idempotency=OTHER_KEY
    )
    assert conflict_identity.status_code == 409
    assert conflict_identity.json()["detail"]["error"] == "idempotency_key_conflict"
    assert conflict_server.status_code == 409


def test_postgres_only_one_replica_can_reserve_a_key(pg_gate):
    """Primary-key uniqueness, not a process lock: two callers racing the same
    key cannot both reserve it."""
    digest = pg_gate["db"].hash_idempotency_key("r" * 48)
    first = pg_gate["db"].reserve_ci_review_idempotency(
        digest, "bind-a", SERVER_ID, 300
    )
    second = pg_gate["db"].reserve_ci_review_idempotency(
        digest, "bind-a", SERVER_ID, 300
    )
    third = pg_gate["db"].reserve_ci_review_idempotency(
        digest, "bind-b", SERVER_ID, 300
    )

    assert first["outcome"] == "reserved"
    assert second["outcome"] == "in_progress"
    assert third["outcome"] == "conflict"
    pg_gate["db"].release_ci_review_idempotency(digest)


def test_postgres_idempotency_retention_prunes_expired_rows(pg_gate):
    db_mod = pg_gate["db"]
    digest = db_mod.hash_idempotency_key("s" * 48)
    db_mod.reserve_ci_review_idempotency(digest, "bind-a", SERVER_ID, 300)
    with db_mod.get_conn() as conn:
        conn.execute(
            "UPDATE ci_review_idempotency SET expires_at = ? WHERE key_digest = ?",
            ("1999-01-01T00:00:00+00:00", digest),
        )
    again = db_mod.reserve_ci_review_idempotency(digest, "bind-b", SERVER_ID, 300)
    assert again["outcome"] == "reserved", "expired rows must be pruned"
    db_mod.release_ci_review_idempotency(digest)


def test_postgres_review_is_post_only_and_uncacheable(pg_gate):
    import httpx

    url = f"{pg_gate['base_url']}/mcp/servers/{SERVER_ID}/boundary-review"
    assert httpx.get(url, timeout=30).status_code == 405
    response = _post(pg_gate)
    assert response.headers["cache-control"].startswith("no-store")
    assert "x-api-key" in response.headers["vary"].lower()


def test_postgres_enforced_deny_is_nonzero_under_every_policy(pg_gate, tmp_path):
    with pg_gate["db"].get_conn() as conn:
        conn.execute(
            "UPDATE mcp_tool_metadata SET status = 'changed', drift_severity = 'high',"
            " drift_action = 'deny' WHERE server_id = ? AND tool_name = 'read_document'",
            (SERVER_ID,),
        )
    for policy in ("material", "any-finding", "quarantine-only"):
        target = tmp_path / policy
        result = run_gate(pg_gate, target, SERVER_ID, "--fail-policy", policy)
        artifact, _ = load_artifact(target)
        assert result.returncode == 21, (policy, result.stdout)
        assert artifact["gate"]["outcome"] == "quarantined"


def test_postgres_snapshot_is_coherent_and_versioned(pg_gate):
    snapshot = pg_gate["db"].get_boundary_review_snapshot(SERVER_ID)
    assert snapshot["ok"] is True
    assert snapshot["snapshot_version"].startswith("sha256:")
    assert snapshot["active"]["surface_hash"].startswith("sha256:")
    assert {t["tool_name"] for t in snapshot["tools"]} == {
        "read_document",
        "list_documents",
    }
    repeat = pg_gate["db"].get_boundary_review_snapshot(SERVER_ID)
    assert repeat["snapshot_version"] == snapshot["snapshot_version"]


# ── Bounded request bodies and anti-cache headers on Postgres ────────────────
def _pg_counts(pg_db):
    with pg_db.get_conn() as conn:
        audits = pg_db.row_value(
            conn.execute("SELECT COUNT(*) AS n FROM mcp_audit_log").fetchone(), "n", 0
        )
        snaps = pg_db.row_value(
            conn.execute("SELECT COUNT(*) AS n FROM tool_surface_snapshots").fetchone(),
            "n",
            0,
        )
        idem = pg_db.row_value(
            conn.execute("SELECT COUNT(*) AS n FROM ci_review_idempotency").fetchone(),
            "n",
            0,
        )
        checkpoints = pg_db.row_value(
            conn.execute(
                "SELECT COUNT(*) AS n FROM audit_chain_checkpoints"
            ).fetchone(),
            "n",
            0,
        )
    return int(audits), int(snaps), int(idem), int(checkpoints)


@pytest.mark.parametrize("size", [1024 * 1024, 32 * 1024 * 1024])
def test_postgres_declared_oversized_body_writes_nothing(pg_gate, size):
    import httpx

    before = _pg_counts(pg_gate["db"])
    response = httpx.post(
        f"{pg_gate['base_url']}/mcp/servers/{SERVER_ID}/boundary-review",
        headers={"x-api-key": pg_gate["ci_key"], "idempotency-key": "e" * 48},
        content=b"A" * size,
        timeout=120,
    )
    assert response.status_code == 413
    assert response.headers["cache-control"] == "no-store"
    assert _pg_counts(pg_gate["db"]) == before


def test_postgres_chunked_oversized_body_writes_nothing(pg_gate):
    import httpx

    before = _pg_counts(pg_gate["db"])

    def chunks():
        for _ in range(16):
            yield b"C" * (64 * 1024)

    response = httpx.post(
        f"{pg_gate['base_url']}/mcp/servers/{SERVER_ID}/boundary-review",
        headers={"x-api-key": pg_gate["ci_key"], "idempotency-key": "f" * 48},
        content=chunks(),
        timeout=120,
    )
    assert response.status_code == 413
    assert _pg_counts(pg_gate["db"]) == before


def test_postgres_anti_cache_headers_on_every_status(pg_gate):
    import httpx

    url = f"{pg_gate['base_url']}/mcp/servers/{SERVER_ID}/boundary-review"
    ci = pg_gate["ci_key"]
    responses = [
        httpx.post(url, headers={"x-api-key": ci}, timeout=90),
        httpx.post(url, timeout=30),
        httpx.get(url, timeout=30),
        httpx.post(url, headers={"x-api-key": ci, "idempotency-key": "x"}, timeout=30),
        httpx.post(
            url, headers={"x-api-key": ci}, content=b"A" * (256 * 1024), timeout=60
        ),
    ]
    assert [r.status_code for r in responses] == [200, 401, 405, 400, 413]
    for response in responses:
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        assert response.headers["expires"] == "0"
        vary = response.headers["vary"].lower()
        assert "authorization" in vary and "x-api-key" in vary


def test_postgres_review_only_key_is_403_on_every_other_authenticated_route(pg_gate):
    import httpx

    with httpx.Client(base_url=pg_gate["base_url"], timeout=20) as client:
        for method, path, body in CI_FORBIDDEN_ROUTES:
            response = client.request(
                method.upper(),
                path,
                headers={"x-api-key": pg_gate["ci_key"]},
                json=body,
            )
            assert response.status_code == 403, (method, path, response.text)


def test_postgres_gate_fixture_leaves_no_rows_or_sequence_state(pg_db):
    with pg_db.get_conn() as conn:
        for table in PG_GATE_TRUNCATE_TABLES:
            count = pg_db.row_value(
                conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone(),
                "n",
                0,
            )
            assert int(count) == 0, table

        for sequence in (
            "api_keys_id_seq",
            "usage_log_id_seq",
            "mcp_audit_log_id_seq",
            "mcp_baseline_versions_id_seq",
            "audit_chain_checkpoints_id_seq",
        ):
            state = dict(
                conn.execute(f"SELECT last_value, is_called FROM {sequence}").fetchone()
            )
            assert int(state["last_value"]) == 1, sequence
            assert state["is_called"] is False, sequence


def test_postgres_config_failure_precedes_database_initialization(pg_db, monkeypatch):
    import asyncio
    import config
    import proxy

    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "NaN")
    touched = []
    monkeypatch.setattr(pg_db, "init_db", lambda: touched.append("init_db"))
    monkeypatch.setattr(pg_db, "seed_legacy_keys", lambda: touched.append("seed"))

    async def enter():
        async with proxy.lifespan(proxy.app):
            pass

    with pytest.raises(config.ConfigurationError):
        asyncio.run(enter())
    assert touched == []
