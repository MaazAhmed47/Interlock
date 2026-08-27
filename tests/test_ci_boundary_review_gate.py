"""
End-to-end proof for the optional self-hosted CI boundary-review gate.

Everything here drives ``scripts/interlock_ci_gate.py`` as a real subprocess
against a live uvicorn-served Interlock app and a live mock MCP server, so the
proofs cover the actual HTTP path — auth, scope enforcement, sanitization,
artifacts, and exit codes — not mocked function calls.

Run: python -m pytest tests/test_ci_boundary_review_gate.py -q
"""

from __future__ import annotations

import asyncio
import copy
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List

import httpx
import pytest
import uvicorn
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import proxy
from core import admin as admin_module
from core import ci_boundary_review
from core import db
from core.tool_metadata import normalize_tool_metadata

ROOT = Path(__file__).resolve().parents[1]
GATE_SCRIPT = ROOT / "scripts" / "interlock_ci_gate.py"
WORKFLOW_TEMPLATE = (
    ROOT / "docs" / "integrations" / "github-actions" / "interlock-boundary-gate.yml"
)

SERVER_ID = "_test_ci_gate_server"
QUARANTINE_SERVER_ID = "_test_ci_gate_quarantined"
UNVERIFIED_SERVER_ID = "_test_ci_gate_unverified"
ALL_SERVER_IDS = (SERVER_ID, QUARANTINE_SERVER_ID, UNVERIFIED_SERVER_ID)

# Markers that must never leave the deployment inside a CI artifact.
DESCRIPTION_MARKER = "ci-gate-description-marker"
SCHEMA_FIELD_MARKER = "ci_gate_secret_marker_token"

READ_DOCUMENT: Dict[str, Any] = {
    "name": "read_document",
    "description": f"Read one document. {DESCRIPTION_MARKER}",
    "inputSchema": {
        "type": "object",
        "properties": {"document_id": {"type": "string"}},
        "required": ["document_id"],
    },
}
LIST_DOCUMENTS: Dict[str, Any] = {
    "name": "list_documents",
    "description": "List available documents.",
    "inputSchema": {"type": "object", "properties": {}},
}
BASE_TOOLS: List[Dict[str, Any]] = [READ_DOCUMENT, LIST_DOCUMENTS]

# Drops an approved required field AND adds a sensitive-looking one: two
# independent `high` findings, so the classifier decision is `deny`.
DRIFTED_READ_DOCUMENT: Dict[str, Any] = {
    "name": "read_document",
    "description": f"Read one document. {DESCRIPTION_MARKER}",
    "inputSchema": {
        "type": "object",
        "properties": {
            "document_id": {"type": "string"},
            SCHEMA_FIELD_MARKER: {"type": "string"},
        },
    },
}

# Fails the static tool validator outright (suspicious tool name).
MALICIOUS_TOOL: Dict[str, Any] = {
    "name": "execute_anything",
    "description": "Run a thing.",
    "inputSchema": {"type": "object", "properties": {}},
}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _serve(app: FastAPI, *, root_path: str = "") -> Iterator[str]:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="critical",
            access_log=False,
            root_path=root_path,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if not thread.is_alive() or time.monotonic() >= deadline:
            raise RuntimeError("test HTTP server did not start")
        time.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=15)


@pytest.fixture
def live_gate(tmp_path_factory):
    """Live Interlock + live mock MCP server + minted least-privilege keys."""
    root = tmp_path_factory.mktemp("ci-gate")
    prior_db_path = db.DB_PATH
    db.DB_PATH = str(Path(root) / "ci_gate.db")
    db.init_db()
    proxy._key_record_cache.clear()
    proxy._usage_cache.clear()
    # Configure admin auth so "the CI key is refused" is a real authorization
    # result rather than the unconfigured-admin 503.
    prior_admin_token = admin_module.ADMIN_TOKEN
    admin_module.ADMIN_TOKEN = "ci-gate-fixture-admin-token"

    state: Dict[str, Any] = {"tools": copy.deepcopy(BASE_TOOLS), "mode": "ok"}
    upstream = FastAPI()

    @upstream.post("/mcp")
    async def upstream_mcp(request: Request):
        message = await request.json()
        mode = state["mode"]
        if mode == "hang":
            await asyncio.sleep(4)
        if mode == "http_500":
            return JSONResponse({"detail": "upstream failure"}, status_code=500)
        if mode == "jsonrpc_error":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {"code": -32000, "message": "upstream failure"},
                }
            )
        if message.get("method") == "tools/call":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "content": [{"type": "text", "text": "safe result"}],
                        "isError": False,
                    },
                }
            )
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {"tools": state["tools"]},
            }
        )

    with _serve(upstream) as upstream_url:
        upstream_mcp_url = f"{upstream_url}/mcp"
        for server_id in ALL_SERVER_IDS:
            db.register_mcp_server(
                server_id,
                {
                    "url": upstream_mcp_url,
                    "description": "CI boundary review fixture",
                    "allowed_tools": ["read_document", "list_documents"],
                    "blocked_tools": [],
                    "environment": "non_production",
                },
            )
            for tool in BASE_TOOLS:
                db.upsert_mcp_tool_metadata(
                    server_id, tool, normalize_tool_metadata(tool)
                )
        db.verify_mcp_server(SERVER_ID)
        db.verify_mcp_server(QUARANTINE_SERVER_ID)
        db.quarantine_mcp_tool(
            QUARANTINE_SERVER_ID,
            "read_document",
            reviewer="fixture",
            reason="fixture quarantine",
        )

        keys = {
            "ci": db.generate_key(
                "developer",
                label="ci-boundary-gate",
                scopes=["mcp.review"],
                role="readonly_agent",
            )["raw_key"],
            "ci_rate_limited": db.generate_key(
                "developer",
                label="ci-boundary-gate-rl",
                scopes=["mcp.review"],
                role="readonly_agent",
                rate_per_min=1,
            )["raw_key"],
            "admin": db.generate_key(
                "developer", label="ci-gate-admin", scopes=["admin"], role="admin_agent"
            )["raw_key"],
            "runtime": db.generate_key(
                "developer",
                label="ci-gate-runtime",
                scopes=["mcp.call", "mcp.read"],
                role="admin_agent",
            )["raw_key"],
        }

        with _serve(proxy.app) as base_url:
            yield {
                "base_url": base_url,
                "upstream_url": upstream_mcp_url,
                "state": state,
                "keys": keys,
            }

    for server_id in ALL_SERVER_IDS:
        db.unregister_mcp_server(server_id)
    admin_module.ADMIN_TOKEN = prior_admin_token
    proxy._key_record_cache.clear()
    proxy._usage_cache.clear()
    db.DB_PATH = prior_db_path


# ── Gate driver ───────────────────────────────────────────────────────────────
def run_gate(
    live,
    tmp_path,
    *,
    server_id: str = SERVER_ID,
    key: str = "",
    extra: tuple = (),
    base_url: str = "",
    unset_key: bool = False,
):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["INTERLOCK_BASE_URL"] = base_url or live["base_url"]
    if unset_key:
        env.pop("INTERLOCK_CI_API_KEY", None)
    else:
        env["INTERLOCK_CI_API_KEY"] = key or live["keys"]["ci"]
    return subprocess.run(
        [
            sys.executable,
            str(GATE_SCRIPT),
            "--server-id",
            server_id,
            "--output-dir",
            str(tmp_path),
            *extra,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


def read_artifacts(output_dir: Path):
    json_path = output_dir / "interlock-boundary-review.json"
    md_path = output_dir / "interlock-boundary-review.md"
    assert json_path.is_file(), "gate must always write the JSON artifact"
    assert md_path.is_file(), "gate must always write the Markdown artifact"
    json_text = json_path.read_text(encoding="utf-8")
    return json.loads(json_text), json_text, md_path.read_text(encoding="utf-8")


def normalize(artifact: Dict[str, Any]) -> Dict[str, Any]:
    """Blank the fields that legitimately move between two identical runs."""
    normalized = copy.deepcopy(artifact)
    normalized["generated_at"] = "<timestamp>"
    receipt = (normalized.get("evidence") or {}).get("receipt")
    if isinstance(receipt, dict):
        receipt["audit_id"] = "<revision>"
        receipt["receipt_path"] = "<revision>"
    evidence_ref = (normalized.get("evidence") or {}).get("evidence_ref")
    if isinstance(evidence_ref, dict):
        evidence_ref["ref"] = "<revision>"
    return normalized


def registry_state() -> Dict[str, Any]:
    return {
        server_id: {
            "baseline": db.get_active_baseline(server_id)["surface_hash"],
            "tools": sorted(
                (t["tool_name"], t["status"], t["drift_severity"], t["drift_action"])
                for t in db.list_mcp_tool_metadata(server_id)
            ),
            "verified": (db.lookup_mcp_server(server_id) or {}).get("verified"),
        }
        for server_id in ALL_SERVER_IDS
    }


# ── 1. Clean server ───────────────────────────────────────────────────────────
def test_clean_registered_server_exits_zero_with_both_safe_artifacts(
    live_gate, tmp_path
):
    result = run_gate(live_gate, tmp_path)
    artifact, json_text, markdown = read_artifacts(tmp_path)

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "clean"
    assert artifact["gate"]["exit_code"] == 0
    assert artifact["format_version"] == "interlock.ci-boundary-review/v1"
    assert artifact["observation"]["status"] == "observed"
    assert artifact["boundary"]["matches_approved_surface"] is True
    assert artifact["boundary"]["approved_surface_hash"].startswith("sha256:")
    assert artifact["findings"] == []
    assert artifact["review_queue"] == []
    assert artifact["evidence"]["receipt"]["hash_chained"] is True
    assert artifact["evidence"]["receipt"]["chain_verified"] is True
    assert artifact["evidence"]["receipt"]["externally_signed"] is False
    assert artifact["evidence"]["receipt"]["independently_anchored"] is False
    assert artifact["limitations"], "artifact must carry its own limitations"
    assert "Interlock MCP boundary review" in markdown
    assert "clean" in markdown
    assert DESCRIPTION_MARKER not in json_text
    assert DESCRIPTION_MARKER not in markdown


# ── 2. Material drift ─────────────────────────────────────────────────────────
def test_material_drift_exits_review_required_with_finding(live_gate, tmp_path):
    live_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]

    result = run_gate(live_gate, tmp_path)
    artifact, json_text, markdown = read_artifacts(tmp_path)

    assert result.returncode == 20, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "review_required"
    assert artifact["gate"]["exit_code"] == 20
    assert artifact["boundary"]["matches_approved_surface"] is False
    assert artifact["severity_summary"]["max_severity"] == "high"
    assert artifact["severity_summary"]["material"] is True

    finding = artifact["findings"][0]
    assert finding["tool_ref"] == "read_document"
    assert finding["severity"] == "high"
    assert finding["decision"] == "deny"
    assert "required_field_removed" in finding["change_types"]
    assert finding["approved_tool_surface_hash"].startswith("sha256:")
    assert finding["observed_tool_surface_hash"].startswith("sha256:")
    assert (
        finding["approved_tool_surface_hash"] != finding["observed_tool_surface_hash"]
    )

    evidence = artifact["evidence"]
    assert evidence["evidence_ref"]["digest"].startswith("sha256:")
    assert evidence["evidence_ref"]["canonicalization"] == "json/jcs-rfc8785"
    # The drift record itself carries the raw server id, so only its digest
    # travels in the artifact; the record is fetched from the receipt.
    assert "drift_record" not in evidence
    assert evidence["evidence_ref"]["ref"].startswith("audit://")

    # The drifted schema's field name is a classifier detail, not artifact data.
    assert SCHEMA_FIELD_MARKER not in json_text
    assert SCHEMA_FIELD_MARKER not in markdown
    assert "required_field_removed" in markdown


def test_fail_policies_change_only_the_policy_dependent_outcome(live_gate, tmp_path):
    live_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]

    strict = run_gate(live_gate, tmp_path / "strict")
    assert strict.returncode == 20

    loose = run_gate(
        live_gate, tmp_path / "loose", extra=("--fail-policy", "quarantine-only")
    )
    loose_artifact, _, _ = read_artifacts(tmp_path / "loose")
    assert loose.returncode == 0
    assert loose_artifact["gate"]["outcome"] == "advisory"
    assert loose_artifact["gate"]["gateway_outcome"] == "review_required"

    # A non-material change must still fail under any-finding.
    live_gate["state"]["tools"] = [
        {**READ_DOCUMENT, "description": "Read one document (reworded)."},
        LIST_DOCUMENTS,
    ]
    any_finding = run_gate(
        live_gate, tmp_path / "any", extra=("--fail-policy", "any-finding")
    )
    any_artifact, _, _ = read_artifacts(tmp_path / "any")
    assert any_finding.returncode == 20
    assert any_artifact["gate"]["outcome"] == "review_required"
    assert any_artifact["severity_summary"]["max_severity"] == "minor"

    material = run_gate(live_gate, tmp_path / "material")
    material_artifact, _, _ = read_artifacts(tmp_path / "material")
    assert material.returncode == 0
    assert material_artifact["gate"]["outcome"] == "advisory"


# ── 3. Inconclusive upstream results ──────────────────────────────────────────
@pytest.mark.parametrize(
    "mode,error_class",
    [
        ("hang", "upstream_timeout"),
        ("http_500", "upstream_error"),
        ("jsonrpc_error", "upstream_protocol_error"),
    ],
)
def test_unavailable_upstream_is_inconclusive_never_clean(
    live_gate, tmp_path, monkeypatch, mode, error_class
):
    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "1")
    live_gate["state"]["mode"] = mode

    result = run_gate(live_gate, tmp_path)
    artifact, _, _ = read_artifacts(tmp_path)

    assert result.returncode == 22, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["observation"]["status"] == "unavailable"
    assert artifact["observation"]["error_class"] == error_class
    assert artifact["boundary"]["observed_surface_hash"] == ""


def test_gateway_rate_limit_is_inconclusive_never_clean(live_gate, tmp_path):
    key = live_gate["keys"]["ci_rate_limited"]
    first = run_gate(live_gate, tmp_path / "first", key=key)
    second = run_gate(live_gate, tmp_path / "second", key=key)
    artifact, json_text, _ = read_artifacts(tmp_path / "second")

    assert first.returncode == 0
    assert second.returncode == 22
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["observation"]["error_class"] == "gateway_rate_limited"
    assert key not in json_text


def test_unreachable_gateway_is_inconclusive_never_clean(live_gate, tmp_path):
    dead_port = _free_port()
    result = run_gate(live_gate, tmp_path, base_url=f"http://127.0.0.1:{dead_port}")
    artifact, _, _ = read_artifacts(tmp_path)

    assert result.returncode == 22
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["observation"]["error_class"] == "gateway_unreachable"


# ── 4. Held boundaries ────────────────────────────────────────────────────────
def test_quarantined_tool_exits_quarantined(live_gate, tmp_path):
    result = run_gate(live_gate, tmp_path, server_id=QUARANTINE_SERVER_ID)
    artifact, _, markdown = read_artifacts(tmp_path)

    assert result.returncode == 21, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "quarantined"
    queue = artifact["review_queue"]
    assert any(
        entry["tool_ref"] == "read_document" and entry["status"] == "quarantined"
        for entry in queue
    )
    assert artifact["gateway_mediation"]["tool_calls_held"] >= 1
    assert artifact["gateway_mediation"]["call_forwarded"] is False
    assert "quarantined" in markdown


def test_unverified_server_is_held_under_every_policy(live_gate, tmp_path):
    for policy in ("material", "any-finding", "quarantine-only"):
        target = tmp_path / policy
        result = run_gate(
            live_gate,
            target,
            server_id=UNVERIFIED_SERVER_ID,
            extra=("--fail-policy", policy),
        )
        artifact, _, _ = read_artifacts(target)
        assert result.returncode == 21, (policy, result.stdout, result.stderr)
        assert artifact["gate"]["outcome"] == "quarantined"
        assert artifact["server"]["verified"] is False
        assert artifact["gateway_mediation"]["server_calls_held"] is True


def test_surface_that_fails_validation_is_held_not_inconclusive(live_gate, tmp_path):
    live_gate["state"]["tools"] = [READ_DOCUMENT, LIST_DOCUMENTS, MALICIOUS_TOOL]

    result = run_gate(live_gate, tmp_path)
    artifact, json_text, _ = read_artifacts(tmp_path)

    assert result.returncode == 21
    assert artifact["gate"]["outcome"] == "quarantined"
    assert artifact["observation"]["status"] == "observed_rejected"
    finding = artifact["findings"][0]
    assert finding["change_types"] == ["surface_validation_failed"]
    assert finding["threat_class"] == "MALICIOUS_MCP_TOOL_NAME"
    assert finding["severity"] == "critical"
    # The validator's reason text quotes the matched pattern; it must not ship.
    assert "matches suspicious pattern" not in json_text


# ── 5. Authority ──────────────────────────────────────────────────────────────
CI_FORBIDDEN_ROUTES = [
    ("get", f"/mcp/servers/{SERVER_ID}/boundary-review", None),
    ("post", "/scan", {"prompt": "safe"}),
    ("post", "/scan/output", {"output": "safe"}),
    ("get", "/scan/history", None),
    ("get", "/scan/stats", None),
    ("post", "/scan/shadow", {"prompt": "safe"}),
    ("get", "/shadow/logs", None),
    ("get", "/shadow/stats", None),
    ("post", "/inspect/tool-call", {"tool_name": "read", "arguments": {}}),
    ("post", "/v1/chat/completions", {"model": "test", "messages": []}),
    ("get", "/providers", None),
    ("get", "/roles", None),
    ("get", "/usage", None),
    ("post", "/siem/test", {"provider": "generic", "config": {}}),
    ("get", "/siem/providers", None),
    ("get", "/metrics/performance", None),
    ("post", "/mcp/servers", {"server_id": "x", "url": "http://safe.example/mcp"}),
    ("post", f"/mcp/servers/{SERVER_ID}/verify", {}),
    (
        "post",
        f"/mcp/servers/{SERVER_ID}/environment",
        {"environment": "non_production", "probes_enabled": True},
    ),
    ("delete", f"/mcp/servers/{SERVER_ID}", None),
    ("get", f"/mcp/servers/{SERVER_ID}/rebaseline", None),
    ("post", f"/mcp/servers/{SERVER_ID}/rebaseline/discover", {}),
    (
        "post",
        f"/mcp/servers/{SERVER_ID}/rebaseline",
        {
            "confirm_rebaseline": True,
            "expected_current_hash": "x",
            "expected_candidate_hash": "y",
        },
    ),
    (
        "post",
        f"/mcp/tools/{SERVER_ID}/read_document/approve",
        {
            "expected_surface_hash": "sha256:" + "0" * 64,
            "reviewer": "ci",
            "reason": "ci",
        },
    ),
    (
        "post",
        f"/mcp/tools/{SERVER_ID}/read_document/quarantine",
        {"reviewer": "ci", "reason": "ci"},
    ),
    (
        "post",
        "/mcp/call",
        {"server_id": SERVER_ID, "tool_name": "read_document", "arguments": {}},
    ),
    ("post", "/mcp/discover", {"server_url": "http://safe.example/mcp"}),
    (
        "post",
        f"/mcp/servers/{SERVER_ID}/probes/run",
        {
            "tool_name": "read_document",
            "arguments": {},
            "expected_outcome": "denied",
            "non_production": True,
            "safety_note": "ci",
        },
    ),
    (
        "post",
        "/mcp/chains/analyze",
        {
            "steps": [{"tool_name": "read_document", "arguments": {}}],
            "safety_note": "x",
        },
    ),
    ("get", "/mcp/audit", None),
    ("get", "/mcp/servers", None),
    ("get", "/mcp/tools", None),
    ("get", "/mcp/tools/drifted", None),
    ("get", "/audit/receipt/1", None),
    ("get", "/audit/receipt/export", None),
]


def test_ci_credential_cannot_mutate_approve_rebaseline_or_call_tools(live_gate):
    key = live_gate["keys"]["ci"]
    before = registry_state()

    with httpx.Client(base_url=live_gate["base_url"], timeout=15) as client:
        for method, path, body in CI_FORBIDDEN_ROUTES:
            response = client.request(
                method.upper(), path, headers={"x-api-key": key}, json=body
            )
            assert response.status_code == 403, (method, path, response.text)
            assert key not in response.text

        # Admin-token routes reject the CI key as well.
        for method, path in (
            ("get", "/admin/mcp/provenance-policy"),
            ("get", "/admin/keys"),
        ):
            response = client.request(method.upper(), path, headers={"x-api-key": key})
            assert response.status_code in (401, 403), (path, response.text)
            assert key not in response.text

    assert registry_state() == before


def test_review_only_credential_is_rejected_before_siem_outbound(
    live_gate, monkeypatch
):
    import core.siem as siem

    attempted = []
    monkeypatch.setattr(
        siem,
        "send_to_siem",
        lambda *args, **kwargs: attempted.append((args, kwargs)),
    )
    response = httpx.post(
        f"{live_gate['base_url']}/siem/test",
        headers={"x-api-key": live_gate["keys"]["ci"]},
        json={"provider": "generic", "config": {}},
        timeout=15,
    )
    assert response.status_code == 403
    assert attempted == []


def test_review_appends_evidence_but_mutates_no_approval_state(live_gate, tmp_path):
    live_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
    before = registry_state()

    result = run_gate(live_gate, tmp_path)
    assert result.returncode == 20

    assert registry_state() == before, "a review must not change approval state"

    artifact, _, _ = read_artifacts(tmp_path)
    audit_id = artifact["evidence"]["receipt"]["audit_id"]
    row = db.get_mcp_audit_log(int(audit_id))
    assert row is not None
    assert row["matched_rule"] == "ci_boundary_review"
    assert db.verify_mcp_audit_record(int(audit_id))["chain_verified"] is True


@pytest.mark.parametrize(
    "scenario,server_id,expected_outcome,expected_action",
    [
        ("clean", SERVER_ID, "clean", "allow"),
        ("material", SERVER_ID, "review_required", "deny"),
        ("quarantined", QUARANTINE_SERVER_ID, "quarantined", "quarantine"),
        ("inconclusive", SERVER_ID, "inconclusive", "monitor"),
    ],
)
def test_live_artifact_and_newest_audit_row_have_identical_outcome_semantics(
    live_gate,
    tmp_path,
    scenario,
    server_id,
    expected_outcome,
    expected_action,
):
    if scenario == "material":
        live_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
    elif scenario == "inconclusive":
        live_gate["state"]["mode"] = "http_500"

    before = len(db.list_mcp_audit_logs(5000))
    result = run_gate(live_gate, tmp_path, server_id=server_id)
    artifact, json_text, markdown = read_artifacts(tmp_path)
    rows = db.list_mcp_audit_logs(5000)

    assert len(rows) == before + 1
    newest = rows[0]
    receipt = artifact["evidence"]["receipt"]
    assert newest["id"] == receipt["audit_id"]
    assert receipt["hash_chained"] is True
    assert receipt["chain_verified"] is True
    assert db.verify_mcp_audit_record(newest["id"])["chain_verified"] is True

    assert artifact["gate"]["outcome"] == expected_outcome
    assert artifact["gate"]["boundary_review_semantic_outcome"] == expected_outcome
    assert artifact["gate"]["boundary_review_final_outcome"] == expected_outcome
    assert (
        artifact["gate"]["boundary_review_final_exit_code"]
        == artifact["gate"]["exit_code"]
    )
    assert newest["observed_outcome"] == expected_outcome
    assert newest["observed_status_code"] == artifact["gate"]["exit_code"]
    assert newest["expected_outcome"] == ""
    assert newest["action"] == expected_action
    assert newest["drift_action"] == expected_action
    assert f"outcome={expected_outcome}" in newest["reason"]
    assert f"exit_code={artifact['gate']['exit_code']}" in newest["reason"]
    assert "fail_policy=" not in newest["reason"]
    metadata = newest["boundary_review_metadata"]
    assert newest["hash_v"] == 5
    assert metadata == {
        "boundary_review_semantic_outcome": expected_outcome,
        "boundary_review_final_outcome": expected_outcome,
        "boundary_review_final_exit_code": artifact["gate"]["exit_code"],
        "fail_policy": artifact["gate"]["fail_policy"],
        "receipt_verification_state": "verified",
    }
    assert receipt["receipt_verification_state"] == "verified"
    assert newest["verification_level"] == "chain_verified"
    assert newest["expected_outcome"] not in ci_boundary_review.FAIL_POLICIES

    metadata_text = json.dumps(metadata, sort_keys=True)
    assert live_gate["keys"]["ci"] not in metadata_text
    assert "x-api-key" not in metadata_text.lower()
    assert "authorization" not in metadata_text.lower()
    assert "inputschema" not in metadata_text.lower()

    for forbidden in (
        server_id,
        live_gate["keys"]["ci"],
        live_gate["upstream_url"],
        DESCRIPTION_MARKER,
        SCHEMA_FIELD_MARKER,
        "x-api-key",
        "Authorization",
        "inputSchema",
        "raw_tool_definition",
        "jsonrpc",
    ):
        assert forbidden not in json_text
        assert forbidden not in markdown
        assert forbidden not in result.stdout
        assert forbidden not in result.stderr


def test_boundary_review_metadata_is_committed_to_the_hash_chain(live_gate, tmp_path):
    result = run_gate(live_gate, tmp_path)
    artifact, _, _ = read_artifacts(tmp_path)
    audit_id = artifact["evidence"]["receipt"]["audit_id"]
    assert result.returncode == 0
    assert db.verify_mcp_audit_record(audit_id)["chain_verified"] is True

    with db.get_conn() as conn:
        conn.execute(
            "UPDATE mcp_audit_log SET boundary_review_metadata = ? WHERE id = ?",
            (json.dumps({"boundary_review_final_outcome": "clean"}), audit_id),
        )

    assert db.verify_mcp_audit_record(audit_id)["chain_verified"] is False


@pytest.mark.parametrize(
    "policy,findings,queue,observed,verified,exceeded,expected",
    [
        ("material", [], [], True, True, False, "clean"),
        ("any-finding", [], [], True, True, False, "clean"),
        ("quarantine-only", [], [], True, True, False, "clean"),
        (
            "material",
            [{"severity": "minor", "decision": "monitor"}],
            [],
            True,
            True,
            False,
            "advisory",
        ),
        (
            "any-finding",
            [{"severity": "minor", "decision": "monitor"}],
            [],
            True,
            True,
            False,
            "review_required",
        ),
        (
            "quarantine-only",
            [{"severity": "minor", "decision": "monitor"}],
            [],
            True,
            True,
            False,
            "advisory",
        ),
        (
            "material",
            [{"severity": "high", "decision": "deny"}],
            [],
            True,
            True,
            False,
            "review_required",
        ),
        (
            "any-finding",
            [{"severity": "high", "decision": "deny"}],
            [],
            True,
            True,
            False,
            "review_required",
        ),
        (
            "quarantine-only",
            [{"severity": "high", "decision": "deny"}],
            [],
            True,
            True,
            False,
            "advisory",
        ),
        (
            "material",
            [{"severity": "critical", "decision": "quarantine"}],
            [],
            True,
            True,
            False,
            "quarantined",
        ),
        (
            "material",
            [],
            [{"status": "changed", "decision": "deny"}],
            True,
            True,
            False,
            "quarantined",
        ),
        ("material", [], [], False, True, False, "inconclusive"),
        ("material", [], [], True, False, False, "quarantined"),
        ("material", [], [], True, True, True, "inconclusive"),
    ],
)
def test_semantic_outcome_evaluator_covers_every_fail_policy(
    policy, findings, queue, observed, verified, exceeded, expected
):
    assert (
        ci_boundary_review.compute_semantic_outcome(
            verified=verified,
            observation_status="observed" if observed else "unavailable",
            findings=findings,
            review_queue=queue,
            caps_exceeded=["max_findings"] if exceeded else [],
            fail_policy=policy,
        )
        == expected
    )


# ── 6. Credential handling ────────────────────────────────────────────────────
def test_missing_credential_fails_closed(live_gate, tmp_path):
    result = run_gate(live_gate, tmp_path, unset_key=True)
    artifact, _, _ = read_artifacts(tmp_path)
    assert result.returncode == 2
    assert artifact["gate"]["outcome"] == "config_error"


def test_credential_on_the_command_line_is_refused(live_gate, tmp_path):
    key = live_gate["keys"]["ci"]
    result = run_gate(live_gate, tmp_path, extra=("--base-url", f"http://x/{key}"))
    assert result.returncode == 2
    assert key not in result.stdout
    assert key not in result.stderr
    assert "command-line argument" in result.stderr


def test_invalid_credential_is_auth_error(live_gate, tmp_path):
    result = run_gate(live_gate, tmp_path, key="lf_not_a_real_key_value")
    artifact, _, _ = read_artifacts(tmp_path)
    assert result.returncode == 3
    assert artifact["gate"]["outcome"] == "auth_error"
    assert artifact["observation"]["status"] == "not_performed"


def test_wrong_scope_is_auth_error(live_gate, tmp_path):
    result = run_gate(live_gate, tmp_path, key=live_gate["keys"]["runtime"])
    artifact, _, _ = read_artifacts(tmp_path)
    assert result.returncode == 3
    assert artifact["gate"]["outcome"] == "auth_error"


def test_unregistered_server_is_config_error(live_gate, tmp_path):
    result = run_gate(live_gate, tmp_path, server_id="_test_ci_gate_absent")
    artifact, _, _ = read_artifacts(tmp_path)
    assert result.returncode == 2
    assert artifact["gate"]["outcome"] == "config_error"
    assert artifact["observation"]["error_class"] == "server_not_registered"


def test_missing_duplicate_and_conflicting_credentials_fail_closed(live_gate):
    key = live_gate["keys"]["ci"]
    url = f"{live_gate['base_url']}/mcp/servers/{SERVER_ID}/boundary-review"
    header_sets = [
        [],
        [("x-api-key", key), ("x-api-key", key)],
        [("x-api-key", key), ("x-api-key", "lf_other_value")],
        [("authorization", f"Bearer {key}"), ("authorization", f"Bearer {key}")],
        [("x-api-key", key), ("authorization", f"Bearer {key}")],
    ]
    for headers in header_sets:
        response = httpx.post(url, headers=headers, timeout=15)
        assert response.status_code == 401, (headers, response.text)
        assert key not in response.text

    # A single well-formed Bearer credential still works.
    accepted = httpx.post(url, headers={"authorization": f"Bearer {key}"}, timeout=60)
    assert accepted.status_code == 200

    # Strict Bearer parsing: a doubled scheme is no longer unwrapped.
    doubled = httpx.post(
        url, headers={"authorization": f"Bearer Bearer {key}"}, timeout=15
    )
    assert doubled.status_code == 401
    assert key not in doubled.text


# ── 7. Sanitization ───────────────────────────────────────────────────────────
def test_artifacts_and_logs_carry_no_secrets_bodies_headers_or_paths(
    live_gate, tmp_path
):
    live_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
    result = run_gate(live_gate, tmp_path)
    artifact, json_text, markdown = read_artifacts(tmp_path)

    key = live_gate["keys"]["ci"]
    forbidden = [
        key,
        live_gate["keys"]["admin"],
        DESCRIPTION_MARKER,
        SCHEMA_FIELD_MARKER,
        live_gate["upstream_url"],
        "127.0.0.1",
        "x-api-key",
        "Authorization",
        "inputSchema",
        "raw_tool_definition",
        str(tmp_path),
        str(ROOT),
    ]
    for needle in forbidden:
        assert needle not in json_text, f"artifact leaked {needle!r}"
        assert needle not in markdown, f"summary leaked {needle!r}"

    assert key not in result.stdout
    assert key not in result.stderr
    assert DESCRIPTION_MARKER not in result.stdout

    assert artifact["redaction"]["profile"] == "default"
    assert "credentials_and_tokens" in artifact["redaction"]["excluded"]
    assert "raw_server_identifiers" in artifact["redaction"]["excluded"]
    # No actor identity: the recorded reviewer embeds a key prefix.
    assert "principal" not in json_text
    assert "reviewer" not in json_text
    # Only an irreversible digest reference for the server.
    assert "server_id" not in artifact["server"]
    assert artifact["server"]["server_ref"] == ci_boundary_review.opaque_ref(SERVER_ID)
    assert SERVER_ID not in json_text


def test_normal_registered_server_id_is_absent_from_all_success_surfaces(
    live_gate, tmp_path
):
    raw_id = "billing-mcp"
    db.register_mcp_server(
        raw_id,
        {
            "url": live_gate["upstream_url"],
            "description": "digest-only identifier proof",
            "allowed_tools": ["read_document", "list_documents"],
            "blocked_tools": [],
            "environment": "non_production",
        },
    )
    try:
        db.verify_mcp_server(raw_id)
        for tool in BASE_TOOLS:
            db.upsert_mcp_tool_metadata(raw_id, tool, normalize_tool_metadata(tool))
        result = run_gate(live_gate, tmp_path, server_id=raw_id)
        artifact, json_text, markdown = read_artifacts(tmp_path)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert artifact["server"]["server_ref"] == ci_boundary_review.opaque_ref(raw_id)
        for surface in (json_text, markdown, result.stdout, result.stderr):
            assert raw_id not in surface
        assert any(
            row.get("server_id") == raw_id for row in db.list_mcp_audit_logs(100)
        ), "the access-controlled audit path must retain the real id"
    finally:
        db.unregister_mcp_server(raw_id)


def test_hostile_tool_names_cannot_forge_markdown_rows(live_gate, tmp_path):
    hostile = {
        "name": "read_document|evil| **injected** |\n| forged | row |",
        "description": "Read one document.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    live_gate["state"]["tools"] = [READ_DOCUMENT, LIST_DOCUMENTS, hostile]

    run_gate(live_gate, tmp_path)
    artifact, json_text, markdown = read_artifacts(tmp_path)

    refs = [f["tool_ref"] for f in artifact["findings"]]
    assert any(ref.startswith("read_document_evil_") for ref in refs)
    for ref in refs:
        assert "|" not in ref and "\n" not in ref and "*" not in ref

    # The hostile name must not be able to open a new Markdown table row or
    # inject emphasis into a CI job summary.
    assert "**injected**" not in markdown
    assert not any(
        line.strip().startswith("| forged") for line in markdown.splitlines()
    )
    findings_rows = [
        line
        for line in markdown.splitlines()
        if line.startswith("| `") and "|" in line[3:]
    ]
    assert len(findings_rows) == len(artifact["findings"]) + len(
        artifact["review_queue"]
    )
    assert "\n" not in json.dumps(refs)[1:-1].replace("\\n", "")


# ── 8. Determinism ────────────────────────────────────────────────────────────
def test_output_is_deterministic_except_timestamp_and_revision_fields(
    live_gate, tmp_path
):
    live_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]

    first = run_gate(live_gate, tmp_path / "run1")
    second = run_gate(live_gate, tmp_path / "run2")
    assert first.returncode == second.returncode == 20

    first_artifact, _, first_md = read_artifacts(tmp_path / "run1")
    second_artifact, _, second_md = read_artifacts(tmp_path / "run2")

    assert normalize(first_artifact) == normalize(second_artifact)
    assert (
        first_artifact["generated_at"] != "" and second_artifact["generated_at"] != ""
    )
    assert (
        first_artifact["evidence"]["receipt"]["audit_id"]
        != second_artifact["evidence"]["receipt"]["audit_id"]
    )

    def strip_volatile(text: str) -> List[str]:
        return [
            line
            for line in text.splitlines()
            if "Generated" not in line and "/audit/receipt/" not in line
        ]

    assert strip_volatile(first_md) == strip_volatile(second_md)


# ── 9. Existing behavior unchanged ────────────────────────────────────────────
def test_existing_mcp_call_and_drift_views_are_unchanged_by_a_review(
    live_gate, tmp_path
):
    runtime = {"x-api-key": live_gate["keys"]["runtime"]}
    admin = {"x-api-key": live_gate["keys"]["admin"]}
    base = live_gate["base_url"]

    with httpx.Client(base_url=base, timeout=30) as client:
        before_call = client.post(
            "/mcp/call",
            headers=runtime,
            json={
                "server_id": SERVER_ID,
                "tool_name": "read_document",
                "arguments": {"document_id": "d-1"},
            },
        )
        before_drifted = client.get("/mcp/tools/drifted", headers=runtime).json()
        before_tools = client.get("/mcp/tools", headers=runtime).json()
        before_servers = client.get("/mcp/servers", headers=admin).json()

        assert before_call.status_code == 200
        assert before_call.json()["ok"] is True

        live_gate["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
        assert run_gate(live_gate, tmp_path).returncode == 20
        live_gate["state"]["tools"] = copy.deepcopy(BASE_TOOLS)

        after_call = client.post(
            "/mcp/call",
            headers=runtime,
            json={
                "server_id": SERVER_ID,
                "tool_name": "read_document",
                "arguments": {"document_id": "d-1"},
            },
        )
        after_drifted = client.get("/mcp/tools/drifted", headers=runtime).json()
        after_tools = client.get("/mcp/tools", headers=runtime).json()
        after_servers = client.get("/mcp/servers", headers=admin).json()

    assert after_call.status_code == 200
    assert after_call.json()["ok"] is True
    assert after_drifted == before_drifted
    assert after_servers == before_servers
    assert [
        (t["tool_name"], t["status"], t["drift_severity"]) for t in after_tools["tools"]
    ] == [
        (t["tool_name"], t["status"], t["drift_severity"])
        for t in before_tools["tools"]
    ]


# ── Contract consistency ──────────────────────────────────────────────────────
def _load_gate_module():
    spec = importlib.util.spec_from_file_location("interlock_ci_gate", GATE_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_and_deployment_share_one_outcome_and_exit_code_table():
    gate = _load_gate_module()
    assert gate.OUTCOME_EXIT_CODES == ci_boundary_review.OUTCOME_EXIT_CODES
    assert gate.OUTCOME_RANK == ci_boundary_review.OUTCOME_RANK
    assert gate.FAIL_POLICIES == ci_boundary_review.FAIL_POLICIES
    assert gate.DEFAULT_FAIL_POLICY == ci_boundary_review.DEFAULT_FAIL_POLICY
    assert gate.FORMAT_VERSION == ci_boundary_review.FORMAT_VERSION
    assert gate.MATERIAL_SEVERITIES == ci_boundary_review.MATERIAL_SEVERITIES
    assert gate.MATERIAL_DECISIONS == ci_boundary_review.MATERIAL_DECISIONS
    # Gate-invocation codes must stay distinct from boundary codes.
    invocation = {
        gate.OUTCOME_EXIT_CODES[k]
        for k in ("config_error", "auth_error", "protocol_error")
    }
    boundary = {
        gate.OUTCOME_EXIT_CODES[k]
        for k in ("review_required", "quarantined", "inconclusive")
    }
    assert invocation.isdisjoint(boundary)
    assert len(invocation) == 3 and len(boundary) == 3


def test_cli_and_deployment_outcome_evaluators_are_exhaustively_equivalent():
    gate = _load_gate_module()
    import itertools

    for policy, verified, status, exceeded, chain, finding, queued in itertools.product(
        ci_boundary_review.FAIL_POLICIES,
        (False, True),
        ci_boundary_review.OBSERVATION_STATUSES,
        (False, True),
        (False, True),
        (None, ("minor", "monitor"), ("high", "deny"), ("critical", "quarantine")),
        (False, True),
    ):
        review = {
            "server": {"verified": verified},
            "observation": {"status": status},
            "caps": {"exceeded": ["max_findings"] if exceeded else []},
            "evidence": {"receipt": {"chain_verified": chain}},
            "findings": (
                []
                if finding is None
                else [{"severity": finding[0], "decision": finding[1]}]
            ),
            "review_queue": (
                [{"status": "changed", "decision": "deny"}] if queued else []
            ),
        }
        assert gate.compute_outcome(
            review, policy
        ) == ci_boundary_review.compute_outcome(review, policy)


def test_new_review_scope_is_narrow_and_not_granted_by_default(live_gate):
    assert "mcp.review" in db.API_KEY_SCOPES
    assert "mcp.review" not in db.DEFAULT_API_KEY_SCOPES
    record = db.generate_key("free", label="ci-gate-default-scopes")
    assert db.lookup_key(record["raw_key"])["scopes"] == ["mcp.call", "mcp.read"]
    assert db.lookup_key(live_gate["keys"]["ci"])["scopes"] == ["mcp.review"]


# ── CI template ───────────────────────────────────────────────────────────────
def test_github_actions_template_is_valid_and_not_active_in_this_repo():
    assert WORKFLOW_TEMPLATE.is_file()
    workflow = yaml.safe_load(WORKFLOW_TEMPLATE.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    assert workflow["name"]
    # PyYAML parses the bare `on:` key as boolean True.
    assert True in workflow or "on" in workflow
    steps = workflow["jobs"]["boundary-review"]["steps"]
    text = WORKFLOW_TEMPLATE.read_text(encoding="utf-8")

    assert "secrets.INTERLOCK_CI_API_KEY" in text
    assert "GITHUB_STEP_SUMMARY" in text
    upload = [
        s for s in steps if str(s.get("uses", "")).startswith("actions/upload-artifact")
    ]
    assert upload and upload[0].get("if") == "always()"
    assert any("--fail-policy" in str(step.get("run", "")) for step in steps)

    # No secret echoing, and the credential is never a command-line argument.
    assert "echo $INTERLOCK_CI_API_KEY" not in text
    assert "echo ${{ secrets" not in text
    assert "--api-key" not in text

    workflows_dir = ROOT / ".github" / "workflows"
    registered = {p.name for p in workflows_dir.glob("*.y*ml")}
    assert WORKFLOW_TEMPLATE.name not in registered
    for path in workflows_dir.glob("*.y*ml"):
        assert "interlock_ci_gate.py" not in path.read_text(encoding="utf-8")
