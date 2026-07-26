"""
Hostile-review regressions for the CI boundary-review gate.

One test per finding from the hostile review, each driving real TCP:
redirect credential capture, proxy environment capture, URL validation,
strict response-schema rejection, degenerate-clean refusal, denied-state
policy independence, POST/cache semantics, idempotent retries, snapshot
coherence under a concurrent rebaseline promotion, cap enforcement, and
identifier sanitization.

Run: python -m pytest tests/test_ci_boundary_review_hardening.py -q
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import proxy
from core import ci_boundary_review as cbr
from core import db
from core.mcp_gateway import validate_mcp_tool_definition
from core.tool_metadata import normalize_tool_metadata
from tests.test_ci_boundary_review_gate import (
    BASE_TOOLS,
    DRIFTED_READ_DOCUMENT,
    GATE_SCRIPT,
    LIST_DOCUMENTS,
    READ_DOCUMENT,
    ROOT,
    _free_port,
    _load_gate_module,
    _serve,
)

FORMAT = cbr.FORMAT_VERSION
SERVER_ID = "_test_hardening_server"
DENY_SERVER_ID = "_test_hardening_denyqueue"
HOSTILE_SERVER_ID = '_test_hardening_<img src=x onerror=alert(1)>|..&"evil'
HARDENING_SERVER_IDS = (SERVER_ID, DENY_SERVER_ID, HOSTILE_SERVER_ID)

DECOY_KEY = "lf_hardening_decoy_credential_value_0123456789"


# ── Local capture servers (stdlib, so the CLI's real transport is exercised) ──
def _serve_handler(handler_fn, port=None):
    port = port or _free_port()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            handler_fn(self)

        def do_GET(self):
            handler_fn(self)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{port}"


def _send_json(handler, payload, status=200, extra_headers=None):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    for key, value in (extra_headers or {}).items():
        handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


def _clean_payload():
    """A structurally valid, fully evidence-bearing clean review."""
    digest = "sha256:" + "a" * 64
    return {
        "format_version": FORMAT,
        "generated_at": "2026-01-01T00:00:00Z",
        "gate": {
            "name": cbr.GATE_NAME,
            "outcome": "clean",
            "exit_code": 0,
            "fail_policy": "material",
            "evaluated_under": "material",
            "boundary_review_semantic_outcome": "clean",
            "boundary_review_final_outcome": "clean",
            "boundary_review_final_exit_code": 0,
        },
        "server": {
            "server_ref": "sha256:0000000000000000",
            "registered": True,
            "verified": True,
            "registry_class": "operator_registered",
            "environment": "non_production",
        },
        "boundary": {
            "approved_surface_hash": digest,
            "observed_surface_hash": digest,
            "matches_approved_surface": True,
            "approved_tool_count": 1,
            "observed_tool_count": 1,
            "snapshot_version": digest,
        },
        "observation": {
            "status": "observed",
            "error_class": "",
            "read_only": True,
            "mutated_state": False,
        },
        "findings": [],
        "review_queue": [],
        "gateway_mediation": {
            "call_forwarded": False,
            "server_calls_held": False,
            "tool_calls_held": 0,
            "note": "n/a",
        },
        "severity_summary": {
            "max_severity": "none",
            "finding_count": 0,
            "review_queue_count": 0,
            "material": False,
        },
        "caps": {
            "timeout_seconds": 10.0,
            "max_response_bytes": 1024,
            "max_request_bytes": 8192,
            "max_observed_tools": 10,
            "max_findings": 10,
            "idempotency_ttl_seconds": 86400,
            "exceeded": [],
        },
        "evidence": {
            "receipt": {
                "audit_id": 1,
                "receipt_path": "/audit/receipt/1",
                "hash_chained": True,
                "chain_verified": True,
                "tamper_evident": True,
                "receipt_verification_state": "verified",
                "externally_signed": False,
                "independently_anchored": False,
            },
            "evidence_ref": None,
            "canonicalization": "json/jcs-rfc8785",
        },
        "limitations": ["synthetic"],
        "redaction": {"profile": "default", "excluded": ["credentials_and_tokens"]},
    }


def _run_cli(base_url, output_dir, *extra, key=DECOY_KEY, env_extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["INTERLOCK_BASE_URL"] = base_url
    env["INTERLOCK_CI_API_KEY"] = key
    env.update(env_extra or {})
    return subprocess.run(
        [
            sys.executable,
            str(GATE_SCRIPT),
            "--server-id",
            "srv",
            "--output-dir",
            str(output_dir),
            *extra,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _artifacts(output_dir: Path):
    json_path = output_dir / "interlock-boundary-review.json"
    md_path = output_dir / "interlock-boundary-review.md"
    assert json_path.is_file(), "the gate must always write the JSON artifact"
    assert md_path.is_file(), "the gate must always write the Markdown artifact"
    text = json_path.read_text(encoding="utf-8")
    return json.loads(text), text, md_path.read_text(encoding="utf-8")


# ── A1. Transport ─────────────────────────────────────────────────────────────
def test_foreign_host_redirect_is_refused_and_leaks_no_credential(tmp_path):
    captured: List[Dict[str, str]] = []

    def sink(handler):
        captured.append({k.lower(): v for k, v in handler.headers.items()})
        _send_json(handler, _clean_payload())

    sink_server, sink_url = _serve_handler(sink)
    sink_port = int(sink_url.rsplit(":", 1)[1])

    def redirector(handler):
        handler.send_response(302)
        handler.send_header("Location", f"http://127.0.0.1:{sink_port}/evil")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    redirect_server, redirect_url = _serve_handler(redirector)
    try:
        result = _run_cli(redirect_url, tmp_path)
        artifact, json_text, markdown = _artifacts(tmp_path)
    finally:
        sink_server.shutdown()
        redirect_server.shutdown()

    assert result.returncode == 4, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "protocol_error"
    assert artifact["observation"]["error_class"] == "redirect_refused"
    assert captured == [], "the redirect target must never be contacted"
    for blob in (json_text, markdown, result.stdout, result.stderr):
        assert DECOY_KEY not in blob


def test_https_to_http_downgrade_redirect_is_refused(tmp_path):
    """A 301 toward a plain-http location must not be followed either."""
    captured: List[Dict[str, str]] = []

    def sink(handler):
        captured.append({k.lower(): v for k, v in handler.headers.items()})
        _send_json(handler, _clean_payload())

    sink_server, sink_url = _serve_handler(sink)

    def redirector(handler):
        handler.send_response(301)
        handler.send_header("Location", f"{sink_url}/downgraded")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    redirect_server, redirect_url = _serve_handler(redirector)
    try:
        result = _run_cli(redirect_url, tmp_path)
        artifact, _, _ = _artifacts(tmp_path)
    finally:
        sink_server.shutdown()
        redirect_server.shutdown()

    assert result.returncode == 4
    assert artifact["observation"]["error_class"] == "redirect_refused"
    assert captured == []


def test_proxy_environment_variables_never_receive_the_credential(tmp_path):
    proxy_hits: List[Dict[str, str]] = []

    def proxy_handler(handler):
        proxy_hits.append({k.lower(): v for k, v in handler.headers.items()})
        _send_json(handler, _clean_payload())

    proxy_server, proxy_url = _serve_handler(proxy_handler)
    origin_server, origin_url = _serve_handler(
        lambda h: _send_json(h, _clean_payload())
    )
    try:
        result = _run_cli(
            origin_url,
            tmp_path,
            env_extra={
                "HTTP_PROXY": proxy_url,
                "HTTPS_PROXY": proxy_url,
                "http_proxy": proxy_url,
                "https_proxy": proxy_url,
                "ALL_PROXY": proxy_url,
            },
        )
    finally:
        proxy_server.shutdown()
        origin_server.shutdown()

    assert proxy_hits == [], "the configured proxy must never see the request"
    assert DECOY_KEY not in result.stdout
    assert DECOY_KEY not in result.stderr


@pytest.mark.parametrize(
    "base_url,error_class",
    [
        ("http://user:password@example.invalid", "base_url_contains_userinfo"),
        ("https://user:password@example.invalid", "base_url_contains_userinfo"),
        (
            "https://example.invalid/path?token=abc",
            "base_url_contains_query_or_fragment",
        ),
        ("https://example.invalid/#frag", "base_url_contains_query_or_fragment"),
        ("http://interlock.example.com", "insecure_base_url_scheme"),
        ("http://10.0.0.5:8001", "insecure_base_url_scheme"),
        ("ftp://example.invalid", "invalid_base_url_scheme"),
        ("file:///etc/passwd", "invalid_base_url_scheme"),
        ("https://", "invalid_base_url_host"),
        ("not-a-url", "invalid_base_url_scheme"),
    ],
)
def test_malformed_or_unsafe_base_urls_fail_closed(tmp_path, base_url, error_class):
    result = _run_cli(base_url, tmp_path)
    artifact, json_text, markdown = _artifacts(tmp_path)

    assert result.returncode == 2, (base_url, result.stderr)
    assert artifact["gate"]["outcome"] == "config_error"
    assert artifact["observation"]["error_class"] == error_class
    for blob in (json_text, markdown, result.stdout, result.stderr):
        assert DECOY_KEY not in blob


def test_loopback_http_is_the_documented_exception(tmp_path):
    server, url = _serve_handler(lambda h: _send_json(h, _clean_payload()))
    try:
        result = _run_cli(url, tmp_path)
    finally:
        server.shutdown()
    assert result.returncode == 0, (result.stdout, result.stderr)


# ── A2. Strict response contract ──────────────────────────────────────────────
def _mutate(**changes):
    payload = _clean_payload()
    payload.update(changes)
    return payload


MALFORMED_PAYLOADS = {
    "findings_is_string": _mutate(findings="nope"),
    "findings_entries_are_strings": _mutate(findings=["nope"]),
    "queue_entries_are_ints": _mutate(review_queue=[1, 2]),
    "server_is_string": _mutate(server="nope"),
    "observation_is_list": _mutate(observation=[]),
    "gate_is_list": _mutate(gate=[]),
    "empty_object": {"format_version": FORMAT},
    "unknown_outcome": _mutate(
        gate={"name": cbr.GATE_NAME, "outcome": "totally_fine", "exit_code": 0}
    ),
    "unknown_severity": _mutate(
        findings=[
            {
                "scope": "tool",
                "tool_ref": "t",
                "change_types": [],
                "severity": "cosmetic",
                "decision": "allow",
                "approved_tool_surface_hash": "",
                "observed_tool_surface_hash": "",
            }
        ]
    ),
    "unknown_decision": _mutate(
        findings=[
            {
                "scope": "tool",
                "tool_ref": "t",
                "change_types": [],
                "severity": "minor",
                "decision": "shrug",
                "approved_tool_surface_hash": "",
                "observed_tool_surface_hash": "",
            }
        ]
    ),
    "malformed_hash": _mutate(
        boundary={
            "approved_surface_hash": "not-a-hash",
            "observed_surface_hash": "",
            "matches_approved_surface": False,
            "approved_tool_count": 0,
            "observed_tool_count": 0,
        }
    ),
    "missing_evidence": _mutate(evidence={}),
    "missing_limitations": _mutate(limitations=[]),
    "bad_format_version": _mutate(format_version="interlock.ci-boundary-review/v99"),
}


@pytest.mark.parametrize("name", sorted(MALFORMED_PAYLOADS))
def test_malformed_responses_are_protocol_errors_with_artifacts(tmp_path, name):
    server, url = _serve_handler(lambda h: _send_json(h, MALFORMED_PAYLOADS[name]))
    try:
        result = _run_cli(url, tmp_path / name)
        artifact, _, _ = _artifacts(tmp_path / name)
    finally:
        server.shutdown()

    assert result.returncode == 4, (name, result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "protocol_error"
    assert "Traceback" not in result.stderr
    assert result.returncode != 1


@pytest.mark.parametrize(
    "body,status",
    [
        (b"<html>not json</html>", 200),
        (b'{"format_version": "interlock', 200),
        (b"[1,2,3]", 200),
        (b"null", 200),
    ],
)
def test_non_json_bodies_are_protocol_errors(tmp_path, body, status):
    def handler(h):
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)

    server, url = _serve_handler(handler)
    try:
        result = _run_cli(url, tmp_path)
        artifact, _, _ = _artifacts(tmp_path)
    finally:
        server.shutdown()

    assert result.returncode == 4
    assert artifact["gate"]["outcome"] == "protocol_error"
    assert "Traceback" not in result.stderr


def test_degenerate_clean_response_cannot_pass(tmp_path):
    """Well-typed but evidence-free: verified server, observed, no findings,
    yet no receipt and no surface hashes. Must never exit 0."""
    payload = _clean_payload()
    payload["evidence"]["receipt"]["audit_id"] = None
    payload["evidence"]["receipt"]["receipt_path"] = ""
    payload["boundary"]["approved_surface_hash"] = ""
    payload["boundary"]["observed_surface_hash"] = ""

    server, url = _serve_handler(lambda h: _send_json(h, payload))
    try:
        result = _run_cli(url, tmp_path)
        artifact, _, _ = _artifacts(tmp_path)
    finally:
        server.shutdown()

    assert result.returncode == 4
    assert artifact["gate"]["outcome"] == "protocol_error"
    assert artifact["observation"]["error_class"] == "incomplete_clean_response"


def test_unverified_evidence_chain_cannot_pass(tmp_path):
    payload = _clean_payload()
    payload["evidence"]["receipt"]["chain_verified"] = False
    server, url = _serve_handler(lambda h: _send_json(h, payload))
    try:
        result = _run_cli(url, tmp_path)
        artifact, _, _ = _artifacts(tmp_path)
    finally:
        server.shutdown()

    assert result.returncode == 22
    assert artifact["gate"]["outcome"] == "inconclusive"


def test_oversized_response_is_refused_not_written(tmp_path):
    payload = _clean_payload()
    payload["padding"] = "A" * (5 * 1024 * 1024)
    server, url = _serve_handler(lambda h: _send_json(h, payload))
    try:
        result = _run_cli(url, tmp_path)
        artifact, json_text, _ = _artifacts(tmp_path)
    finally:
        server.shutdown()

    assert result.returncode == 4
    assert artifact["observation"]["error_class"] == "response_too_large"
    assert len(json_text) < 100_000, "an oversized response must not become an artifact"


def test_conflicting_idempotency_key_is_reported_as_auth_error(tmp_path):
    def handler(h):
        _send_json(
            h,
            {"detail": {"error": "idempotency_key_conflict", "message": "x"}},
            status=409,
        )

    server, url = _serve_handler(handler)
    try:
        result = _run_cli(url, tmp_path)
        artifact, _, _ = _artifacts(tmp_path)
    finally:
        server.shutdown()

    assert result.returncode == 3
    assert artifact["observation"]["error_class"] == "idempotency_key_conflict"


def test_review_in_progress_is_inconclusive(tmp_path):
    def handler(h):
        _send_json(
            h, {"detail": {"error": "review_in_progress", "message": "x"}}, status=409
        )

    server, url = _serve_handler(handler)
    try:
        result = _run_cli(url, tmp_path)
        artifact, _, _ = _artifacts(tmp_path)
    finally:
        server.shutdown()

    assert result.returncode == 22
    assert artifact["observation"]["error_class"] == "review_in_progress"


def test_hostile_server_id_argument_is_sanitized_in_error_artifacts(tmp_path):
    def handler(h):
        _send_json(h, {"detail": "nope"}, status=403)

    server, url = _serve_handler(handler)
    hostile = "<img src=x onerror=alert(1)>|forged|\n| row | row |../../etc/passwd"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["INTERLOCK_BASE_URL"] = url
    env["INTERLOCK_CI_API_KEY"] = DECOY_KEY
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(GATE_SCRIPT),
                "--server-id",
                hostile,
                "--output-dir",
                str(tmp_path),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        server.shutdown()

    artifact, json_text, markdown = _artifacts(tmp_path)
    assert result.returncode == 3
    ref = artifact["server"]["server_ref"]
    for bad in ("<", ">", "|", "\n", "..", "/", "&"):
        assert bad not in ref, (bad, ref)
    # The tag characters and the attribute form are gone; the surviving
    # letters are inert text, which is exactly what sanitization should leave.
    assert "<" not in markdown and ">" not in markdown
    assert "<img" not in json_text
    assert "onerror=" not in markdown and "onerror=" not in json_text
    assert "/etc/passwd" not in json_text
    assert not any(line.strip().startswith("| row") for line in markdown.splitlines())


def test_normal_server_id_is_digest_only_on_every_cli_surface(tmp_path):
    raw_id = "billing-mcp"

    def handler(h):
        _send_json(h, {"detail": "nope"}, status=403)

    server, url = _serve_handler(handler)
    try:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        env["INTERLOCK_BASE_URL"] = url
        env["INTERLOCK_CI_API_KEY"] = DECOY_KEY
        result = subprocess.run(
            [
                sys.executable,
                str(GATE_SCRIPT),
                "--server-id",
                raw_id,
                "--output-dir",
                str(tmp_path),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        server.shutdown()
    artifact, json_text, markdown = _artifacts(tmp_path)
    assert artifact["server"] == {
        "registered": None,
        "server_ref": cbr.opaque_ref(raw_id),
    }
    assert raw_id not in json_text + markdown + result.stdout + result.stderr


def test_docs_example_is_mechanically_validated_against_artifact_shape():
    doc = (ROOT / "docs" / "integrations" / "ci-boundary-review-gate.md").read_text(
        encoding="utf-8"
    )
    block = doc.split("### Example (synthetic placeholders)", 1)[1]
    example = json.loads(block.split("```json", 1)[1].split("```", 1)[0])
    gate = _load_gate_module()
    gate.validate_review(example)
    assert set(example) == set(_clean_payload())
    assert "server_id" not in example["server"]


def test_foreign_credential_shaped_argv_is_never_echoed(tmp_path):
    foreign = "ghp_FOREIGN_CREDENTIAL_FORMAT_abcdefghijklmnopqrstuvwxyz"
    env = dict(os.environ)
    env["INTERLOCK_CI_API_KEY"] = DECOY_KEY
    result = subprocess.run(
        [
            sys.executable,
            str(GATE_SCRIPT),
            "--server-id",
            "billing-mcp",
            "--output-dir",
            str(tmp_path),
            "--api-key",
            foreign,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2
    assert foreign not in result.stdout + result.stderr


# ── Live-deployment hardening ─────────────────────────────────────────────────
@pytest.fixture
def live(tmp_path_factory):
    root = tmp_path_factory.mktemp("hardening")
    prior_db_path = db.DB_PATH
    db.DB_PATH = str(Path(root) / "hardening.db")
    db.init_db()
    proxy._key_record_cache.clear()
    proxy._usage_cache.clear()

    state: Dict[str, Any] = {"tools": copy.deepcopy(BASE_TOOLS), "mode": "ok"}
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
        for server_id in HARDENING_SERVER_IDS:
            db.register_mcp_server(
                server_id,
                {
                    "url": f"{upstream_url}/mcp",
                    "description": "hardening fixture",
                    "allowed_tools": ["read_document", "list_documents"],
                    "blocked_tools": [],
                    "environment": "non_production",
                },
            )
            db.verify_mcp_server(server_id)
            for tool in BASE_TOOLS:
                db.upsert_mcp_tool_metadata(
                    server_id, tool, normalize_tool_metadata(tool)
                )
        # A tool the gateway is DENYING right now (high drift, not quarantine).
        with db.get_conn() as conn:
            conn.execute(
                "UPDATE mcp_tool_metadata SET status = 'changed', "
                "drift_severity = 'high', drift_action = 'deny' "
                "WHERE server_id = ? AND tool_name = 'read_document'",
                (DENY_SERVER_ID,),
            )

        ci_key = db.generate_key(
            "developer", label="hardening-ci", scopes=["mcp.review"]
        )["raw_key"]
        other_key = db.generate_key(
            "developer", label="hardening-other", scopes=["mcp.review"]
        )["raw_key"]

        with _serve(proxy.app) as base_url:
            yield {
                "base_url": base_url,
                "state": state,
                "ci_key": ci_key,
                "other_key": other_key,
            }

    for server_id in HARDENING_SERVER_IDS:
        db.unregister_mcp_server(server_id)
    proxy._key_record_cache.clear()
    proxy._usage_cache.clear()
    db.DB_PATH = prior_db_path


def _review_url(live, server_id=SERVER_ID):
    return f"{live['base_url']}/mcp/servers/{server_id}/boundary-review"


def _gate(live, output_dir, server_id=SERVER_ID, *extra, key=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["INTERLOCK_BASE_URL"] = live["base_url"]
    env["INTERLOCK_CI_API_KEY"] = key or live["ci_key"]
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


# ── B4. HTTP semantics ────────────────────────────────────────────────────────
def test_review_is_post_only_with_no_store_headers(live):
    url = _review_url(live)
    get_response = httpx.get(url, timeout=30)
    assert get_response.status_code == 405, "the side-effecting review must not be GET"

    post_response = httpx.post(url, headers={"x-api-key": live["ci_key"]}, timeout=60)
    assert post_response.status_code == 200
    assert post_response.headers["cache-control"].startswith("no-store")
    assert post_response.headers["pragma"] == "no-cache"
    assert post_response.headers["expires"] == "0"
    vary = post_response.headers["vary"].lower()
    assert "x-api-key" in vary and "authorization" in vary


def test_request_body_cannot_supply_baseline_identity_or_decision(live):
    """The route ignores any body: server state decides everything."""
    hostile_body = {
        "server_id": "someone-else",
        "reviewer": "attacker",
        "principal_id": "attacker",
        "approved_surface_hash": "sha256:" + "0" * 64,
        "gate": {"outcome": "clean"},
        "evidence": {"receipt": {"chain_verified": True}},
        "findings": [],
    }
    response = httpx.post(
        _review_url(live, DENY_SERVER_ID),
        headers={"x-api-key": live["ci_key"]},
        json=hostile_body,
        timeout=60,
    )
    assert response.status_code == 200
    review = response.json()
    assert review["gate"]["outcome"] == "quarantined"
    assert review["server"]["server_ref"].startswith("sha256:")
    assert DENY_SERVER_ID not in json.dumps(review)
    assert "attacker" not in json.dumps(review)


# ── B4. Idempotency ───────────────────────────────────────────────────────────
KEY_A = "a" * 48
KEY_B = "b" * 48


def _audit_count():
    return len(db.list_mcp_audit_logs(2000))


def _snapshot_count():
    with db.get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM tool_surface_snapshots").fetchone()
    return int(row[0] if not isinstance(row, dict) else row["count"])


def _persistence_counts():
    with db.get_conn() as conn:
        tables = (
            "mcp_audit_log",
            "tool_surface_snapshots",
            "ci_review_idempotency",
            "audit_chain_checkpoints",
        )
        return tuple(
            int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        )


def _unique_drift_surface(marker):
    tool = copy.deepcopy(DRIFTED_READ_DOCUMENT)
    tool["description"] = f"Unique atomicity drift {marker}"
    tool["inputSchema"]["properties"][f"atomicity_{marker}"] = {"type": "string"}
    return [tool, copy.deepcopy(LIST_DOCUMENTS)]


@pytest.mark.parametrize(
    "failure_mode,idempotency_key",
    [
        ("verifier_false", "vf" * 24),
        ("verifier_exception", "ve" * 24),
        ("append_failure", "af" * 24),
        ("commit_failure", "cf" * 24),
    ],
)
def test_receipt_transaction_failure_writes_nothing_and_same_key_retries(
    live, monkeypatch, failure_mode, idempotency_key
):
    live["state"]["tools"] = _unique_drift_surface(failure_mode)
    headers = {
        "x-api-key": live["ci_key"],
        "idempotency-key": idempotency_key,
    }
    before = _persistence_counts()
    assert before == (0, 0, 0, 0)

    with monkeypatch.context() as injected:
        if failure_mode == "verifier_false":
            injected.setattr(
                db,
                "_verify_mcp_audit_record_on_conn",
                lambda *args, **kwargs: {
                    "chain_verified": False,
                    "reason": "forced",
                },
            )
        elif failure_mode == "verifier_exception":

            def fail_verifier(*args, **kwargs):
                raise RuntimeError("forced verifier exception")

            injected.setattr(db, "_verify_mcp_audit_record_on_conn", fail_verifier)
        elif failure_mode == "append_failure":

            def fail_append(*args, **kwargs):
                raise RuntimeError("forced append failure")

            injected.setattr(db, "_append_mcp_audit_event", fail_append)
        else:

            def fail_commit(*args, **kwargs):
                raise RuntimeError("forced commit failure")

            injected.setattr(db, "_commit_verified_mcp_audit_transaction", fail_commit)

        failed = httpx.post(_review_url(live), headers=headers, timeout=60)

    assert failed.status_code == 200
    failed_artifact = failed.json()
    assert failed.headers.get("idempotent-replay") is None
    assert failed_artifact["gate"]["outcome"] == "inconclusive"
    assert failed_artifact["gate"]["exit_code"] == 22
    assert failed_artifact["evidence"]["receipt"]["audit_id"] is None
    assert _persistence_counts() == before

    retry = httpx.post(_review_url(live), headers=headers, timeout=60)
    assert retry.status_code == 200
    assert retry.headers.get("idempotent-replay") is None
    retry_artifact = retry.json()
    assert retry_artifact["evidence"]["receipt"]["chain_verified"] is True
    after_retry = _persistence_counts()
    assert after_retry == (1, 2, 1, 0)

    replay = httpx.post(_review_url(live), headers=headers, timeout=60)
    assert replay.headers.get("idempotent-replay") == "true"
    assert replay.json() == retry_artifact
    assert _persistence_counts() == after_retry


def test_repeated_idempotency_key_replays_without_new_evidence(live):
    live["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
    headers = {"x-api-key": live["ci_key"], "idempotency-key": KEY_A}

    audits_before = _audit_count()
    first = httpx.post(_review_url(live), headers=headers, timeout=60)
    audits_after_first = _audit_count()
    snapshots_after_first = _snapshot_count()

    second = httpx.post(_review_url(live), headers=headers, timeout=60)
    third = httpx.post(_review_url(live), headers=headers, timeout=60)

    assert first.status_code == second.status_code == third.status_code == 200
    assert second.headers.get("idempotent-replay") == "true"
    assert third.headers.get("idempotent-replay") == "true"
    assert second.json() == first.json()
    assert third.json() == first.json()
    assert audits_after_first == audits_before + 1
    assert _audit_count() == audits_after_first, "a replay must append no audit row"
    assert _snapshot_count() == snapshots_after_first


def test_verified_upstream_inconclusive_result_is_idempotently_replayable(live):
    live["state"]["mode"] = "http_500"
    headers = {
        "x-api-key": live["ci_key"],
        "idempotency-key": "ui" * 24,
    }
    assert _persistence_counts() == (0, 0, 0, 0)

    first = httpx.post(_review_url(live), headers=headers, timeout=60)
    assert first.status_code == 200
    artifact = first.json()
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["evidence"]["receipt"]["chain_verified"] is True
    assert _persistence_counts() == (1, 0, 1, 0)

    replay = httpx.post(_review_url(live), headers=headers, timeout=60)
    assert replay.headers.get("idempotent-replay") == "true"
    assert replay.json() == artifact
    assert _persistence_counts() == (1, 0, 1, 0)


def test_idempotency_key_reused_under_another_identity_or_server_fails_closed(live):
    headers = {"x-api-key": live["ci_key"], "idempotency-key": KEY_B}
    first = httpx.post(_review_url(live), headers=headers, timeout=60)
    assert first.status_code == 200

    other_identity = httpx.post(
        _review_url(live),
        headers={"x-api-key": live["other_key"], "idempotency-key": KEY_B},
        timeout=60,
    )
    other_server = httpx.post(
        _review_url(live, DENY_SERVER_ID),
        headers={"x-api-key": live["ci_key"], "idempotency-key": KEY_B},
        timeout=60,
    )

    assert other_identity.status_code == 409
    assert other_identity.json()["detail"]["error"] == "idempotency_key_conflict"
    assert other_server.status_code == 409
    assert other_server.json()["detail"]["error"] == "idempotency_key_conflict"
    assert live["ci_key"] not in other_identity.text


@pytest.mark.parametrize(
    "value", ["short", "x" * 200, "has spaces in it" + "y" * 40, "bad/chars" + "z" * 40]
)
def test_malformed_idempotency_keys_fail_closed(live, value):
    response = httpx.post(
        _review_url(live),
        headers={"x-api-key": live["ci_key"], "idempotency-key": value},
        timeout=60,
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_idempotency_key"


def test_duplicate_idempotency_headers_fail_closed(live):
    response = httpx.post(
        _review_url(live),
        headers=[
            ("x-api-key", live["ci_key"]),
            ("idempotency-key", KEY_A),
            ("idempotency-key", KEY_B),
        ],
        timeout=60,
    )
    assert response.status_code == 400


def test_the_raw_idempotency_key_is_never_persisted(live):
    httpx.post(
        _review_url(live),
        headers={"x-api-key": live["ci_key"], "idempotency-key": KEY_A},
        timeout=60,
    )
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT key_digest, principal_binding, server_id FROM ci_review_idempotency"
        ).fetchall()
    blob = str([tuple(r) if not isinstance(r, dict) else r for r in rows])
    assert KEY_A not in blob
    assert db.hash_idempotency_key(KEY_A) in blob


def test_expired_idempotency_rows_are_pruned(live):
    digest = db.hash_idempotency_key(KEY_A)
    db.reserve_ci_review_idempotency(digest, "binding", SERVER_ID, 60)
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE ci_review_idempotency SET expires_at = ? WHERE key_digest = ?",
            ("1999-01-01T00:00:00+00:00", digest),
        )
    # Any later reservation prunes expired rows first, so the key is free again.
    result = db.reserve_ci_review_idempotency(
        digest, "different-binding", SERVER_ID, 60
    )
    assert result["outcome"] == "reserved"
    db.release_ci_review_idempotency(digest)


# ── B3. Denied states never pass ──────────────────────────────────────────────
@pytest.mark.parametrize("policy", ["material", "any-finding", "quarantine-only"])
def test_enforced_deny_never_exits_zero_under_any_policy(live, tmp_path, policy):
    result = _gate(live, tmp_path / policy, DENY_SERVER_ID, "--fail-policy", policy)
    artifact, _, _ = _artifacts(tmp_path / policy)

    assert result.returncode == 21, (policy, result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "quarantined"
    queue = artifact["review_queue"]
    assert any(
        entry["decision"] == "deny" and entry["enforced_now"] is True for entry in queue
    )


def test_unknown_gateway_outcome_fails_closed(tmp_path):
    payload = _clean_payload()
    payload["gate"]["outcome"] = "definitely_fine"
    server, url = _serve_handler(lambda h: _send_json(h, payload))
    try:
        result = _run_cli(url, tmp_path)
        artifact, _, _ = _artifacts(tmp_path)
    finally:
        server.shutdown()
    assert result.returncode == 4
    assert artifact["gate"]["outcome"] == "protocol_error"


# ── B5. Snapshot coherence ────────────────────────────────────────────────────
def test_concurrent_rebaseline_promotion_yields_inconclusive_not_incoherence(live):
    """The former defect: a promotion landing mid-review produced an artifact
    claiming matches_approved_surface=true alongside high-severity findings."""
    live["state"]["tools"] = [DRIFTED_READ_DOCUMENT, LIST_DOCUMENTS]
    validated = [
        {
            "tool": tool,
            "normalized_metadata": validate_mcp_tool_definition(tool).tool_metadata,
        }
        for tool in live["state"]["tools"]
    ]
    before_hash = db.get_active_baseline(SERVER_ID)["surface_hash"]

    real_snapshot = db.get_boundary_review_snapshot
    gate_event = threading.Event()
    calls = {"n": 0}

    def slow_snapshot(server_id):
        calls["n"] += 1
        if calls["n"] == 1:
            result = real_snapshot(server_id)
            gate_event.set()
            time.sleep(1.2)
            return result
        return real_snapshot(server_id)

    def promote():
        gate_event.wait(15)
        db.save_rebaseline_candidate(SERVER_ID, validated, "race-operator")
        candidate = db.get_rebaseline_candidate(SERVER_ID)["candidate_surface_hash"]
        db.promote_rebaseline_candidate(
            SERVER_ID,
            before_hash,
            candidate,
            actor={"reviewer": "op", "principal_id": "op"},
        )

    db.get_boundary_review_snapshot = slow_snapshot
    worker = threading.Thread(target=promote, daemon=True)
    worker.start()
    try:
        review = asyncio.run(
            cbr.run_boundary_review(
                SERVER_ID, principal={"reviewer": "t", "principal_id": "t"}
            )
        )
    finally:
        worker.join(30)
        db.get_boundary_review_snapshot = real_snapshot

    assert review["observation"]["status"] == "superseded"
    assert review["observation"]["error_class"] == "snapshot_changed_during_review"
    assert review["gate"]["outcome"] == "inconclusive"
    assert review["gate"]["exit_code"] == 22
    assert review["findings"] == [], "stale findings must not be published"
    assert review["boundary"]["matches_approved_surface"] is False
    assert not (
        review["boundary"]["matches_approved_surface"] and review["findings"]
    ), "artifact must never claim a match alongside findings"


def test_snapshot_version_is_reported_and_stable_when_nothing_changes(live):
    first = asyncio.run(
        cbr.run_boundary_review(
            SERVER_ID, principal={"reviewer": "t", "principal_id": "t"}
        )
    )
    second = asyncio.run(
        cbr.run_boundary_review(
            SERVER_ID, principal={"reviewer": "t", "principal_id": "t"}
        )
    )
    assert first["boundary"]["snapshot_version"].startswith("sha256:")
    assert (
        first["boundary"]["snapshot_version"] == second["boundary"]["snapshot_version"]
    )


# ── C6. Caps ──────────────────────────────────────────────────────────────────
def test_too_many_advertised_tools_is_inconclusive_and_writes_no_snapshots(
    live, tmp_path, monkeypatch
):
    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", "5")
    live["state"]["tools"] = [
        dict(
            READ_DOCUMENT,
            name=f"tool_{index}",
            inputSchema={
                "type": "object",
                "properties": {f"f{index}": {"type": "string"}},
            },
        )
        for index in range(50)
    ]
    snapshots_before = _snapshot_count()

    result = _gate(live, tmp_path)
    artifact, _, _ = _artifacts(tmp_path)

    assert result.returncode == 22
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert "max_observed_tools" in artifact["caps"]["exceeded"]
    assert artifact["observation"]["error_class"] == "observed_surface_too_large"
    assert _snapshot_count() == snapshots_before


def test_oversized_upstream_body_is_inconclusive(live, tmp_path, monkeypatch):
    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_MAX_RESPONSE_BYTES", "2048")
    live["state"]["tools"] = [
        dict(READ_DOCUMENT, name=f"tool_{index}", description="x" * 400)
        for index in range(40)
    ]
    result = _gate(live, tmp_path)
    artifact, _, _ = _artifacts(tmp_path)

    assert result.returncode == 22
    assert artifact["observation"]["error_class"] == "upstream_response_too_large"
    assert "max_response_bytes" in artifact["caps"]["exceeded"]


def test_findings_cap_bounds_artifact_and_snapshot_writes(live, tmp_path, monkeypatch):
    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_MAX_FINDINGS", "3")
    live["state"]["tools"] = [
        dict(
            READ_DOCUMENT,
            name=f"tool_{index}",
            inputSchema={
                "type": "object",
                "properties": {f"f{index}": {"type": "string"}},
            },
        )
        for index in range(30)
    ] + [READ_DOCUMENT, LIST_DOCUMENTS]
    snapshots_before = _snapshot_count()

    result = _gate(live, tmp_path)
    artifact, _, _ = _artifacts(tmp_path)

    assert result.returncode != 0
    assert result.returncode in (21, 22), result.stdout
    assert "max_findings" in artifact["caps"]["exceeded"]
    assert len(artifact["findings"]) <= 3
    # Worst-first ordering means truncation can never drop the worst finding.
    assert artifact["findings"][0]["severity"] in ("high", "critical")
    assert (
        _snapshot_count() == snapshots_before
    ), "a capped review must retain no surface snapshots"


def test_a_breached_cap_alone_is_inconclusive():
    """Cap precedence in isolation: no held finding, nothing observed wrong,
    but a cap was breached -> inconclusive, never clean."""
    review = {
        "findings": [],
        "review_queue": [],
        "observation": {"status": "observed"},
        "server": {"verified": True},
        "caps": {"exceeded": ["max_findings"]},
        "evidence": {"receipt": {"chain_verified": True}},
    }
    for policy in cbr.FAIL_POLICIES:
        assert cbr.compute_outcome(review, policy) == "inconclusive"
        assert cbr.exit_code_for(cbr.compute_outcome(review, policy)) == 22


def test_cap_configuration_is_validated_and_fails_closed(monkeypatch):
    """An explicitly configured but unusable limit raises instead of silently
    substituting a different one. Unset still means the documented default."""
    from config import (
        BOUNDARY_REVIEW_MAX_TOOLS_CEILING,
        ConfigurationError,
        boundary_review_max_tools,
        boundary_review_timeout_seconds,
    )

    monkeypatch.delenv("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", raising=False)
    monkeypatch.delenv("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", raising=False)
    assert boundary_review_max_tools() == 200
    assert boundary_review_timeout_seconds() == 10.0

    for bad in ("not-a-number", "-5", str(BOUNDARY_REVIEW_MAX_TOOLS_CEILING + 1)):
        monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", bad)
        with pytest.raises(ConfigurationError):
            boundary_review_max_tools()
    monkeypatch.delenv("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", raising=False)

    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "0")
    with pytest.raises(ConfigurationError):
        boundary_review_timeout_seconds()

    # A valid explicit value is honored, not clamped away.
    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", "37")
    assert boundary_review_max_tools() == 37


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("audit_id", 0),
        ("audit_id", -1),
        ("hash_chained", False),
        ("tamper_evident", False),
        ("chain_verified", False),
        ("externally_signed", True),
        ("independently_anchored", True),
    ],
)
def test_pass_evidence_contract_rejects_invalid_or_contradictory_receipts(
    field, bad_value
):
    gate = _load_gate_module()
    review = _clean_payload()
    review["evidence"]["receipt"][field] = bad_value
    with pytest.raises(gate.SchemaError):
        gate.require_evidence_for_pass(review)


def test_every_enforced_limit_is_reported_in_artifact_caps(live):
    response = httpx.post(
        _review_url(live), headers={"x-api-key": live["ci_key"]}, timeout=60
    )
    assert response.status_code == 200
    assert {
        "timeout_seconds",
        "max_response_bytes",
        "max_request_bytes",
        "max_observed_tools",
        "max_findings",
        "idempotency_ttl_seconds",
        "exceeded",
    } <= set(response.json()["caps"])


def test_audit_append_failure_returns_inconclusive_without_claiming_receipt(
    live, monkeypatch
):
    before = _audit_count()

    def fail_append(*args, **kwargs):
        raise RuntimeError("forced append failure")

    monkeypatch.setattr(db, "log_verified_mcp_audit_event", fail_append)
    response = httpx.post(
        _review_url(live), headers={"x-api-key": live["ci_key"]}, timeout=60
    )
    assert response.status_code == 200
    artifact = response.json()
    receipt = artifact["evidence"]["receipt"]
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["gate"]["exit_code"] == 22
    assert receipt["audit_id"] is None
    assert receipt["receipt_path"] == ""
    assert receipt["hash_chained"] is False
    assert receipt["chain_verified"] is False
    assert receipt["tamper_evident"] is False
    assert receipt["receipt_verification_state"] == "append_failed"
    assert artifact["gate"]["boundary_review_semantic_outcome"] == "clean"
    assert artifact["gate"]["boundary_review_final_outcome"] == "inconclusive"
    assert artifact["gate"]["boundary_review_final_exit_code"] == 22
    assert _audit_count() == before


def test_chain_verification_failure_returns_inconclusive_without_valid_receipt(
    live, monkeypatch
):
    before = _audit_count()
    monkeypatch.setattr(
        db,
        "_verify_mcp_audit_record_on_conn",
        lambda *args, **kwargs: {"chain_verified": False, "reason": "forced"},
    )
    response = httpx.post(
        _review_url(live), headers={"x-api-key": live["ci_key"]}, timeout=60
    )
    assert response.status_code == 200
    artifact = response.json()
    receipt = artifact["evidence"]["receipt"]
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["gate"]["exit_code"] == 22
    assert receipt["audit_id"] is None
    assert receipt["receipt_path"] == ""
    assert receipt["hash_chained"] is False
    assert receipt["chain_verified"] is False
    assert receipt["tamper_evident"] is False
    assert receipt["receipt_verification_state"] == "failed"
    assert artifact["gate"]["boundary_review_semantic_outcome"] == "clean"
    assert artifact["gate"]["boundary_review_final_outcome"] == "inconclusive"
    assert artifact["gate"]["boundary_review_final_exit_code"] == 22
    assert _audit_count() == before


def test_chain_verifier_exception_rolls_back_and_returns_inconclusive(
    live, monkeypatch
):
    before = _audit_count()

    def fail_verification(*args, **kwargs):
        raise RuntimeError("forced verifier exception")

    monkeypatch.setattr(db, "_verify_mcp_audit_record_on_conn", fail_verification)
    response = httpx.post(
        _review_url(live), headers={"x-api-key": live["ci_key"]}, timeout=60
    )
    assert response.status_code == 200
    artifact = response.json()
    receipt = artifact["evidence"]["receipt"]
    assert artifact["gate"]["outcome"] == "inconclusive"
    assert artifact["gate"]["exit_code"] == 22
    assert artifact["gate"]["boundary_review_semantic_outcome"] == "clean"
    assert artifact["gate"]["boundary_review_final_outcome"] == "inconclusive"
    assert receipt["audit_id"] is None
    assert receipt["hash_chained"] is False
    assert receipt["chain_verified"] is False
    assert receipt["receipt_verification_state"] == "failed"
    assert _audit_count() == before


# ── D7. Identifier sanitization on the deployment side ────────────────────────
def test_hostile_registered_server_id_is_sanitized_in_the_artifact(live, tmp_path):
    result = _gate(live, tmp_path, HOSTILE_SERVER_ID)
    artifact, json_text, markdown = _artifacts(tmp_path)

    assert result.returncode in (0, 20, 21, 22)
    ref = artifact["server"]["server_ref"]
    for bad in ("<", ">", "|", "&", "..", '"', " "):
        assert bad not in ref, (bad, ref)
    assert "server_id" not in artifact["server"]
    assert "<" not in markdown and ">" not in markdown
    assert "<img" not in json_text
    assert "onerror=" not in markdown and "onerror=" not in json_text
    assert HOSTILE_SERVER_ID not in json_text
    assert HOSTILE_SERVER_ID not in markdown


# ── E9. Strict Bearer parsing ─────────────────────────────────────────────────
@pytest.mark.parametrize(
    "header_value",
    [
        "Bearer Bearer {key}",
        "Basic {key}",
        "Bearer",
        "Bearer  {key}  extra",
        "{key}",
        "Token {key}",
    ],
)
def test_non_conforming_authorization_headers_fail_closed(live, header_value):
    value = header_value.format(key=live["ci_key"])
    response = httpx.post(
        _review_url(live), headers={"authorization": value}, timeout=30
    )
    assert response.status_code == 401, value
    assert live["ci_key"] not in response.text


def test_exactly_one_bearer_token_is_accepted(live):
    response = httpx.post(
        _review_url(live),
        headers={"authorization": f"Bearer {live['ci_key']}"},
        timeout=60,
    )
    assert response.status_code == 200


def test_whitespace_only_api_key_header_fails_closed(live):
    """Sent over a raw socket: httpx refuses to transmit this header, but a
    hostile client will, and the server must still fail closed."""
    import socket as _socket
    from urllib.parse import urlsplit

    crlf = "\r\n"
    parts = urlsplit(live["base_url"])
    request = crlf.join(
        [
            f"POST /mcp/servers/{SERVER_ID}/boundary-review HTTP/1.1",
            f"Host: {parts.hostname}:{parts.port}",
            "X-API-Key:   ",
            "Content-Length: 0",
            "Connection: close",
            "",
            "",
        ]
    ).encode("ascii")
    with _socket.create_connection((parts.hostname, parts.port), timeout=15) as sock:
        sock.sendall(request)
        status_line = sock.recv(128).split(crlf.encode(), 1)[0]
    assert b" 401 " in status_line, status_line
