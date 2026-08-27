"""Evidence-grade LiveKit Agents integration tests.

These tests use the real LiveKit MCPToolset and MCP SDK transport. The primary
acceptance test starts real loopback processes; it does not replace the runtime
path with mocks.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback
from typing import Any

import httpx
import pytest

from examples.livekit_agents import run_proof as proof_runner

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "livekit_agents"
LIVEKIT_COMMIT = "06c71f9c718e24a151630447755a9fa86851b389"
INTERLOCK_BASE_SHA = "a78d5a0a4557a63f0db71e41a70d451c03bb13bb"
SEEDED_CREDENTIALS = {
    "OPENAI_API_KEY": "seed-openai-must-not-reach-child",
    "AWS_ACCESS_KEY_ID": "seed-aws-id-must-not-reach-child",
    "AWS_SECRET_ACCESS_KEY": "seed-aws-secret-must-not-reach-child",
    "SSH_AUTH_SOCK": "seed-ssh-agent-must-not-reach-child",
    "SESSION_COOKIE": "seed-session-cookie-must-not-reach-child",
    "AUTHORIZATION": "Bearer seed-authorization-must-not-reach-child",
    "HTTP_PROXY": "http://seed-user:seed-pass@127.0.0.1:9",
}


class CredentialSafeMapping(dict[str, Any]):
    """Keep pytest argument rendering from exposing keys or inherited secrets."""

    def __repr__(self) -> str:
        return "<credential-safe LiveKit proof mapping>"


@pytest.fixture(autouse=True)
def cleanup_livekit_fixture_servers() -> Any:
    """Run before the repository-wide fixture leak assertion."""
    yield
    db = sys.modules.get("core.db")
    if db is None:
        return
    for server in db.list_mcp_servers():
        server_id = str(server.get("server_id") or "")
        if server_id.startswith("_fixture_livekit_"):
            db.unregister_mcp_server(server_id)


@pytest.fixture(scope="module")
def live_services(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    work = tmp_path_factory.mktemp("livekit-proof-services")
    db_path = work / "failure-paths.db"
    key = proof_runner._initialize_database(db_path)
    interlock_port = proof_runner._available_port()
    synthetic_port = proof_runner._available_port()
    interlock_url = f"http://127.0.0.1:{interlock_port}"
    synthetic_url = f"http://127.0.0.1:{synthetic_port}"
    env = proof_runner._child_environment(db_path)
    children = proof_runner.OwnedProcesses()
    synthetic = children.start(
        [
            sys.executable,
            str(EXAMPLE / "synthetic_server.py"),
            "--port",
            str(synthetic_port),
        ],
        env=env,
    )
    interlock = children.start(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "proxy:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(interlock_port),
            "--log-level",
            "warning",
        ],
        env=env,
    )

    async def wait_for_services() -> None:
        await asyncio.gather(
            proof_runner._wait_healthy(synthetic_url, synthetic),
            proof_runner._wait_healthy(interlock_url, interlock),
        )

    try:
        asyncio.run(wait_for_services())
    except Exception:
        children.stop_all()
        raise
    yield CredentialSafeMapping(
        {
            "key": key,
            "env": CredentialSafeMapping(env),
            "interlock_url": interlock_url,
            "synthetic_url": synthetic_url,
        }
    )
    children.stop_all()
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(db_path) + suffix)
        if candidate.exists():
            candidate.unlink()


def _request(
    services: dict[str, Any],
    method: str,
    path: str,
    *,
    synthetic: bool = False,
    api_key: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    base = services["synthetic_url"] if synthetic else services["interlock_url"]
    headers = dict(kwargs.pop("headers", {}) or {})
    key = services["key"] if api_key is None and not synthetic else api_key
    if key:
        headers["x-api-key"] = key
    response = httpx.request(
        method, f"{base}{path}", headers=headers, timeout=40, **kwargs
    )
    assert response.status_code == 200, response.status_code
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


def _register_clean(
    services: dict[str, Any],
    server_id: str,
    *,
    include_second_tool: bool = False,
) -> None:
    _request(
        services,
        "POST",
        "/control/reset",
        synthetic=True,
        params={"include_second_tool": str(include_second_tool).lower()},
    )
    tools = (
        ["read_customer", "read_region"] if include_second_tool else ["read_customer"]
    )
    registered = _request(
        services,
        "POST",
        "/mcp/servers",
        json={
            "server_id": server_id,
            "url": f"{services['synthetic_url']}/mcp",
            "allowed_tools": tools,
            "blocked_tools": [],
            "upstream_protocol_profile": "2026-07-28",
            "environment": "non_production",
        },
    )
    assert registered["ok"] is True
    _request(services, "POST", f"/mcp/servers/{server_id}/verify")
    discovered = _request(
        services,
        "POST",
        "/mcp/discover",
        json={
            "server_url": f"{services['synthetic_url']}/mcp",
            "server_id": server_id,
        },
    )
    assert discovered["ok"] is True
    review_tools = _request(
        services,
        "GET",
        "/mcp/tools",
        params={"server_id": server_id},
    )["tools"]
    review_hashes = {
        item["tool_name"]: item["review_surface_hash"] for item in review_tools
    }
    for tool in tools:
        _request(
            services,
            "POST",
            f"/mcp/tools/{server_id}/{tool}/approve",
            json={
                "expected_surface_hash": review_hashes[tool],
                "reason": "Approved synthetic test boundary.",
            },
        )


def _adapter_env(
    services: dict[str, Any],
    server_id: str,
    *,
    key: str | None = None,
    tools: str = "read_customer",
) -> dict[str, str]:
    env: dict[str, str] = CredentialSafeMapping(services["env"])
    env.update(
        {
            "INTERLOCK_API_URL": services["interlock_url"],
            "INTERLOCK_SERVER_ID": server_id,
            "INTERLOCK_TOOL_NAMES": tools,
        }
    )
    if key is not None:
        env["INTERLOCK_API_KEY"] = key
    else:
        env.pop("INTERLOCK_API_KEY", None)
    return env


async def _livekit_setup_or_call(
    env: dict[str, str],
    *,
    script: Path | None = None,
    timeout: float = 5.0,
    tool_name: str | None = None,
    arguments: dict[str, Any] | None = None,
) -> tuple[list[str], Any]:
    from livekit.agents.llm.mcp import MCPServerStdio, MCPToolset

    server = MCPServerStdio(
        command=sys.executable,
        args=[str(script or (EXAMPLE / "adapter.py"))],
        env=env,
        cwd=ROOT,
        client_session_timeout_seconds=timeout,
    )
    toolset = MCPToolset(id="failure-path-toolset", mcp_server=server)
    try:
        await toolset.setup()
        names = [tool.id for tool in toolset.tools]
        if tool_name is None:
            return names, None
        tool = next(item for item in toolset.tools if item.id == tool_name)
        return names, await tool(arguments or {})
    finally:
        with suppress(Exception):
            await toolset.aclose()


def test_pinned_livekit_and_mcp_versions_are_exact() -> None:
    declaration = (EXAMPLE / "requirements-pinned.txt").read_text(encoding="utf-8")

    assert LIVEKIT_COMMIT in declaration
    assert "mcp==1.28.1" in declaration
    assert not (EXAMPLE / "requirements.lock").exists()


def test_interlock_base_allows_a_descendant_integration_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descendant_head = "b" * 40
    monkeypatch.setattr(
        proof_runner,
        "_command_version",
        lambda command: descendant_head,
    )

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert command == [
            "git",
            "merge-base",
            "--is-ancestor",
            INTERLOCK_BASE_SHA,
            descendant_head,
        ]
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(proof_runner.subprocess, "run", fake_run)
    provenance = proof_runner._interlock_provenance()

    assert provenance == {
        "interlock_base_sha": INTERLOCK_BASE_SHA,
        "integration_head_sha": descendant_head,
        "interlock_base_is_ancestor": True,
    }


def test_synthetic_boundary_contract_is_material() -> None:
    from examples.livekit_agents.synthetic_server import (
        CLEAN_READ_CUSTOMER,
        MUTATED_READ_CUSTOMER,
    )

    clean = CLEAN_READ_CUSTOMER
    mutated = MUTATED_READ_CUSTOMER
    assert clean["name"] == mutated["name"] == "read_customer"
    assert clean["annotations"]["readOnlyHint"] is True
    assert clean["_meta"]["interlock"]["externality"] == "internal"
    assert clean["_meta"]["interlock"]["effects"] == ["read"]
    assert mutated["annotations"]["readOnlyHint"] is False
    assert mutated["_meta"]["interlock"]["externality"] == "external"
    assert mutated["_meta"]["interlock"]["effects"] == ["read", "export"]


def test_adapter_hold_message_is_safe_and_understandable() -> None:
    from examples.livekit_agents.adapter import (
        SAFE_DENIAL_MESSAGE,
        SAFE_HOLD_MESSAGE,
        SAFE_UPSTREAM_ERROR_MESSAGE,
        safe_gateway_message,
    )

    raw_key = "lf_developer_RAW_KEY_MUST_NOT_SURVIVE"
    reflected = (
        f"{raw_key} Authorization: Bearer private-token "
        f"{proof_runner.PRIVATE_SENTINEL} "
        "Traceback (most recent call last)"
    )
    messages = [
        safe_gateway_message(
            "read_customer",
            {"error": "tool_quarantined", "message": reflected},
        ),
        safe_gateway_message(
            "read_customer",
            {"error": "upstream_jsonrpc_error", "message": reflected},
        ),
        safe_gateway_message(
            "read_customer",
            {"error": reflected, "message": reflected},
        ),
    ]
    assert messages == [
        SAFE_HOLD_MESSAGE,
        SAFE_UPSTREAM_ERROR_MESSAGE,
        SAFE_DENIAL_MESSAGE,
    ]
    for message in messages:
        for forbidden in (
            raw_key,
            "Authorization",
            proof_runner.PRIVATE_SENTINEL,
            "Traceback",
        ):
            assert forbidden.lower() not in message.lower()


def test_child_environment_allowlist_excludes_seeded_credentials_everywhere(
    live_services: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw_key = live_services["key"]
    assert raw_key not in repr(live_services)

    adapter_env = _adapter_env(live_services, "repr-probe", key=raw_key)
    assert raw_key not in repr(adapter_env)

    for name, value in SEEDED_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    child_env = proof_runner._child_environment(tmp_path / "repr.db")
    assert set(SEEDED_CREDENTIALS).isdisjoint(child_env)
    assert set(SEEDED_CREDENTIALS.values()).isdisjoint(child_env.values())
    expected_inherited = {
        name for name in os.environ if name.upper() in proof_runner._CHILD_ENV_ALLOWLIST
    }
    assert set(child_env) == expected_inherited | {
        "DATABASE_URL",
        "FIREWALL_DB_PATH",
        "GROQ_API_KEY",
        "PYTHON_DOTENV_DISABLED",
    }

    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                f"import json, os; names={sorted(SEEDED_CREDENTIALS)!r}; "
                "print(json.dumps(sorted(name for name in names if name in os.environ)))"
            ),
        ],
        env=child_env,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert json.loads(probe.stdout) == []

    try:
        raise RuntimeError(f"child launch failed with environment {child_env!r}")
    except RuntimeError as exc:
        exception_message = str(exc)
        formatted_traceback = traceback.format_exc()

    rendered_fixture = repr(live_services)
    rendered_adapter_env = repr(adapter_env)
    for name, value in SEEDED_CREDENTIALS.items():
        for rendered in (
            exception_message,
            formatted_traceback,
            rendered_fixture,
            rendered_adapter_env,
        ):
            assert name not in rendered
            assert value not in rendered


def test_end_to_end_livekit_drift_proof_and_cleanup(tmp_path: Path) -> None:
    evidence = tmp_path / "proof-evidence"
    result = subprocess.run(
        [
            sys.executable,
            str(EXAMPLE / "run_proof.py"),
            "--evidence-dir",
            str(evidence),
        ],
        cwd=ROOT,
        env={**os.environ, **SEEDED_CREDENTIALS},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "PASS LiveKit MCPToolset initialized" in result.stdout
    proof = json.loads((evidence / "proof.json").read_text(encoding="utf-8"))

    assert proof["inputs"]["interlock_base_sha"] == INTERLOCK_BASE_SHA
    assert (
        proof["inputs"]["integration_head_sha"]
        == subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    assert proof["inputs"]["interlock_base_is_ancestor"] is True
    assert proof["livekit"]["agent_type"] == "Agent"
    assert proof["livekit"]["mcp_toolset_type"] == "MCPToolset"
    assert proof["livekit"]["mcp_toolset_initialized"] is True
    assert proof["livekit"]["agent_session_started"] is False
    assert proof["livekit"]["invocation_mode"] == "direct_mcp_tool_wrapper_call"
    assert proof["calls"]["initial"]["upstream_delta"] == 1
    assert "direct_wrapper_result" in proof["calls"]["initial"]
    assert "livekit_result" not in proof["calls"]["initial"]
    assert proof["approval"]["boundary"] == {
        "effects": ["read"],
        "side_effect": "read_only",
        "data_classes": ["user_content"],
        "externality": "internal",
    }
    assert proof["approval"]["approval_endpoint_called_before_toolset_setup"] is True
    assert (
        proof["approval"]["approval_audit_event_verified_before_toolset_setup"] is True
    )
    assert proof["approval"]["adapter_enforced_explicit_approval"] is False
    assert proof["approval"]["approval_audit_event"]["server_id"] == (
        proof_runner.SERVER_ID
    )
    assert proof["approval"]["approval_audit_event"]["matched_rule"] == (
        "tool_baseline_approved"
    )
    assert proof["approval"]["approval_audit_event"]["action"] == "approve"
    assert proof["mutation"]["tool_identity_unchanged"] is True
    assert proof["mutation"]["selected_boundary_changed"] is True
    assert proof["drift"]["severity"] == "critical"
    assert proof["drift"]["decision"] == "quarantine"
    assert proof["drift"]["observation_refresh"] == {
        "endpoint": "POST /mcp/discover",
        "triggered_explicitly": True,
        "ok": True,
    }
    assert proof["drift"]["quarantined_tools"] == ["read_customer"]
    assert proof["calls"]["held"]["upstream_delta"] == 0
    assert proof["calls"]["held"]["safe_message"] == (
        "Interlock held this tool call before upstream forwarding. "
        "Review the Interlock audit evidence before retrying."
    )
    assert proof["review_evidence"]["tool_name"] == "read_customer"
    assert proof["review_evidence"]["approved_surface_hash"].startswith("sha256:")
    assert proof["review_evidence"]["observed_surface_hash"].startswith("sha256:")
    assert proof["review_evidence"]["decision"] == "quarantine"
    verification = proof["receipt"]["verification"]
    assert verification["verified"] is True
    assert verification["checks"] == {
        "record_found": True,
        "chain": True,
        "receipt_match": True,
        "evidence_digest": True,
        "binding": True,
    }
    execution = proof["receipt"]["claims"]["execution_after_detection"]
    assert execution["executed_count"] == 0
    assert execution["blocked_attempts"] >= 1

    retained = (evidence / "proof.json").read_text(encoding="utf-8")
    for forbidden in (
        "lf_developer_",
        proof_runner.PRIVATE_SENTINEL,
        "x-api-key",
        "authorization",
        "Traceback (most recent call last)",
        "-----BEGIN PRIVATE KEY-----",
    ):
        assert forbidden.lower() not in retained.lower()
    for name, value in SEEDED_CREDENTIALS.items():
        assert name.lower() not in retained.lower()
        assert value.lower() not in retained.lower()
        assert value.lower() not in result.stdout.lower()
        assert value.lower() not in result.stderr.lower()
    assert sorted(path.name for path in evidence.iterdir()) == [
        proof_runner.MARKER_NAME,
        proof_runner.PROOF_NAME,
    ]

    cleaned = subprocess.run(
        [
            sys.executable,
            str(EXAMPLE / "run_proof.py"),
            "--cleanup",
            "--evidence-dir",
            str(evidence),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert cleaned.returncode == 0, cleaned.stderr
    assert not evidence.exists()


def test_interlock_unavailable_fails_livekit_initialization() -> None:
    unavailable_port = proof_runner._available_port()
    env = dict(os.environ)
    env.update(
        {
            "INTERLOCK_API_URL": f"http://127.0.0.1:{unavailable_port}",
            "INTERLOCK_API_KEY": "invalid-ephemeral-value",
            "INTERLOCK_SERVER_ID": "_fixture_unavailable_interlock",
            "INTERLOCK_TOOL_NAMES": "read_customer",
        }
    )
    with pytest.raises(Exception, match="Interlock inventory is unavailable"):
        asyncio.run(_livekit_setup_or_call(env))


def test_adapter_unavailable_fails_livekit_initialization(tmp_path: Path) -> None:
    missing = tmp_path / "missing-adapter.py"
    with pytest.raises(Exception):
        asyncio.run(
            _livekit_setup_or_call(dict(os.environ), script=missing, timeout=0.5)
        )


def test_missing_and_invalid_interlock_keys_fail_closed(
    live_services: dict[str, Any],
) -> None:
    server_id = "_fixture_livekit_missing_invalid_key"
    _register_clean(live_services, server_id)
    with pytest.raises(Exception, match="API key is missing"):
        asyncio.run(
            _livekit_setup_or_call(_adapter_env(live_services, server_id, key=None))
        )
    with pytest.raises(Exception, match="inventory failed with HTTP 403"):
        asyncio.run(
            _livekit_setup_or_call(
                _adapter_env(live_services, server_id, key="invalid-ephemeral-value")
            )
        )


def test_livekit_initialization_timeout_is_observed(
    live_services: dict[str, Any],
) -> None:
    server_id = "_fixture_livekit_init_timeout"
    _register_clean(live_services, server_id)
    env = _adapter_env(live_services, server_id, key=live_services["key"])
    env["INTERLOCK_ADAPTER_STARTUP_DELAY_SECONDS"] = "1.0"
    with pytest.raises(Exception):
        asyncio.run(_livekit_setup_or_call(env, timeout=0.1))


def test_synthetic_upstream_unavailable_is_reported(
    live_services: dict[str, Any],
) -> None:
    unavailable_port = proof_runner._available_port()
    server_id = "_fixture_livekit_upstream_unavailable"
    registered = _request(
        live_services,
        "POST",
        "/mcp/servers",
        json={
            "server_id": server_id,
            "url": f"http://127.0.0.1:{unavailable_port}/mcp",
            "allowed_tools": ["read_customer"],
            "upstream_protocol_profile": "2026-07-28",
            "environment": "non_production",
        },
    )
    assert registered["ok"] is True
    _request(live_services, "POST", f"/mcp/servers/{server_id}/verify")
    discovery = _request(
        live_services,
        "POST",
        "/mcp/discover",
        json={
            "server_url": f"http://127.0.0.1:{unavailable_port}/mcp",
            "server_id": server_id,
        },
    )
    assert discovery["ok"] is False


def test_initial_allowed_call_can_fail_at_real_synthetic_upstream(
    live_services: dict[str, Any],
) -> None:
    from livekit.agents.llm.tool_context import ToolError

    server_id = "_fixture_livekit_initial_upstream_failure"
    _register_clean(live_services, server_id)
    _request(live_services, "POST", "/control/fail-next-call", synthetic=True)
    before = _request(live_services, "GET", "/control/state", synthetic=True)
    env = _adapter_env(live_services, server_id, key=live_services["key"])
    with pytest.raises(
        ToolError,
        match="Interlock forwarded this tool call, but the upstream MCP server failed",
    ):
        asyncio.run(
            _livekit_setup_or_call(
                env,
                tool_name="read_customer",
                arguments={"customer_id": "customer-demo-failure"},
            )
        )
    after = _request(live_services, "GET", "/control/state", synthetic=True)
    assert (
        after["execution_counts"]["read_customer"]
        - before["execution_counts"]["read_customer"]
        == 1
    )


def test_drift_refresh_failure_leaves_approved_baseline_active(
    live_services: dict[str, Any],
) -> None:
    server_id = "_fixture_livekit_drift_refresh_failure"
    _register_clean(live_services, server_id)
    _request(
        live_services,
        "POST",
        "/control/mutate/read_customer",
        synthetic=True,
    )
    _request(
        live_services,
        "POST",
        "/control/fail-discovery",
        synthetic=True,
        params={"enabled": "true"},
    )
    refresh = _request(
        live_services,
        "POST",
        "/mcp/discover",
        json={
            "server_url": f"{live_services['synthetic_url']}/mcp",
            "server_id": server_id,
        },
    )
    assert refresh["ok"] is False
    inventory = _request(
        live_services, "GET", "/mcp/tools", params={"server_id": server_id}
    )["tools"]
    assert inventory[0]["status"] == "active"
    assert inventory[0]["normalized_metadata"]["externality"] == "internal"
    _request(
        live_services,
        "POST",
        "/control/fail-discovery",
        synthetic=True,
        params={"enabled": "false"},
    )


def test_no_drift_refresh_remains_allowed(live_services: dict[str, Any]) -> None:
    server_id = "_fixture_livekit_no_drift"
    _register_clean(live_services, server_id)
    refresh = _request(
        live_services,
        "POST",
        "/mcp/discover",
        json={
            "server_url": f"{live_services['synthetic_url']}/mcp",
            "server_id": server_id,
        },
    )
    assert refresh["ok"] is True
    assert refresh["safe_tools"] == 1
    inventory = _request(
        live_services, "GET", "/mcp/tools", params={"server_id": server_id}
    )["tools"]
    assert inventory[0]["status"] == "active"
    assert inventory[0]["drift_action"] == "allow"


def test_different_tool_drift_is_tool_scoped_and_other_tool_executes(
    live_services: dict[str, Any],
) -> None:
    server_id = "_fixture_livekit_other_tool_drift"
    _register_clean(live_services, server_id, include_second_tool=True)
    _request(
        live_services,
        "POST",
        "/control/mutate/read_region",
        synthetic=True,
    )
    refresh = _request(
        live_services,
        "POST",
        "/mcp/discover",
        json={
            "server_url": f"{live_services['synthetic_url']}/mcp",
            "server_id": server_id,
        },
    )
    assert refresh["ok"] is True
    inventory = _request(
        live_services, "GET", "/mcp/tools", params={"server_id": server_id}
    )["tools"]
    by_name = {row["tool_name"]: row for row in inventory}
    assert by_name["read_region"]["status"] == "quarantined"
    assert by_name["read_customer"]["status"] == "active"
    drifted = _request(
        live_services,
        "GET",
        "/mcp/tools/drifted",
        params={"server_id": server_id},
    )["tools"]
    assert {row["tool_name"] for row in drifted} == {"read_region"}

    before = _request(live_services, "GET", "/control/state", synthetic=True)
    names, result = asyncio.run(
        _livekit_setup_or_call(
            _adapter_env(
                live_services,
                server_id,
                key=live_services["key"],
                tools="read_customer,read_region",
            ),
            tool_name="read_customer",
            arguments={"customer_id": "customer-demo-still-allowed"},
        )
    )
    after = _request(live_services, "GET", "/control/state", synthetic=True)
    assert names == ["read_customer"]
    assert "Synthetic ordinary-data result" in result
    assert (
        after["execution_counts"]["read_customer"]
        - before["execution_counts"]["read_customer"]
        == 1
    )


def test_fresh_mcp_toolset_after_quarantine_exposes_no_held_tool(
    live_services: dict[str, Any],
) -> None:
    server_id = "_fixture_livekit_fresh_after_quarantine"
    _register_clean(live_services, server_id)
    _request(
        live_services,
        "POST",
        "/control/mutate/read_customer",
        synthetic=True,
    )
    refresh = _request(
        live_services,
        "POST",
        "/mcp/discover",
        json={
            "server_url": f"{live_services['synthetic_url']}/mcp",
            "server_id": server_id,
        },
    )
    assert refresh["ok"] is True

    names, _ = asyncio.run(
        _livekit_setup_or_call(
            _adapter_env(live_services, server_id, key=live_services["key"])
        )
    )
    assert names == []


def test_public_inventory_has_same_eligible_fields_before_and_after_approval(
    live_services: dict[str, Any],
) -> None:
    server_id = "_fixture_livekit_preapproval_state"
    _request(live_services, "POST", "/control/reset", synthetic=True)
    registered = _request(
        live_services,
        "POST",
        "/mcp/servers",
        json={
            "server_id": server_id,
            "url": f"{live_services['synthetic_url']}/mcp",
            "allowed_tools": ["read_customer"],
            "blocked_tools": [],
            "upstream_protocol_profile": "2026-07-28",
            "environment": "non_production",
        },
    )
    assert registered["ok"] is True
    _request(live_services, "POST", f"/mcp/servers/{server_id}/verify")
    discovered = _request(
        live_services,
        "POST",
        "/mcp/discover",
        json={
            "server_url": f"{live_services['synthetic_url']}/mcp",
            "server_id": server_id,
        },
    )
    assert discovered["ok"] is True

    before = _request(
        live_services, "GET", "/mcp/tools", params={"server_id": server_id}
    )["tools"][0]
    unrelated_call = _request(
        live_services,
        "POST",
        "/mcp/call",
        json={
            "server_id": server_id,
            "tool_name": "read_customer",
            "arguments": {"customer_id": "customer-preapproval-audit"},
        },
    )
    assert unrelated_call["ok"] is True
    audits_before = _request(live_services, "GET", "/mcp/audit", params={"limit": 100})[
        "events"
    ]
    assert any(
        event.get("server_id") == server_id
        and event.get("tool_name") == "read_customer"
        and event.get("matched_rule") == "default_allow"
        for event in audits_before
    )
    approval_event_ids_before = {
        event["id"]
        for event in audits_before
        if event.get("server_id") == server_id
        and event.get("tool_name") == "read_customer"
        and event.get("matched_rule") == "tool_baseline_approved"
        and event.get("action") == "approve"
    }

    current_review = _request(
        live_services,
        "GET",
        "/mcp/tools",
        params={"server_id": server_id},
    )["tools"]
    reviewed_hash = next(
        item["review_surface_hash"]
        for item in current_review
        if item["tool_name"] == "read_customer"
    )
    approved = _request(
        live_services,
        "POST",
        f"/mcp/tools/{server_id}/read_customer/approve",
        json={
            "expected_surface_hash": reviewed_hash,
            "reason": "Endpoint-backed approval-state regression.",
        },
    )
    assert approved["ok"] is True
    after = _request(
        live_services, "GET", "/mcp/tools", params={"server_id": server_id}
    )["tools"][0]
    audits_after = _request(live_services, "GET", "/mcp/audit", params={"limit": 100})[
        "events"
    ]
    new_approval_events = [
        event
        for event in audits_after
        if event.get("server_id") == server_id
        and event.get("tool_name") == "read_customer"
        and event.get("matched_rule") == "tool_baseline_approved"
        and event.get("action") == "approve"
        and event["id"] not in approval_event_ids_before
    ]

    def selected(row: dict[str, Any]) -> tuple[Any, Any, Any]:
        return (
            row.get("status"),
            row.get("drift_action"),
            row.get("drift_severity"),
        )

    assert selected(before) == selected(after) == ("active", "allow", "none")
    assert approval_event_ids_before == set()
    assert len(new_approval_events) == 1


def test_find_event_is_bound_to_server_id() -> None:
    events = [
        {
            "id": 1,
            "server_id": "wrong-server",
            "tool_name": "read_customer",
            "matched_rule": "tool_baseline_approved",
        },
        {
            "id": 2,
            "server_id": proof_runner.SERVER_ID,
            "tool_name": "read_customer",
            "matched_rule": "tool_baseline_approved",
        },
    ]

    selected = proof_runner._find_event(
        events,
        server_id=proof_runner.SERVER_ID,
        rule="tool_baseline_approved",
        tool="read_customer",
    )

    assert selected["id"] == 2


def test_adapter_inventory_rejects_non_eligible_rows() -> None:
    from examples.livekit_agents.adapter import _is_eligible_inventory_row

    active = {
        "status": "active",
        "drift_action": "allow",
        "drift_severity": "none",
    }
    assert _is_eligible_inventory_row(active) is True
    assert _is_eligible_inventory_row({**active, "status": "allowed"}) is False
    assert _is_eligible_inventory_row({**active, "status": "changed"}) is False
    assert _is_eligible_inventory_row({**active, "status": "quarantined"}) is False
    assert _is_eligible_inventory_row({**active, "drift_action": "quarantine"}) is False
    assert _is_eligible_inventory_row({**active, "drift_severity": "critical"}) is False


def test_unwritable_evidence_path_fails_without_traceback(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("owned by test", encoding="utf-8")
    evidence = blocker / "proof"
    result = subprocess.run(
        [
            sys.executable,
            str(EXAMPLE / "run_proof.py"),
            "--evidence-dir",
            str(evidence),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 2
    assert "Evidence directory is not writable" in result.stderr
    assert "Traceback" not in result.stderr
    assert blocker.read_text(encoding="utf-8") == "owned by test"


def test_keyboard_interrupt_inside_owned_process_context_stops_child(
    tmp_path: Path,
) -> None:
    evidence = proof_runner.EvidenceDirectory(tmp_path / "interrupted")
    evidence.create()
    process: subprocess.Popen[bytes] | None = None
    try:
        with pytest.raises(KeyboardInterrupt):
            with proof_runner.OwnedProcesses() as children:
                process = children.start(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    env=dict(os.environ),
                )
                raise KeyboardInterrupt
    finally:
        evidence.cleanup()
    assert process is not None
    assert process.poll() is not None
    assert not evidence.path.exists()


def test_readme_states_exact_boundary_and_required_limitations() -> None:
    readme = (EXAMPLE / "README.md").read_text(encoding="utf-8")
    required = (
        "LiveKit Agents integration through Interlock's local MCP compatibility adapter",
        "not native LiveKit/Interlock MCP interoperability",
        "must not target LiveKit production",
        "not a LiveKit endorsement, partnership, customer validation, or native compatibility claim",
        "06c71f9c718e24a151630447755a9fa86851b389",
        "a78d5a0a4557a63f0db71e41a70d451c03bb13bb",
        "Python 3.12.9",
        "LiveKit Agents 1.6.10",
        "MCP SDK 1.28.1",
        "Docker 29.6.2",
        "Cleanup",
        "occupied ports",
        "Docker build",
        "No `AgentSession` is started",
        "no Agent or LLM selects or invokes the tool",
        "invokes that wrapper directly",
        "Drift detection is not automatic",
        "explicitly calls `POST /mcp/discover`",
        "last successfully observed approved state remains active",
        "does not send an operating-system interrupt to the full runner",
        "requirements-pinned.txt",
        "eligible-state filter",
        "runner calls the explicit approval endpoint before `MCPToolset.setup()`",
        "configured tool-name allowlist",
        "`/mcp/tools` does not expose a distinct explicit-approval marker",
        "does not prove a general adapter-level explicit-approval guarantee",
    )
    for statement in required:
        assert statement in readme

    assert "requirements.lock" not in readme
    assert "Agent can use a real LiveKit" not in readme
    assert "unapproved and quarantined inventory" not in readme
    assert "Unapproved, changed, denied" not in readme
