#!/usr/bin/env python3
"""Run the evidence-grade LiveKit Agents drift proof on loopback.

The proof attaches a real MCPToolset to a real LiveKit Agent, then the harness
directly invokes the discovered wrapper through the local stdio compatibility
adapter -> Interlock /mcp/call -> synthetic MCP 2026-07-28 server. No
AgentSession or LLM tool selection is involved.

No LiveKit Cloud connection or production data is used.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Any
import uuid

import httpx

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_DIR = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
ADAPTER = EXAMPLE_DIR / "adapter.py"
SYNTHETIC_SERVER = EXAMPLE_DIR / "synthetic_server.py"
DEFAULT_EVIDENCE_DIR = EXAMPLE_DIR / ".proof-artifacts"
MARKER_NAME = ".interlock-livekit-proof-owner.json"
PROOF_NAME = "proof.json"
SERVER_ID = "_fixture_livekit_agents_proof"
LIVEKIT_COMMIT = "06c71f9c718e24a151630447755a9fa86851b389"
INTERLOCK_BASE_SHA = "a78d5a0a4557a63f0db71e41a70d451c03bb13bb"
PRIVATE_SENTINEL = "LIVEKIT_PROOF_PRIVATE_SENTINEL_7D4E2A"
_CHILD_ENV_ALLOWLIST = {
    "COMSPEC",
    "HOME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "WINDIR",
}


class ProofError(RuntimeError):
    """A credential-safe proof failure."""


class EvidenceDirectory:
    """Own one newly-created, marker-guarded artifact directory."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.marker = self.path / MARKER_NAME
        self.run_id = str(uuid.uuid4())

    def create(self) -> None:
        if self.path.exists():
            raise ProofError(
                "Evidence directory already exists; inspect it or run --cleanup first."
            )
        if self.path in {Path(self.path.anchor), ROOT.resolve(), Path.home().resolve()}:
            raise ProofError("Refusing an unsafe evidence directory.")
        try:
            self.path.mkdir(parents=True, exist_ok=False)
            self.marker.write_text(
                json.dumps(
                    {
                        "owner": "interlock-livekit-agents-proof",
                        "run_id": self.run_id,
                        "path": str(self.path),
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            if self.path.exists() and not self.marker.exists():
                try:
                    self.path.rmdir()
                except OSError:
                    pass
            raise ProofError("Evidence directory is not writable.") from exc

    def validate_owner(self) -> None:
        try:
            marker = json.loads(self.marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProofError(
                "Refusing cleanup: evidence ownership marker is invalid."
            ) from exc
        if (
            marker.get("owner") != "interlock-livekit-agents-proof"
            or Path(str(marker.get("path") or "")).resolve() != self.path
        ):
            raise ProofError(
                "Refusing cleanup: evidence ownership marker does not match."
            )

    def cleanup(self) -> None:
        self.validate_owner()
        if self.path in {Path(self.path.anchor), ROOT.resolve(), Path.home().resolve()}:
            raise ProofError("Refusing unsafe cleanup target.")
        shutil.rmtree(self.path)


class OwnedProcesses:
    """Track and terminate only child processes started by this runner."""

    def __init__(self) -> None:
        self.processes: list[subprocess.Popen[bytes]] = []

    def start(
        self, command: list[str], *, env: dict[str, str]
    ) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.processes.append(process)
        return process

    def stop_all(self) -> None:
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
        deadline = time.monotonic() + 5.0
        for process in reversed(self.processes):
            if process.poll() is None:
                remaining = max(0.1, deadline - time.monotonic())
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5.0)

    def __enter__(self) -> "OwnedProcesses":
        return self

    def __exit__(self, *_: object) -> None:
        self.stop_all()


def _available_port(requested: int | None = None) -> int:
    if requested is not None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", requested))
            except OSError as exc:
                raise ProofError(
                    f"Requested loopback port {requested} is occupied."
                ) from exc
        return requested
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def _wait_healthy(url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15.0
    async with httpx.AsyncClient(timeout=0.5, trust_env=False) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ProofError("A proof service exited before becoming healthy.")
            try:
                response = await client.get(f"{url}/health")
                if response.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
    raise ProofError("A proof service did not become healthy before timeout.")


def _child_environment(db_path: Path) -> dict[str, str]:
    env = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in _CHILD_ENV_ALLOWLIST
    }
    env.update(
        {
            "PYTHON_DOTENV_DISABLED": "1",
            "DATABASE_URL": "",
            "FIREWALL_DB_PATH": str(db_path),
            "GROQ_API_KEY": "",
        }
    )
    return env


def _initialize_database(db_path: Path) -> str:
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    os.environ["DATABASE_URL"] = ""
    os.environ["FIREWALL_DB_PATH"] = str(db_path)
    from core import db

    db.DATABASE_URL = ""
    db.USE_POSTGRES = False
    db.DB_PATH = str(db_path)
    db.init_db()
    issued = db.generate_key(
        "developer",
        label="livekit-proof-ephemeral",
        scopes=["admin"],
        role="admin_agent",
    )
    return str(issued["raw_key"])


async def _json_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    api_key: str | None = None,
    expected_status: int = 200,
    **kwargs: Any,
) -> dict[str, Any]:
    headers = dict(kwargs.pop("headers", {}) or {})
    if api_key:
        headers["x-api-key"] = api_key
    response = await client.request(method, url, headers=headers, **kwargs)
    if response.status_code != expected_status:
        raise ProofError(
            f"Proof HTTP operation failed with status {response.status_code}."
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise ProofError("Proof HTTP operation returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise ProofError("Proof HTTP operation returned a non-object response.")
    return payload


def _boundary(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "effects": list(metadata.get("effects") or []),
        "side_effect": metadata.get("side_effect") or "unknown",
        "data_classes": list(metadata.get("data_classes") or []),
        "externality": metadata.get("externality") or "unknown",
    }


def _find_event(
    events: list[dict[str, Any]], *, server_id: str, rule: str, tool: str
) -> dict[str, Any]:
    for event in events:
        if (
            event.get("server_id") == server_id
            and event.get("matched_rule") == rule
            and event.get("tool_name") == tool
        ):
            return event
    raise ProofError(
        f"Expected audit evidence for {server_id}/{tool}/{rule} was not observed."
    )


def _receipt_context(receipt: dict[str, Any]) -> dict[str, Any]:
    binding = receipt.get("binding") or {}
    return {
        "server_id": receipt.get("server_id") or "",
        "tool_name": receipt.get("tool_name") or "",
        "argument_hash": binding.get("argument_hash") or "",
        "call_id": binding.get("call_id") or "",
        "surface_hash": binding.get("surface_hash") or "",
        "approved_surface_hash": binding.get("approved_surface_hash") or "",
    }


def _command_version(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return (result.stdout or result.stderr).strip()


def _interlock_provenance() -> dict[str, Any]:
    """Verify the pinned base is an ancestor and report the actual review head."""
    integration_head = _command_version(["git", "rev-parse", "HEAD"])
    if not re.fullmatch(r"[0-9a-f]{40}", integration_head):
        raise ProofError("Could not resolve the integration checkout HEAD.")
    try:
        ancestor = subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                INTERLOCK_BASE_SHA,
                integration_head,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProofError("Could not verify the pinned Interlock base.") from exc
    if ancestor.returncode != 0:
        raise ProofError(
            "Pinned Interlock base is not an ancestor of the integration HEAD."
        )
    return {
        "interlock_base_sha": INTERLOCK_BASE_SHA,
        "integration_head_sha": integration_head,
        "interlock_base_is_ancestor": True,
    }


def _assert_acceptance(proof: dict[str, Any]) -> None:
    if proof["inputs"]["interlock_base_sha"] != INTERLOCK_BASE_SHA:
        raise ProofError("Proof artifact does not record the pinned Interlock base.")
    if proof["inputs"]["interlock_base_is_ancestor"] is not True:
        raise ProofError("Pinned Interlock base ancestry was not verified.")
    if not re.fullmatch(r"[0-9a-f]{40}", proof["inputs"]["integration_head_sha"]):
        raise ProofError("Proof artifact does not record the integration HEAD.")
    if proof["livekit"]["mcp_toolset_initialized"] is not True:
        raise ProofError("LiveKit MCPToolset did not initialize.")
    if proof["livekit"]["agent_attached_toolset"] is not True:
        raise ProofError("LiveKit Agent was not attached to the MCPToolset.")
    if proof["livekit"]["agent_session_started"] is not False:
        raise ProofError("Proof must not claim an AgentSession was started.")
    if proof["livekit"]["invocation_mode"] != "direct_mcp_tool_wrapper_call":
        raise ProofError("Proof does not record direct wrapper invocation.")
    approval = proof["approval"]
    if approval["approval_endpoint_called_before_toolset_setup"] is not True:
        raise ProofError("Explicit approval endpoint ordering was not recorded.")
    if approval["approval_audit_event_verified_before_toolset_setup"] is not True:
        raise ProofError("Explicit approval audit evidence was not verified in order.")
    if approval["adapter_enforced_explicit_approval"] is not False:
        raise ProofError("Proof must not claim adapter-enforced explicit approval.")
    approval_event = approval["approval_audit_event"]
    if not isinstance(approval_event.get("id"), int) or {
        key: approval_event.get(key)
        for key in ("server_id", "tool_name", "matched_rule", "action")
    } != {
        "server_id": SERVER_ID,
        "tool_name": "read_customer",
        "matched_rule": "tool_baseline_approved",
        "action": "approve",
    }:
        raise ProofError("Explicit approval audit evidence is inconsistent.")
    if proof["calls"]["initial"]["upstream_delta"] != 1:
        raise ProofError("Initial allowed call was not forwarded exactly once.")
    if proof["drift"]["material"] is not True:
        raise ProofError("Selected boundary mutation was not classified as material.")
    if proof["drift"]["decision"] != "quarantine":
        raise ProofError("Changed tool was not quarantined.")
    if proof["drift"]["observation_refresh"] != {
        "endpoint": "POST /mcp/discover",
        "triggered_explicitly": True,
        "ok": True,
    }:
        raise ProofError("Explicit drift observation refresh was not recorded.")
    if proof["drift"]["quarantined_tools"] != ["read_customer"]:
        raise ProofError("Quarantine was not scoped to the changed tool.")
    if proof["calls"]["held"]["upstream_delta"] != 0:
        raise ProofError("Held call reached the synthetic upstream.")
    if proof["calls"]["held"]["safe_message"] != (
        "Interlock held this tool call before upstream forwarding. "
        "Review the Interlock audit evidence before retrying."
    ):
        raise ProofError("LiveKit did not receive a safe hold explanation.")
    verification = proof["receipt"]["verification"]
    if verification.get("verified") is not True:
        raise ProofError("Security Receipt context verification failed.")
    if any(value not in (True, None) for value in verification["checks"].values()):
        raise ProofError("A supported Security Receipt verification check failed.")
    execution = proof["receipt"]["claims"]["execution_after_detection"]
    if execution["executed_count"] != 0 or execution["blocked_attempts"] < 1:
        raise ProofError("Post-detection execution evidence is inconsistent.")


def _sanitize_and_write(
    evidence: EvidenceDirectory,
    proof: dict[str, Any],
    *,
    raw_key: str,
) -> None:
    rendered = json.dumps(proof, indent=2, sort_keys=True)
    forbidden = {
        raw_key,
        PRIVATE_SENTINEL,
        "-----BEGIN PRIVATE KEY-----",
        "x-api-key",
        "authorization",
        "traceback (most recent call last)",
    }
    lowered = rendered.lower()
    hits = [value for value in forbidden if value and value.lower() in lowered]
    if hits:
        raise ProofError("Artifact sanitization rejected retained sensitive content.")
    (evidence.path / PROOF_NAME).write_text(rendered + "\n", encoding="utf-8")


async def run_proof(
    evidence_path: Path,
    *,
    interlock_port: int | None = None,
    synthetic_port: int | None = None,
) -> dict[str, Any]:
    evidence = EvidenceDirectory(evidence_path)
    evidence.create()
    db_path = evidence.path / "interlock-livekit-proof.db"
    raw_key = ""
    toolset: Any = None
    succeeded = False

    try:
        provenance = _interlock_provenance()
        raw_key = _initialize_database(db_path)
        interlock_port = _available_port(interlock_port)
        synthetic_port = _available_port(synthetic_port)
        interlock_url = f"http://127.0.0.1:{interlock_port}"
        synthetic_url = f"http://127.0.0.1:{synthetic_port}"
        child_env = _child_environment(db_path)

        with OwnedProcesses() as children:
            synthetic_process = children.start(
                [
                    sys.executable,
                    str(SYNTHETIC_SERVER),
                    "--port",
                    str(synthetic_port),
                ],
                env=child_env,
            )
            interlock_process = children.start(
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
                env=child_env,
            )
            await asyncio.gather(
                _wait_healthy(synthetic_url, synthetic_process),
                _wait_healthy(interlock_url, interlock_process),
            )

            async with httpx.AsyncClient(timeout=40.0, trust_env=False) as client:
                registered = await _json_request(
                    client,
                    "POST",
                    f"{interlock_url}/mcp/servers",
                    api_key=raw_key,
                    json={
                        "server_id": SERVER_ID,
                        "url": f"{synthetic_url}/mcp",
                        "description": "Synthetic LiveKit Agents proof upstream",
                        "allowed_tools": ["read_customer"],
                        "blocked_tools": [],
                        "upstream_protocol_profile": "2026-07-28",
                        "environment": "non_production",
                        "probes_enabled": False,
                    },
                )
                if registered.get("ok") is not True:
                    raise ProofError("Synthetic MCP server registration failed.")
                await _json_request(
                    client,
                    "POST",
                    f"{interlock_url}/mcp/servers/{SERVER_ID}/verify",
                    api_key=raw_key,
                )
                discovered = await _json_request(
                    client,
                    "POST",
                    f"{interlock_url}/mcp/discover",
                    api_key=raw_key,
                    json={
                        "server_url": f"{synthetic_url}/mcp",
                        "server_id": SERVER_ID,
                    },
                )
                if (
                    discovered.get("ok") is not True
                    or discovered.get("safe_tools") != 1
                ):
                    raise ProofError("Initial Interlock discovery failed.")
                approval_result = await _json_request(
                    client,
                    "POST",
                    f"{interlock_url}/mcp/tools/{SERVER_ID}/read_customer/approve",
                    api_key=raw_key,
                    json={"reason": "Approved narrow synthetic read-only boundary."},
                )
                if approval_result.get("ok") is not True:
                    raise ProofError("Explicit tool approval endpoint failed.")
                approval_audit_payload = await _json_request(
                    client,
                    "GET",
                    f"{interlock_url}/mcp/audit",
                    api_key=raw_key,
                    params={"limit": 100},
                )
                approval_event = _find_event(
                    approval_audit_payload["events"],
                    server_id=SERVER_ID,
                    rule="tool_baseline_approved",
                    tool="read_customer",
                )
                if approval_event.get("action") != "approve":
                    raise ProofError(
                        "Explicit tool approval audit event was not verified."
                    )
                baseline_inventory = await _json_request(
                    client,
                    "GET",
                    f"{interlock_url}/mcp/tools",
                    api_key=raw_key,
                    params={"server_id": SERVER_ID},
                )
                baseline_row = baseline_inventory["tools"][0]
                approved_boundary = _boundary(baseline_row["normalized_metadata"])

                from livekit.agents import Agent
                from livekit.agents.llm.mcp import MCPServerStdio, MCPToolset
                from livekit.agents.llm.tool_context import ToolError

                adapter_env = dict(child_env)
                adapter_env.update(
                    {
                        "INTERLOCK_API_URL": interlock_url,
                        "INTERLOCK_API_KEY": raw_key,
                        "INTERLOCK_SERVER_ID": SERVER_ID,
                        "INTERLOCK_TOOL_NAMES": "read_customer",
                    }
                )
                mcp_server = MCPServerStdio(
                    command=sys.executable,
                    args=[str(ADAPTER)],
                    env=adapter_env,
                    cwd=ROOT,
                    client_session_timeout_seconds=5,
                )
                toolset = MCPToolset(
                    id="interlock-livekit-agents-proof", mcp_server=mcp_server
                )
                agent = Agent(
                    instructions="Use only the synthetic proof tool.",
                    tools=[toolset],
                    llm=None,
                )
                await toolset.setup()
                tool_names = [tool.id for tool in toolset.tools]
                if tool_names != ["read_customer"]:
                    raise ProofError("LiveKit discovered an unexpected tool inventory.")
                livekit_tool = toolset.tools[0]
                agent_attached = any(item is toolset for item in agent.tools)

                state_before = await _json_request(
                    client, "GET", f"{synthetic_url}/control/state"
                )
                initial_result = await livekit_tool(
                    {"customer_id": "customer-demo-001"}
                )
                state_after_initial = await _json_request(
                    client, "GET", f"{synthetic_url}/control/state"
                )
                initial_delta = (
                    state_after_initial["execution_counts"]["read_customer"]
                    - state_before["execution_counts"]["read_customer"]
                )
                initial_audit_payload = await _json_request(
                    client,
                    "GET",
                    f"{interlock_url}/mcp/audit",
                    api_key=raw_key,
                    params={"limit": 100},
                )
                initial_allow = _find_event(
                    initial_audit_payload["events"],
                    server_id=SERVER_ID,
                    rule="default_allow",
                    tool="read_customer",
                )

                mutation = await _json_request(
                    client,
                    "POST",
                    f"{synthetic_url}/control/mutate/read_customer",
                )
                refresh = await _json_request(
                    client,
                    "POST",
                    f"{interlock_url}/mcp/discover",
                    api_key=raw_key,
                    json={
                        "server_url": f"{synthetic_url}/mcp",
                        "server_id": SERVER_ID,
                    },
                )
                if refresh.get("ok") is not True:
                    raise ProofError("Drift refresh failed.")
                inventory = await _json_request(
                    client,
                    "GET",
                    f"{interlock_url}/mcp/tools",
                    api_key=raw_key,
                    params={"server_id": SERVER_ID},
                )
                drifted = await _json_request(
                    client,
                    "GET",
                    f"{interlock_url}/mcp/tools/drifted",
                    api_key=raw_key,
                    params={"server_id": SERVER_ID},
                )
                drift_row = next(
                    row
                    for row in inventory["tools"]
                    if row["tool_name"] == "read_customer"
                )
                observed_boundary = _boundary(drift_row["normalized_metadata"])
                quarantined_tools = sorted(
                    row["tool_name"]
                    for row in drifted["tools"]
                    if row.get("status") == "quarantined"
                )

                state_before_held = await _json_request(
                    client, "GET", f"{synthetic_url}/control/state"
                )
                held_message = ""
                try:
                    await livekit_tool({"customer_id": "customer-demo-002"})
                except ToolError as exc:
                    held_message = exc.message
                if not held_message:
                    raise ProofError("Changed LiveKit call was not held.")
                state_after_held = await _json_request(
                    client, "GET", f"{synthetic_url}/control/state"
                )
                held_delta = (
                    state_after_held["execution_counts"]["read_customer"]
                    - state_before_held["execution_counts"]["read_customer"]
                )

                audit_payload = await _json_request(
                    client,
                    "GET",
                    f"{interlock_url}/mcp/audit",
                    api_key=raw_key,
                    params={"limit": 100},
                )
                events = audit_payload["events"]
                detection = _find_event(
                    events,
                    server_id=SERVER_ID,
                    rule="drift_detected",
                    tool="read_customer",
                )
                held_event = _find_event(
                    events,
                    server_id=SERVER_ID,
                    rule="tool_quarantined",
                    tool="read_customer",
                )
                receipt = await _json_request(
                    client,
                    "GET",
                    f"{interlock_url}/audit/receipt/{detection['id']}",
                    api_key=raw_key,
                )
                verification = await _json_request(
                    client,
                    "POST",
                    f"{interlock_url}/audit/receipt/verify",
                    api_key=raw_key,
                    json={
                        "context": _receipt_context(receipt),
                        "receipt": receipt,
                        "audit_id": detection["id"],
                    },
                )
                claims = await _json_request(
                    client,
                    "GET",
                    f"{interlock_url}/audit/receipt/{detection['id']}/claims",
                    api_key=raw_key,
                )

                proof = {
                    "proof": (
                        "LiveKit Agents integration through Interlock's local "
                        "MCP compatibility adapter."
                    ),
                    "inputs": {
                        **provenance,
                        "livekit_agents_commit": LIVEKIT_COMMIT,
                        "python": platform.python_version(),
                        "livekit_agents": importlib.metadata.version("livekit-agents"),
                        "mcp_sdk": importlib.metadata.version("mcp"),
                        "docker": _command_version(["docker", "--version"]),
                        "docker_compose": _command_version(
                            ["docker", "compose", "version"]
                        ),
                    },
                    "architecture": [
                        "real LiveKit Agent with attached MCPToolset; no AgentSession",
                        "directly invoked discovered MCPToolset wrapper",
                        "local legacy-MCP compatibility adapter",
                        "Interlock /mcp/call",
                        "synthetic MCP 2026-07-28 server",
                    ],
                    "livekit": {
                        "agent_type": type(agent).__name__,
                        "agent_attached_toolset": agent_attached,
                        "mcp_toolset_type": type(toolset).__name__,
                        "mcp_toolset_initialized": bool(mcp_server.initialized),
                        "discovered_tools": tool_names,
                        "agent_session_started": False,
                        "invocation_mode": "direct_mcp_tool_wrapper_call",
                    },
                    "approval": {
                        "tool_name": "read_customer",
                        "status": baseline_row["status"],
                        "boundary": approved_boundary,
                        "approval_endpoint_called_before_toolset_setup": True,
                        "approval_audit_event_verified_before_toolset_setup": True,
                        "adapter_enforced_explicit_approval": False,
                        "approval_audit_event": {
                            "id": approval_event["id"],
                            "server_id": approval_event["server_id"],
                            "tool_name": approval_event["tool_name"],
                            "matched_rule": approval_event["matched_rule"],
                            "action": approval_event["action"],
                        },
                    },
                    "calls": {
                        "initial": {
                            "gateway_audit_id": initial_allow["id"],
                            "gateway_decision": initial_allow["action"],
                            "upstream_delta": initial_delta,
                            "direct_wrapper_result": str(initial_result),
                        },
                        "held": {
                            "gateway_audit_id": held_event["id"],
                            "gateway_decision": held_event["action"],
                            "upstream_delta": held_delta,
                            "safe_message": held_message,
                        },
                    },
                    "mutation": {
                        "tool_identity_unchanged": (
                            mutation["tool"]["name"] == "read_customer"
                        ),
                        "selected_boundary_changed": (
                            approved_boundary != observed_boundary
                        ),
                    },
                    "drift": {
                        "material": drift_row["drift_severity"] in {"high", "critical"},
                        "status": drift_row["status"],
                        "severity": drift_row["drift_severity"],
                        "decision": drift_row["drift_action"],
                        "observation_refresh": {
                            "endpoint": "POST /mcp/discover",
                            "triggered_explicitly": True,
                            "ok": refresh.get("ok") is True,
                        },
                        "types": drift_row["drift_types"],
                        "reasons": drift_row["drift_reasons"],
                        "approved_boundary": _boundary(drift_row["previous_metadata"]),
                        "observed_boundary": observed_boundary,
                        "quarantined_tools": quarantined_tools,
                    },
                    "review_evidence": {
                        "tool_name": detection["tool_name"],
                        "approved_surface_hash": detection["drift_baseline_hash"],
                        "observed_surface_hash": detection["drift_current_hash"],
                        "reason": detection["reason"],
                        "decision": detection["action"],
                    },
                    "receipt": {
                        "audit_id": detection["id"],
                        "receipt": receipt,
                        "verification": verification,
                        "claims": {
                            "approved": claims["claim_1_approved"],
                            "observed": claims["claim_2_observed"],
                            "decision": claims["claim_3_decision"],
                            "execution_after_detection": claims[
                                "claim_4_execution_after_detection"
                            ],
                        },
                    },
                    "sanitization": {
                        "raw_api_key_retained": False,
                        "private_sentinel_retained": False,
                        "exception_trace_retained": False,
                    },
                }
                _assert_acceptance(proof)

        if toolset is not None:
            await toolset.aclose()
            toolset = None

        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(db_path) + suffix)
            if candidate.exists():
                candidate.unlink()
        _sanitize_and_write(evidence, proof, raw_key=raw_key)
        succeeded = True
        return proof
    finally:
        if toolset is not None:
            await toolset.aclose()
        if not succeeded and evidence.path.exists():
            evidence.cleanup()


def cleanup(evidence_path: Path) -> None:
    EvidenceDirectory(evidence_path).cleanup()


def _print_summary(proof: dict[str, Any], evidence_path: Path) -> None:
    print("PASS LiveKit MCPToolset initialized through the local adapter")
    print("PASS initial gateway call forwarded upstream exactly once")
    print("PASS material same-tool drift quarantined read_customer")
    print("PASS later LiveKit call held with upstream execution delta zero")
    print("PASS receipt chain, evidence digest, and context binding verified")
    print(f"Evidence: {evidence_path.resolve() / PROOF_NAME}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--interlock-port", type=int)
    parser.add_argument("--synthetic-port", type=int)
    args = parser.parse_args()
    try:
        if args.cleanup:
            cleanup(args.evidence_dir)
            print(f"Removed owned proof artifacts: {args.evidence_dir.resolve()}")
            return 0
        proof = asyncio.run(
            run_proof(
                args.evidence_dir,
                interlock_port=args.interlock_port,
                synthetic_port=args.synthetic_port,
            )
        )
        _print_summary(proof, args.evidence_dir)
        return 0
    except (ProofError, KeyboardInterrupt) as exc:
        message = str(exc) if isinstance(exc, ProofError) else "interrupted"
        print(f"FAIL LiveKit proof: {message}", file=sys.stderr)
        return 2
    except Exception:
        print("FAIL LiveKit proof: unexpected internal error.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
