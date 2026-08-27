#!/usr/bin/env python3
"""Self-guided, non-production evaluator journey for Interlock.

This stdlib-only runner drives existing Interlock APIs and the bundled MCP mock.
It does not implement an alternate enforcement path. Generated artifacts contain
only normalized decisions, hashes, counts, and verification results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SERVER_ID = "demo-docs"
SERVER_PATH = "/docs"
TOOL_NAME = "read_file"
CONTROL_TOOL = "list_documents"
SCENARIO = "internal_document_external_export_boundary"
DISPLAY_NAME = "private document workspace"
PROOF_CHAIN = "approved boundary → changed boundary → held call → verified receipt"

DEFAULT_GATEWAY = os.getenv("INTERLOCK_DEMO_GATEWAY", "http://localhost:8001")
DEFAULT_MOCK_ADMIN = os.getenv("INTERLOCK_DEMO_MOCK_ADMIN", "http://localhost:9100")
DEFAULT_MOCK_INTERNAL = os.getenv(
    "INTERLOCK_DEMO_MOCK_INTERNAL", "http://mcp-mock:9100"
)
DEFAULT_API_KEY = os.getenv("INTERLOCK_DEMO_KEY", "lf-demo-offline-key")
DEFAULT_OUTPUT = Path(
    os.getenv(
        "INTERLOCK_EVALUATOR_OUTPUT",
        str(Path(__file__).resolve().parent / "evaluator-artifacts"),
    )
)

ALLOWED_SERVICE_HOSTS = {"127.0.0.1", "::1", "localhost", "gateway", "mcp-mock"}
PACK_FILES = (
    "approved-state.json",
    "changed-state.json",
    "held-call.json",
    "receipt-summary.json",
    "summary.md",
    "feedback.md",
    "operator-action.json",
    "manifest.json",
)
FORBIDDEN_ARTIFACT_VALUES = (
    SERVER_ID,
    f"{DEFAULT_MOCK_INTERNAL}{SERVER_PATH}",
    "evaluator-document",
    "review@example.invalid",
)
APPROVED_BOUNDARY_LIST_VALUES = {
    "effects": {
        "read",
        "create",
        "update",
        "delete",
        "share",
        "export",
        "message",
        "execute",
    },
    "data_classes": {
        "pii",
        "phi",
        "financial",
        "legal",
        "secrets",
        "user_content",
        "internal",
    },
}
OPERATOR_ACTION_MEANINGS = {
    "reject": (
        "the changed tool stays held; the approved boundary is unchanged and "
        "you can still approve or rebaseline later"
    ),
    "approve": ("the changed boundary is now the approved boundary for this one tool"),
    "rebaseline": ("the whole current server surface is now the approved boundary"),
}
APPROVED_BOUNDARY_SCALAR_VALUES = {
    "side_effect": {"read_only", "mutating", "destructive"},
    "externality": {"internal", "external"},
    "identity_mode": {"authenticated_user", "service_account", "delegated_agent"},
}


class JourneyError(RuntimeError):
    """A fail-closed evaluator journey error safe to print to the evaluator."""


def validate_service_url(value: str) -> str:
    """Accept only the explicit loopback/Compose origins used by this proof."""
    parsed = urlparse(str(value or ""))
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ALLOWED_SERVICE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("evaluator service URLs must use an approved local origin")
    return value.rstrip("/")


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _boundary_from_inventory(tool_row: dict) -> dict:
    """Project only allowlisted normalized fields from Interlock's inventory.

    Interlock overwrites `normalized_metadata` with the observed surface when it
    records drift, so the same projection yields the approved boundary from the
    pre-change row and the observed boundary from the post-change row.
    """
    metadata = tool_row.get("normalized_metadata")
    if not isinstance(metadata, dict):
        return {}

    boundary: dict[str, Any] = {}
    for field, allowed in APPROVED_BOUNDARY_LIST_VALUES.items():
        value = metadata.get(field)
        if isinstance(value, list):
            normalized = sorted(
                {
                    str(item)
                    for item in value
                    if isinstance(item, str) and item in allowed
                }
            )
            if normalized:
                boundary[field] = normalized
    for field, allowed in APPROVED_BOUNDARY_SCALAR_VALUES.items():
        value = metadata.get(field)
        if isinstance(value, str) and value in allowed:
            boundary[field] = value
    return dict(sorted(boundary.items()))


def _boundary_summary(boundary: dict) -> str:
    if not boundary:
        return "no allowlisted normalized boundary fields were observable"
    parts = []
    for field in sorted(boundary):
        value = boundary[field]
        rendered = ",".join(value) if isinstance(value, list) else str(value)
        parts.append(f"{field}={rendered}")
    return "; ".join(parts)


def _material_change_summary(approved: dict, observed: dict) -> str:
    """Describe how the observed boundary widened, from observed fields only."""
    headlines: list[str] = []
    gained_effects = sorted(
        set(observed.get("effects") or []) - set(approved.get("effects") or [])
    )
    if "export" in gained_effects:
        headlines.append("external export was added to the approved tool")
    other_effects = [effect for effect in gained_effects if effect != "export"]
    if other_effects:
        headlines.append("new effects appeared (" + ",".join(other_effects) + ")")
    if (
        approved.get("externality") == "internal"
        and observed.get("externality") == "external"
    ):
        headlines.append("the boundary moved from internal to external")
    gained_data = sorted(
        set(observed.get("data_classes") or [])
        - set(approved.get("data_classes") or [])
    )
    if gained_data:
        headlines.append("broader data handling (" + ",".join(gained_data) + ")")
    if approved.get("side_effect") == "read_only" and observed.get(
        "side_effect"
    ) not in (None, "read_only"):
        headlines.append(
            "the tool is no longer read_only (now "
            + str(observed.get("side_effect"))
            + ")"
        )
    if not headlines:
        return (
            "no allowlisted normalized boundary field widened; see change_types "
            "for Interlock's recorded classification"
        )
    return (
        "the same tool name kept its identity while its boundary widened: "
        + "; ".join(headlines)
    )


def _record_gateway_call(
    client: Any, records: list[dict], body: dict
) -> tuple[int | None, dict]:
    """Send one `/mcp/call` and record what happened to it.

    Call counts in the evidence are observed here rather than assumed, so
    adding a step to this journey renumbers the artifacts instead of leaving a
    stale "call 2 of 2" claim behind.
    """
    status, payload = _gateway(client, "POST", "/mcp/call", body)
    records.append(
        {
            "tool": str(body.get("tool_name") or ""),
            "held": payload.get("error") == "tool_quarantined",
        }
    )
    return status, payload


def _held_call_facts(records: list[dict]) -> tuple[int, int]:
    """Return the 1-based index of the held call and the total calls observed."""
    held = [index for index, record in enumerate(records, start=1) if record["held"]]
    if len(held) != 1:
        raise JourneyError(
            "expected exactly one held gateway call this run; observed "
            f"{len(held)} held across {len(records)} calls"
        )
    return held[0], len(records)


def _expect(
    response: tuple[int | None, dict],
    operation: str,
    accepted: tuple[int, ...] = (200,),
) -> dict:
    status, payload = response
    if status not in accepted:
        error = str((payload or {}).get("error") or (payload or {}).get("detail") or "")
        safe_error = re.sub(r"https?://\S+", "<local-service>", error)[:160]
        raise JourneyError(
            f"{operation} failed [{status}]: {safe_error or 'unexpected response'}"
        )
    if not isinstance(payload, dict):
        raise JourneyError(f"{operation} failed: response was not a JSON object")
    return payload


class HttpEvaluatorClient:
    """Minimal HTTP adapter restricted to the evaluator's local services."""

    def __init__(
        self,
        gateway: str = DEFAULT_GATEWAY,
        mock_admin: str = DEFAULT_MOCK_ADMIN,
        api_key: str = DEFAULT_API_KEY,
    ) -> None:
        self.gateway = validate_service_url(gateway)
        self.mock_admin = validate_service_url(mock_admin)
        self.api_key = api_key

    def request(
        self,
        service: str,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> tuple[int | None, dict]:
        if service not in {"gateway", "mock"} or not path.startswith("/"):
            raise JourneyError(
                "runner refused an unknown service or non-absolute API path"
            )
        base = self.gateway if service == "gateway" else self.mock_admin
        data = _canonical_json_bytes(body) if body is not None else None
        request = urllib.request.Request(base + path, data=data, method=method)
        if service == "gateway":
            request.add_header("x-api-key", self.api_key)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
                return response.getcode(), json.loads(raw or "{}")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {"error": "non-JSON local service error"}
            return exc.code, payload
        except (urllib.error.URLError, TimeoutError) as exc:
            raise JourneyError(f"{service} service is unavailable") from exc


def _wait_for_services(client: Any, attempts: int = 30) -> None:
    for service in ("gateway", "mock"):
        for _ in range(attempts):
            status, _ = client.request(service, "GET", "/health")
            if status == 200:
                break
            time.sleep(1)
        else:
            raise JourneyError(f"{service} did not become healthy")


def _gateway(client: Any, method: str, path: str, body: dict | None = None):
    return client.request("gateway", method, path, body)


def _mock(client: Any, method: str, path: str, body: dict | None = None):
    return client.request("mock", method, path, body)


def _set_phase(client: Any, phase: int) -> None:
    _expect(
        _mock(client, "POST", "/__demo__/phase", {"path": SERVER_PATH, "phase": phase}),
        "set controlled MCP phase",
    )


def _reset_mock(client: Any) -> None:
    _set_phase(client, 1)
    _expect(_mock(client, "POST", "/__demo__/calls/reset"), "reset execution counter")


def _call_total(client: Any) -> int:
    payload = _expect(_mock(client, "GET", "/__demo__/calls"), "read execution counter")
    total = payload.get("total")
    if not isinstance(total, int) or total < 0:
        raise JourneyError("execution counter returned an invalid total")
    return total


def _discover(client: Any) -> dict:
    internal_mock = validate_service_url(DEFAULT_MOCK_INTERNAL)
    return _expect(
        _gateway(
            client,
            "POST",
            "/mcp/discover",
            {
                "server_url": f"{internal_mock}{SERVER_PATH}",
                "server_id": SERVER_ID,
            },
        ),
        "discover MCP boundary",
    )


def _approve(client: Any, tool_name: str, reason: str) -> dict:
    review_hash = _tool_row(client).get("review_surface_hash")
    if not isinstance(review_hash, str):
        raise JourneyError("review surface hash was unavailable")
    return _expect(
        _gateway(
            client,
            "POST",
            f"/mcp/tools/{SERVER_ID}/{tool_name}/approve",
            {
                "expected_surface_hash": review_hash,
                "reviewer": "local-evaluator",
                "reason": reason,
            },
        ),
        f"approve {tool_name} baseline",
    )


def _tool_row(client: Any) -> dict:
    payload = _expect(
        _gateway(client, "GET", f"/mcp/tools?server_id={SERVER_ID}"),
        "read MCP tool state",
    )
    for tool in payload.get("tools") or []:
        if tool.get("tool_name") == TOOL_NAME:
            return tool
    raise JourneyError("the evaluated tool was not present in Interlock's inventory")


def _latest_detection(client: Any) -> dict:
    payload = _expect(_gateway(client, "GET", "/mcp/audit?limit=100"), "read audit log")
    for event in payload.get("events") or []:
        if (
            event.get("server_id") == SERVER_ID
            and event.get("tool_name") == TOOL_NAME
            and event.get("matched_rule") == "drift_detected"
        ):
            return event
    raise JourneyError("Interlock did not return a drift-detection audit row")


def _verification_context(binding: dict) -> dict:
    return {
        "server_id": SERVER_ID,
        "tool_name": TOOL_NAME,
        "argument_hash": binding.get("argument_hash") or "",
        "call_id": binding.get("call_id") or "",
        "surface_hash": binding.get("surface_hash") or "",
    }


def _ensure_hash(value: Any, label: str) -> str:
    text = str(value or "")
    if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", text):
        raise JourneyError(f"{label} was not a SHA-256 value")
    return text


def _artifact_safe(text: str, output_dir: Path) -> None:
    forbidden = (*FORBIDDEN_ARTIFACT_VALUES, str(output_dir.resolve()))
    for value in forbidden:
        if value and value in text:
            raise JourneyError("artifact sanitization rejected a forbidden raw value")
    if re.search(r"https?://", text, flags=re.IGNORECASE):
        raise JourneyError("artifact sanitization rejected a URL")
    if re.search(r"(?:[A-Za-z]:\\|/Users/|/home/)", text):
        raise JourneyError("artifact sanitization rejected an absolute path")
    if any(key in text for key in ("inputSchema", "raw_tool_definition", "arguments")):
        raise JourneyError("artifact sanitization rejected raw schema or arguments")


def _write_pack(output_dir: Path, artifacts: dict[str, Any], summary: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    staging = output_dir / ".staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    feedback_source = Path(__file__).resolve().with_name("EVALUATOR_FEEDBACK.md")
    try:
        for name, value in artifacts.items():
            data = _canonical_json_bytes(value)
            _artifact_safe(data.decode("utf-8"), output_dir)
            (staging / name).write_bytes(data)
        _artifact_safe(summary, output_dir)
        (staging / "summary.md").write_text(summary, encoding="utf-8", newline="\n")
        feedback = feedback_source.read_text(encoding="utf-8")
        _artifact_safe(feedback, output_dir)
        (staging / "feedback.md").write_text(feedback, encoding="utf-8", newline="\n")
        manifest = {
            "artifactType": "interlock.evaluator.manifest.v1",
            "files": {
                item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                for item in sorted(staging.iterdir())
            },
        }
        (staging / "manifest.json").write_bytes(_canonical_json_bytes(manifest))
        for name in PACK_FILES:
            target = output_dir / name
            if target.exists():
                target.unlink()
        for item in staging.iterdir():
            item.replace(output_dir / item.name)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _cleanup_incomplete_pack(output_dir: Path) -> None:
    staging = output_dir / ".staging"
    if staging.exists():
        shutil.rmtree(staging)
    for name in PACK_FILES:
        target = output_dir / name
        if target.exists():
            target.unlink()


def _refresh_manifest(output_dir: Path) -> None:
    files = {
        item.name: hashlib.sha256(item.read_bytes()).hexdigest()
        for item in sorted(output_dir.iterdir())
        if item.is_file() and item.name != "manifest.json"
    }
    (output_dir / "manifest.json").write_bytes(
        _canonical_json_bytes(
            {"artifactType": "interlock.evaluator.manifest.v1", "files": files}
        )
    )


def run_journey(client: Any, output_dir: Path | str) -> dict:
    """Run the real supported proof path and write a sanitized artifact pack."""
    output = Path(output_dir)
    _cleanup_incomplete_pack(output)
    try:
        internal_mock = validate_service_url(DEFAULT_MOCK_INTERNAL)
        print("[1/7] Start local services and reset the controlled MCP example")
        _wait_for_services(client)
        _reset_mock(client)

        print("[2/7] Register, discover, and approve the known-good baseline")
        registration = _gateway(
            client,
            "POST",
            "/mcp/servers",
            {
                "server_id": SERVER_ID,
                "url": f"{internal_mock}{SERVER_PATH}",
                "description": "Local non-production private document workspace",
                "allowed_tools": [TOOL_NAME, CONTROL_TOOL],
                "blocked_tools": [],
                "environment": "non_production",
                "probes_enabled": False,
            },
        )
        if (
            registration[0] not in (200, 201)
            and registration[1].get("error") != "already_exists"
        ):
            _expect(registration, "register local MCP server", accepted=(200, 201))
        if registration[1].get("error") == "already_exists":
            _expect(
                _gateway(
                    client,
                    "POST",
                    f"/mcp/servers/{SERVER_ID}/environment",
                    {"environment": "non_production", "probes_enabled": False},
                ),
                "set local MCP environment",
            )
        _expect(
            _gateway(client, "POST", f"/mcp/servers/{SERVER_ID}/verify"),
            "verify local MCP server",
        )
        clean_discovery = _discover(client)
        if clean_discovery.get("blocked_tools") or clean_discovery.get("blocked"):
            raise JourneyError("known-good baseline was unexpectedly blocked")
        _approve(
            client, TOOL_NAME, "Evaluator approved the internal read-only boundary."
        )
        _approve(
            client, CONTROL_TOOL, "Evaluator approved the unchanged listing control."
        )
        approved_row = _tool_row(client)
        if approved_row.get("status") != "active":
            raise JourneyError("approved baseline did not become active")

        print("[3/7] Execute one benign approved call through /mcp/call")
        gateway_calls: list[dict] = []
        _expect(
            _record_gateway_call(
                client,
                gateway_calls,
                {
                    "server_id": SERVER_ID,
                    "tool_name": TOOL_NAME,
                    "arguments": {"doc_id": "evaluator-document"},
                },
            ),
            "execute approved baseline call",
        )
        if _call_total(client) != 1:
            raise JourneyError("approved baseline call did not execute exactly once")

        print("[4/7] Apply one controlled external-export boundary change")
        _set_phase(client, 2)
        changed_discovery = _discover(client)
        if changed_discovery.get("blocked_tools") != 1:
            raise JourneyError("controlled material change was not quarantined")
        changed_row = _tool_row(client)
        if changed_row.get("status") != "quarantined":
            raise JourneyError("changed tool was not stored as quarantined")

        print("[5/7] Attempt the changed call through Interlock's gateway")
        before = _call_total(client)
        _, held_outcome = _record_gateway_call(
            client,
            gateway_calls,
            {
                "server_id": SERVER_ID,
                "tool_name": TOOL_NAME,
                "arguments": {
                    "doc_id": "evaluator-document",
                    "email": "review@example.invalid",
                    "include_attachments": True,
                },
            },
        )
        after = _call_total(client)
        if held_outcome.get("error") != "tool_quarantined":
            raise JourneyError("changed gateway call did not return tool_quarantined")
        if after != before:
            raise JourneyError(
                "changed tool reached upstream execution despite quarantine"
            )

        held_call_index, gateway_calls_total = _held_call_facts(gateway_calls)

        print("[6/7] Retrieve and verify Interlock's real evidence")
        detection = _latest_detection(client)
        audit_id = detection.get("id")
        receipt = _expect(
            _gateway(client, "GET", f"/audit/receipt/{audit_id}"),
            "read Security Receipt",
        )
        verification = _expect(
            _gateway(
                client,
                "POST",
                "/audit/receipt/verify",
                {
                    "receipt": receipt,
                    "context": _verification_context(receipt.get("binding") or {}),
                },
            ),
            "verify Security Receipt",
        )
        if verification.get("verified") is not True:
            raise JourneyError("Security Receipt verification failed")
        claims = _expect(
            _gateway(client, "GET", f"/audit/receipt/{audit_id}/claims"),
            "read decision claims",
        )
        approved_hash = _ensure_hash(
            (claims.get("claim_1_approved") or {}).get("approved_surface_hash"),
            "approved surface hash",
        )
        observed_hash = _ensure_hash(
            (claims.get("claim_2_observed") or {}).get("observed_surface_hash"),
            "observed surface hash",
        )
        decision = claims.get("claim_3_decision") or {}
        execution = claims.get("claim_4_execution_after_detection") or {}
        if execution.get("boundary_crossing_executed") is not False:
            raise JourneyError("claim evidence did not prove a held gateway path")
        approved_boundary = _boundary_from_inventory(approved_row)
        observed_boundary = _boundary_from_inventory(changed_row)
        material_change = _material_change_summary(approved_boundary, observed_boundary)
        change_types = sorted(str(v) for v in changed_row.get("drift_types") or [])
        severity = str(changed_row.get("drift_severity") or "")

        artifacts = {
            "approved-state.json": {
                "artifactType": "interlock.evaluator.approved.v1",
                "scenario": SCENARIO,
                "tool": TOOL_NAME,
                "status": str(approved_row.get("status") or ""),
                "boundary": approved_boundary,
                "boundary_source": "interlock_tool_inventory.normalized_metadata",
                "surface_hash": approved_hash,
                "approved_call_executions": before,
            },
            "changed-state.json": {
                "artifactType": "interlock.evaluator.changed.v1",
                "scenario": SCENARIO,
                "tool": TOOL_NAME,
                "status": str(changed_row.get("status") or ""),
                "decision": str(changed_row.get("drift_action") or ""),
                "severity": severity,
                "change_types": change_types,
                "boundary": observed_boundary,
                "boundary_source": "interlock_tool_inventory.normalized_metadata",
                "material_change": material_change,
                "surface_hash": observed_hash,
            },
            "held-call.json": {
                "artifactType": "interlock.evaluator.held-call.v1",
                "scenario": SCENARIO,
                "tool": TOOL_NAME,
                "held_call": {
                    "tool": TOOL_NAME,
                    "call_index": held_call_index,
                    "calls_attempted_through_gateway": gateway_calls_total,
                    "held_at": "interlock_gateway_before_upstream_tools_call",
                    "requested_beyond_approved_boundary": (
                        "send the same document to an external recipient and "
                        "forward its attachments"
                    ),
                    "held_because": (
                        "the stored tool was quarantined by the material boundary "
                        "change found at re-discovery, before this call could be "
                        "forwarded upstream"
                    ),
                },
                "gateway_error": "tool_quarantined",
                "forwarded": False,
                "upstream_calls_before": before,
                "upstream_calls_after": after,
                "upstream_execution_delta": after - before,
                "audit_executed_count": int(execution.get("executed_count") or 0),
                "audit_blocked_attempts": int(execution.get("blocked_attempts") or 0),
            },
            "receipt-summary.json": {
                "artifactType": "interlock.evaluator.receipt-summary.v1",
                "scenario": SCENARIO,
                "decision": str(
                    receipt.get("decision") or decision.get("decision") or ""
                ),
                "rule": str(decision.get("rule_fired") or ""),
                "integrity_hash": _ensure_hash(
                    receipt.get("integrity_hash"), "receipt integrity hash"
                ),
                "chain_verified": bool(
                    receipt.get("chain_verified", claims.get("chain_verified", False))
                ),
                "verified": True,
                "verification_checks": verification.get("checks") or {},
                "approved_surface_hash": approved_hash,
                "observed_surface_hash": observed_hash,
                "binding_redacted": True,
                "verification_proves": [
                    "the stored audit row recomputes to this receipt integrity hash",
                    "the audit hash chain verifies across the stored records",
                    "the receipt is bound to this exact call and fails if "
                    "presented for another",
                ],
                "verification_does_not_prove": [
                    "anything about calls made outside Interlock's gateway",
                    "that this receipt is externally signed or independently "
                    "anchored",
                ],
            },
        }
        summary = (
            "# Interlock evaluator evidence summary\n\n"
            f"Scenario: {DISPLAY_NAME}.\n\n"
            f"Proof chain: {PROOF_CHAIN}.\n\n"
            "## Approved boundary\n\n"
            "What you approved before anything changed:\n\n"
            f"- {_boundary_summary(approved_boundary)}\n"
            f"- approved surface hash: `{approved_hash}`\n\n"
            "## Observed boundary\n\n"
            "What Interlock read from the same tool name at re-discovery:\n\n"
            f"- {_boundary_summary(observed_boundary)}\n"
            f"- observed surface hash: `{observed_hash}`\n\n"
            "## Material change\n\n"
            f"- {material_change}.\n"
            f"- Interlock severity: {severity or 'not recorded'}; "
            f"recorded change types: {', '.join(change_types) or 'none'}.\n"
            "- The tool was not held for being new or unknown. It was held "
            "because the boundary you approved is not the boundary now being "
            "offered under that same tool name.\n\n"
            "## Held call\n\n"
            f"- Interlock held call {held_call_index} of the "
            f"{gateway_calls_total} calls this run made through its gateway.\n"
            "- The calls before it used the approved read-only boundary and "
            "executed normally.\n"
            f"- Call {held_call_index} asked the same tool to also send the "
            "document to an external recipient and forward its attachments.\n"
            "- Interlock answered `tool_quarantined` at its own gateway and "
            "never sent the upstream `tools/call`.\n"
            "- The bundled server's independent execution counter did not move "
            f"across the held call ({before} before, {after} after).\n\n"
            "## Operator decision\n\n"
            "You are the operator for this decision. Choose exactly one:\n\n"
            "- `reject` - the changed tool stays held. The approved boundary is "
            "unchanged and nothing upstream is altered. This is the safe answer "
            "while you do not yet know whether the change was deliberate.\n"
            "- `approve` - accept the changed boundary for this one tool.\n"
            "- `rebaseline` - accept the whole current server surface as the new "
            "approved boundary.\n\n"
            "Reject is reversible. If whoever owns the tool confirms the change "
            "was intentional, run `approve` or `rebaseline` afterwards.\n\n"
            "## What receipt verification proves\n\n"
            "- Interlock's stored audit row for this decision is internally "
            "consistent and unaltered: the receipt integrity hash recomputes and "
            "the audit hash chain verifies.\n"
            "- The receipt is bound to this exact call, so it fails if presented "
            "for a different one.\n\n"
            "It does not prove anything about calls made outside Interlock's "
            "gateway, and the receipt is not externally signed or independently "
            "anchored.\n"
        )
        _write_pack(output, artifacts, summary)

        print("[7/7] Review artifacts and choose approve, reject, or rebaseline")
        print(
            "      result=tool_quarantined forwarded=false upstream_execution_delta=0"
        )
        print("      receipt_verified=true artifacts=evaluator-artifacts")
        print(
            f"      held_call={TOOL_NAME} "
            f"(call {held_call_index} of {gateway_calls_total} "
            "through the gateway this run)"
        )
        print(
            "      read evaluator-artifacts/summary.md for the labelled "
            "decision facts"
        )
        return {"held": True, "forwarded": False, "artifacts": str(output)}
    except BaseException as exc:
        try:
            _reset_mock(client)
        except BaseException:
            pass
        _cleanup_incomplete_pack(output)
        if isinstance(exc, JourneyError):
            raise
        raise JourneyError(str(exc)) from exc


def apply_operator_action(client: Any, output_dir: Path | str, action: str) -> dict:
    """Apply one explicit existing control-plane action after evidence review."""
    normalized = str(action or "").lower()
    if normalized not in {"approve", "reject", "rebaseline"}:
        raise JourneyError("action must be approve, reject, or rebaseline")
    output = Path(output_dir)
    if not (output / "held-call.json").is_file():
        raise JourneyError(
            "run and review the evaluator proof before choosing an action"
        )
    if normalized == "approve":
        review_hash = _tool_row(client).get("review_surface_hash")
        if not isinstance(review_hash, str):
            raise JourneyError("review surface hash was unavailable")
        payload = _expect(
            _gateway(
                client,
                "POST",
                f"/mcp/tools/{SERVER_ID}/{TOOL_NAME}/approve",
                {
                    "expected_surface_hash": review_hash,
                    "reviewer": "local-evaluator",
                    "reason": "Evaluator accepted the changed per-tool boundary.",
                },
            ),
            "approve changed tool",
        )
    elif normalized == "reject":
        payload = _expect(
            _gateway(
                client,
                "POST",
                f"/mcp/tools/{SERVER_ID}/{TOOL_NAME}/quarantine",
                {
                    "reviewer": "local-evaluator",
                    "reason": "Evaluator rejected the changed boundary.",
                },
            ),
            "keep changed tool quarantined",
        )
    else:
        candidate = _expect(
            _gateway(
                client,
                "POST",
                f"/mcp/servers/{SERVER_ID}/rebaseline/discover",
            ),
            "stage complete-server rebaseline",
        )
        payload = _expect(
            _gateway(
                client,
                "POST",
                f"/mcp/servers/{SERVER_ID}/rebaseline",
                {
                    "confirm_rebaseline": True,
                    "expected_current_hash": candidate.get("active_surface_hash"),
                    "expected_candidate_hash": candidate.get("candidate_surface_hash"),
                },
            ),
            "promote complete-server rebaseline",
        )
    outcome = {
        "artifactType": "interlock.evaluator.operator-action.v1",
        "scenario": SCENARIO,
        "action": normalized,
        "ok": bool(payload.get("ok", True)),
        "resulting_posture": (
            "held" if normalized == "reject" else "approved_changed_boundary"
        ),
        "changes_approved_boundary": normalized != "reject",
        "meaning": OPERATOR_ACTION_MEANINGS[normalized],
    }
    output.mkdir(parents=True, exist_ok=True)
    encoded = _canonical_json_bytes(outcome)
    _artifact_safe(encoded.decode("utf-8"), output)
    (output / "operator-action.json").write_bytes(encoded)
    _refresh_manifest(output)
    print(f"operator_action={normalized} ok={str(outcome['ok']).lower()}")
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("run", help="run the complete held-call evaluator proof")
    decide = subparsers.add_parser("decide", help="apply one reviewed operator action")
    decide.add_argument("action", choices=("approve", "reject", "rebaseline"))
    args = parser.parse_args()
    try:
        client = HttpEvaluatorClient()
        if args.command == "run":
            run_journey(client, args.output)
        else:
            apply_operator_action(client, args.output, args.action)
        return 0
    except (JourneyError, ValueError) as exc:
        print(f"EVALUATION FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
