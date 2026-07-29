"""Contracts for the self-guided, loopback-only evaluator journey."""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "demo" / "offline" / "evaluator_journey.py"
FEEDBACK = ROOT / "demo" / "offline" / "EVALUATOR_FEEDBACK.md"
GUIDE = ROOT / "docs" / "evaluator-quickstart.md"
COMPOSE = ROOT / "demo" / "offline" / "docker-compose.yml"

QUESTIONS = [
    "What did you think Interlock was checking before you ran it?",
    "What changed in the MCP tool?",
    "Why was the call held?",
    "What evidence supported the decision?",
    "What would you do next: approve, reject, or rebaseline?",
    "Where did the process confuse or slow you down?",
    "Would you keep Interlock in this workflow? Why or why not?",
]


def _load_runner():
    spec = importlib.util.spec_from_file_location("evaluator_journey", RUNNER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeEvaluatorClient:
    """Deterministic API double; it models only responses the runner consumes."""

    def __init__(
        self,
        *,
        receipt_suffix="a",
        fail_on_changed_discovery=False,
        approved_metadata=None,
    ):
        self.phase = 1
        self.upstream_calls = 0
        self.receipt_suffix = receipt_suffix
        self.fail_on_changed_discovery = fail_on_changed_discovery
        self.approved_metadata = (
            approved_metadata
            if approved_metadata is not None
            else {
                "effects": ["read"],
                "side_effect": "read_only",
                "data_classes": ["user_content", "internal"],
                "externality": "internal",
                "source": "mcp_annotations",
            }
        )
        self.requests = []

    def request(self, service, method, path, body=None):
        self.requests.append((service, method, path, body))
        if service == "mock":
            if path == "/health":
                return 200, {"ok": True}
            if path == "/__demo__/calls/reset":
                self.upstream_calls = 0
                return 200, {"ok": True}
            if path == "/__demo__/calls":
                return 200, {"total": self.upstream_calls}
            if path == "/__demo__/phase":
                self.phase = int(body["phase"])
                return 200, {"ok": True, "phase": self.phase}
        if service != "gateway":
            raise AssertionError(f"unexpected service: {service}")
        if path == "/health":
            return 200, {"ok": True}
        if path == "/mcp/servers":
            return 201, {"ok": True}
        if path.startswith("/mcp/servers/") and path.endswith("/verify"):
            return 200, {"ok": True}
        if path == "/mcp/discover":
            if self.phase == 2 and self.fail_on_changed_discovery:
                raise RuntimeError("synthetic discovery failure")
            if self.phase == 1:
                return 200, {"ok": True, "blocked": [], "blocked_tools": 0}
            return 200, {
                "ok": True,
                "blocked_tools": 1,
                "blocked": [{"name": "read_file", "reason": "material drift"}],
            }
        if path.endswith("/approve"):
            return 200, {"ok": True}
        if path.endswith("/quarantine"):
            return 200, {"ok": True}
        if path == "/mcp/tools?server_id=demo-docs":
            return 200, {
                "tools": [
                    {
                        "tool_name": "read_file",
                        "status": "active" if self.phase == 1 else "quarantined",
                        "drift_action": "allow" if self.phase == 1 else "quarantine",
                        "drift_severity": "none" if self.phase == 1 else "critical",
                        "drift_types": (
                            []
                            if self.phase == 1
                            else [
                                "schema_field_added",
                                "side_effect_escalated",
                                "externality_expanded",
                            ]
                        ),
                        "normalized_metadata": self.approved_metadata,
                    }
                ]
            }
        if path == "/mcp/call":
            if self.phase == 1:
                self.upstream_calls += 1
                return 200, {"ok": True}
            return 409, {"error": "tool_quarantined", "audit": 99}
        if path == "/mcp/audit?limit=100":
            return 200, {
                "events": [
                    {
                        "id": 99,
                        "server_id": "demo-docs",
                        "tool_name": "read_file",
                        "matched_rule": "drift_detected",
                    }
                ]
            }
        if path == "/audit/receipt/99":
            return 200, {
                "receipt_id": f"receipt-{self.receipt_suffix}",
                "decision": "quarantine",
                "integrity_hash": self.receipt_suffix * 64,
                "binding": {
                    "target": "demo-docs/read_file",
                    "argument_hash": "sha256:" + "b" * 64,
                    "call_id": "call-private",
                    "surface_hash": "sha256:" + "2" * 64,
                },
            }
        if path == "/audit/receipt/verify":
            return 200, {"verified": True, "checks": {"integrity_hash": True}}
        if path == "/audit/receipt/99/claims":
            return 200, {
                "claim_1_approved": {"approved_surface_hash": "sha256:" + "1" * 64},
                "claim_2_observed": {"observed_surface_hash": "sha256:" + "2" * 64},
                "claim_3_decision": {
                    "decision": "quarantine",
                    "rule_fired": "drift_detected",
                },
                "claim_4_execution_after_detection": {
                    "boundary_crossing_executed": False,
                    "executed_count": 0,
                    "blocked_attempts": 1,
                },
            }
        if path == "/mcp/servers/demo-docs/rebaseline/discover":
            return 200, {
                "ok": True,
                "active_surface_hash": "sha256:" + "1" * 64,
                "candidate_surface_hash": "sha256:" + "2" * 64,
            }
        if path == "/mcp/servers/demo-docs/rebaseline":
            return 200, {"ok": True, "new_surface_hash": "sha256:" + "2" * 64}
        raise AssertionError(f"unexpected request: {service} {method} {path}")


def _json_artifacts(path):
    return {
        item.name: json.loads(item.read_text(encoding="utf-8"))
        for item in path.glob("*.json")
    }


def test_feedback_template_contains_exactly_the_required_questions():
    text = FEEDBACK.read_text(encoding="utf-8")
    assert [
        line[3:]
        for line in text.splitlines()
        if line.startswith("1. ") or line[:3] in {f"{n}. " for n in range(2, 8)}
    ] == QUESTIONS
    assert text.count("?") == sum(question.count("?") for question in QUESTIONS)


def test_full_happy_path_writes_complete_real_evidence_pack(tmp_path):
    runner = _load_runner()
    client = FakeEvaluatorClient()

    result = runner.run_journey(client, tmp_path)

    assert result["held"] is True
    assert result["forwarded"] is False
    assert client.phase == 2
    assert client.upstream_calls == 1, "only the approved baseline call may execute"
    assert {p.name for p in tmp_path.iterdir()} == {
        "approved-state.json",
        "changed-state.json",
        "held-call.json",
        "receipt-summary.json",
        "summary.md",
        "feedback.md",
        "manifest.json",
    }
    artifacts = _json_artifacts(tmp_path)
    assert artifacts["approved-state.json"]["status"] == "active"
    assert artifacts["approved-state.json"]["boundary"] == {
        "data_classes": ["internal", "user_content"],
        "effects": ["read"],
        "externality": "internal",
        "side_effect": "read_only",
    }
    assert artifacts["approved-state.json"]["approved_call_executions"] == 1
    assert artifacts["changed-state.json"]["decision"] == "quarantine"
    assert artifacts["held-call.json"]["upstream_execution_delta"] == 0
    assert artifacts["receipt-summary.json"]["verified"] is True


def test_material_change_is_held_before_changed_tool_execution(tmp_path):
    runner = _load_runner()
    client = FakeEvaluatorClient()

    runner.run_journey(client, tmp_path)

    held = json.loads((tmp_path / "held-call.json").read_text(encoding="utf-8"))
    assert held["gateway_error"] == "tool_quarantined"
    assert held["forwarded"] is False
    assert held["upstream_calls_before"] == held["upstream_calls_after"] == 1


def test_artifacts_exclude_raw_identity_url_arguments_paths_and_schema(tmp_path):
    runner = _load_runner()
    runner.run_journey(FakeEvaluatorClient(), tmp_path)

    combined = "\n".join(
        item.read_text(encoding="utf-8") for item in sorted(tmp_path.iterdir())
    )
    forbidden = (
        "demo-docs",
        "http://mcp-mock:9100/docs",
        "q3-report",
        "review@example.invalid",
        str(tmp_path),
        "inputSchema",
        "raw_tool_definition",
    )
    for value in forbidden:
        assert value not in combined


def test_approved_artifact_tracks_authoritative_inventory_metadata(tmp_path):
    runner = _load_runner()
    first = tmp_path / "first"
    second = tmp_path / "second"
    runner.run_journey(
        FakeEvaluatorClient(
            approved_metadata={
                "effects": ["read"],
                "side_effect": "read_only",
                "externality": "internal",
            }
        ),
        first,
    )
    runner.run_journey(
        FakeEvaluatorClient(
            approved_metadata={
                "effects": ["read", "export"],
                "side_effect": "read_only",
                "externality": "external",
                "unobserved_assertion": "must not escape",
            }
        ),
        second,
    )

    first_state = json.loads((first / "approved-state.json").read_text())
    second_state = json.loads((second / "approved-state.json").read_text())
    assert first_state["boundary"] != second_state["boundary"]
    assert second_state["boundary"] == {
        "effects": ["export", "read"],
        "externality": "external",
        "side_effect": "read_only",
    }
    assert "unobserved_assertion" not in json.dumps(second_state)
    assert "required_input_classes" not in json.dumps(first_state)


def test_normalized_decision_artifacts_are_deterministic(tmp_path):
    runner = _load_runner()
    first = tmp_path / "first"
    second = tmp_path / "second"
    runner.run_journey(FakeEvaluatorClient(receipt_suffix="a"), first)
    runner.run_journey(FakeEvaluatorClient(receipt_suffix="f"), second)

    for name in ("approved-state.json", "changed-state.json", "held-call.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_failure_resets_mock_and_removes_incomplete_artifacts(tmp_path):
    runner = _load_runner()
    client = FakeEvaluatorClient(fail_on_changed_discovery=True)

    with pytest.raises(runner.JourneyError, match="synthetic discovery failure"):
        runner.run_journey(client, tmp_path)

    assert client.phase == 1
    assert client.upstream_calls == 0
    assert not list(tmp_path.glob("*.json"))
    assert not list(tmp_path.glob("*.md"))
    assert not (tmp_path / ".staging").exists()


@pytest.mark.parametrize("action", ["approve", "reject", "rebaseline"])
def test_operator_actions_use_existing_control_plane_apis(tmp_path, action):
    runner = _load_runner()
    client = FakeEvaluatorClient()
    runner.run_journey(client, tmp_path)

    outcome = runner.apply_operator_action(client, tmp_path, action)

    assert outcome["action"] == action
    assert outcome["ok"] is True
    assert (tmp_path / "operator-action.json").exists()
    paths = [request[2] for request in client.requests]
    expected = {
        "approve": "/mcp/tools/demo-docs/read_file/approve",
        "reject": "/mcp/tools/demo-docs/read_file/quarantine",
        "rebaseline": "/mcp/servers/demo-docs/rebaseline",
    }
    assert expected[action] in paths


def test_runner_rejects_direct_external_service_origins():
    runner = _load_runner()
    for allowed in (
        "http://127.0.0.1:8001",
        "http://localhost:9100",
        "http://gateway:8001",
        "http://mcp-mock:9100",
    ):
        assert runner.validate_service_url(allowed) == allowed
    for rejected in (
        "https://example.com",
        "http://8.8.8.8",
        "http://metadata.google.internal",
        "file:///tmp/socket",
    ):
        with pytest.raises(ValueError):
            runner.validate_service_url(rejected)


def test_compose_runtime_is_internal_and_host_ports_are_loopback_only():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert compose["networks"]["demo-net"]["internal"] is True
    assert "evaluator-runner" in compose["services"]
    assert all(
        str(binding).startswith("127.0.0.1:")
        for binding in compose["services"]["host-proxy"]["ports"]
    )
    for service in ("gateway", "dashboard", "mcp-mock", "evaluator-runner"):
        assert compose["services"][service]["networks"] == ["demo-net"]


def test_linux_runner_uses_invoking_uid_gid_and_documented_user_owned_directory(
    tmp_path,
):
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    runner = compose["services"]["evaluator-runner"]
    guide = GUIDE.read_text(encoding="utf-8")

    assert runner["user"] == (
        "${INTERLOCK_EVALUATOR_UID:-0}:${INTERLOCK_EVALUATOR_GID:-0}"
    )
    assert "mkdir -p evaluator-artifacts" in guide
    assert 'export INTERLOCK_EVALUATOR_UID="$(id -u)"' in guide
    assert 'export INTERLOCK_EVALUATOR_GID="$(id -g)"' in guide
    assert "sudo" not in guide.lower()

    artifact_dir = tmp_path / "evaluator-artifacts"
    artifact_dir.mkdir()
    probe = artifact_dir / "ownership-probe"
    probe.write_text("invoking-user", encoding="utf-8")
    probe.unlink()
    artifact_dir.rmdir()
    assert not artifact_dir.exists()


def test_manifest_hashes_every_evidence_file_except_itself(tmp_path):
    runner = _load_runner()
    runner.run_journey(FakeEvaluatorClient(), tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert set(manifest["files"]) == {
        "approved-state.json",
        "changed-state.json",
        "held-call.json",
        "receipt-summary.json",
        "summary.md",
        "feedback.md",
    }
    for name, digest in manifest["files"].items():
        assert digest == hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()


def test_published_guide_is_complete_and_claim_limited():
    guide = GUIDE.read_text(encoding="utf-8")
    required = (
        "docker compose up -d --build",
        "docker compose run --rm evaluator-runner run",
        "docker compose run --rm evaluator-runner decide reject",
        "docker compose down -v",
        "tool_quarantined",
        "evaluator-artifacts",
        "Troubleshooting",
        "loopback-only",
        "non-production",
        "Direct MCP connections that bypass Interlock",
        "approve, reject, or rebaseline",
        "may take several minutes",
        "There is no universal first-run duration",
        "failed to solve",
    )
    for text in required:
        assert text in guide
    for question in QUESTIONS:
        assert question in guide
