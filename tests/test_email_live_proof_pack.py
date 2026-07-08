"""Tests for credential-gated live email/messaging provider proof packs.

Run: python3 -m pytest tests/test_email_live_proof_pack.py -q -s
"""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.email_live import (
    LiveProviderConfig,
    ProviderExecutionError,
    ProviderState,
    SlackProvider,
    print_report,
    run_email_live_proof_pack,
)


class FakeLiveProvider:
    provider_name = "fake-gmail-sandbox"
    provider_kind = "gmail"

    def __init__(self):
        self.sent_count = 0

    def read_state(self) -> ProviderState:
        return ProviderState(
            provider_kind=self.provider_kind,
            provider_name=self.provider_name,
            item_count=self.sent_count,
            item_digests=[f"digest-{idx}" for idx in range(self.sent_count)],
        )

    def send_canary(self, *, mode: str) -> dict:
        self.sent_count += 1
        return {
            "provider": self.provider_kind,
            "mode": mode,
            "sent": True,
            "message_id": "live-message-secret",
            "recipient": "buyer@example.com",
            "body": "live-body-secret",
        }


class FailingSendProvider:
    provider_name = "failing-slack-sandbox"
    provider_kind = "slack"

    def read_state(self) -> ProviderState:
        return ProviderState(
            provider_kind=self.provider_kind,
            provider_name=self.provider_name,
            item_count=0,
            item_digests=[],
        )

    def send_canary(self, *, mode: str) -> dict:
        raise ProviderExecutionError("slack_api_error:not_in_channel")


class FakeSlackResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self.payload


class DelayedReadbackProvider:
    provider_name = "delayed-slack-sandbox"
    provider_kind = "slack"

    def __init__(self):
        self.sent_count = 0
        self.visible_count = 0
        self.stale_reads = 0

    def read_state(self) -> ProviderState:
        if self.stale_reads > 0:
            self.stale_reads -= 1
        else:
            self.visible_count = self.sent_count
        return ProviderState(
            provider_kind=self.provider_kind,
            provider_name=self.provider_name,
            item_count=self.visible_count,
            item_digests=[f"digest-{idx}" for idx in range(self.visible_count)],
        )

    def send_canary(self, *, mode: str) -> dict:
        self.sent_count += 1
        self.stale_reads = 1
        return {"provider": self.provider_kind, "mode": mode, "sent": True}


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_live_email_pack_skips_safely_without_explicit_credentials(monkeypatch):
    for key in list(os.environ):
        if key.startswith("INTERLOCK_LIVE_") or key.startswith("INTERLOCK_GMAIL_"):
            monkeypatch.delenv(key, raising=False)
        if key.startswith("INTERLOCK_IMAP_") or key.startswith("INTERLOCK_SMTP_"):
            monkeypatch.delenv(key, raising=False)
        if key.startswith("INTERLOCK_SLACK_"):
            monkeypatch.delenv(key, raising=False)

    report = run_email_live_proof_pack(env={})

    assert report["provider"] == "email_messaging"
    assert report["mode"] == "credential_gated_live_provider"
    assert report["summary"]["executed"] is False
    assert report["summary"]["status"] == "skipped_missing_live_provider_config"
    assert report["summary"]["all_passed"] is True
    assert report["scenarios"] == []
    assert "INTERLOCK_ALLOW_LIVE_PROVIDER_PROOFS=1" in " ".join(report["requirements"])


def test_live_email_pack_detects_hidden_send_with_injected_provider():
    report = run_email_live_proof_pack(
        provider=FakeLiveProvider(),
        config=LiveProviderConfig(
            provider_kind="gmail",
            provider_name="fake-gmail-sandbox",
            canary_label="test-canary",
            allow_live=True,
        ),
    )
    scenarios = _by_name(report)

    assert report["provider"] == "email_messaging"
    assert report["mode"] == "credential_gated_live_provider"
    assert report["summary"]["executed"] is True
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "live_provider_preview_no_send_control",
        "live_provider_hidden_send_readback_drift",
        "live_provider_expected_send_allowed_control",
    }

    preview = scenarios["live_provider_preview_no_send_control"]
    assert preview["ok"] is True
    assert preview["severity"] == "none"
    assert preview["decision"] == "allow"
    assert preview["drift_detected"] is False

    hidden = scenarios["live_provider_hidden_send_readback_drift"]
    assert hidden["ok"] is True
    assert hidden["severity"] == "critical"
    assert hidden["decision"] == "quarantine"
    assert "silent_side_effect_drift" in hidden["finding_types"]
    assert "effect_response_contradicted_by_readback" in hidden["finding_types"]
    assert (
        hidden["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    allowed = scenarios["live_provider_expected_send_allowed_control"]
    assert allowed["ok"] is True
    assert allowed["severity"] == "none"
    assert allowed["decision"] == "allow"
    assert allowed["drift_detected"] is False


def test_live_email_pack_output_is_evidence_safe_with_injected_provider():
    report = run_email_live_proof_pack(
        provider=FakeLiveProvider(),
        config=LiveProviderConfig(
            provider_kind="gmail",
            provider_name="fake-gmail-sandbox",
            canary_label="test-canary",
            allow_live=True,
        ),
    )
    encoded = json.dumps(report, sort_keys=True)

    assert "buyer@example.com" not in encoded
    assert "live-body-secret" not in encoded
    assert "live-message-secret" not in encoded
    assert "Authorization" not in encoded
    assert "Bearer" not in encoded
    assert "sha256:" in encoded


def test_live_email_pack_cli_skips_without_credentials():
    script = (
        Path(__file__).resolve().parents[1] / "demo" / "run_email_live_proof_pack.py"
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("INTERLOCK_LIVE_")
        and not key.startswith("INTERLOCK_GMAIL_")
        and not key.startswith("INTERLOCK_IMAP_")
        and not key.startswith("INTERLOCK_SMTP_")
        and not key.startswith("INTERLOCK_SLACK_")
    }
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
        env=env,
    )

    assert "SKIP skipped_missing_live_provider_config" in out.stdout
    assert "No live Gmail/iCloud/Fastmail/Slack credentials were used" in out.stdout


def test_live_email_pack_surfaces_provider_send_errors_without_claiming_drift():
    report = run_email_live_proof_pack(
        provider=FailingSendProvider(),
        config=LiveProviderConfig(
            provider_kind="slack",
            provider_name="failing-slack-sandbox",
            canary_label="test-canary",
            allow_live=True,
        ),
    )
    scenarios = _by_name(report)

    assert report["summary"]["executed"] is True
    assert report["summary"]["all_passed"] is False
    assert scenarios["live_provider_preview_no_send_control"]["ok"] is True

    hidden = scenarios["live_provider_hidden_send_readback_drift"]
    assert hidden["ok"] is False
    assert hidden["severity"] == "inconclusive"
    assert hidden["decision"] == "monitor"
    assert hidden["finding_types"] == ["provider_probe_error"]
    assert hidden["provider_error"] == "slack_api_error:not_in_channel"

    encoded = json.dumps(report, sort_keys=True)
    assert "xoxb" not in encoded
    assert "Bearer" not in encoded


def test_slack_provider_rejects_slack_api_ok_false(monkeypatch):
    provider = SlackProvider(
        bot_token="slack-secret-token",
        channel_id="C123",
        canary_label="test-canary",
    )

    def fake_urlopen(request, timeout):
        return FakeSlackResponse(b'{"ok": false, "error": "not_in_channel"}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    try:
        provider.send_canary(mode="hidden_send_drift")
    except ProviderExecutionError as exc:
        assert str(exc) == "slack_api_error:not_in_channel"
    else:
        raise AssertionError("SlackProvider must reject Slack API ok=false responses")


def test_live_email_pack_polls_for_delayed_provider_readback():
    report = run_email_live_proof_pack(
        provider=DelayedReadbackProvider(),
        config=LiveProviderConfig(
            provider_kind="slack",
            provider_name="delayed-slack-sandbox",
            canary_label="test-canary",
            allow_live=True,
        ),
    )
    scenarios = _by_name(report)

    assert report["summary"]["all_passed"] is True
    assert (
        scenarios["live_provider_hidden_send_readback_drift"]["severity"] == "critical"
    )
    assert (
        scenarios["live_provider_hidden_send_readback_drift"]["decision"]
        == "quarantine"
    )
    assert (
        scenarios["live_provider_expected_send_allowed_control"]["severity"] == "none"
    )
    assert (
        scenarios["live_provider_expected_send_allowed_control"]["decision"] == "allow"
    )


def test_live_email_pack_prints_provider_errors(capsys):
    report = run_email_live_proof_pack(
        provider=FailingSendProvider(),
        config=LiveProviderConfig(
            provider_kind="slack",
            provider_name="failing-slack-sandbox",
            canary_label="test-canary",
            allow_live=True,
        ),
    )

    print_report(report)
    out = capsys.readouterr().out

    assert "provider_error=slack_api_error:not_in_channel" in out
    assert "xoxb" not in out
    assert "Bearer" not in out
