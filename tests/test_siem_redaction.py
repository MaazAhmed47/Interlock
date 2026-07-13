"""Every outbound alert formatter redacts prompt content by default."""

import json

from core.siem import (
    build_datadog_event,
    build_elastic_event,
    build_pagerduty_event,
    build_slack_event,
    build_splunk_event,
    build_webhook_event,
)
from core.webhook import _build_payload
from models.schemas import ScanResult, ThreatLevel

RAW_PROMPT = "secret customer prompt: card 4111111111111111"
RAW_REASON = "judge quoted secret customer prompt: card 4111111111111111"


def _result():
    return ScanResult(
        is_threat=True,
        threat_level=ThreatLevel.CRITICAL,
        threat_type="PII_EXPOSURE",
        reason=RAW_REASON,
        original_prompt=RAW_PROMPT,
        confidence=0.99,
        layer_caught="test",
        risk_score=100,
        safe_to_proceed=False,
    )


def _formatters(result):
    return [
        build_datadog_event(result, "lf_test"),
        build_splunk_event(result, "lf_test"),
        build_elastic_event(result, "lf_test"),
        build_slack_event(result, "lf_test"),
        build_pagerduty_event(result, "routing-key", "lf_test"),
        build_webhook_event(result, "lf_test"),
        _build_payload(result),
    ]


def test_default_formatters_emit_hash_and_length_without_raw_content(monkeypatch):
    monkeypatch.delenv("SIEM_INCLUDE_CONTENT", raising=False)
    expected_length = len(RAW_PROMPT.encode("utf-8"))

    for event in _formatters(_result()):
        encoded = json.dumps(event)
        assert RAW_PROMPT not in encoded
        assert RAW_REASON not in encoded
        assert "sha256:" in encoded
        assert str(expected_length) in encoded


def test_content_preview_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("SIEM_INCLUDE_CONTENT", "true")

    for event in _formatters(_result()):
        encoded = json.dumps(event)
        assert RAW_PROMPT in encoded
        assert RAW_REASON in encoded
