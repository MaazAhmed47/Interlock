import re
import json
import time
from typing import List
from models.schemas import ResponseScanResult, ThreatLevel
from core.detector import INJECTION_PATTERNS

# ── MCP06: Prompt injection detection ────────────────────────────────────────
# Response-specific patterns not in the request-side INJECTION_PATTERNS.
_RESPONSE_INJECTION_EXTRAS = [
    r"new instructions\s*:",
    r"disregard your system prompt",
    r"\bact as\b",
    r"from now on (you will|your task is|you must)",
]

_ALL_INJECTION_PATTERNS = INJECTION_PATTERNS + _RESPONSE_INJECTION_EXTRAS


def scan_injection(text: str) -> ResponseScanResult:
    # TODO: add encoding-bypass detection (base64, unicode lookalikes, ROT13)
    # for future hardening — see core/detector.py for existing decode utilities
    t0 = time.monotonic()
    matched = []
    for pattern in _ALL_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)

    elapsed_ms = (time.monotonic() - t0) * 1000

    if not matched:
        return ResponseScanResult(
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            reason="No injection patterns detected in tool response.",
            safe_to_proceed=True,
            scan_time_ms=elapsed_ms,
        )

    confidence = min(1.0, len(matched) * 0.35)
    return ResponseScanResult(
        is_threat=True,
        threat_level=ThreatLevel.HIGH,
        threat_type="PROMPT_INJECTION",
        reason=f"Tool response contains {len(matched)} injection pattern(s).",
        safe_to_proceed=False,
        confidence=confidence,
        matched_patterns=matched,
        scan_time_ms=elapsed_ms,
    )


# ── MCP10: PII redaction + volume anomaly ────────────────────────────────────
# Each rule: (compiled_regex, in_text_marker, label_for_redactions_list)
# In-text marker uses brackets: "[REDACTED-SSN]".
# Label (no brackets) goes into the `redactions` and `matched_patterns` lists.
_PII_RULES = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]", "REDACTED-SSN"),
    (re.compile(r"\b\d{9}\b"), "[REDACTED-SSN]", "REDACTED-SSN"),
    (
        re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),
        "[REDACTED-CREDIT-CARD]",
        "REDACTED-CREDIT-CARD",
    ),
    (re.compile(r"\b\d{16}\b"), "[REDACTED-CREDIT-CARD]", "REDACTED-CREDIT-CARD"),
    (
        re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
        "[REDACTED-EMAIL]",
        "REDACTED-EMAIL",
    ),
    (
        re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
        "[REDACTED-PHONE]",
        "REDACTED-PHONE",
    ),
    (
        re.compile(r"(?i)password\s*[:=]\s*\S+"),
        "[REDACTED-PASSWORD]",
        "REDACTED-PASSWORD",
    ),
    (
        re.compile(r"(?i)api[_\-]?key\s*[:=]\s*\S+"),
        "[REDACTED-API-KEY]",
        "REDACTED-API-KEY",
    ),
    (re.compile(r"(?i)secret\s*[:=]\s*\S+"), "[REDACTED-API-KEY]", "REDACTED-API-KEY"),
    (
        re.compile(r"Bearer [A-Za-z0-9._\-]{20,}"),
        "[REDACTED-BEARER-TOKEN]",
        "REDACTED-BEARER-TOKEN",
    ),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "[REDACTED-API-KEY]", "REDACTED-API-KEY"),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED-PRIVATE-KEY]",
        "REDACTED-PRIVATE-KEY",
    ),
]


def scan_pii_and_volume(
    text: str, max_bytes: int = 50_000, max_items: int = 500
) -> ResponseScanResult:
    t0 = time.monotonic()
    sanitized = text
    redaction_labels: List[str] = []
    matched: List[str] = []

    for pattern, marker, label in _PII_RULES:
        new_text, count = pattern.subn(marker, sanitized)
        if count:
            sanitized = new_text
            if label not in redaction_labels:
                redaction_labels.append(label)
            if label not in matched:
                matched.append(label)

    has_pii = bool(redaction_labels)

    # Volume anomaly: raw text byte count, or top-level / result-field array length.
    volume_anomaly = False
    if len(text) > max_bytes:
        volume_anomaly = True
        matched.append("volume_anomaly")
    else:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list) and len(parsed) > max_items:
                volume_anomaly = True
                matched.append("volume_anomaly")
            elif isinstance(parsed, dict):
                result_field = parsed.get("result")
                if isinstance(result_field, list) and len(result_field) > max_items:
                    volume_anomaly = True
                    matched.append("volume_anomaly")
        except (json.JSONDecodeError, ValueError):
            pass

    elapsed_ms = (time.monotonic() - t0) * 1000

    if has_pii:
        # PII wins over volume; "volume_anomaly" is already appended to matched if present.
        return ResponseScanResult(
            is_threat=True,
            threat_level=ThreatLevel.HIGH,
            threat_type="OUTPUT_DATA_LEAK",
            reason=f"Tool response contains sensitive data: {', '.join(set(redaction_labels))}.",
            safe_to_proceed=True,
            sanitized_content=sanitized,
            redactions=redaction_labels,
            matched_patterns=matched,
            scan_time_ms=elapsed_ms,
        )

    if volume_anomaly:
        return ResponseScanResult(
            is_threat=True,
            threat_level=ThreatLevel.MEDIUM,
            threat_type="CONTEXT_OVERSHARING",
            reason="Tool response exceeds configured volume threshold.",
            safe_to_proceed=True,
            sanitized_content=None,
            matched_patterns=matched,
            scan_time_ms=elapsed_ms,
        )

    return ResponseScanResult(
        is_threat=False,
        threat_level=ThreatLevel.SAFE,
        reason="No sensitive data or volume anomalies detected.",
        safe_to_proceed=True,
        scan_time_ms=elapsed_ms,
    )
