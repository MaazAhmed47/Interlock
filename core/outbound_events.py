"""Evidence-safe content fields shared by SIEM and webhook formatters."""

import hashlib

import config
from models.schemas import ScanResult


def prompt_evidence(result: ScanResult) -> dict:
    raw = result.original_prompt or ""
    encoded = raw.encode("utf-8")
    evidence = {
        "content_included": False,
        "prompt_sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        "prompt_length_bytes": len(encoded),
    }
    if config.siem_include_content():
        evidence["content_included"] = True
        evidence["prompt_preview"] = raw[:200]
    return evidence


def alert_reason(result: ScanResult, limit: int = 300) -> str:
    if config.siem_include_content():
        return (result.reason or "")[:limit]
    return f"{result.threat_type or 'Scan'} detected; content redacted by default."
