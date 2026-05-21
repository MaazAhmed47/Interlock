# Response Scanner Design — MCP06 & MCP10 Full Coverage

**Date:** 2026-05-21
**Status:** Approved
**OWASP targets:** MCP06 (Intent Flow Subversion / Prompt Injection via Context), MCP10 (Context Injection & Over-Sharing)

---

## Goal

Upgrade Interlock's response scanning from a block-or-pass PII check into a two-layer scanner that:

1. **MCP06** — Detects prompt injection attempts embedded in tool responses and blocks them before they reach the model.
2. **MCP10** — Redacts PII and sensitive credentials in-place (returning sanitized content rather than blocking), and flags data volume anomalies as warnings.

---

## New Files

- `core/response_scanner.py` — two public scan functions
- `tests/test_response_scanner.py` — 13 unit tests

## Modified Files

- `models/schemas.py` — add `ResponseScanResult` model
- `core/db.py` — two new columns on `api_keys`, updated `PLAN_DEFAULTS`
- `core/admin.py` — two new fields on `UpdateKeyRequest`
- `core/mcp_gateway.py` — replace inline response scan block with calls to the new scanner
- `docs/interlock-owasp-mcp-coverage.md` — promote MCP06 and MCP10 from Partial to Covered

---

## Data Model

Add `ResponseScanResult` to `models/schemas.py`:

```python
class ResponseScanResult(BaseModel):
    is_threat: bool
    threat_level: ThreatLevel
    threat_type: Optional[str] = None       # PROMPT_INJECTION | OUTPUT_DATA_LEAK | CONTEXT_OVERSHARING
    reason: str
    safe_to_proceed: bool
    confidence: Optional[float] = None
    sanitized_content: Optional[str] = None  # set only when redactions were made; None = untouched
    redactions: Optional[List[str]] = None   # e.g. ["REDACTED-SSN", "REDACTED-API-KEY"]
    matched_patterns: Optional[List[str]] = None  # which patterns triggered detection
    scan_time_ms: Optional[float] = None
    risk_score: Optional[int] = None
```

`sanitized_content` is `None` unless actual redactions were applied — `None` means "content untouched", a value means "content was modified". This is a hard semantic invariant.

---

## `core/response_scanner.py`

### `scan_injection(text: str) -> ResponseScanResult`

**Purpose:** MCP06 — detect instruction-hijacking content in tool outputs.

**Pattern sources:**
- Reuse all 16 `INJECTION_PATTERNS` from `core/detector.py`
- Add 4 response-specific patterns:
  - `r"new instructions\s*:"` (i)
  - `r"disregard your system prompt"` (i)
  - `r"\bact as\b"` (i) — standalone, not caught by existing "act as if"
  - `r"from now on (you will|your task is|you must)"` (i)

**Scoring:**
- `confidence = min(1.0, len(matched) * 0.35)`
- One or more matches → `is_threat=True`, `threat_level=HIGH`, `threat_type="PROMPT_INJECTION"`, `safe_to_proceed=False`
- `sanitized_content` is always `None` — injection means block, never sanitize

**Implementation note:**
```python
# TODO: add encoding-bypass detection (base64, unicode lookalikes, ROT13)
# for future hardening — see core/detector.py for existing decode utilities
```

**Detection note:** The response text passed in is `json.dumps(data)` — this flattens nested JSON values into a single string, so injection patterns embedded anywhere in a nested structure are caught without recursive traversal.

### `scan_pii_and_volume(text: str, max_bytes: int = 50_000, max_items: int = 500) -> ResponseScanResult`

**Purpose:** MCP10 — redact sensitive data and flag oversized responses.

**PII patterns (extend `PII_PATTERNS` from `core/detector.py` with 3 new ones):**

| Pattern | Redaction marker | Notes |
|---|---|---|
| `\b\d{3}-\d{2}-\d{4}\b` | `[REDACTED-SSN]` | Dashed SSN |
| `\b\d{9}\b` | `[REDACTED-SSN]` | Undashed SSN — commonly missed |
| `\b4[0-9]{12}(?:[0-9]{3})?\b` | `[REDACTED-CREDIT-CARD]` | Visa format |
| `\b\d{16}\b` | `[REDACTED-CREDIT-CARD]` | Generic 16-digit |
| `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` | `[REDACTED-EMAIL]` | |
| `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b` | `[REDACTED-PHONE]` | |
| `(?i)password\s*[:=]\s*\S+` | `[REDACTED-PASSWORD]` | |
| `(?i)api[_-]?key\s*[:=]\s*\S+` | `[REDACTED-API-KEY]` | |
| `(?i)secret\s*[:=]\s*\S+` | `[REDACTED-API-KEY]` | |
| `Bearer [A-Za-z0-9._\-]{20,}` | `[REDACTED-BEARER-TOKEN]` | New |
| `AKIA[A-Z0-9]{16}` | `[REDACTED-API-KEY]` | AWS key format — New |
| `-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----` | `[REDACTED-PRIVATE-KEY]` | New, multiline |

**Redaction logic:**
- Apply all patterns sequentially with `re.sub`; track which markers were added
- If any redactions were made: `sanitized_content` = redacted text, `redactions` = list of unique marker types applied, `is_threat=True`, `threat_type="OUTPUT_DATA_LEAK"`, `threat_level=HIGH`, `safe_to_proceed=True`

**Volume anomaly logic (runs after PII redaction):**
- Check `len(text) > max_bytes` OR attempt `json.loads(text)` and count top-level array items > `max_items`
- If anomaly AND PII was already detected: PII wins — keep `threat_type="OUTPUT_DATA_LEAK"`, append `"volume_anomaly"` to `matched_patterns`
- If anomaly AND no PII: `is_threat=True`, `threat_type="CONTEXT_OVERSHARING"`, `threat_level=MEDIUM`, `safe_to_proceed=True`, `sanitized_content=None`

**Clean response:**
- No PII, no volume anomaly → `is_threat=False`, `threat_level=SAFE`, `safe_to_proceed=True`, all Optional fields `None`

---

## DB Schema Changes

**`core/db.py` — `init_db()`**

Add two columns using the existing try/except migration guard pattern:

```python
for col, definition in [
    ("max_response_bytes", "INTEGER DEFAULT 50000"),
    ("max_array_items",    "INTEGER DEFAULT 500"),
]:
    try:
        conn.execute(f"ALTER TABLE api_keys ADD COLUMN {col} {definition}")
    except Exception:
        pass  # column already exists
```

**`PLAN_DEFAULTS`** — add to all plans:
```python
"max_response_bytes": 50_000,
"max_array_items": 500,
```

**`core/admin.py` — `UpdateKeyRequest`**

```python
max_response_bytes: Optional[int] = None
max_array_items: Optional[int] = None
```

The existing field-iteration handler in `PATCH /admin/keys/{key_id}` picks these up with no further changes.

---

## Integration in `core/mcp_gateway.py`

Replace lines 462–474 (the current inline PII block) with:

```python
from core.response_scanner import scan_injection, scan_pii_and_volume

# 6. Scan the response for injection and data leaks
response_text = json.dumps(data)

inj_result = scan_injection(response_text)
if inj_result.is_threat:
    _log_mcp_policy_audit(policy_decision, blocked_by="response_injection",
                          extra={"threat_type": inj_result.threat_type,
                                 "confidence": inj_result.confidence,
                                 "matched_patterns": inj_result.matched_patterns})
    return {
        "ok": False,
        "error": "response_prompt_injection",
        "message": "Tool response contains prompt injection attempt. Blocked.",
        "blocked_response": True,
        "threat_type": inj_result.threat_type,
        "confidence": inj_result.confidence,
        "matched_patterns": inj_result.matched_patterns,
        "policy_decision": policy_decision,
    }

pii_result = scan_pii_and_volume(
    response_text,
    max_bytes=key_config.get("max_response_bytes", 50_000),
    max_items=key_config.get("max_array_items", 500),
)
if pii_result.is_threat:
    _log_mcp_policy_audit(policy_decision, blocked_by="response_pii",
                          extra={"threat_type": pii_result.threat_type,
                                 "confidence": pii_result.confidence,
                                 "matched_patterns": pii_result.matched_patterns,
                                 "redactions": pii_result.redactions})

if pii_result.is_threat and pii_result.sanitized_content is not None:
    effective_result = pii_result.sanitized_content
else:
    effective_result = response_text

_log_mcp_policy_audit(policy_decision, blocked_by="")
return {
    "ok": True,
    "server_id": server_id,
    "tool_name": tool_name,
    "result": json.loads(effective_result).get("result"),
    "scanned": True,
    "threat_flags": [pii_result.threat_type] if pii_result.is_threat else [],
    "redactions": pii_result.redactions,
    "drift": drift_context,
    "policy_decision": policy_decision,
}
```

`key_config` is already available earlier in `proxy_mcp_tool_call` via `db.lookup_key()` — pass it through to this point.

**Note:** `_log_mcp_policy_audit` currently takes only `(policy_decision, blocked_by)`. Add an optional `extra: dict = None` parameter and merge it into the audit dict.

---

## Test Coverage — `tests/test_response_scanner.py`

13 pure-unit tests (no DB, no HTTP):

| # | Scenario | Asserts |
|---|---|---|
| 1 | Clean response | `is_threat=False`, `sanitized_content=None`, both scanners |
| 2 | "ignore previous instructions" | `is_threat=True`, `PROMPT_INJECTION`, `confidence≥0.35`, `matched_patterns` populated |
| 3 | Two injection patterns in one response | confidence accumulates, still `PROMPT_INJECTION` |
| 4 | SSN (dashed: 123-45-6789) | redacted to `[REDACTED-SSN]`, `safe_to_proceed=True`, `sanitized_content` set |
| 5 | Credit card (16-digit) | redacted to `[REDACTED-CREDIT-CARD]` |
| 6 | `api_key: sk-abc123` | redacted to `[REDACTED-API-KEY]` |
| 7 | AWS key `AKIAIOSFODNN7EXAMPLE` | redacted to `[REDACTED-API-KEY]` |
| 8 | Response > 50 KB, no PII | `CONTEXT_OVERSHARING`, `safe_to_proceed=True`, `sanitized_content=None` |
| 9 | JSON array with 501 items | `CONTEXT_OVERSHARING`, `safe_to_proceed=True` |
| 10 | PII + volume anomaly together | `OUTPUT_DATA_LEAK` wins, `"volume_anomaly"` in `matched_patterns`, `sanitized_content` set |
| 11 | Bearer token | redacted to `[REDACTED-BEARER-TOKEN]` |
| 12 | `-----BEGIN RSA PRIVATE KEY-----` block | redacted to `[REDACTED-PRIVATE-KEY]` |
| 13 | Injection inside nested JSON value | detected via `json.dumps` flattening |

---

## OWASP Coverage Update

After implementation, update `docs/interlock-owasp-mcp-coverage.md`:

- **MCP06:** `⚠️ PARTIAL` → `✅ COVERED` — add: semantic injection pattern matching on tool responses, confidence scoring, full audit trail with matched patterns
- **MCP10:** `⚠️ PARTIAL` → `✅ COVERED` — add: in-place PII redaction with typed markers, volume anomaly flagging, per-key configurable thresholds, sanitized content passthrough

Coverage summary table: 8 of 10 fully covered (up from 6 of 10).

---

## What This Does NOT Cover (explicit non-scope)

- Encoding-bypass detection (base64, unicode lookalikes, ROT13) in injection scanner — marked TODO for future hardening
- Semantic/LLM-based injection scoring — regex-only for now
- Per-tool (not per-key) volume thresholds — deferred
