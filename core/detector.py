import re
import base64
import unicodedata
from models.schemas import ScanResult, ThreatLevel

# ── Standard injection patterns ──────────────────────────────────────────────
INJECTION_PATTERNS = [
    r"ignore (all |previous |above )?(instructions|prompts|rules|guidelines)",
    r"you are now (a |an )?(?!assistant)",
    r"forget (everything|all|your instructions)",
    r"(pretend|act|behave) (like|as if|as though)",
    r"do anything now",
    r"jailbreak",
    r"bypass (safety|filter|restriction|rule)",
    r"disregard (your|all|previous)",
    r"override (your|the|all)",
    r"new (persona|personality|identity|role)",
    r"system prompt",
    r"reveal (your|the) (prompt|instructions|system)",
    r"you have no (restrictions|limits|rules)",
    r"(act|behave) as (if )?you (have no|without) (restrictions|rules|limits)",
    r"(start|begin) (new|fresh) (conversation|session|context)",
    r"(above|previous) (text|content|message) (is|was) (a |an )?(lie|fake|test)",
]

PII_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",
    r"\b4[0-9]{12}(?:[0-9]{3})?\b",
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    r"\b\d{16}\b",                          # credit card no spaces
    r"(?i)password\s*[:=]\s*\S+",           # password: xyz
    r"(?i)api[_-]?key\s*[:=]\s*\S+",        # api_key: xyz
    r"(?i)secret\s*[:=]\s*\S+",             # secret: xyz
]

# ── Unicode normalization attack detector ─────────────────────────────────────
UNICODE_LOOKALIKES = {
    'ı': 'i', 'і': 'i', 'ο': 'o', 'а': 'a', 'е': 'e',
    'ѕ': 's', 'р': 'p', 'х': 'x', 'с': 'c', 'ԁ': 'd',
}

def normalize_unicode(text: str) -> str:
    # Normalize unicode to catch lookalike character attacks
    normalized = unicodedata.normalize('NFKC', text)
    for fake, real in UNICODE_LOOKALIKES.items():
        normalized = normalized.replace(fake, real)
    return normalized

# ── Leetspeak decoder ─────────────────────────────────────────────────────────
LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b', '@': 'a',
    '$': 's', '!': 'i', '+': 't',
}

def decode_leet(text: str) -> str:
    return ''.join(LEET_MAP.get(c, c) for c in text.lower())

# ── Base64 decoder ────────────────────────────────────────────────────────────
def decode_base64_chunks(text: str) -> str:
    words = text.split()
    decoded_parts = []
    for word in words:
        if len(word) > 8 and len(word) % 4 == 0:
            try:
                decoded = base64.b64decode(word).decode('utf-8', errors='ignore')
                if decoded.isprintable():
                    decoded_parts.append(decoded)
            except Exception:
                pass
    return ' '.join(decoded_parts) if decoded_parts else ''

# ── Invisible character detector ──────────────────────────────────────────────
INVISIBLE_CHARS = [
    '\u200b',  # zero width space
    '\u200c',  # zero width non-joiner
    '\u200d',  # zero width joiner
    '\ufeff',  # BOM
    '\u00ad',  # soft hyphen
    '\u2060',  # word joiner
]

def has_invisible_chars(text: str) -> bool:
    return any(char in text for char in INVISIBLE_CHARS)

# ── HTML/Markdown injection detector ─────────────────────────────────────────
HTML_PATTERNS = [
    r"<script.*?>",
    r"<iframe.*?>",
    r"javascript:",
    r"<!--.*?-->",
    r"\[.*?\]\(javascript:",
]

# ── Prompt length check ───────────────────────────────────────────────────────
MAX_PROMPT_LENGTH = 4000  # characters

def rule_based_scan(prompt: str) -> ScanResult:

    # 1. Length check
    if len(prompt) > MAX_PROMPT_LENGTH:
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.MEDIUM,
            threat_type="PROMPT_TOO_LONG",
            reason=f"Prompt exceeds max length ({len(prompt)} chars). Possible overflow attack.",
            original_prompt=prompt,
            safe_to_proceed=False
        )

    # 2. Invisible character check
    if has_invisible_chars(prompt):
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.HIGH,
            threat_type="INVISIBLE_CHARS",
            reason="Invisible/zero-width characters detected. Possible token smuggling attack.",
            original_prompt=prompt,
            safe_to_proceed=False
        )

    # 3. HTML/script injection check
    for pattern in HTML_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.HIGH,
                threat_type="HTML_INJECTION",
                reason=f"HTML/script injection attempt detected.",
                original_prompt=prompt,
                safe_to_proceed=False
            )

    # 4. Run checks on multiple versions of the prompt
    versions = {
        "original": prompt.lower(),
        "unicode_normalized": normalize_unicode(prompt).lower(),
        "leet_decoded": decode_leet(prompt),
        "base64_decoded": decode_base64_chunks(prompt),
    }

    for version_name, text in versions.items():
        if not text:
            continue

        # Check injection patterns
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, text):
                return ScanResult(
                    is_threat=True,
                    threat_level=ThreatLevel.HIGH,
                    threat_type="PROMPT_INJECTION",
                    reason=f"Injection pattern matched in {version_name}: '{pattern}'",
                    original_prompt=prompt,
                    safe_to_proceed=False
                )

    # 5. PII check (on original only)
    for pattern in PII_PATTERNS:
        if re.search(pattern, prompt):
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.MEDIUM,
                threat_type="PII_DETECTED",
                reason="Sensitive personal information detected in prompt.",
                original_prompt=prompt,
                safe_to_proceed=False
            )

    return ScanResult(
        is_threat=False,
        threat_level=ThreatLevel.SAFE,
        threat_type=None,
        reason="No threats detected by rule engine.",
        original_prompt=prompt,
        safe_to_proceed=True
    )