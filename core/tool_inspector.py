import re
import base64
from models.schemas import ScanResult, ThreatLevel
from typing import Optional

# ── SQL Injection & Destruction ───────────────────────────────────────────────
DANGEROUS_SQL = [
    # Destructive operations
    r"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|TRIGGER|PROCEDURE|FUNCTION)\b",
    r"\bTRUNCATE\s+TABLE\b",
    r"\bDELETE\s+FROM\b(?!\s+\w+\s+WHERE\s+\w)",  # DELETE without WHERE
    r"\bALTER\s+TABLE.+DROP\b",
    r"\bDROP\s+ALL\b",
    # Privilege escalation
    r"\bGRANT\s+ALL\b",
    r"\bGRANT\s+.+TO\s+'?root'?\b",
    r"\bCREATE\s+USER.+SUPERUSER\b",
    r"\bALTER\s+USER.+SUPERUSER\b",
    # Data exfiltration
    r"\bINTO\s+OUTFILE\b",
    r"\bINTO\s+DUMPFILE\b",
    r"\bLOAD_FILE\s*\(",
    r"\bxp_cmdshell\b",
    r"\bsp_executesql\b",
    r"\bOPENROWSET\b",
    r"\bOPENDATASOURCE\b",
    # SQL injection tricks
    r"';\s*DROP\b",
    r"';\s*DELETE\b",
    r"--.*DROP\b",
    r"/\*.*DROP.*\*/",
    r"\bUNION\s+(ALL\s+)?SELECT.+FROM\b",
    r"\b1\s*=\s*1\b",  # always true condition
    r"\b1\s*=\s*'1'\b",
    r"\bOR\s+'[^']+'\s*=\s*'[^']+'\b",  # OR 'x'='x'
    r"\bWAITFOR\s+DELAY\b",  # time-based injection
    r"\bSLEEP\s*\(\s*\d+\s*\)\b",
    r"\bBENCHMARK\s*\(",
    # Encoded SQL injection
    r"0x[0-9a-fA-F]+",  # hex encoded
    r"%27",  # URL encoded quote
    r"&#x27;",  # HTML encoded quote
    r"\bCHAR\s*\(\s*\d+\s*\)",  # CHAR() injection
    r"\bCONCAT\s*\(.+SELECT\b",
]

# ── Code Execution ────────────────────────────────────────────────────────────
DANGEROUS_CODE = [
    # Python dangerous
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bos\.exec\w*\s*\(",
    r"\bsubprocess\.(call|run|Popen|check_output)\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\b__import__\s*\(",
    r"\bcompile\s*\(.+exec\b",
    r"\bgetattr\s*\(.+__\w+__",
    r"\bctypes\b",
    r"\bcffi\b",
    r"\bimportlib\b",
    # Shell injection
    r"\brm\s+-rf?\b",
    r"\bformat\s+[cCdD]:\\\b",
    r"\bdel\s+/[fFsS]\b",
    r"\bchmod\s+[0-7]*7[0-7]*\b",
    r"\bchown\s+root\b",
    r"\bsudo\s+\b",
    r"\bsu\s+-\b",
    r"\bcurl.+\|\s*(ba)?sh\b",
    r"\bwget.+\|\s*(ba)?sh\b",
    r"\bpython\s+-c\b",
    r"\bpython3\s+-c\b",
    r"\bnc\s+-e\b",  # netcat reverse shell
    r"\bbash\s+-i\b",  # interactive bash
    r"\b/bin/sh\b",
    r"\b/bin/bash\b",
    r"\bpowershell\s+-\w*[eE][nN][cC]\b",  # encoded powershell
    # Node.js dangerous
    r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)",
    r"\bprocess\.exit\s*\(",
    r"\bfs\.unlink\s*\(",
    r"\bfs\.rmdir\s*\(",
    # Obfuscated execution
    r"base64\.b64decode.+exec\b",
    r"\bexec\s*\(\s*base64\b",
    r"\beval\s*\(\s*atob\b",
]

# ── File System ───────────────────────────────────────────────────────────────
DANGEROUS_FILES = [
    # Linux sensitive files
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/sudoers",
    r"/etc/crontab",
    r"/etc/hosts",
    r"/proc/self",
    r"/proc/\d+",
    r"/sys/kernel",
    r"~/.ssh/",
    r"\.ssh/id_rsa",
    r"\.ssh/authorized_keys",
    r"/var/log/auth",
    r"/root/",
    # Windows sensitive
    r"C:\\Windows\\System32",
    r"C:\\Windows\\SysWOW64",
    r"C:\\Users\\.+\\AppData",
    r"HKEY_LOCAL_MACHINE",
    r"HKEY_CURRENT_USER",
    r"SAM\b",
    r"NTDS\.dit",
    # Path traversal
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.%2f",
    r"%252e",  # double encoded
    r"\.\./\.\./",
    # Sensitive files
    r"\.env\b",
    r"\.env\.local",
    r"\.env\.production",
    r"config\.yaml",
    r"secrets\.yaml",
    r"credentials\.json",
    r"service-account\.json",
    r"id_rsa\b",
    r"\.pem\b",
    r"\.key\b",
    r"\.pfx\b",
    r"\.p12\b",
    r"private[-_]key",
    r"api[-_]key",
    r"\.htpasswd",
]

# ── Network ───────────────────────────────────────────────────────────────────
DANGEROUS_NETWORK = [
    # Internal IP ranges
    r"\b127\.\d+\.\d+\.\d+\b",
    r"\b10\.\d+\.\d+\.\d+\b",
    r"\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b",
    r"\b192\.168\.\d+\.\d+\b",
    r"\b169\.254\.\d+\.\d+\b",  # link-local
    r"\b0\.0\.0\.0\b",
    r"\blocalhost\b",
    r"\bhost\.docker\.internal\b",
    r"\bkubernetes\.default\b",
    r"\bkubernetes\.default\.svc\b",
    # Cloud metadata endpoints
    r"169\.254\.169\.254",  # AWS/GCP/Azure metadata
    r"metadata\.google\.internal",
    r"metadata\.azure\.internal",
    r"169\.254\.170\.2",  # ECS metadata
    # SSRF tricks
    r"http://[^/]+@",  # URL with credentials
    r"file://",
    r"gopher://",
    r"dict://",
    r"ftp://\d+\.\d+\.\d+\.\d+",
    r"\bxip\.io\b",  # SSRF bypass
    r"\bnip\.io\b",
    r"0x[0-9a-f]{8}\b",  # hex IP
    r"\b0+\.\d+\.\d+\.\d+\b",  # octal IP
]

# ── Cryptomining / Malware ────────────────────────────────────────────────────
DANGEROUS_CRYPTO = [
    r"\bxmrig\b",
    r"\bminerd\b",
    r"\bstratum\+tcp://\b",
    r"\bmonero\b.{0,30}\bmining\b",
    r"pool\.minexmr\.com",
    r"\bc3pool\b",
    r"\bnanopool\b",
]

# ── Tool-specific strict policies ─────────────────────────────────────────────
TOOL_POLICIES = {
    "execute_sql": {
        "patterns": DANGEROUS_SQL,
        "severity": "CRITICAL",
        "msg": "Destructive SQL operation detected",
    },
    "run_sql": {
        "patterns": DANGEROUS_SQL,
        "severity": "CRITICAL",
        "msg": "Destructive SQL operation detected",
    },
    "query_database": {
        "patterns": DANGEROUS_SQL,
        "severity": "CRITICAL",
        "msg": "Dangerous database query detected",
    },
    "run_code": {
        "patterns": DANGEROUS_CODE,
        "severity": "CRITICAL",
        "msg": "Dangerous code execution detected",
    },
    "execute_python": {
        "patterns": DANGEROUS_CODE,
        "severity": "CRITICAL",
        "msg": "Dangerous Python execution detected",
    },
    "execute_js": {
        "patterns": DANGEROUS_CODE,
        "severity": "CRITICAL",
        "msg": "Dangerous JavaScript execution detected",
    },
    "bash": {
        "patterns": DANGEROUS_CODE,
        "severity": "CRITICAL",
        "msg": "Dangerous shell command detected",
    },
    "shell": {
        "patterns": DANGEROUS_CODE,
        "severity": "CRITICAL",
        "msg": "Dangerous shell command detected",
    },
    "terminal": {
        "patterns": DANGEROUS_CODE,
        "severity": "CRITICAL",
        "msg": "Dangerous terminal command detected",
    },
    "read_file": {
        "patterns": DANGEROUS_FILES,
        "severity": "HIGH",
        "msg": "Access to sensitive file path detected",
    },
    "write_file": {
        "patterns": DANGEROUS_FILES,
        "severity": "CRITICAL",
        "msg": "Write to sensitive file path detected",
    },
    "delete_file": {
        "patterns": DANGEROUS_FILES,
        "severity": "CRITICAL",
        "msg": "Deletion of sensitive file detected",
    },
    "http_request": {
        "patterns": DANGEROUS_NETWORK,
        "severity": "HIGH",
        "msg": "Request to internal/restricted network",
    },
    "web_request": {
        "patterns": DANGEROUS_NETWORK,
        "severity": "HIGH",
        "msg": "Request to internal/restricted network",
    },
    "fetch_url": {
        "patterns": DANGEROUS_NETWORK,
        "severity": "HIGH",
        "msg": "Request to restricted URL detected",
    },
    "send_request": {
        "patterns": DANGEROUS_NETWORK,
        "severity": "HIGH",
        "msg": "Request to restricted endpoint detected",
    },
}


def _flatten(obj, depth=0) -> str:
    """Recursively flatten any object to a string for scanning."""
    if depth > 5:
        return str(obj)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten(i, depth + 1) for i in obj)
    return str(obj)


def _decode_obfuscation(text: str) -> list[str]:
    """Return multiple decoded versions to catch obfuscated attacks."""
    versions = [text]

    # Try base64 decode
    words = text.split()
    for word in words:
        if len(word) > 8 and len(word) % 4 == 0:
            try:
                decoded = base64.b64decode(word).decode("utf-8", errors="ignore")
                if decoded.isprintable() and len(decoded) > 4:
                    versions.append(decoded)
            except Exception:
                pass

    # URL decode
    try:
        from urllib.parse import unquote

        versions.append(unquote(text))
        versions.append(unquote(unquote(text)))  # double decode
    except Exception:
        pass

    # Unicode normalize
    try:
        import unicodedata

        versions.append(unicodedata.normalize("NFKC", text))
    except Exception:
        pass

    return versions


def inspect_tool_call(
    tool_name: str,
    tool_args: dict,
    role: Optional[str] = None,
    user_id: Optional[str] = None,
) -> ScanResult:
    """
    Inspect an AI agent tool call before execution.
    Handles SQL injection, code execution, path traversal,
    SSRF, obfuscation, and cryptomining detection.
    """
    # Flatten all args to string — handles nested dicts/lists
    args_flat = _flatten(tool_args)
    tool_lower = tool_name.lower().replace("-", "_").replace(" ", "_")

    # Get all decoded versions to catch obfuscation
    versions = _decode_obfuscation(args_flat)

    def make_threat(severity, threat_type, reason):
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel(severity),
            threat_type=threat_type,
            reason=reason,
            original_prompt=f"Tool: {tool_name} | Args: {args_flat[:300]}",
            safe_to_proceed=False,
            confidence=0.99,
            layer_caught="Tool Call Inspector",
            scan_time_ms=0.1,
        )

    # 1. Tool-specific policy check
    for tool_key, policy in TOOL_POLICIES.items():
        if tool_key in tool_lower:
            for version in versions:
                for pattern in policy["patterns"]:
                    if re.search(pattern, version, re.IGNORECASE):
                        return make_threat(
                            policy["severity"],
                            "DANGEROUS_TOOL_CALL",
                            f"{policy['msg']} in '{tool_name}': pattern '{pattern[:60]}'",
                        )

    # 2. Cryptomining check on all tools
    for version in versions:
        for pattern in DANGEROUS_CRYPTO:
            if re.search(pattern, version, re.IGNORECASE):
                return make_threat(
                    "CRITICAL",
                    "CRYPTOMINING_DETECTED",
                    f"Cryptomining pattern detected in tool '{tool_name}'",
                )

    # 3. Generic cross-tool dangerous pattern check
    all_patterns = [
        (DANGEROUS_SQL, "CRITICAL", "SQL_INJECTION"),
        (DANGEROUS_CODE, "CRITICAL", "CODE_INJECTION"),
        (DANGEROUS_FILES, "HIGH", "PATH_TRAVERSAL"),
        (DANGEROUS_NETWORK, "HIGH", "SSRF_ATTEMPT"),
    ]

    for version in versions:
        for patterns, severity, threat_type in all_patterns:
            for pattern in patterns:
                if re.search(pattern, version, re.IGNORECASE):
                    return make_threat(
                        severity,
                        threat_type,
                        f"Dangerous pattern in tool '{tool_name}' args: '{pattern[:60]}'",
                    )

    # 4. Empty/null injection check
    if not args_flat.strip() or args_flat.strip() in ["{}", "[]", "null", "None"]:
        pass  # empty args are fine

    # 5. Extremely long args (potential overflow attack)
    if len(args_flat) > 10000:
        return make_threat(
            "MEDIUM",
            "OVERSIZED_TOOL_CALL",
            f"Tool args exceed safe size limit ({len(args_flat)} chars). Possible overflow attack.",
        )

    return ScanResult(
        is_threat=False,
        threat_level=ThreatLevel.SAFE,
        threat_type=None,
        reason=f"Tool call '{tool_name}' passed all inspections.",
        original_prompt=f"Tool: {tool_name} | Args: {args_flat[:300]}",
        safe_to_proceed=True,
        confidence=0.97,
        layer_caught="Tool Call Inspector",
        scan_time_ms=0.1,
    )
