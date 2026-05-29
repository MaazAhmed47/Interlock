import json
import os
from datetime import datetime, timezone
from models.schemas import ScanResult
from typing import Optional

SHADOW_LOG = "data/shadow_log.json"
MAX_LOGS = 10000


def _load() -> list:
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(SHADOW_LOG):
        with open(SHADOW_LOG, "w") as f:
            json.dump([], f)
        return []
    try:
        with open(SHADOW_LOG) as f:
            return json.load(f)
    except Exception:
        return []


def _save(data: list):
    try:
        os.makedirs("data", exist_ok=True)
        with open(SHADOW_LOG, "w") as f:
            json.dump(data[:MAX_LOGS], f, indent=2)
    except Exception:
        pass


def calculate_risk_score(result: ScanResult) -> int:
    """
    0-100 risk score.
    Combines threat level + confidence + threat type severity.
    """
    if not result.is_threat:
        return 0

    base = {"CRITICAL": 88, "HIGH": 68, "MEDIUM": 44, "LOW": 18, "SAFE": 0}.get(
        result.threat_level.value, 0
    )

    # Confidence multiplier
    confidence = result.confidence or 0.5
    conf_bonus = int(confidence * 12)

    # Threat type bonus
    type_bonus = {
        "PROMPT_INJECTION": 5,
        "DANGEROUS_TOOL_CALL": 8,
        "RBAC_VIOLATION": 4,
        "PII_DETECTED": 3,
        "CRYPTOMINING": 10,
        "SQL_INJECTION": 8,
        "CODE_INJECTION": 8,
        "SSRF_ATTEMPT": 6,
        "PATH_TRAVERSAL": 6,
        "SOCIAL_ENGINEERING": 5,
        "JAILBREAK": 7,
    }.get(result.threat_type or "", 0)

    return min(100, base + conf_bonus + type_bonus)


def log_shadow(result: ScanResult, api_key: str):
    """Log what WOULD have been blocked — never actually block."""
    if not result.is_threat:
        return
    try:
        logs = _load()
        logs.insert(
            0,
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "api_key_prefix": api_key[:8] + "...",
                "would_block": True,
                "threat_level": result.threat_level.value,
                "threat_type": result.threat_type,
                "reason": result.reason,
                "confidence": result.confidence,
                "risk_score": calculate_risk_score(result),
                "layer_caught": result.layer_caught,
                "prompt_preview": result.original_prompt[:120],
                "scan_time_ms": result.scan_time_ms,
            },
        )
        _save(logs)
    except Exception:
        pass  # Shadow mode must NEVER crash the main flow


def get_shadow_logs(
    limit: int = 50,
    threat_level: Optional[str] = None,
    threat_type: Optional[str] = None,
) -> list:
    logs = _load()
    if threat_level:
        logs = [
            entry for entry in logs if entry.get("threat_level") == threat_level.upper()
        ]
    if threat_type:
        logs = [
            entry for entry in logs if entry.get("threat_type") == threat_type.upper()
        ]
    return logs[:limit]


def get_shadow_stats() -> dict:
    logs = _load()
    if not logs:
        return {"total": 0, "by_level": {}, "by_type": {}, "avg_risk_score": 0}

    by_level: dict[str, int] = {}
    by_type: dict[str, int] = {}
    total_risk = 0

    for log in logs:
        level = log.get("threat_level", "UNKNOWN")
        ttype = log.get("threat_type", "UNKNOWN")
        by_level[level] = by_level.get(level, 0) + 1
        by_type[ttype] = by_type.get(ttype, 0) + 1
        total_risk += log.get("risk_score", 0)

    return {
        "total": len(logs),
        "by_level": by_level,
        "by_type": by_type,
        "avg_risk_score": round(total_risk / len(logs), 1),
        "top_threats": sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:5],
    }
