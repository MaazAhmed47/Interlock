from collections import defaultdict
from datetime import datetime, timezone
from models.schemas import ScanResult

# In-memory store (moves to PostgreSQL in production)
scan_history = defaultdict(list)
MAX_HISTORY = 500  # per key

def save_scan(api_key: str, result: ScanResult, endpoint: str = "/scan"):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_threat": result.is_threat,
        "threat_level": result.threat_level.value,
        "threat_type": result.threat_type,
        "reason": result.reason,
        "confidence": result.confidence,
        "layer_caught": result.layer_caught,
        "scan_time_ms": result.scan_time_ms,
        "risk_score": result.risk_score,
        "endpoint": endpoint,
        "prompt_preview": result.original_prompt[:80] + "..." if len(result.original_prompt) > 80 else result.original_prompt,
    }
    scan_history[api_key].insert(0, record)
    # Keep only last 500
    scan_history[api_key] = scan_history[api_key][:MAX_HISTORY]

def get_history(api_key: str, limit: int = 50) -> list:
    return scan_history[api_key][:limit]

def get_stats(api_key: str) -> dict:
    history = scan_history[api_key]
    if not history:
        return {
            "total": 0,
            "threats": 0,
            "safe": 0,
            "critical": 0,
            "block_rate": 0,
            "avg_risk_score": 0,
            "by_level": {},
        }

    threats = [h for h in history if h["is_threat"]]
    critical = [h for h in threats if h["threat_level"] == "CRITICAL"]
    by_level = {}
    risk_scores = []
    for item in history:
        level = item.get("threat_level") or "UNKNOWN"
        by_level[level] = by_level.get(level, 0) + 1
        if isinstance(item.get("risk_score"), (int, float)):
            risk_scores.append(item["risk_score"])

    return {
        "total": len(history),
        "threats": len(threats),
        "safe": len(history) - len(threats),
        "critical": len(critical),
        "block_rate": round(len(threats) / len(history) * 100, 1),
        "avg_risk_score": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0,
        "by_level": by_level,
    }
