from collections import defaultdict
from datetime import datetime, timezone
from models.schemas import ScanResult

# In-memory store (moves to PostgreSQL in production)
scan_history = defaultdict(list)
MAX_HISTORY = 500  # per key

def save_scan(api_key: str, result: ScanResult):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_threat": result.is_threat,
        "threat_level": result.threat_level.value,
        "threat_type": result.threat_type,
        "reason": result.reason,
        "confidence": result.confidence,
        "layer_caught": result.layer_caught,
        "scan_time_ms": result.scan_time_ms,
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
        return {"total": 0, "threats": 0, "safe": 0, "critical": 0}

    threats = [h for h in history if h["is_threat"]]
    critical = [h for h in threats if h["threat_level"] == "CRITICAL"]

    return {
        "total": len(history),
        "threats": len(threats),
        "safe": len(history) - len(threats),
        "critical": len(critical),
        "block_rate": round(len(threats) / len(history) * 100, 1),
    }