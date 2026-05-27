import json
from datetime import datetime, timezone

from core import db
from models.schemas import ScanResult

MAX_HISTORY = 500  # per key


def _key_hash(api_key: str) -> str:
    return db._hash_key(api_key)


def _row_to_record(row) -> dict:
    record = dict(row)
    raw_redactions = record.pop("redactions", "[]")
    try:
        redactions = json.loads(raw_redactions or "[]")
    except (json.JSONDecodeError, TypeError):
        redactions = []
    return {
        "timestamp": record.get("ts"),
        "is_threat": bool(record.get("is_threat")),
        "threat_level": record.get("threat_level") or "SAFE",
        "threat_type": record.get("threat_type") or None,
        "reason": record.get("reason") or "",
        "confidence": record.get("confidence"),
        "layer_caught": record.get("layer_caught") or None,
        "scan_time_ms": record.get("scan_time_ms"),
        "risk_score": record.get("risk_score"),
        "endpoint": record.get("endpoint") or "/scan",
        "prompt_preview": record.get("prompt_preview") or "",
        "sanitized_output": record.get("sanitized_output"),
        "redactions": redactions,
    }


def save_scan(api_key: str, result: ScanResult, endpoint: str = "/scan"):
    key_hash = _key_hash(api_key)
    prompt = result.original_prompt or ""
    prompt_preview = prompt[:80] + "..." if len(prompt) > 80 else prompt
    now = datetime.now(timezone.utc).isoformat()

    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO scan_history
              (key_hash, ts, is_threat, threat_level, threat_type, reason,
               confidence, layer_caught, scan_time_ms, risk_score, endpoint,
               prompt_preview, sanitized_output, redactions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_hash,
                now,
                bool(result.is_threat),
                result.threat_level.value,
                result.threat_type or "",
                result.reason,
                result.confidence,
                result.layer_caught or "",
                result.scan_time_ms,
                result.risk_score,
                endpoint,
                prompt_preview,
                result.sanitized_output,
                json.dumps(result.redactions or []),
            ),
        )
        conn.execute(
            """
            DELETE FROM scan_history
             WHERE key_hash = ?
               AND id NOT IN (
                 SELECT id FROM scan_history
                  WHERE key_hash = ?
                  ORDER BY id DESC
                  LIMIT ?
               )
            """,
            (key_hash, key_hash, MAX_HISTORY),
        )


def get_history(api_key: str, limit: int = 50) -> list:
    key_hash = _key_hash(api_key)
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT ts, is_threat, threat_level, threat_type, reason, confidence,
                   layer_caught, scan_time_ms, risk_score, endpoint, prompt_preview,
                   sanitized_output, redactions
              FROM scan_history
             WHERE key_hash = ?
             ORDER BY id DESC
             LIMIT ?
            """,
            (key_hash, limit),
        ).fetchall()
    return [_row_to_record(row) for row in rows]


def get_stats(api_key: str) -> dict:
    history = get_history(api_key, MAX_HISTORY)
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
