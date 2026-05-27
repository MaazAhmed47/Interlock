import logging
import os
import re as _re
import threading
import time
from queue import Full, Queue
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException

import proxy
from core import db
from core.detector import PII_PATTERNS
from core.history import get_history, get_stats, save_scan
from core.policy import rbac_scan
from core.shadow_mode import (
    calculate_risk_score,
    get_shadow_logs,
    get_shadow_stats,
    log_shadow,
)
from core.tool_inspector import inspect_tool_call
from models.schemas import ScanRequest, ScanResult, ShadowScanRequest, ThreatLevel, ToolCallRequest

router = APIRouter()
logger = logging.getLogger("interlock.scan")
ASYNC_SCAN_PERSISTENCE = os.getenv("INTERLOCK_ASYNC_SCAN_PERSISTENCE", "true").lower() not in {
    "0",
    "false",
    "no",
}
PERSISTENCE_QUEUE_SIZE = int(os.getenv("INTERLOCK_SCAN_PERSISTENCE_QUEUE_SIZE", "1000"))
PERSISTENCE_DEFER_S = float(os.getenv("INTERLOCK_SCAN_PERSISTENCE_DEFER_S", "0.05"))
_persistence_queue: Queue = Queue(maxsize=PERSISTENCE_QUEUE_SIZE)
_persistence_worker_started = False
_persistence_worker_lock = threading.Lock()


def _persist_scan_event(
    raw_key: str,
    key_id: int,
    endpoint: str,
    result: ScanResult,
    count_usage: bool = True,
) -> None:
    try:
        save_scan(raw_key, result, endpoint=endpoint)
        if count_usage:
            db.log_usage(key_id, endpoint, threat_blocked=result.is_threat)
            proxy._bump_usage_cache(key_id)
    except Exception:
        logger.exception("Failed to persist scan event for %s", endpoint)


def _persistence_worker() -> None:
    while True:
        not_before, args = _persistence_queue.get()
        try:
            delay = not_before - time.time()
            if delay > 0:
                time.sleep(delay)
            _persist_scan_event(*args)
        finally:
            _persistence_queue.task_done()


def _ensure_persistence_worker() -> None:
    global _persistence_worker_started
    if _persistence_worker_started:
        return
    with _persistence_worker_lock:
        if _persistence_worker_started:
            return
        threading.Thread(
            target=_persistence_worker,
            name="interlock-scan-persistence",
            daemon=True,
        ).start()
        _persistence_worker_started = True


def _record_scan_event(
    raw_key: str,
    key_id: int,
    endpoint: str,
    result: ScanResult,
    count_usage: bool = True,
    background_tasks: BackgroundTasks | None = None,
) -> None:
    if ASYNC_SCAN_PERSISTENCE:
        if background_tasks is not None:
            background_tasks.add_task(_persist_scan_event, raw_key, key_id, endpoint, result, count_usage)
            return

        _ensure_persistence_worker()
        try:
            _persistence_queue.put_nowait((
                time.time() + PERSISTENCE_DEFER_S,
                (raw_key, key_id, endpoint, result, count_usage),
            ))
        except Full:
            logger.error("Scan persistence queue is full; dropping event for %s", endpoint)
        return

    _persist_scan_event(raw_key, key_id, endpoint, result, count_usage=count_usage)


OUTPUT_REDACTION_PATTERNS = [
    ("REDACTED-SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("REDACTED-CARD", r"\b4[0-9]{12}(?:[0-9]{3})?\b"),
    ("REDACTED-EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("REDACTED-PHONE", r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
    ("REDACTED-SECRET", r"(?i)(password|api[_-]?key|secret)\s*[:=]\s*\S+"),
]


def redact_output_content(content: str) -> tuple[str, list[str]]:
    sanitized = content
    redactions: list[str] = []
    for label, pattern in OUTPUT_REDACTION_PATTERNS:
        replacement = f"[{label}]"
        sanitized, count = _re.subn(pattern, replacement, sanitized)
        if count > 0:
            redactions.append(label)
    return sanitized, redactions


@router.post("/scan", response_model=ScanResult)
async def scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks = None,
    x_api_key: Optional[str] = Header(None),
):
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    mode = (request.mode or "").lower()
    if mode in proxy.FAST_SCAN_MODES:
        result = proxy.run_fast_scan(request.prompt, raw_key, key_record=key_info)
    else:
        result = proxy.run_scan(request.prompt, raw_key, key_record=key_info)
    _record_scan_event(raw_key, key_info["id"], "/scan", result, background_tasks=background_tasks)
    if result.is_threat:
        proxy.trigger_all_alerts(result, raw_key, key_info)
    proxy.asyncio.get_running_loop().create_task(proxy._broadcast({
        "type": "scan",
        "is_threat": result.is_threat,
        "threat_level": result.threat_level.value,
        "threat_type": result.threat_type,
        "prompt_preview": request.prompt[:60],
        "scan_time_ms": result.scan_time_ms,
        "layer_caught": result.layer_caught,
        "confidence": result.confidence,
    }))
    return result


@router.post("/scan/output", response_model=ScanResult)
async def scan_output(
    request: ScanRequest,
    background_tasks: BackgroundTasks = None,
    x_api_key: Optional[str] = Header(None),
):
    """Scan an LLM response for PII / data-leak patterns."""
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    start = time.time()
    sanitized_output, redactions = redact_output_content(request.prompt)
    if redactions or any(_re.search(pattern, request.prompt) for pattern in PII_PATTERNS):
        result = ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.HIGH,
            threat_type="OUTPUT_DATA_LEAK",
            reason="LLM response contains sensitive data.",
            original_prompt=request.prompt,
            safe_to_proceed=False,
            confidence=0.95,
            layer_caught="Output Scanner",
            scan_time_ms=round((time.time() - start) * 1000, 2),
            sanitized_output=sanitized_output,
            redactions=redactions,
        )
        result.risk_score = calculate_risk_score(result)
        _record_scan_event(raw_key, key_info["id"], "/scan/output", result, background_tasks=background_tasks)
        return result

    result = ScanResult(
        is_threat=False,
        threat_level=ThreatLevel.SAFE,
        threat_type=None,
        reason="Output scan clean.",
        original_prompt=request.prompt,
        safe_to_proceed=True,
        confidence=0.99,
        layer_caught="Output Scanner",
        scan_time_ms=round((time.time() - start) * 1000, 2),
    )
    result.risk_score = calculate_risk_score(result)
    _record_scan_event(raw_key, key_info["id"], "/scan/output", result, background_tasks=background_tasks)
    return result


@router.get("/scan/history")
async def scan_history(limit: int = 50, x_api_key: Optional[str] = Header(None)):
    _, raw_key = proxy.verify_key(x_api_key)
    return {"events": get_history(raw_key, limit)}


@router.get("/scan/stats")
async def scan_stats(x_api_key: Optional[str] = Header(None)):
    _, raw_key = proxy.verify_key(x_api_key)
    return get_stats(raw_key)


@router.post("/scan/shadow")
async def shadow_scan(
    request: ShadowScanRequest,
    background_tasks: BackgroundTasks = None,
    x_api_key: Optional[str] = Header(None),
):
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])
    result = proxy.run_scan(request.prompt, raw_key, key_record=key_info)
    log_shadow(result, raw_key)
    _record_scan_event(raw_key, key_info["id"], "/scan/shadow", result, count_usage=False, background_tasks=background_tasks)
    return {
        "would_block": result.is_threat,
        "threat_level": result.threat_level.value,
        "threat_type": result.threat_type,
        "reason": result.reason,
        "confidence": result.confidence,
        "risk_score": calculate_risk_score(result),
        "layer_caught": result.layer_caught,
        "scan_time_ms": result.scan_time_ms,
        "shadow_mode": True,
        "action_taken": "LOGGED_ONLY",
    }


@router.get("/shadow/logs")
async def shadow_logs(limit: int = 50, x_api_key: Optional[str] = Header(None)):
    proxy.verify_key(x_api_key)
    return {"logs": get_shadow_logs(limit)}


@router.get("/shadow/stats")
async def shadow_stats(x_api_key: Optional[str] = Header(None)):
    """Aggregated stats from shadow mode logs."""
    proxy.verify_key(x_api_key)
    return get_shadow_stats()


@router.post("/inspect/tool-call")
async def inspect_tool(
    request: ToolCallRequest,
    background_tasks: BackgroundTasks = None,
    x_api_key: Optional[str] = Header(None),
):
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    if request.role:
        rbac_result = rbac_scan(str(request.tool_args), request.tool_name, request.role)
        if rbac_result:
            rbac_result.scan_time_ms = 0.1
            rbac_result.risk_score = calculate_risk_score(rbac_result)
            _record_scan_event(raw_key, key_info["id"], "/inspect/tool-call", rbac_result, count_usage=False, background_tasks=background_tasks)
            return rbac_result

    result = inspect_tool_call(request.tool_name, request.tool_args)
    result.risk_score = calculate_risk_score(result)
    _record_scan_event(raw_key, key_info["id"], "/inspect/tool-call", result, count_usage=False, background_tasks=background_tasks)
    return result
