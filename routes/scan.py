import re as _re
import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException

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


@router.post("/scan", response_model=ScanResult)
async def scan(request: ScanRequest, x_api_key: Optional[str] = Header(None)):
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    result = proxy.run_scan(request.prompt, raw_key)
    save_scan(raw_key, result, endpoint="/scan")
    db.log_usage(key_info["id"], "/scan", threat_blocked=result.is_threat)
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
async def scan_output(request: ScanRequest, x_api_key: Optional[str] = Header(None)):
    """Scan an LLM response for PII / data-leak patterns."""
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    start = time.time()
    for pattern in PII_PATTERNS:
        if _re.search(pattern, request.prompt):
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
            )
            result.risk_score = calculate_risk_score(result)
            save_scan(raw_key, result, endpoint="/scan/output")
            db.log_usage(key_info["id"], "/scan/output", threat_blocked=True)
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
    save_scan(raw_key, result, endpoint="/scan/output")
    db.log_usage(key_info["id"], "/scan/output", threat_blocked=False)
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
async def shadow_scan(request: ShadowScanRequest, x_api_key: Optional[str] = Header(None)):
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])
    result = proxy.run_scan(request.prompt, raw_key)
    log_shadow(result, raw_key)
    save_scan(raw_key, result, endpoint="/scan/shadow")
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
async def inspect_tool(request: ToolCallRequest, x_api_key: Optional[str] = Header(None)):
    key_info, raw_key = proxy.verify_key(x_api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    if request.role:
        rbac_result = rbac_scan(str(request.tool_args), request.tool_name, request.role)
        if rbac_result:
            rbac_result.scan_time_ms = 0.1
            rbac_result.risk_score = calculate_risk_score(rbac_result)
            save_scan(raw_key, rbac_result, endpoint="/inspect/tool-call")
            return rbac_result

    result = inspect_tool_call(request.tool_name, request.tool_args)
    result.risk_score = calculate_risk_score(result)
    save_scan(raw_key, result, endpoint="/inspect/tool-call")
    return result
