import asyncio
import logging
import time
from collections import defaultdict
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from core import db
from core.detector import rule_based_scan
from core.learning import check_learned_patterns, learn_from_result
from core.llm_judge import llm_judge_scan
from core.pattern_matcher import pattern_match_scan
from core.policy import policy_scan
from core.shadow_mode import calculate_risk_score
from core.siem import trigger_siem_dispatch
from core.webhook import trigger_webhook
from models.schemas import (
    ChatMessage,
    ChatRequest,
    MCPDiscoverRequest,
    MCPRegisterRequest,
    MCPToolCallRequest,
    MCPToolReviewRequest,
    MCPToolValidateRequest,
    SIEMTestRequest,
    ScanRequest,
    ScanResult,
    ShadowScanRequest,
    ThreatLevel,
    ToolCallRequest,
)

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)
logger = logging.getLogger("interlock.proxy")

app = FastAPI(
    title="Interlock",
    description="OpenAI-compatible reverse proxy with AI security scanning",
    version="1.0.0",
)
_default_openapi_builder = app.openapi

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# API keys, rate limits, plan info, SIEM configs, and fail modes live in SQLite.
# See core/db.py for the schema. Use /admin/keys endpoints to manage keys.
request_counts = defaultdict(list)  # in-memory rate-limit window (replace with Redis for HA)
_active_ws: list = []

CONFIDENCE_MAP = {
    "CRITICAL": 0.99,
    "HIGH": 0.90,
    "MEDIUM": 0.75,
    "LOW": 0.55,
    "SAFE": 0.95,
}


@app.on_event("startup")
def _init_db():
    db.init_db()
    db.seed_legacy_keys()
    db.seed_mcp_servers()


@app.on_event("startup")
async def _start_shadow_scan():
    import os as _os

    if _os.getenv("SHADOW_SCAN_ENABLED", "false").lower() != "true":
        return
    import asyncio as _asyncio
    from core.shadow_scanner import run_shadow_scan as _run_shadow_scan

    _scan_interval = int(_os.getenv("SHADOW_SCAN_INTERVAL", "3600"))

    async def _shadow_scan_loop():
        while True:
            try:
                with db.get_conn() as conn:
                    findings = await _run_shadow_scan(conn)
                    if findings:
                        logger.info("Shadow scan: %d new finding(s)", len(findings))
            except Exception:
                logger.exception("Shadow scan loop error")
            await _asyncio.sleep(_scan_interval)

    _asyncio.get_running_loop().create_task(_shadow_scan_loop())


def verify_key(api_key: Optional[str]):
    """
    Look the key up in the DB. Returns (key_record_dict, raw_key) on success.
    Raises 401/403 on bad input.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key.")
    raw = api_key.replace("Bearer ", "").replace("bearer ", "").strip()

    record = db.lookup_key(raw)
    if not record:
        raise HTTPException(status_code=403, detail="Invalid or revoked API key.")

    if record["monthly_limit"] > 0:
        used = db.usage_this_month(record["id"])
        if used >= record["monthly_limit"]:
            raise HTTPException(
                status_code=429,
                detail=f"Monthly quota exceeded ({used}/{record['monthly_limit']}). Upgrade plan or wait for reset.",
            )

    return record, raw


def check_rate(api_key: str, rate_per_min: int):
    """Sliding-window per-minute rate limit. In-memory; not multi-worker safe."""
    now = time.time()
    request_counts[api_key] = [t for t in request_counts[api_key] if now - t < 60]
    if len(request_counts[api_key]) >= rate_per_min:
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    request_counts[api_key].append(now)


def run_scan(prompt: str, api_key: str) -> ScanResult:
    start = time.time()

    result = check_learned_patterns(prompt)
    if result:
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        result.risk_score = calculate_risk_score(result)
        return result

    result = policy_scan(prompt, api_key)
    if result:
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        result.risk_score = calculate_risk_score(result)
        return result

    result = rule_based_scan(prompt)
    if result.is_threat:
        result.layer_caught = "Layer 1 - Rule Engine"
        result.confidence = CONFIDENCE_MAP.get(result.threat_level.value, 0.8)
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        result.risk_score = calculate_risk_score(result)
        return result

    result = pattern_match_scan(prompt)
    if result.is_threat:
        result.layer_caught = "Layer 2 - Pattern Matcher"
        result.confidence = CONFIDENCE_MAP.get(result.threat_level.value, 0.8)
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        result.risk_score = calculate_risk_score(result)
        return result

    # Layers 1 & 2 returned SAFE if we got here. Pass that context into the judge
    # so fail_open_safe can decide whether bypassing is acceptable on Groq outage.
    result = llm_judge_scan(prompt, api_key=api_key, prior_layers_safe=True)
    if not result.layer_caught:
        result.layer_caught = "Layer 3 - LLM Judge"
    if result.confidence is None:
        result.confidence = CONFIDENCE_MAP.get(result.threat_level.value, 0.8)
    result.scan_time_ms = round((time.time() - start) * 1000, 2)
    learn_from_result(prompt, result)
    result.risk_score = calculate_risk_score(result)
    return result


def trigger_all_alerts(result, api_key, key_record=None):
    """Trigger webhook + SIEM in parallel. SIEM configs come from the key record."""
    trigger_webhook(api_key, result)
    siem_configs = (key_record or {}).get("siem_configs") or []
    if siem_configs and any(c.get("webhook_url") or c.get("api_key") or c.get("integration_key") for c in siem_configs):
        trigger_siem_dispatch(result, api_key, siem_configs)


async def _broadcast(message: dict):
    for conn in list(_active_ws):
        try:
            await conn.send_json(message)
        except Exception:
            pass


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = _default_openapi_builder()
    schema["components"]["securitySchemes"] = {
        "APIKeyHeader": {
            "type": "apiKey",
            "in": "header",
            "name": "x-api-key",
        }
    }
    schema["security"] = [{"APIKeyHeader": []}]
    app.openapi_schema = schema
    return schema


from routes import admin_routes, chat as chat_routes, mcp as mcp_routes, scan as scan_routes, system as system_routes

app.include_router(admin_routes.router)
app.include_router(system_routes.router)
app.include_router(chat_routes.router)
app.include_router(scan_routes.router)
app.include_router(mcp_routes.router)
app.openapi = custom_openapi

# Backward-compatible aliases for tests and direct function callers.
root = system_routes.root
health = system_routes.health
get_roles = system_routes.get_roles
usage = system_routes.usage
test_siem = system_routes.test_siem
list_siem_providers = system_routes.list_siem_providers
websocket_feed = system_routes.websocket_feed

chat_completions = chat_routes.chat_completions
list_providers = chat_routes.list_providers

scan = scan_routes.scan
scan_output = scan_routes.scan_output
scan_history = scan_routes.scan_history
scan_stats = scan_routes.scan_stats
shadow_scan = scan_routes.shadow_scan
shadow_logs = scan_routes.shadow_logs
shadow_stats = scan_routes.shadow_stats
inspect_tool = scan_routes.inspect_tool

mcp_list_servers = mcp_routes.mcp_list_servers
mcp_register = mcp_routes.mcp_register
mcp_discover = mcp_routes.mcp_discover
mcp_tools = mcp_routes.mcp_tools
mcp_drifted_tools = mcp_routes.mcp_drifted_tools
mcp_approve_tool_baseline = mcp_routes.mcp_approve_tool_baseline
mcp_quarantine_tool = mcp_routes.mcp_quarantine_tool
mcp_audit = mcp_routes.mcp_audit
mcp_validate = mcp_routes.mcp_validate
mcp_call = mcp_routes.mcp_call
mcp_unregister = mcp_routes.mcp_unregister
