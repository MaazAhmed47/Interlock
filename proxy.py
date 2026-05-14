import asyncio
import httpx
import time
import os
from fastapi import FastAPI, HTTPException, Header, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional
from collections import defaultdict

# ── Local imports ─────────────────────────────────────────────────────────────
from core.siem import dispatch_to_siems, trigger_siem_dispatch
from core.router import detect_provider, forward_to_provider, PROVIDERS
from models.schemas import ScanResult, ThreatLevel
from core.detector import rule_based_scan, PII_PATTERNS
from core.pattern_matcher import pattern_match_scan
from core.llm_judge import llm_judge_scan
from core.policy import policy_scan
from core.learning import check_learned_patterns, learn_from_result
from core.history import save_scan
from core.webhook import trigger_webhook
from core.tool_inspector import inspect_tool_call
from core.shadow_mode import log_shadow, get_shadow_logs, calculate_risk_score
from core.policy import rbac_scan
from fastapi.security import APIKeyHeader
from core.shadow_mode import log_shadow, get_shadow_logs, get_shadow_stats, calculate_risk_score
from core.mcp_gateway import (
    discover_mcp_tools,
    proxy_mcp_tool_call,
    validate_mcp_tool_definition,
    register_mcp_server,
    list_mcp_servers,
)
from core import db
from core.admin import router as admin_router

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)



# ── Pydantic Models ───────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: List[ChatMessage]
    stream: Optional[bool] = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None

class ScanRequest(BaseModel):
    prompt: str
    user_id: Optional[str] = "anonymous"

class ToolCallRequest(BaseModel):
    tool_name: str
    tool_args: dict
    role: Optional[str] = None

class ShadowScanRequest(BaseModel):
    prompt: str
    user_id: Optional[str] = "anonymous"

class SIEMTestRequest(BaseModel):
    provider: str  # "datadog", "splunk_hec", "elastic", "slack", "pagerduty", "webhook"
    config: dict  # Provider-specific config

class MCPToolCallRequest(BaseModel):
    server_id: str
    tool_name: str
    arguments: dict
    role: Optional[str] = None

class MCPRegisterRequest(BaseModel):
    server_id: str
    url: str
    description: Optional[str] = ""
    allowed_tools: Optional[List[str]] = []
    blocked_tools: Optional[List[str]] = []
    rate_limit: Optional[int] = 60

class MCPDiscoverRequest(BaseModel):
    server_url: str

class MCPToolValidateRequest(BaseModel):
    tool_definition: dict
# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Interlock",
    description="OpenAI-compatible reverse proxy with AI security scanning",
    version="1.0.0"
)
_default_openapi_builder = app.openapi

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize DB and seed legacy keys at startup
@app.on_event("startup")
def _init_db():
    db.init_db()
    db.seed_legacy_keys()
    db.seed_mcp_servers()

# Mount admin endpoints
app.include_router(admin_router)

# ── Config ────────────────────────────────────────────────────────────────────
# API keys, rate limits, plan info, SIEM configs, fail modes — all moved to SQLite.
# See core/db.py for the schema. Use /admin/keys endpoints to manage keys.

request_counts = defaultdict(list)  # in-memory rate-limit window (replace with Redis for HA)

CONFIDENCE_MAP = {
    "CRITICAL": 0.99, "HIGH": 0.90,
    "MEDIUM": 0.75,   "LOW": 0.55, "SAFE": 0.95,
}

# ── Helpers ───────────────────────────────────────────────────────────────────
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

    # Monthly quota check (0 = unlimited)
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
        result.layer_caught = "Layer 1 — Rule Engine"
        result.confidence = CONFIDENCE_MAP.get(result.threat_level.value, 0.8)
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        result.risk_score = calculate_risk_score(result)
        return result

    result = pattern_match_scan(prompt)
    if result.is_threat:
        result.layer_caught = "Layer 2 — Pattern Matcher"
        result.confidence = CONFIDENCE_MAP.get(result.threat_level.value, 0.8)
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        result.risk_score = calculate_risk_score(result)
        return result

    # Layers 1 & 2 returned SAFE if we got here. Pass that context into the judge
    # so fail_open_safe can decide whether bypassing is acceptable on Groq outage.
    result = llm_judge_scan(prompt, api_key=api_key, prior_layers_safe=True)
    # Preserve layer_caught if the judge already set one (e.g. fail-mode label)
    if not result.layer_caught:
        result.layer_caught = "Layer 3 — LLM Judge"
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
# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "status": "Interlock running",
        "version": "1.0.0",
        "endpoints": {
            "openai_proxy": "POST /v1/chat/completions",
            "direct_scan":  "POST /scan",
            "health":       "GET /health"
        }
    }

@app.get("/health")
def health():
    return {"status": "healthy", "version": "1.0.0"}


@app.post("/v1/chat/completions")
@app.post("/v1/chat/completions")
async def chat_completions(
    chat: ChatRequest,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None)
):
    """
    Universal AI proxy — works with OpenAI, Anthropic, Gemini, Groq, Ollama.
    Just change base_url and use any model name from any provider.
    """
    api_key = authorization or x_api_key
    key_info, raw_key = verify_key(api_key)
    check_rate(raw_key, key_info["rate_per_min"])

    # Auto-detect provider from model name
    provider = detect_provider(chat.model)

    # Scan all user messages
    user_prompts = [m.content for m in chat.messages if m.role == "user"]
    for prompt in user_prompts:
        result = run_scan(prompt, raw_key)
        save_scan(raw_key, result)
        if result.is_threat:
            trigger_all_alerts(result, raw_key, key_info)
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "policy_violation",
                    "message": "Request blocked by Interlock.",
                    "threat_level": result.threat_level.value,
                    "threat_type": result.threat_type,
                    "reason": result.reason,
                    "confidence": result.confidence,
                    "layer_caught": result.layer_caught,
                    "scan_time_ms": result.scan_time_ms,
                    "provider": provider,
                    "safe_to_proceed": False
                }
            )

    # All prompts safe — forward to detected provider
    body = chat.dict(exclude_none=True)
    response = await forward_to_provider(provider, body)

    # Add firewall metadata
    if isinstance(response, dict) and "error" not in response:
        response["firewall"] = {
            "status": "clean",
            "provider": provider,
            "scans": len(user_prompts),
            "model": chat.model,
        }

    return response


@app.get("/providers")
async def list_providers(x_api_key: Optional[str] = Header(None)):
    """List supported AI providers and their models."""
    verify_key(x_api_key)
    return {
        "providers": {
            name: {
                "model_prefixes": cfg["model_prefixes"],
                "format": cfg["format"],
                "configured": bool(os.getenv(cfg["key_env"])) if cfg["key_env"] else True,
            }
            for name, cfg in PROVIDERS.items()
        },
        "auto_detection": "Provider is detected automatically from model name."
    }

@app.post("/scan", response_model=ScanResult)
async def scan(request: ScanRequest, x_api_key: Optional[str] = Header(None)):
    key_info, raw_key = verify_key(x_api_key)
    check_rate(raw_key, key_info["rate_per_min"])

    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    result = run_scan(request.prompt, raw_key)
    save_scan(raw_key, result)
    db.log_usage(key_info["id"], "/scan", threat_blocked=result.is_threat)
    if result.is_threat:
        trigger_all_alerts(result, raw_key, key_info)
    asyncio.get_running_loop().create_task(_broadcast({
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

@app.post("/inspect/tool-call")
async def inspect_tool(
    request: ToolCallRequest,
    x_api_key: Optional[str] = Header(None)
):
    key_info, raw_key = verify_key(x_api_key)
    check_rate(raw_key, key_info["rate_per_min"])

    # RBAC check first — always runs if role provided
    if request.role:
        from core.policy import rbac_scan
        rbac_result = rbac_scan(
            str(request.tool_args),
            request.tool_name,
            request.role
        )
        if rbac_result:
            rbac_result.scan_time_ms = 0.1
            rbac_result.risk_score = calculate_risk_score(rbac_result)
            save_scan(raw_key, rbac_result)
            return rbac_result  # return directly, don't raise

    # Tool inspection
    result = inspect_tool_call(request.tool_name, request.tool_args)
    result.risk_score = calculate_risk_score(result)
    save_scan(raw_key, result)
    return result

@app.post("/scan/shadow")
async def shadow_scan(
    request: ShadowScanRequest,
    x_api_key: Optional[str] = Header(None)
):
    key_info, raw_key = verify_key(x_api_key)
    check_rate(raw_key, key_info["rate_per_min"])
    result = run_scan(request.prompt, raw_key)
    log_shadow(result, raw_key)
    save_scan(raw_key, result)
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
        "action_taken": "LOGGED_ONLY"
    }

@app.get("/shadow/logs")
async def shadow_logs(limit: int = 50, x_api_key: Optional[str] = Header(None)):
    verify_key(x_api_key)
    return {"logs": get_shadow_logs(limit)}

@app.get("/roles")
async def get_roles(x_api_key: Optional[str] = Header(None)):
    verify_key(x_api_key)
    from core.policy import ROLE_POLICIES
    return {"roles": ROLE_POLICIES}

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    # #region agent log
    try:
        import json
        with open("debug-cef37a.log", "a", encoding="utf-8") as _debug_log:
            _debug_log.write(json.dumps({
                "sessionId": "cef37a",
                "runId": "pre-fix",
                "hypothesisId": "H2",
                "location": "proxy.py:376",
                "message": "custom_openapi using default app builder",
                "data": {"default_builder_module": getattr(_default_openapi_builder, "__module__", "unknown")},
                "timestamp": int(time.time() * 1000)
            }) + "\n")
    except Exception:
        pass
    # #endregion
    schema = _default_openapi_builder()
    schema["components"]["securitySchemes"] = {
        "APIKeyHeader": {
            "type": "apiKey",
            "in": "header",
            "name": "x-api-key"
        }
    }
    schema["security"] = [{"APIKeyHeader": []}]
    app.openapi_schema = schema
    return schema

app.openapi = custom_openapi

@app.get("/shadow/stats")
async def shadow_stats(x_api_key: Optional[str] = Header(None)):
    """Aggregated stats from shadow mode logs."""
    verify_key(x_api_key)
    return get_shadow_stats()

@app.post("/siem/test")
async def test_siem(
    request: SIEMTestRequest,
    x_api_key: Optional[str] = Header(None)
):
    """Test SIEM integration with a sample threat event."""
    verify_key(x_api_key)

    # Create a test threat
    test_result = ScanResult(
        is_threat=True,
        threat_level=ThreatLevel.HIGH,
        threat_type="SIEM_TEST",
        reason="This is a test alert from Interlock to verify SIEM integration.",
        original_prompt="[TEST] Sample prompt for SIEM verification",
        safe_to_proceed=False,
        confidence=0.95,
        layer_caught="SIEM Test",
        scan_time_ms=0.1,
    )

    from core.siem import send_to_siem
    result = await send_to_siem(request.provider, request.config, test_result, "test-key")
    return result


@app.get("/siem/providers")
async def list_siem_providers(x_api_key: Optional[str] = Header(None)):
    """List supported SIEM providers."""
    verify_key(x_api_key)
    from core.siem import SIEM_PROVIDERS
    return {
        "providers": list(SIEM_PROVIDERS.keys()),
        "config_examples": {
            "datadog": {"provider": "datadog", "api_key": "your-dd-key", "region": "us", "min_severity": "MEDIUM"},
            "splunk_hec": {"provider": "splunk_hec", "url": "https://splunk.company.com:8088", "token": "hec-token", "min_severity": "HIGH"},
            "elastic": {"provider": "elastic", "url": "https://elastic.company.com:9200", "api_key": "elastic-key", "index": "interlock", "min_severity": "MEDIUM"},
            "slack": {"provider": "slack", "webhook_url": "https://hooks.slack.com/services/xxx", "min_severity": "HIGH"},
            "pagerduty": {"provider": "pagerduty", "integration_key": "pd-integration-key", "min_severity": "CRITICAL"},
            "webhook": {"provider": "webhook", "url": "https://your-endpoint.com/alerts", "headers": {}, "min_severity": "LOW"},
        }
    }

@app.get("/mcp/servers")
async def mcp_list_servers(x_api_key: Optional[str] = Header(None)):
    """List all registered MCP servers."""
    verify_key(x_api_key)
    return {"servers": list_mcp_servers()}


@app.post("/mcp/servers")
async def mcp_register(
    request: MCPRegisterRequest,
    x_api_key: Optional[str] = Header(None)
):
    """Register a new MCP server (requires manual verification before use)."""
    verify_key(x_api_key)
    return register_mcp_server(request.server_id, request.dict())


@app.post("/mcp/discover")
async def mcp_discover(
    request: MCPDiscoverRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Discover tools from an MCP server.
    Every tool is validated for malicious patterns before being returned.
    """
    verify_key(x_api_key)
    return await discover_mcp_tools(request.server_url)


@app.post("/mcp/validate-tool")
async def mcp_validate(
    request: MCPToolValidateRequest,
    x_api_key: Optional[str] = Header(None)
):
    """Validate a single MCP tool definition for security issues."""
    verify_key(x_api_key)
    result = validate_mcp_tool_definition(request.tool_definition)
    return result


@app.post("/mcp/call")
async def mcp_call(
    request: MCPToolCallRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Proxy an MCP tool call through the firewall.
    Pipeline: trust check → tool whitelist → inspector → RBAC → forward → response scan.
    """
    key_info, raw_key = verify_key(x_api_key)
    check_rate(raw_key, key_info["rate_per_min"])

    result = await proxy_mcp_tool_call(
        server_id=request.server_id,
        tool_name=request.tool_name,
        arguments=request.arguments,
        role=request.role,
        api_key=raw_key,
    )
    return result


@app.delete("/mcp/servers/{server_id}")
async def mcp_unregister(server_id: str, x_api_key: Optional[str] = Header(None)):
    """Remove an MCP server from the registry."""
    verify_key(x_api_key)
    removed = db.unregister_mcp_server(server_id)
    if removed:
        return {"ok": True, "removed": server_id}
    return {"ok": False, "error": "not_found"}


# ── Output scanning ───────────────────────────────────────────────────────────

import re as _re

@app.post("/scan/output", response_model=ScanResult)
async def scan_output(request: ScanRequest, x_api_key: Optional[str] = Header(None)):
    """Scan an LLM response for PII / data-leak patterns."""
    key_info, raw_key = verify_key(x_api_key)
    check_rate(raw_key, key_info["rate_per_min"])

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
    db.log_usage(key_info["id"], "/scan/output", threat_blocked=False)
    return result


# ── Customer usage stats ──────────────────────────────────────────────────────

@app.get("/usage")
async def usage(x_api_key: Optional[str] = Header(None)):
    """Return the calling key's own quota consumption for the current month."""
    key_info, _ = verify_key(x_api_key)
    used = db.usage_this_month(key_info["id"])
    limit = key_info["monthly_limit"]
    return {
        "plan": key_info["plan"],
        "used_this_month": used,
        "monthly_limit": limit,
        "remaining": None if limit == 0 else max(0, limit - used),
    }


# ── WebSocket live feed ───────────────────────────────────────────────────────

_active_ws: list = []


async def _broadcast(message: dict):
    for conn in list(_active_ws):
        try:
            await conn.send_json(message)
        except Exception:
            pass


@app.websocket("/ws")
async def websocket_feed(websocket: WebSocket):
    """Real-time scan-event feed consumed by dashboard.html."""
    await websocket.accept()
    _active_ws.append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _active_ws:
            _active_ws.remove(websocket)