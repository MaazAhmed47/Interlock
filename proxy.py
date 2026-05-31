import asyncio
import logging
import os
import time
from typing import Optional

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocketDisconnect  # noqa: F401
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware

from core import db
from core import rate_limit
from core.detector import rule_based_scan
from core.learning import check_learned_patterns, learn_from_result
from core.llm_judge import llm_judge_scan
from core.pattern_matcher import pattern_match_scan
from core.policy import policy_scan, ROLE_POLICIES
from core.shadow_mode import calculate_risk_score
from core.siem import trigger_siem_dispatch
from core.webhook import trigger_webhook
from models.schemas import (  # noqa: F401
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

_START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    db.seed_legacy_keys()
    db.seed_mcp_servers()
    db.seed_default_policies(ROLE_POLICIES, policy_type="role")
    if not os.getenv("REDIS_URL"):
        logger.warning(
            "WARNING: Using in-memory rate limiting. "
            "Set REDIS_URL for production multi-instance deployments."
        )
    if os.getenv("SHADOW_SCAN_ENABLED", "false").lower() == "true":
        from core.shadow_scanner import run_shadow_scan as _run_shadow_scan

        _scan_interval = int(os.getenv("SHADOW_SCAN_INTERVAL", "3600"))

        async def _shadow_scan_loop():
            while True:
                try:
                    with db.get_conn() as conn:
                        findings = await _run_shadow_scan(conn)
                        if findings:
                            logger.info("Shadow scan: %d new finding(s)", len(findings))
                except Exception:
                    logger.exception("Shadow scan loop error")
                await asyncio.sleep(_scan_interval)

        asyncio.get_running_loop().create_task(_shadow_scan_loop())
    yield


app = FastAPI(
    title="Interlock",
    description="OpenAI-compatible reverse proxy with AI security scanning",
    version="0.1.0",
    lifespan=lifespan,
)
_default_openapi_builder = app.openapi

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

# API keys, rate limits, plan info, SIEM configs, and fail modes live in SQLite.
# See core/db.py for the schema. Use /admin/keys endpoints to manage keys.
_active_ws: list = []

KEY_CACHE_TTL_S = float(os.getenv("INTERLOCK_KEY_CACHE_TTL_S", "10"))
USAGE_CACHE_TTL_S = float(os.getenv("INTERLOCK_USAGE_CACHE_TTL_S", "5"))
_key_record_cache: dict[str, tuple[float, dict]] = {}
_usage_cache: dict[int, tuple[float, int]] = {}

CONFIDENCE_MAP = {
    "CRITICAL": 0.99,
    "HIGH": 0.90,
    "MEDIUM": 0.75,
    "LOW": 0.55,
    "SAFE": 0.95,
}


def _cached_lookup_key(raw_key: str):
    cache_key = db._hash_key(raw_key)
    now = time.time()
    cached = _key_record_cache.get(cache_key)
    if cached and now - cached[0] <= KEY_CACHE_TTL_S:
        return dict(cached[1])

    record = db.lookup_key(raw_key)
    if record:
        _key_record_cache[cache_key] = (now, dict(record))
    else:
        _key_record_cache.pop(cache_key, None)
    return record


def _cached_usage_this_month(key_id: int) -> int:
    now = time.time()
    cached = _usage_cache.get(key_id)
    if cached and now - cached[0] <= USAGE_CACHE_TTL_S:
        return cached[1]

    used = db.usage_this_month(key_id)
    _usage_cache[key_id] = (now, used)
    return used


def _bump_usage_cache(key_id: int, delta: int = 1) -> None:
    cached = _usage_cache.get(key_id)
    if cached:
        _usage_cache[key_id] = (time.time(), cached[1] + delta)


def verify_key(api_key: Optional[str]):
    """
    Look the key up in the DB. Returns (key_record_dict, raw_key) on success.
    Raises 401/403 on bad input.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key.")
    raw = api_key.replace("Bearer ", "").replace("bearer ", "").strip()

    record = _cached_lookup_key(raw)
    if not record:
        raise HTTPException(status_code=403, detail="Invalid or revoked API key.")

    if record["monthly_limit"] > 0:
        used = _cached_usage_this_month(record["id"])
        if used >= record["monthly_limit"]:
            raise HTTPException(
                status_code=429,
                detail=f"Monthly quota exceeded ({used}/{record['monthly_limit']}). Upgrade plan or wait for reset.",
            )

    return record, raw


# WARNING: In-memory rate limiting. Does not work across multiple
# workers or pods. Run with --workers 1 (default in Dockerfile)
# or deploy Redis and swap this for a Redis-backed counter.
def check_rate(api_key: str, rate_per_min: int):
    """Sliding-window per-minute rate limit with optional Redis shared state."""
    try:
        return rate_limit.check_rate(api_key, rate_per_min)
    except rate_limit.RateLimitExceeded:
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")


FAST_SCAN_MODES = {"fast", "runtime", "deterministic", "demo"}


def _finalize_scan_result(
    result: ScanResult,
    start: float,
    default_layer: str,
    default_confidence: Optional[float] = None,
    endpoint: str = "/scan",
) -> ScanResult:
    if not result.layer_caught:
        result.layer_caught = default_layer
    if result.confidence is None:
        result.confidence = default_confidence or CONFIDENCE_MAP.get(
            result.threat_level.value, 0.8
        )
    result.scan_time_ms = round((time.time() - start) * 1000, 2)
    result.risk_score = calculate_risk_score(result)
    try:
        db.record_latency_sample(endpoint, result.scan_time_ms, result.is_threat)
    except Exception:
        logger.debug("Failed to record latency sample", exc_info=True)
    return result


def _run_deterministic_scan_layers(
    prompt: str,
    api_key: str,
    start: float,
    key_record: Optional[dict] = None,
) -> Optional[ScanResult]:
    result = check_learned_patterns(prompt)
    if result:
        return _finalize_scan_result(result, start, "Learned Pattern Cache")

    result = policy_scan(prompt, api_key, key_record=key_record)
    if result:
        return _finalize_scan_result(result, start, "Custom Policy Engine")

    result = rule_based_scan(prompt)
    if result.is_threat:
        return _finalize_scan_result(result, start, "Layer 1 - Rule Engine")

    result = pattern_match_scan(prompt)
    if result.is_threat:
        return _finalize_scan_result(result, start, "Layer 2 - Pattern Matcher")

    return None


def run_fast_scan(
    prompt: str, api_key: str, key_record: Optional[dict] = None
) -> ScanResult:
    """Run only deterministic runtime checks so demos never wait on an external judge."""
    start = time.time()
    result = _run_deterministic_scan_layers(
        prompt, api_key, start, key_record=key_record
    )
    if result:
        return result

    result = ScanResult(
        is_threat=False,
        threat_level=ThreatLevel.SAFE,
        threat_type=None,
        reason="No threats detected by policy, rule engine, or pattern matcher. LLM judge skipped in fast mode.",
        original_prompt=prompt,
        safe_to_proceed=True,
        confidence=0.93,
        layer_caught="Runtime Policy Engine",
    )
    return _finalize_scan_result(result, start, "Runtime Policy Engine")


def run_scan(
    prompt: str, api_key: str, key_record: Optional[dict] = None
) -> ScanResult:
    start = time.time()

    result = _run_deterministic_scan_layers(
        prompt, api_key, start, key_record=key_record
    )
    if result:
        return result

    # Layers 1 & 2 returned SAFE if we got here. Pass that context into the judge
    # so fail_open_safe can decide whether bypassing is acceptable on Groq outage.
    result = llm_judge_scan(prompt, api_key=api_key, prior_layers_safe=True)
    result = _finalize_scan_result(result, start, "Layer 3 - LLM Judge")
    learn_from_result(prompt, result)
    return result


def trigger_all_alerts(result, api_key, key_record=None):
    """Trigger webhook + SIEM in parallel. SIEM configs come from the key record."""
    trigger_webhook(api_key, result)
    siem_configs = (key_record or {}).get("siem_configs") or []
    if siem_configs and any(
        c.get("webhook_url") or c.get("api_key") or c.get("integration_key")
        for c in siem_configs
    ):
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


from routes import (  # noqa: E402
    admin_routes,
    chat as chat_routes,
    mcp as mcp_routes,
    scan as scan_routes,
    system as system_routes,
)

app.include_router(admin_routes.router)  # type: ignore[attr-defined,has-type]
app.include_router(system_routes.router)  # type: ignore[attr-defined,has-type]
app.include_router(chat_routes.router)  # type: ignore[attr-defined,has-type]
app.include_router(scan_routes.router)  # type: ignore[attr-defined,has-type]
app.include_router(mcp_routes.router)  # type: ignore[attr-defined,has-type]
app.openapi = custom_openapi  # type: ignore[method-assign]

# Backward-compatible aliases for tests and direct function callers.
root = system_routes.root  # type: ignore[has-type]
health = system_routes.health  # type: ignore[has-type]
get_roles = system_routes.get_roles  # type: ignore[has-type]
usage = system_routes.usage  # type: ignore[has-type]
test_siem = system_routes.test_siem  # type: ignore[has-type]
list_siem_providers = system_routes.list_siem_providers  # type: ignore[has-type]
websocket_feed = system_routes.websocket_feed  # type: ignore[has-type]

chat_completions = chat_routes.chat_completions  # type: ignore[has-type]
list_providers = chat_routes.list_providers  # type: ignore[has-type]

scan = scan_routes.scan  # type: ignore[has-type]
scan_output = scan_routes.scan_output  # type: ignore[has-type]
scan_history = scan_routes.scan_history  # type: ignore[has-type]
scan_stats = scan_routes.scan_stats  # type: ignore[has-type]
shadow_scan = scan_routes.shadow_scan  # type: ignore[has-type]
shadow_logs = scan_routes.shadow_logs  # type: ignore[has-type]
shadow_stats = scan_routes.shadow_stats  # type: ignore[has-type]
inspect_tool = scan_routes.inspect_tool  # type: ignore[has-type]

mcp_list_servers = mcp_routes.mcp_list_servers  # type: ignore[has-type]
mcp_register = mcp_routes.mcp_register  # type: ignore[has-type]
mcp_discover = mcp_routes.mcp_discover  # type: ignore[has-type]
mcp_tools = mcp_routes.mcp_tools  # type: ignore[has-type]
mcp_drifted_tools = mcp_routes.mcp_drifted_tools  # type: ignore[has-type]
mcp_approve_tool_baseline = mcp_routes.mcp_approve_tool_baseline  # type: ignore[has-type]
mcp_quarantine_tool = mcp_routes.mcp_quarantine_tool  # type: ignore[has-type]
mcp_audit = mcp_routes.mcp_audit  # type: ignore[has-type]
mcp_validate = mcp_routes.mcp_validate  # type: ignore[has-type]
mcp_call = mcp_routes.mcp_call  # type: ignore[has-type]
mcp_unregister = mcp_routes.mcp_unregister  # type: ignore[has-type]
