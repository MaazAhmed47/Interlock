from typing import Optional

from fastapi import APIRouter, Header, WebSocket, WebSocketDisconnect

import proxy
from core import db, rate_limit
from models.schemas import SIEMTestRequest, ScanResult, ThreatLevel

router = APIRouter()


@router.api_route("/", methods=["GET", "HEAD"])
def root():
    return {
        "status": "Interlock gateway running",
        "version": "0.1.0",
        "endpoints": {
            "openai_proxy": "POST /v1/chat/completions",
            "direct_scan": "POST /scan",
            "health": "GET /health",
        },
    }


@router.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {
        "status": "ok",
        "service": "interlock",
        "rate_limit": rate_limit.status(),
    }


@router.get("/roles")
async def get_roles(x_api_key: Optional[str] = Header(None)):
    proxy.verify_key(x_api_key)
    from core.policy import ROLE_POLICIES

    return {"roles": ROLE_POLICIES}


@router.get("/usage")
async def usage(x_api_key: Optional[str] = Header(None)):
    """Return the calling key's own quota consumption for the current month."""
    key_info, _ = proxy.verify_key(x_api_key)
    used = proxy._cached_usage_this_month(key_info["id"])
    limit = key_info["monthly_limit"]
    return {
        "plan": key_info["plan"],
        "used_this_month": used,
        "monthly_limit": limit,
        "remaining": None if limit == 0 else max(0, limit - used),
    }


@router.post("/siem/test")
async def test_siem(request: SIEMTestRequest, x_api_key: Optional[str] = Header(None)):
    """Test SIEM integration with a sample threat event."""
    proxy.verify_key(x_api_key)

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

    return await send_to_siem(request.provider, request.config, test_result, "test-key")


@router.get("/siem/providers")
async def list_siem_providers(x_api_key: Optional[str] = Header(None)):
    """List supported SIEM providers."""
    proxy.verify_key(x_api_key)
    from core.siem import SIEM_PROVIDERS

    return {
        "providers": list(SIEM_PROVIDERS.keys()),
        "config_examples": {
            "datadog": {
                "provider": "datadog",
                "api_key": "your-dd-key",
                "region": "us",
                "min_severity": "MEDIUM",
            },
            "splunk_hec": {
                "provider": "splunk_hec",
                "url": "https://splunk.company.com:8088",
                "token": "hec-token",
                "min_severity": "HIGH",
            },
            "elastic": {
                "provider": "elastic",
                "url": "https://elastic.company.com:9200",
                "api_key": "elastic-key",
                "index": "interlock",
                "min_severity": "MEDIUM",
            },
            "slack": {
                "provider": "slack",
                "webhook_url": "https://hooks.slack.com/services/xxx",
                "min_severity": "HIGH",
            },
            "pagerduty": {
                "provider": "pagerduty",
                "integration_key": "pd-integration-key",
                "min_severity": "CRITICAL",
            },
            "webhook": {
                "provider": "webhook",
                "url": "https://your-endpoint.com/alerts",
                "headers": {},
                "min_severity": "LOW",
            },
        },
    }


@router.websocket("/ws")
async def websocket_feed(websocket: WebSocket):
    """Real-time scan-event feed consumed by dashboard.html."""
    await websocket.accept()
    proxy._active_ws.append(websocket)
    try:
        while True:
            await proxy.asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in proxy._active_ws:
            proxy._active_ws.remove(websocket)


@router.get("/metrics/performance")
def performance_metrics(
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    from core.admin import _require_admin

    _require_admin(x_admin_token, "metrics:read", authorization=authorization)
    import time as _time

    metrics = db.get_performance_metrics()
    metrics["uptime_seconds"] = int(_time.time() - proxy._START_TIME)
    return metrics
