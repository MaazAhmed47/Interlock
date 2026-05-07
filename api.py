from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from models.schemas import ScanRequest, ScanResult, ThreatLevel
from core.detector import rule_based_scan, PII_PATTERNS
from core.pattern_matcher import pattern_match_scan
from core.llm_judge import llm_judge_scan
from pydantic import BaseModel
from core.policy import policy_scan
from core.webhook import trigger_webhook
from fastapi import WebSocket, WebSocketDisconnect
from core.learning import learn_from_result, check_learned_patterns
from core.history import save_scan, get_history, get_stats
from typing import Optional
from core.learning import report_false_negative
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Header, WebSocket, WebSocketDisconnect
import asyncio
import time
import re

active_connections: list = []

app = FastAPI(
    title="LLM Firewall",
    description="Real-time prompt injection and threat detection API",
    version="0.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VALID_API_KEYS = {
    "lf-free-demo-key-123":  {"plan": "free",      "limit": 1000},
    "lf-dev-key-456":        {"plan": "developer",  "limit": 50000},
    "lf-startup-key-789":    {"plan": "startup",    "limit": 500000},
}

RATE_LIMITS = {"free": 10, "developer": 60, "startup": 300}
request_counts = defaultdict(list)

CONFIDENCE_MAP = {
    "CRITICAL": 0.99, "HIGH": 0.90,
    "MEDIUM": 0.75,   "LOW": 0.55, "SAFE": 0.95,
}

def verify_api_key(api_key: Optional[str]) -> dict:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key. Pass it as x-api-key header.")
    if api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key.")
    return VALID_API_KEYS[api_key]

def check_rate_limit(api_key: str, plan: str):
    now = time.time()
    request_counts[api_key] = [t for t in request_counts[api_key] if now - t < 60]
    if len(request_counts[api_key]) >= RATE_LIMITS[plan]:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. {plan} plan: {RATE_LIMITS[plan]} req/min.")
    request_counts[api_key].append(now)

def run_scan(prompt: str, api_key: str) -> ScanResult:
    start = time.time()

    # Layer 0 — Learned memory (fastest, from past decisions)
    result = check_learned_patterns(prompt)
    if result:
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        return result

    # Custom policy
    result = policy_scan(prompt, api_key)
    if result:
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        return result

    # Layer 1
    result = rule_based_scan(prompt)
    if result.is_threat:
        result.layer_caught = "Layer 1 — Rule Engine"
        result.confidence = CONFIDENCE_MAP.get(result.threat_level.value, 0.8)
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        return result

    # Layer 2
    result = pattern_match_scan(prompt)
    if result.is_threat:
        result.layer_caught = "Layer 2 — Pattern Matcher"
        result.confidence = CONFIDENCE_MAP.get(result.threat_level.value, 0.8)
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        return result

    # Layer 3
    result = llm_judge_scan(prompt)
    result.layer_caught = "Layer 3 — LLM Judge"
    result.confidence = CONFIDENCE_MAP.get(result.threat_level.value, 0.8)
    result.scan_time_ms = round((time.time() - start) * 1000, 2)

    # Learn from LLM decision
    learn_from_result(prompt, result)

    return result


@app.get("/")
def root():
    return {"status": "LLM Firewall is running", "version": "0.3.0"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/scan", response_model=ScanResult)
async def scan(request: ScanRequest, x_api_key: Optional[str] = Header(None)):
    key_info = verify_api_key(x_api_key)
    check_rate_limit(x_api_key, key_info["plan"])

    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    result = run_scan(request.prompt, x_api_key)
    save_scan(x_api_key, result)

    await broadcast({
    "type": "scan",
    "is_threat": result.is_threat,
    "threat_level": result.threat_level.value,
    "threat_type": result.threat_type,
    "prompt_preview": request.prompt[:60],
    "scan_time_ms": result.scan_time_ms,
    "layer_caught": result.layer_caught,
    "confidence": result.confidence,
})

    # Fire webhook for high severity threats
    if result.is_threat:
        trigger_webhook(x_api_key, result)

    return result


@app.post("/scan/output", response_model=ScanResult)
def scan_output(request: ScanRequest, x_api_key: Optional[str] = Header(None)):
    key_info = verify_api_key(x_api_key)
    check_rate_limit(x_api_key, key_info["plan"])

    for pattern in PII_PATTERNS:
        if re.search(pattern, request.prompt):
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.HIGH,
                threat_type="OUTPUT_DATA_LEAK",
                reason="LLM response contains sensitive data.",
                original_prompt=request.prompt,
                safe_to_proceed=False,
                confidence=0.95,
                layer_caught="Output Scanner",
                scan_time_ms=0.1
            )

    return ScanResult(
        is_threat=False,
        threat_level=ThreatLevel.SAFE,
        threat_type=None,
        reason="Output scan clean.",
        original_prompt=request.prompt,
        safe_to_proceed=True,
        confidence=0.95,
        layer_caught="Output Scanner",
        scan_time_ms=0.1
    )


@app.get("/usage")
def usage(x_api_key: Optional[str] = Header(None)):
    key_info = verify_api_key(x_api_key)
    now = time.time()
    recent = [t for t in request_counts[x_api_key] if now - t < 60]
    return {
        "plan": key_info["plan"],
        "requests_last_minute": len(recent),
        "rate_limit_per_minute": RATE_LIMITS[key_info["plan"]],
        "monthly_limit": key_info["limit"],
    }


@app.get("/policy")
def get_policy(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    from core.policy import CUSTOM_POLICIES
    policy = CUSTOM_POLICIES.get(x_api_key, {})
    return {"api_key_plan": VALID_API_KEYS[x_api_key]["plan"], "policy": policy}

@app.get("/history")
def history(limit: int = 50, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    return {"history": get_history(x_api_key, limit)}

@app.get("/stats")
def stats(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    return get_stats(x_api_key)
class FalseNegativeReport(BaseModel):
    prompt: str
    correct_threat_type: str

@app.post("/report/false-negative")
def report_fn(report: FalseNegativeReport, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    report_false_negative(report.prompt, report.correct_threat_type)
    return {"status": "reported", "message": "Thank you. This will improve our detection."}

@app.get("/learned-patterns")
def learned(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    from core.learning import _load
    data = _load()
    return {
        "total_learned": len(data["patterns"]),
        "false_negatives_reported": len(data["false_negatives"]),
        "patterns": data["patterns"][:20]
    }


async def broadcast(message: dict):
    for conn in active_connections:
        try:
            await conn.send_json(message)
        except:
            pass

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)