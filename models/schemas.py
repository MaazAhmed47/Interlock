from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "llama-3.3-70b-versatile"
    messages: List[ChatMessage]
    stream: Optional[bool] = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None


class ScanRequest(BaseModel):
    prompt: str
    user_id: Optional[str] = "anonymous"
    context: Optional[str] = None
    mode: Optional[str] = None


class ToolCallRequest(BaseModel):
    tool_name: str
    tool_args: dict
    role: Optional[str] = None


class ShadowScanRequest(BaseModel):
    prompt: str
    user_id: Optional[str] = "anonymous"


class SIEMTestRequest(BaseModel):
    provider: str
    config: dict


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
    auth_type: Literal["none", "bearer", "x-api-key"] = "none"
    auth_header: Optional[str] = None
    auth_token_env: Optional[str] = None


class MCPDiscoverRequest(BaseModel):
    server_url: str
    server_id: Optional[str] = None


class MCPRebaselineRequest(BaseModel):
    confirm_rebaseline: bool = False


class MCPToolValidateRequest(BaseModel):
    tool_definition: dict


class MCPToolReviewRequest(BaseModel):
    reviewer: Optional[str] = "operator"
    reason: Optional[str] = ""


class MCPEffectivePermissionProbeRequest(BaseModel):
    probe_id: Optional[str] = None
    tool_name: str
    arguments: dict
    expected_outcome: Literal["denied", "allowed"]
    expected_status_code: Optional[int] = None
    expected_error_fingerprint: Optional[str] = None
    non_production: bool = False
    safety_note: str


class MCPReadbackCall(BaseModel):
    tool_name: str
    arguments: dict


class MCPEffectReadbackProbeRequest(BaseModel):
    probe_id: Optional[str] = None
    target: MCPReadbackCall
    readback: MCPReadbackCall
    expected_effect: Literal["no_change", "change_allowed"]
    non_production: bool = False
    safety_note: str


class MCPChainStep(BaseModel):
    server_id: Optional[str] = ""
    tool_name: str
    arguments: dict = {}
    effects: Optional[List[str]] = []
    data_classes: Optional[List[str]] = []
    externality: Optional[str] = "internal"
    side_effect: Optional[str] = "unknown"


class MCPChainAnalyzeRequest(BaseModel):
    chain_id: Optional[str] = None
    steps: List[MCPChainStep]
    role: Optional[str] = "operator"
    safety_note: str


class ScanResult(BaseModel):
    is_threat: bool
    threat_level: ThreatLevel
    threat_type: Optional[str] = None
    reason: str
    original_prompt: str
    safe_to_proceed: bool
    confidence: Optional[float] = None
    layer_caught: Optional[str] = None
    scan_time_ms: Optional[float] = None
    risk_score: Optional[int] = None
    sanitized_output: Optional[str] = None
    redactions: Optional[List[str]] = None
    tool_metadata: Optional[dict] = None


class ResponseScanResult(BaseModel):
    is_threat: bool
    threat_level: ThreatLevel
    threat_type: Optional[str] = None
    reason: str
    safe_to_proceed: bool
    confidence: Optional[float] = None
    sanitized_content: Optional[str] = None
    redactions: Optional[List[str]] = None
    matched_patterns: Optional[List[str]] = None
    scan_time_ms: Optional[float] = None
    risk_score: Optional[int] = None
