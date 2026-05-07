from pydantic import BaseModel
from typing import Optional
from enum import Enum

class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ScanRequest(BaseModel):
    prompt: str
    user_id: Optional[str] = "anonymous"
    context: Optional[str] = None


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
    risk_score: Optional[int] = None      # 0-100


