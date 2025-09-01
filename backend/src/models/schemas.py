from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List, Dict, Union
from enum import Enum
from datetime import datetime

class ThreatType(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    TYPOSQUATTING = "typosquatting"
    SUSPICIOUS = "suspicious"
    SAFE = "safe"

# Minimal request - only essential data
class URLAnalysisRequest(BaseModel):
    url: HttpUrl
    confidence: Optional[float] = Field(0.0, ge=0.0, le=1.0)
    reason: Optional[str] = Field("", max_length=50)  # Limit reason length

# Minimal response - only what extension needs
class URLAnalysisResponse(BaseModel):
    suspicious: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(max_length=100)  # Concise reason
    type: ThreatType

# Detailed response for debugging/analytics (optional endpoint)
class DetailedURLAnalysisResponse(BaseModel):
    suspicious: bool
    confidence: float
    reason: str
    type: ThreatType
    sources: list[str]
    vt_details: Optional[dict] = None
    processing_ms: Optional[int] = None

class HealthResponse(BaseModel):
    status: str = Field(..., description="Service status")
    services: Dict[str, str] = Field(..., description="Status of individual services")
    timestamp: str = Field(..., description="Response timestamp")
    version: str = Field("1.0.0", description="API version")

class ErrorResponse(BaseModel):
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    timestamp: str = Field(..., description="Error timestamp")
