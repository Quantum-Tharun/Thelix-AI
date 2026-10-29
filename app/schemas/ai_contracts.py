from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from uuid import UUID

class BaseUniformResponse(BaseModel):
    """
    The strict contract guaranteed by the Risk Engine for the Backend.
    """
    trust_score: int = Field(..., ge=0, le=100, description="Final aggregated safe score")
    risk_score: int = Field(..., ge=0, le=100, description="Final aggregated danger score")
    threat_level: str = Field(..., description="'Low', 'Medium', 'High', 'Critical'")
    reasons: List[str] = Field(..., description="Array of strings explaining the risk factors")
    recommendations: List[str] = Field(..., description="Array of strings suggesting user actions")
    explanation: Optional[str] = Field(None, description="Human-readable LLM explanation")
    evidence: Dict[str, Any] = Field(..., description="Raw outputs from OCR, Safe Browsing, etc.")
    model_versions: Dict[str, str] = Field(..., description="Audit trail of models used (e.g., {'ocr': 'google-mlkit-v1'})")
    processed_offline: bool = Field(..., description="True if resolved without internet")

class ScreenshotAnalysisRequest(BaseModel):
    user_id: str
    image_base64: str = Field(..., description="Base64 encoded image data")
    source: str = Field(..., description="E.g., 'WhatsApp', 'SMS', 'Gallery'")
    locale: str = Field("en-US")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class URLAnalysisRequest(BaseModel):
    user_id: str
    url: str
    source: str
    locale: str = Field("en-US")

class QRAnalysisRequest(BaseModel):
    user_id: str
    image_base64: str
