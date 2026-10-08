"""
Pydantic Schemas for ML Inference Service
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class URLInferenceRequest(BaseModel):
    url: str = Field(..., description="Raw URL string to evaluate")


class URLInferenceResponse(BaseModel):
    model_id: str = "url-phishing"
    model_version: str = "2.0.0"
    detector_version: str = "url-phishing-2.0.0"
    score: float
    raw_score: Optional[float] = None
    calibrated_probability: Optional[float] = None
    calibrated: bool = True
    threshold: float = 0.50
    predicted_class: str
    top_signals: List[Dict[str, Any]]
    features: Dict[str, Any]
    feature_extraction_time_ms: Optional[float] = None
    model_inference_time_ms: Optional[float] = None
    processing_time_ms: float
    analysis_status: str = "success"
    errors: List[str] = []


class MessageInferenceRequest(BaseModel):
    message: str = Field(..., description="Unstructured email or message text")
    context: Optional[str] = "generic"


class MessageInferenceResponse(BaseModel):
    model_id: str = "text-scam"
    model_version: str = "2.0.0"
    detector_version: str = "text-scam-2.0.0"
    score: float
    raw_score: Optional[float] = None
    calibrated_probability: Optional[float] = None
    calibrated: bool = True
    threshold: float = 0.50
    predicted_class: str
    entities: Dict[str, Any]
    signals: List[Dict[str, Any]]
    processing_time_ms: float
    analysis_status: str = "success"
    errors: List[str] = []


class ModelMetadataResponse(BaseModel):
    models: List[Dict[str, Any]]
