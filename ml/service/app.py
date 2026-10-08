"""
FastAPI Machine Learning Inference Microservice
Loads trained models (URL Phishing Classifier & Message Scam Intent Classifier),
performs feature extraction, returns structured predictions and evidence signals.
"""

import os
import sys
import json
import time
import hashlib
import joblib
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

# Ensure ml root is in path
ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ML_ROOT)

from features.url_features import extract_url_features, extract_features_vector, FEATURE_NAMES
from features.entity_extraction import extract_entities
from features.text_features import normalize_message_text, extract_text_meta_features
from service.schemas import (
    URLInferenceRequest, URLInferenceResponse,
    MessageInferenceRequest, MessageInferenceResponse,
    ModelMetadataResponse
)

app = FastAPI(
    title="AI Scam & Phishing Detection ML Service",
    version="2.0.0",
    description="Production ML inference service for multimodal scam & phishing detection."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model state
URL_MODEL = None
URL_METADATA = {}
URL_SCHEMA = {}
URL_EVALUATION = {}
URL_LOAD_ERROR = None
URL_EXPECTED_SHA256 = "b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156"

TEXT_MODEL = None
TEXT_VECTORIZER = None
TEXT_METADATA = {}
TEXT_SCHEMA = {}
TEXT_EVALUATION = {}
TEXT_LOAD_ERROR = None
TEXT_EXPECTED_SHA256 = "3dd3b1713b667c64d3acb190be6673ea284efb88a9f69d4434dc1ed07e9c952c"
TEXT_VEC_EXPECTED_SHA256 = "9d95f84636b0f289cb46fbe29c93a2b33f4de1ab54315684fe283d26c25a15e6"


def compute_sha256(filepath: str) -> str:
    """Computes SHA-256 digest of a local file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def load_artifacts():
    global URL_MODEL, URL_METADATA, URL_SCHEMA, URL_EVALUATION, URL_LOAD_ERROR
    global TEXT_MODEL, TEXT_VECTORIZER, TEXT_METADATA, TEXT_SCHEMA, TEXT_EVALUATION, TEXT_LOAD_ERROR

    # 1. Load URL Phishing Model (v2.0.0 active)
    url_dir = os.path.join(ML_ROOT, "models", "url_phishing")
    url_model_path = os.path.join(url_dir, "model.joblib")
    if not os.path.exists(url_model_path):
        url_model_path = os.path.join(url_dir, "v2.0.0", "model.joblib")

    if os.path.exists(url_model_path):
        try:
            actual_hash = compute_sha256(url_model_path)
            if actual_hash != URL_EXPECTED_SHA256:
                URL_LOAD_ERROR = f"MODEL_HASH_MISMATCH: Expected {URL_EXPECTED_SHA256}, got {actual_hash}"
                print(f"[!] {URL_LOAD_ERROR}")
                URL_MODEL = None
            else:
                loaded_model = joblib.load(url_model_path)
                if not hasattr(loaded_model, "predict_proba") or not hasattr(loaded_model, "predict"):
                    URL_LOAD_ERROR = "MODEL_SCHEMA_INVALID: Missing predict_proba or predict interface"
                    print(f"[!] {URL_LOAD_ERROR}")
                    URL_MODEL = None
                else:
                    URL_MODEL = loaded_model
                    meta_path = os.path.join(url_dir, "metadata.json")
                    if not os.path.exists(meta_path):
                        meta_path = os.path.join(url_dir, "v2.0.0", "metadata.json")
                    with open(meta_path, "r", encoding="utf-8") as f:
                        URL_METADATA = json.load(f)
                    
                    schema_path = os.path.join(url_dir, "feature_schema.json")
                    if os.path.exists(schema_path):
                        with open(schema_path, "r", encoding="utf-8") as f:
                            URL_SCHEMA = json.load(f)
                    
                    eval_path = os.path.join(url_dir, "evaluation.json")
                    if os.path.exists(eval_path):
                        with open(eval_path, "r", encoding="utf-8") as f:
                            URL_EVALUATION = json.load(f)
                    URL_LOAD_ERROR = None
                    print(f"[OK] Loaded URL Phishing Model v{URL_METADATA.get('version', '2.0.0')} (SHA-256: {actual_hash[:16]}...)")
        except Exception as e:
            URL_LOAD_ERROR = f"MODEL_LOAD_FAILED: {str(e)}"
            print(f"[!] {URL_LOAD_ERROR}")
            URL_MODEL = None
    else:
        URL_LOAD_ERROR = "MODEL_ARTIFACT_NOT_FOUND: URL phishing model.joblib not found"
        print(f"[!] {URL_LOAD_ERROR}")
        URL_MODEL = None

    # 2. Load Text Scam Intent Model (v2.0.0 active)
    text_dir = os.path.join(ML_ROOT, "models", "text_scam")
    text_model_path = os.path.join(text_dir, "model.joblib")
    text_vec_path = os.path.join(text_dir, "vectorizer.joblib")
    if not os.path.exists(text_model_path):
        text_model_path = os.path.join(text_dir, "v2.0.0", "model.joblib")
    if not os.path.exists(text_vec_path):
        text_vec_path = os.path.join(text_dir, "v2.0.0", "vectorizer.joblib")

    if os.path.exists(text_model_path) and os.path.exists(text_vec_path):
        try:
            actual_model_hash = compute_sha256(text_model_path)
            actual_vec_hash = compute_sha256(text_vec_path)
            
            if actual_model_hash != TEXT_EXPECTED_SHA256:
                TEXT_LOAD_ERROR = f"TEXT_MODEL_HASH_MISMATCH: Expected {TEXT_EXPECTED_SHA256}, got {actual_model_hash}"
                print(f"[!] {TEXT_LOAD_ERROR}")
                TEXT_MODEL = None
            elif actual_vec_hash != TEXT_VEC_EXPECTED_SHA256:
                TEXT_LOAD_ERROR = f"TEXT_VEC_HASH_MISMATCH: Expected {TEXT_VEC_EXPECTED_SHA256}, got {actual_vec_hash}"
                print(f"[!] {TEXT_LOAD_ERROR}")
                TEXT_MODEL = None
            else:
                TEXT_MODEL = joblib.load(text_model_path)
                TEXT_VECTORIZER = joblib.load(text_vec_path)
                
                meta_path = os.path.join(text_dir, "metadata.json")
                if not os.path.exists(meta_path):
                    meta_path = os.path.join(text_dir, "v2.0.0", "metadata.json")
                with open(meta_path, "r", encoding="utf-8") as f:
                    TEXT_METADATA = json.load(f)
                
                schema_path = os.path.join(text_dir, "feature_schema.json")
                if os.path.exists(schema_path):
                    with open(schema_path, "r", encoding="utf-8") as f:
                        TEXT_SCHEMA = json.load(f)
                
                eval_path = os.path.join(text_dir, "evaluation.json")
                if os.path.exists(eval_path):
                    with open(eval_path, "r", encoding="utf-8") as f:
                        TEXT_EVALUATION = json.load(f)
                TEXT_LOAD_ERROR = None
                print(f"[OK] Loaded Text Scam Model v{TEXT_METADATA.get('version', '2.0.0')} (SHA-256: {actual_model_hash[:16]}...)")
        except Exception as e:
            TEXT_LOAD_ERROR = f"TEXT_MODEL_LOAD_FAILED: {str(e)}"
            print(f"[!] {TEXT_LOAD_ERROR}")
            TEXT_MODEL = None
    else:
        TEXT_LOAD_ERROR = "MODEL_ARTIFACT_NOT_FOUND: Text scam model or vectorizer not found"
        print(f"[!] {TEXT_LOAD_ERROR}")
        TEXT_MODEL = None


@app.on_event("startup")
def startup_event():
    load_artifacts()


# Eagerly load artifacts on import
load_artifacts()


@app.get("/health")
def health_check():
    return {
        "status": "healthy" if (URL_MODEL is not None and TEXT_MODEL is not None) else "degraded",
        "service": "ps5-scam-detection-ml",
        "url_model_loaded": URL_MODEL is not None,
        "url_model_error": URL_LOAD_ERROR,
        "url_model_version": URL_METADATA.get("version", "2.0.0"),
        "text_model_loaded": TEXT_MODEL is not None,
        "text_model_error": TEXT_LOAD_ERROR,
        "text_model_version": TEXT_METADATA.get("version", "2.0.0"),
        "timestamp": time.time()
    }


@app.get("/models/metadata", response_model=ModelMetadataResponse)
def get_model_metadata():
    models = []
    if URL_METADATA:
        models.append({
            "model_id": URL_METADATA.get("model_id", "url-phishing"),
            "version": URL_METADATA.get("version", "2.0.0"),
            "algorithm": URL_METADATA.get("algorithm", "XGBoost + Platt/Sigmoid Probability Calibration"),
            "dataset_version": URL_METADATA.get("dataset_version", "url_phishing_curated_v2"),
            "artifact_hash": URL_METADATA.get("artifact_hash", URL_EXPECTED_SHA256),
            "metrics": URL_EVALUATION or URL_METADATA.get("frozen_test_metrics", {}),
            "feature_schema": URL_SCHEMA
        })
    if TEXT_METADATA:
        models.append({
            "model_id": TEXT_METADATA.get("model_id", "text-scam"),
            "version": TEXT_METADATA.get("version", "2.0.0"),
            "algorithm": TEXT_METADATA.get("model_family", "TF-IDF + Calibrated Logistic Regression"),
            "dataset_version": TEXT_METADATA.get("dataset_version", "email_message_scam_curated_v3"),
            "artifact_hash": TEXT_METADATA.get("artifact_hash", TEXT_EXPECTED_SHA256),
            "metrics": TEXT_EVALUATION or TEXT_METADATA.get("frozen_test_metrics", {}),
            "feature_schema": TEXT_SCHEMA
        })
    return {"models": models}


@app.post("/inference/url", response_model=URLInferenceResponse)
def infer_url(payload: URLInferenceRequest):
    t_start = time.perf_counter()
    if URL_MODEL is None:
        load_artifacts()
    if URL_MODEL is None:
        error_msg = URL_LOAD_ERROR or "URL_MODEL_UNAVAILABLE: URL phishing classifier artifact is unavailable"
        raise HTTPException(status_code=503, detail=error_msg)

    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="INVALID_INPUT: Empty URL provided")

    # Step 1: Feature Extraction
    t_feat_0 = time.perf_counter()
    features_dict = extract_url_features(raw_url)
    vector = [features_dict[name] for name in FEATURE_NAMES]
    feat_time_ms = (time.perf_counter() - t_feat_0) * 1000

    # Step 2: Model Inference & Probability Calculation
    t_infer_0 = time.perf_counter()
    calibrated_proba = float(URL_MODEL.predict_proba([vector])[0, 1])
    
    # Extract raw model probability from base estimator if available
    raw_score = calibrated_proba
    try:
        if hasattr(URL_MODEL, "calibrated_classifiers_") and len(URL_MODEL.calibrated_classifiers_) > 0:
            base_est = getattr(URL_MODEL.calibrated_classifiers_[0], "estimator", None)
            if base_est is not None and hasattr(base_est, "predict_proba"):
                raw_score = float(base_est.predict_proba([vector])[0, 1])
    except Exception:
        raw_score = calibrated_proba

    infer_time_ms = (time.perf_counter() - t_infer_0) * 1000
    predicted_class = "phishing" if calibrated_proba >= 0.5 else "legitimate"

    # Step 3: Extract Deterministic Lexical Signals
    top_signals = []
    if features_dict.get("has_ip_address") == 1:
        top_signals.append({"signal": "ip_hostname", "severity": "high", "weight": 0.3})
    if features_dict.get("subdomain_depth", 0) >= 2:
        top_signals.append({"signal": "excessive_subdomains", "severity": "medium", "weight": 0.2})
    if features_dict.get("has_suspicious_tld") == 1:
        top_signals.append({"signal": "suspicious_tld", "severity": "medium", "weight": 0.25})
    if features_dict.get("suspicious_token_count", 0) > 0:
        top_signals.append({"signal": "security_tokens_in_url", "severity": "medium", "weight": 0.2})
    if features_dict.get("has_at_symbol") == 1:
        top_signals.append({"signal": "at_symbol_obfuscation", "severity": "high", "weight": 0.35})

    total_time_ms = (time.perf_counter() - t_start) * 1000

    return URLInferenceResponse(
        model_id="url-phishing",
        model_version=URL_METADATA.get("version", "2.0.0"),
        detector_version="url-phishing-2.0.0",
        score=round(calibrated_proba, 6),
        raw_score=round(raw_score, 6),
        calibrated_probability=round(calibrated_proba, 6),
        calibrated=True,
        threshold=0.50,
        predicted_class=predicted_class,
        top_signals=top_signals,
        features=features_dict,
        feature_extraction_time_ms=round(feat_time_ms, 3),
        model_inference_time_ms=round(infer_time_ms, 3),
        processing_time_ms=round(total_time_ms, 2),
        analysis_status="success",
        errors=[]
    )


@app.post("/inference/message", response_model=MessageInferenceResponse)
def infer_message(payload: MessageInferenceRequest):
    t0 = time.perf_counter()
    if TEXT_MODEL is None or TEXT_VECTORIZER is None:
        load_artifacts()
    if TEXT_MODEL is None or TEXT_VECTORIZER is None:
        raise HTTPException(status_code=503, detail="MODEL_NOT_TRAINED: Message scam classifier artifact is unavailable")

    raw_message = payload.message.strip()
    normalized = normalize_message_text(raw_message)
    entities = extract_entities(raw_message)

    vec = TEXT_VECTORIZER.transform([normalized])
    proba = float(TEXT_MODEL.predict_proba(vec)[0, 1])
    predicted_class = "scam_phishing" if proba >= 0.50 else "legitimate"

    signals = []
    intent_signals = entities.get("intent_signals", {})
    if intent_signals.get("has_urgency"):
        signals.append({"type": "urgency", "triggers": intent_signals.get("urgency_triggers", [])})
    if intent_signals.get("has_credential_request"):
        signals.append({"type": "credential_request", "triggers": intent_signals.get("credential_triggers", [])})
    if intent_signals.get("has_payment_request"):
        signals.append({"type": "payment_request", "triggers": intent_signals.get("payment_triggers", [])})
    if intent_signals.get("has_authority_impersonation"):
        signals.append({"type": "authority_impersonation", "triggers": intent_signals.get("authority_triggers", [])})

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return MessageInferenceResponse(
        model_id="text-scam",
        model_version=TEXT_METADATA.get("version", "2.0.0"),
        detector_version="text-scam-2.0.0",
        score=round(proba, 6),
        raw_score=round(proba, 6),
        calibrated_probability=round(proba, 6),
        calibrated=True,
        threshold=0.50,
        predicted_class=predicted_class,
        entities=entities,
        signals=signals,
        processing_time_ms=round(elapsed_ms, 2),
        analysis_status="success",
        errors=[]
    )
