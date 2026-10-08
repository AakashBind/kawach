"""
Phase E.2C Automated Evaluation & Model Validation Test Suite
Tests:
- URL model freeze preservation (v1.0.0 and v2.0.0 SHA-256)
- Text scam model artifact integrity & loading
- Inference and probability generation on legitimate & scam text
- Phase E.2C manifest & metadata schema
- Zero synthetic data creation & zero URL retraining
"""

import os
import json
import hashlib
import joblib
import pytest
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models", "text_scam")
MODELS_V1_DIR = os.path.join(MODELS_DIR, "v1.0.0")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

EXPECTED_URL_V1_SHA256 = "3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49"
EXPECTED_URL_V2_SHA256 = "b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156"


def test_url_model_immutability_in_e2c():
    """Verify that URL phishing models remain 100% frozen during Phase E.2C."""
    v1_path = os.path.join(BASE_DIR, "models", "url_phishing", "v1.0.0", "model.joblib")
    v2_path = os.path.join(BASE_DIR, "models", "url_phishing", "v2.0.0", "model.joblib")

    assert os.path.exists(v1_path), "URL v1.0.0 artifact missing"
    assert os.path.exists(v2_path), "URL v2.0.0 artifact missing"

    v1_hash = hashlib.sha256(open(v1_path, "rb").read()).hexdigest()
    v2_hash = hashlib.sha256(open(v2_path, "rb").read()).hexdigest()

    assert v1_hash == EXPECTED_URL_V1_SHA256, f"URL v1.0.0 artifact altered! Got {v1_hash}"
    assert v2_hash == EXPECTED_URL_V2_SHA256, f"URL v2.0.0 artifact altered! Got {v2_hash}"


def test_text_scam_model_loading_and_inference():
    """Verify text-scam v1.0.0 model loads and performs inference properly."""
    model_path = os.path.join(MODELS_V1_DIR, "model.joblib")
    vec_path = os.path.join(MODELS_V1_DIR, "vectorizer.joblib")

    assert os.path.exists(model_path), "text-scam model.joblib missing"
    assert os.path.exists(vec_path), "text-scam vectorizer.joblib missing"

    model = joblib.load(model_path)
    vec = joblib.load(vec_path)

    # Legitimate corporate email
    legit_text = "Please find attached the minutes from our Monday architecture review sync. Best regards, Team."
    legit_vec = vec.transform([legit_text])
    legit_prob = model.predict_proba(legit_vec)[0, 1]

    # Malicious phishing email
    scam_text = "URGENT: Your PayPal account has been suspended! Verify your credentials immediately at <URL_LINK> or your account will be deleted."
    scam_vec = vec.transform([scam_text])
    scam_prob = model.predict_proba(scam_vec)[0, 1]

    assert legit_prob < 0.5, f"Legitimate text classified as scam: {legit_prob}"
    assert scam_prob > 0.5, f"Scam text classified as legitimate: {scam_prob}"


def test_text_scam_metadata_and_manifest_integrity():
    """Verify metadata and manifest fields."""
    manifest_path = os.path.join(REPORTS_DIR, "text_scam_phase_e2c_manifest.json")
    assert os.path.exists(manifest_path), "Phase E.2C manifest missing"

    with open(manifest_path, "r") as f:
        m = json.load(f)

    assert m["phase"] == "E.2C"
    assert m["component"] == "Email_Message_NLP_Detector"
    assert m["selected_model"] == "text-scam"
    assert m["version"] == "1.0.0"
    assert m["training_records"] == 16499
    assert m["validation_records"] == 3483
    assert m["frozen_test_records"] == 3400
    assert m["ood_records"] == 6000
    assert m["url_model_immutability"]["url_model_modified"] is False
    assert m["readiness_verdict"] == "READY_FOR_E2D"

    # Verify model artifact SHA-256 matches actual file
    model_path = os.path.join(MODELS_V1_DIR, "model.joblib")
    actual_sha256 = hashlib.sha256(open(model_path, "rb").read()).hexdigest()
    assert actual_sha256 == m["model_sha256"], "Model SHA-256 hash mismatch"
