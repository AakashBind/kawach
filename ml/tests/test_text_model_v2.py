"""
Phase E.2E Automated Test Suite for text-scam-2.0.0 and Baseline Preservation
Tests:
- v1.0.0 baseline immutability (model and vectorizer SHA-256)
- URL models v1.0.0 and v2.0.0 immutability
- v2.0.0 model loading and prediction accuracy
- v2.0.0 metadata and comparison manifest integrity
- Conversational benign message discrimination (NUS resolution)
"""

import os
import json
import hashlib
import pytest
import joblib
import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models", "text_scam")
MODELS_V1_DIR = os.path.join(MODELS_DIR, "v1.0.0")
MODELS_V2_DIR = os.path.join(MODELS_DIR, "v2.0.0")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

EXPECTED_TEXT_V1_MODEL_SHA256 = "fc533b14161475482661f73cb34e400991586a327cff47c34e246379a69b1ab5"
EXPECTED_TEXT_V1_VEC_SHA256 = "82dec31d11037ea219d430027341f3988792c55c4c97b93a9328a858962bd95e"
EXPECTED_URL_V1_SHA256 = "3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49"
EXPECTED_URL_V2_SHA256 = "b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156"


def test_v1_baseline_and_url_immutability_in_e2e():
    """Verify that v1.0.0 baseline and URL models remain strictly immutable."""
    v1_m_path = os.path.join(MODELS_V1_DIR, "model.joblib")
    v1_v_path = os.path.join(MODELS_V1_DIR, "vectorizer.joblib")
    url_v1_path = os.path.join(BASE_DIR, "models", "url_phishing", "v1.0.0", "model.joblib")
    url_v2_path = os.path.join(BASE_DIR, "models", "url_phishing", "v2.0.0", "model.joblib")

    assert os.path.exists(v1_m_path)
    assert os.path.exists(v1_v_path)
    assert os.path.exists(url_v1_path)
    assert os.path.exists(url_v2_path)

    assert hashlib.sha256(open(v1_m_path, "rb").read()).hexdigest() == EXPECTED_TEXT_V1_MODEL_SHA256
    assert hashlib.sha256(open(v1_v_path, "rb").read()).hexdigest() == EXPECTED_TEXT_V1_VEC_SHA256
    assert hashlib.sha256(open(url_v1_path, "rb").read()).hexdigest() == EXPECTED_URL_V1_SHA256
    assert hashlib.sha256(open(url_v2_path, "rb").read()).hexdigest() == EXPECTED_URL_V2_SHA256


def test_text_scam_v2_model_loading_and_inference():
    """Verify v2.0.0 model loads and predicts properly on legitimate and scam text."""
    v2_m_path = os.path.join(MODELS_V2_DIR, "model.joblib")
    v2_v_path = os.path.join(MODELS_V2_DIR, "vectorizer.joblib")

    assert os.path.exists(v2_m_path)
    assert os.path.exists(v2_v_path)

    model = joblib.load(v2_m_path)
    vec = joblib.load(v2_v_path)

    # Conversational chat (which failed on v1.0.0)
    chat_text = "Hey bro, meet at canteen 2 for breakfast before the tutorial starts."
    chat_prob = model.predict_proba(vec.transform([chat_text]))[0, 1]

    # Phishing attack
    phish_text = "URGENT: Your PayPal account is suspended. Verify password immediately at <URL_LINK> to restore access."
    phish_prob = model.predict_proba(vec.transform([phish_text]))[0, 1]

    assert chat_prob < 0.50, f"Conversational chat falsely flagged as scam: {chat_prob}"
    assert phish_prob > 0.50, f"Phishing attack missed: {phish_prob}"


def test_v2_manifest_and_metadata_integrity():
    """Verify metadata and comparison report schema."""
    comp_path = os.path.join(REPORTS_DIR, "text_scam_v1_v2_comparison.json")
    manifest_path = os.path.join(REPORTS_DIR, "text_scam_phase_e2e_manifest.json")

    assert os.path.exists(comp_path)
    assert os.path.exists(manifest_path)

    with open(manifest_path, "r") as f:
        m = json.load(f)

    assert m["phase"] == "E.2E"
    assert m["model_version"] == "2.0.0"
    assert m["comparison_summary"]["model_v2"]["nus_sms_fpr"] == 0.0
    assert m["comparison_summary"]["model_v2"]["frozen_test_f1"] == 1.0
    assert m["readiness_verdict"] == "READY_FOR_E3_INTEGRATION"
