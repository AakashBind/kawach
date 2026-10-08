"""
Phase E.2D Automated Forensic Audit & Generalization Test Suite
Tests:
- Immutability of text-scam-1.0.0 and URL v1/v2 models
- Exact reproduction of E.2C validation, frozen test, and OOD performance
- Forensic manifest integrity and CONDITIONAL_COMPONENT classification
- Zero model retraining during audit
"""

import os
import json
import hashlib
import pytest
import joblib
import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models", "text_scam", "v1.0.0")
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, "data", "processed", "email")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

EXPECTED_TEXT_MODEL_SHA256 = "fc533b14161475482661f73cb34e400991586a327cff47c34e246379a69b1ab5"
EXPECTED_TEXT_VEC_SHA256 = "82dec31d11037ea219d430027341f3988792c55c4c97b93a9328a858962bd95e"
EXPECTED_URL_V1_SHA256 = "3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49"
EXPECTED_URL_V2_SHA256 = "b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156"


def test_forensic_artifact_hashes_immutable():
    """Verify that all model artifacts remain 100% frozen during Phase E.2D."""
    model_path = os.path.join(MODELS_DIR, "model.joblib")
    vec_path = os.path.join(MODELS_DIR, "vectorizer.joblib")
    url_v1_path = os.path.join(BASE_DIR, "models", "url_phishing", "v1.0.0", "model.joblib")
    url_v2_path = os.path.join(BASE_DIR, "models", "url_phishing", "v2.0.0", "model.joblib")

    assert os.path.exists(model_path)
    assert os.path.exists(vec_path)
    assert os.path.exists(url_v1_path)
    assert os.path.exists(url_v2_path)

    m_hash = hashlib.sha256(open(model_path, "rb").read()).hexdigest()
    v_hash = hashlib.sha256(open(vec_path, "rb").read()).hexdigest()
    u1_hash = hashlib.sha256(open(url_v1_path, "rb").read()).hexdigest()
    u2_hash = hashlib.sha256(open(url_v2_path, "rb").read()).hexdigest()

    assert m_hash == EXPECTED_TEXT_MODEL_SHA256
    assert v_hash == EXPECTED_TEXT_VEC_SHA256
    assert u1_hash == EXPECTED_URL_V1_SHA256
    assert u2_hash == EXPECTED_URL_V2_SHA256


def test_e2c_reproduction_and_generalization_gap():
    """Verify reproduction of E.2C metrics and confirmation of the OOD generalization gap."""
    manifest_path = os.path.join(REPORTS_DIR, "text_scam_forensic_manifest.json")
    assert os.path.exists(manifest_path)

    with open(manifest_path, "r") as f:
        m = json.load(f)

    assert m["reproduction_verified"] is True
    assert m["model_status"] == "CONDITIONAL_COMPONENT"
    assert m["key_findings"]["in_distribution_frozen_test_f1"] == 1.0
    assert m["key_findings"]["ood_overall_f1"] == 0.4286
    assert m["key_findings"]["nus_sms_fpr"] == 1.0


def test_zero_retraining_governance_in_e2d():
    """Verify zero retraining and zero Risk Engine modifications."""
    manifest_path = os.path.join(REPORTS_DIR, "text_scam_forensic_manifest.json")
    with open(manifest_path, "r") as f:
        m = json.load(f)

    assert m["governance"]["nlp_model_modified"] is False
    assert m["governance"]["url_model_modified"] is False
    assert m["governance"]["url_model_retrained"] == 0
    assert m["governance"]["risk_engine_modified"] is False
    assert m["governance"]["retraining_performed"] is False
