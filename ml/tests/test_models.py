"""
Tests for Saved ML Model Artifacts & Inference
"""

import os
import sys
import json
import joblib
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.url_features import extract_features_vector, FEATURE_NAMES
from features.text_features import normalize_message_text

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_url_model_artifact_loading():
    model_dir = os.path.join(ML_ROOT, "models", "url_phishing")
    model_path = os.path.join(model_dir, "model.joblib")
    meta_path = os.path.join(model_dir, "metadata.json")
    eval_path = os.path.join(model_dir, "evaluation.json")

    assert os.path.exists(model_path), "URL model artifact must exist"
    assert os.path.exists(meta_path), "URL metadata must exist"
    assert os.path.exists(eval_path), "URL evaluation metrics must exist"

    model = joblib.load(model_path)
    with open(meta_path) as f:
        meta = json.load(f)

    assert meta["model_id"] == "url-phishing"
    assert meta["version"] in ["1.0.0", "2.0.0"]

    # Test inference on known phishing pattern
    phish_url = "http://192.168.1.1/paypal/verify-account.php"
    feats = extract_features_vector(phish_url)
    proba = model.predict_proba([feats])[0, 1]
    assert proba > 0.5, "Phishing fixture should predict high probability"

    # Test inference on known benign pattern
    benign_url = "https://www.google.com/search?q=machine+learning"
    feats_benign = extract_features_vector(benign_url)
    proba_benign = model.predict_proba([feats_benign])[0, 1]
    assert proba_benign < 0.5, "Benign fixture should predict low probability"


def test_text_model_artifact_loading():
    model_dir = os.path.join(ML_ROOT, "models", "text_scam")
    model_path = os.path.join(model_dir, "model.joblib")
    vec_path = os.path.join(model_dir, "vectorizer.joblib")
    meta_path = os.path.join(model_dir, "metadata.json")

    assert os.path.exists(model_path), "Text model artifact must exist"
    assert os.path.exists(vec_path), "Text vectorizer artifact must exist"

    model = joblib.load(model_path)
    vectorizer = joblib.load(vec_path)

    scam_text = "URGENT: Your bank account will be suspended! Verify credentials now at http://fake.com"
    vec = vectorizer.transform([normalize_message_text(scam_text)])
    proba = model.predict_proba(vec)[0, 1]
    assert proba > 0.5, "Scam fixture should predict high scam probability"

    ham_text = "Hey, are we still meeting for lunch at 12:30 today?"
    vec_ham = vectorizer.transform([normalize_message_text(ham_text)])
    proba_ham = model.predict_proba(vec_ham)[0, 1]
    assert proba_ham < 0.5, "Ham fixture should predict low probability"
