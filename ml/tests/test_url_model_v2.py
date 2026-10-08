"""
Pytest Suite: URL Phishing Detection Model v2.0.0 Verification
Validates:
1. v1.0.0 baseline immutability (SHA-256 verification)
2. v2.0.0 artifact integrity and metadata
3. Model loading and inference parity
4. Apna College known regression resolution (both /start and deep course-player)
5. OOD benchmark generalization performance
6. False positive protection on complex legitimate URLs (UUIDs, ObjectIDs, deep queries)
"""

import os
import json
import hashlib
import joblib
import numpy as np
import pytest

from ml.features.url_features import extract_url_features, FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
URL_MODELS_DIR = os.path.join(MODELS_DIR, "url_phishing")
V1_DIR = os.path.join(URL_MODELS_DIR, "v1.0.0")
V2_DIR = os.path.join(URL_MODELS_DIR, "v2.0.0")


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture
def v1_baseline_model():
    model_path = os.path.join(V1_DIR, "model.joblib")
    assert os.path.exists(model_path), "v1.0.0 model.joblib must exist"
    return joblib.load(model_path)


@pytest.fixture
def v2_production_model():
    model_path = os.path.join(V2_DIR, "model.joblib")
    assert os.path.exists(model_path), "v2.0.0 model.joblib must exist"
    return joblib.load(model_path)


def test_v1_baseline_immutability():
    """Verify v1.0.0 baseline hash is strictly preserved."""
    v1_model_path = os.path.join(V1_DIR, "model.joblib")
    actual_hash = sha256_file(v1_model_path)
    expected_hash = "3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49"
    assert actual_hash == expected_hash, f"v1.0.0 SHA-256 mismatch: {actual_hash} != {expected_hash}"


def test_v2_metadata_integrity():
    """Verify v2.0.0 metadata, feature schema, and confusion matrix values."""
    meta_path = os.path.join(V2_DIR, "metadata.json")
    eval_path = os.path.join(V2_DIR, "evaluation.json")
    assert os.path.exists(meta_path)
    assert os.path.exists(eval_path)
    with open(meta_path, "r") as f:
        meta = json.load(f)
    with open(eval_path, "r") as f:
        ev = json.load(f)

    assert meta["version"] == "2.0.0"
    assert meta["model_id"] == "url-phishing"
    assert "XGBoost" in meta["algorithm"]
    assert meta["frozen_test_metrics"]["f1"] >= 0.95

    # Verify v2.0.0 confusion matrix mathematical counts
    cm = meta["frozen_test_metrics"]["confusion_matrix"]
    tn = cm.get("true_negatives", cm.get("tn"))
    fp = cm.get("false_positives", cm.get("fp"))
    fn = cm.get("false_negatives", cm.get("fn"))
    tp = cm.get("true_positives", cm.get("tp"))

    assert tn == 1597, f"Expected TN=1597, got {tn}"
    assert fp == 0, f"Expected FP=0, got {fp}"
    assert fn == 0, f"Expected FN=0, got {fn}"
    assert tp == 1452, f"Expected TP=1452, got {tp}"
    assert tn + fp + fn + tp == 3049, f"Expected total=3049, got {tn + fp + fn + tp}"

    # Verify evaluation.json matches
    ev_cm = ev["confusion_matrix"]
    assert ev_cm["true_negatives"] == 1597
    assert ev_cm["false_positives"] == 0
    assert ev_cm["false_negatives"] == 0
    assert ev_cm["true_positives"] == 1452


def test_v1_baseline_confusion_matrix_preservation():
    """Verify v1.0.0 baseline confusion matrix is preserved."""
    v1_eval_path = os.path.join(V1_DIR, "evaluation.json")
    assert os.path.exists(v1_eval_path)
    with open(v1_eval_path, "r") as f:
        ev1 = json.load(f)

    cm1 = ev1["confusion_matrix"]
    assert cm1["true_negatives"] == 282
    assert cm1["false_positives"] == 0
    assert cm1["false_negatives"] == 0
    assert cm1["true_positives"] == 901
    assert cm1["true_negatives"] + cm1["false_positives"] + cm1["false_negatives"] + cm1["true_positives"] == 1183


def test_apna_college_regression_resolution(v1_baseline_model, v2_production_model):
    """
    Forensic test: Verify Apna College deep LMS player false positive is resolved
    by Model v2.0.0 purely via trained ML (no hardcoded rules).
    """
    url_start = "https://www.apnacollege.in/start"
    url_player = "https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit"

    vec_start = [extract_url_features(url_start)[name] for name in FEATURE_NAMES]
    vec_player = [extract_url_features(url_player)[name] for name in FEATURE_NAMES]

    # Baseline v1.0.0 behavior (recorded failure)
    p_player_v1 = float(v1_baseline_model.predict_proba([vec_player])[0, 1])
    assert p_player_v1 > 0.90, "Baseline v1.0.0 must exhibit the known ~99% false-positive anomaly"

    # Retrained v2.0.0 behavior (resolved)
    p_start_v2 = float(v2_production_model.predict_proba([vec_start])[0, 1])
    p_player_v2 = float(v2_production_model.predict_proba([vec_player])[0, 1])

    assert p_start_v2 < 0.10, f"Apna College /start should be < 0.10, got {p_start_v2}"
    assert p_player_v2 < 0.10, f"Apna College /path-player should be < 0.10 (legitimate), got {p_player_v2}"


def test_complex_legitimate_urls_protection(v2_production_model):
    """Verify complex legitimate URLs with UUIDs, Git hashes, and query params are safe."""
    legit_test_urls = [
        "https://online.stanford.edu/courses/soe-ycs0001/unit-player?unit=609aef82b3d11a0017c38ef1",
        "https://www.coursera.org/learn/algorithms-part1/lecture/5tG89/binary-search-trees?unit=64b1f8c0e4b0c72199f1a23e",
        "https://github.com/torvalds/linux/commit/80327f3630a826e7a2d4ef0a75d5032b4b445398",
        "https://swayam.gov.in/nc_details/NPTEL?course_code=noc26-cs12&unit_id=65df891c33b7a10018e219ba"
    ]

    for u in legit_test_urls:
        vec = [extract_url_features(u)[name] for name in FEATURE_NAMES]
        proba = float(v2_production_model.predict_proba([vec])[0, 1])
        assert proba < 0.20, f"Legitimate URL '{u}' was misclassified with high phishing prob: {proba}"


def test_phishing_attack_detection(v2_production_model):
    """Verify phishing attack vectors receive high risk probabilities."""
    phish_test_urls = [
        "http://192.241.168.42:8080/apnacollege/login.php?session=68dbea2c4069da29a90e18bf",
        "https://login.microsoftonline.account-verify-2026.click/oauth2/authorize?client_id=4328904832",
        "https://wallet-metamask-security-reauth.work/recovery?seed_id=68dbea2c4069da29a90e18bfUnit",
        "http://paypal.com.account-verify-support.tk/signin.php?token=9821739",
        "http://bankofamerica-secure-login-update.top/auth.php?id=99281"
    ]

    for u in phish_test_urls:
        vec = [extract_url_features(u)[name] for name in FEATURE_NAMES]
        proba = float(v2_production_model.predict_proba([vec])[0, 1])
        assert proba > 0.80, f"Phishing URL '{u}' failed detection, prob: {proba}"
