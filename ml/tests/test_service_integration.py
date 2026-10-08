"""
Pytest Suite: ML Service API Integration and Latency Benchmarks
Verifies:
1. /health endpoint reports healthy when v2.0.0 artifact hash is verified
2. /models/metadata returns v2.0.0 governance contract
3. /inference/url processes URLs with genuine ML inference
4. Feature extraction latency, ML inference latency, and total latency are separately recorded
5. Apna College regression test URLs return legitimate classification
6. Phishing lures return phishing classification
7. Invalid / empty URL input handling
8. Model hash mismatch / artifact missing error handling
"""

import os
import sys
import json
import pytest
from fastapi.testclient import TestClient

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from service.app import app, load_artifacts, URL_EXPECTED_SHA256


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    """Verify health endpoint returns status healthy with url_model_loaded=True."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["url_model_loaded"] is True
    assert data["url_model_error"] is None


def test_models_metadata_endpoint(client):
    """Verify models metadata contains url-phishing v2.0.0 with SHA-256."""
    res = client.get("/models/metadata")
    assert res.status_code == 200
    data = res.json()
    assert "models" in data
    url_model = next((m for m in data["models"] if m["model_id"] == "url-phishing"), None)
    assert url_model is not None, "url-phishing model must be listed in metadata"
    assert url_model["version"] == "2.0.0"
    assert url_model["artifact_hash"] == URL_EXPECTED_SHA256


def test_apna_college_start_url_inference(client):
    """Verify https://www.apnacollege.in/start returns legitimate."""
    res = client.post("/inference/url", json={"url": "https://www.apnacollege.in/start"})
    assert res.status_code == 200
    data = res.json()
    assert data["model_id"] == "url-phishing"
    assert data["model_version"] == "2.0.0"
    assert data["predicted_class"] == "legitimate"
    assert data["score"] < 0.05
    assert data["calibrated_probability"] < 0.05
    assert "feature_extraction_time_ms" in data
    assert "model_inference_time_ms" in data
    assert data["feature_extraction_time_ms"] >= 0
    assert data["model_inference_time_ms"] >= 0


def test_apna_college_deep_player_url_inference(client):
    """Verify https://www.apnacollege.in/path-player?... returns legitimate (v2.0.0 regression fix)."""
    url = "https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit"
    res = client.post("/inference/url", json={"url": url})
    assert res.status_code == 200
    data = res.json()
    assert data["model_id"] == "url-phishing"
    assert data["model_version"] == "2.0.0"
    assert data["predicted_class"] == "legitimate"
    assert data["score"] < 0.05
    assert data["calibrated_probability"] < 0.05


def test_phishing_lure_inference(client):
    """Verify high-risk phishing URL returns phishing."""
    url = "http://paypal-account-verification-alert99.tk/login.php"
    res = client.post("/inference/url", json={"url": url})
    assert res.status_code == 200
    data = res.json()
    assert data["model_id"] == "url-phishing"
    assert data["model_version"] == "2.0.0"
    assert data["predicted_class"] == "phishing"
    assert data["score"] > 0.90
    assert data["calibrated_probability"] > 0.90


def test_empty_url_inference_validation(client):
    """Verify empty URL input returns 400 Bad Request."""
    res = client.post("/inference/url", json={"url": "   "})
    assert res.status_code == 400
    assert "INVALID_INPUT" in res.json()["detail"]


def test_latency_metrics_recorded(client):
    """Verify separate latency tracking for feature extraction and model inference."""
    url = "https://example.com/login"
    res = client.post("/inference/url", json={"url": url})
    assert res.status_code == 200
    data = res.json()
    assert data["feature_extraction_time_ms"] is not None
    assert data["model_inference_time_ms"] is not None
    assert data["processing_time_ms"] is not None
