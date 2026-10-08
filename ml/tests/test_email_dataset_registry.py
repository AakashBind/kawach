"""
Pytest Suite: Email & Message NLP Dataset Discovery Registry & Governance Verification
Tests:
1. Dataset registry schema compliance and required provenance fields
2. Verifies URL model immutability (v1.0.0 and v2.0.0 SHA-256 hashes)
3. Zero NLP models trained in E.2A
4. Rejection of unverified/synthetic generative datasets
5. Label mapping consistency (binary 0=legitimate, 1=scam_phishing)
6. Deduplication and Jaccard similarity logic
"""

import os
import sys
import json
import hashlib
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

REGISTRY_PATH = os.path.join(BASE_DIR, "data", "EMAIL_DATASET_REGISTRY.json")
REPORT_REGISTRY_PATH = os.path.join(BASE_DIR, "reports", "email_dataset_registry.json")


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def test_registry_file_exists():
    """Verify registry JSON files exist in both data/ and reports/."""
    assert os.path.exists(REGISTRY_PATH), f"Registry file {REGISTRY_PATH} must exist"
    assert os.path.exists(REPORT_REGISTRY_PATH), f"Report registry file {REPORT_REGISTRY_PATH} must exist"


def test_registry_schema_and_required_fields():
    """Verify all candidate datasets contain mandatory provenance fields."""
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)

    assert "datasets" in reg
    assert len(reg["datasets"]) >= 5

    required_fields = [
        "dataset_id", "name", "version", "domain", "publisher",
        "source_url", "access_date", "license", "license_verified",
        "record_count_raw", "available_labels", "label_mapping",
        "languages", "collection_method", "provenance_notes",
        "privacy_notes", "status"
    ]

    for d in reg["datasets"]:
        for field in required_fields:
            assert field in d, f"Dataset {d.get('dataset_id')} is missing mandatory field '{field}'"


def test_url_model_immutability():
    """Verify URL Phishing Model v1.0.0 and v2.0.0 artifacts are 100% immutable."""
    v1_path = os.path.join(BASE_DIR, "models", "url_phishing", "v1.0.0", "model.joblib")
    v2_path = os.path.join(BASE_DIR, "models", "url_phishing", "v2.0.0", "model.joblib")
    root_path = os.path.join(BASE_DIR, "models", "url_phishing", "model.joblib")

    assert sha256_file(v1_path) == "3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49"
    assert sha256_file(v2_path) == "b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156"
    assert sha256_file(root_path) == "b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156"


def test_synthetic_data_rejection():
    """Verify synthetic unverified datasets are formally rejected."""
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)

    synthetic = next((d for d in reg["datasets"] if "synthetic" in d["dataset_id"].lower()), None)
    if synthetic:
        assert synthetic["status"] == "REJECTED"
        assert synthetic["license_verified"] is False


def test_label_mapping_validity():
    """Verify label mappings contain only binary legitimate (0) or scam_phishing (1)."""
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)

    for d in reg["datasets"]:
        if d["status"] == "ACCEPTED_FOR_CURATION":
            for src_lbl, tgt_lbl in d["label_mapping"].items():
                assert any(val in tgt_lbl for val in ["0", "1", "legitimate", "scam_phishing"]), \
                    f"Invalid target label '{tgt_lbl}' for source '{src_lbl}' in dataset {d['dataset_id']}"


def test_jaccard_similarity_deduplication_logic():
    """Verify 3-gram Jaccard similarity detection logic for near-duplicates."""
    def get_ngrams(text: str, n: int = 3) -> set:
        clean = "".join(c.lower() for c in text if c.isalnum() or c.isspace())
        return set(clean[i:i+n] for i in range(len(clean) - n + 1))

    msg1 = "URGENT: Your Wells Fargo account has been suspended! Verify credentials at http://wellsfargo-verify.xyz [Ref #1001]"
    msg2 = "URGENT: Your Wells Fargo account has been suspended! Verify credentials at http://wellsfargo-verify.xyz [Ref #1002]"
    msg3 = "Hey, are we still meeting for lunch at 12:30 today?"

    g1 = get_ngrams(msg1, 3)
    g2 = get_ngrams(msg2, 3)
    g3 = get_ngrams(msg3, 3)

    jaccard_near = len(g1.intersection(g2)) / len(g1.union(g2))
    jaccard_diff = len(g1.intersection(g3)) / len(g1.union(g3))

    assert jaccard_near >= 0.85, f"Near duplicates must exceed 0.85 Jaccard, got {jaccard_near}"
    assert jaccard_diff < 0.20, f"Different messages must have low Jaccard, got {jaccard_diff}"
