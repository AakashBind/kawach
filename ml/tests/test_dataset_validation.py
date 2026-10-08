"""
Pytest Suite: Phase C Quality Gates Validation
Verifies all 12 Phase C quality, provenance, leakage, and compliance gates.
"""

import os
import json
import hashlib
import pandas as pd
import pytest

from ml.datasets.public_suffix import extract_registered_domain, extract_public_suffix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
PROCESSED_DIR = os.path.join(DATASETS_DIR, "processed")
MANIFEST_DIR = os.path.join(DATASETS_DIR, "manifests")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
MODELS_DIR = os.path.join(BASE_DIR, "models")


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture
def manifest():
    manifest_path = os.path.join(MANIFEST_DIR, "dataset_manifest.json")
    assert os.path.exists(manifest_path), "dataset_manifest.json must exist"
    with open(manifest_path, "r") as f:
        return json.load(f)


@pytest.fixture
def dataset_splits():
    train_df = pd.read_csv(os.path.join(PROCESSED_DIR, "url_train_expanded.csv"))
    val_df = pd.read_csv(os.path.join(PROCESSED_DIR, "url_val_expanded.csv"))
    test_df = pd.read_csv(os.path.join(PROCESSED_DIR, "url_test_frozen_expanded.csv"))
    ood_df = pd.read_csv(os.path.join(PROCESSED_DIR, "url_ood_benchmark.csv"))
    return train_df, val_df, test_df, ood_df


def test_gate_g1_deduplication(dataset_splits):
    """G1: Verified exact deduplication across splits."""
    train_df, val_df, test_df, _ = dataset_splits
    assert len(train_df) == len(train_df["normalized_url"].drop_duplicates())
    assert len(val_df) == len(val_df["normalized_url"].drop_duplicates())
    assert len(test_df) == len(test_df["normalized_url"].drop_duplicates())
    assert len(train_df) + len(val_df) + len(test_df) > 15000


def test_gate_g2_conflicting_labels(dataset_splits):
    """G2: Zero conflicting labels in curated dataset."""
    train_df, val_df, test_df, _ = dataset_splits
    full_df = pd.concat([train_df, val_df, test_df])
    conflicts = full_df.groupby("normalized_url")["label"].nunique()
    assert (conflicts > 1).sum() == 0, "No URL may have conflicting legitimate/phishing labels"


def test_gate_g3_ood_strict_isolation(dataset_splits):
    """G3: OOD suite (and Apna College specifically) is strictly isolated from train/val/test."""
    train_df, val_df, test_df, ood_df = dataset_splits
    ood_urls = set(ood_df["url"])
    train_urls = set(train_df["url"])
    val_urls = set(val_df["url"])
    test_urls = set(test_df["url"])

    assert len(train_urls.intersection(ood_urls)) == 0, "OOD URLs must never appear in training set"
    assert len(val_urls.intersection(ood_urls)) == 0, "OOD URLs must never appear in validation set"
    assert len(test_urls.intersection(ood_urls)) == 0, "OOD URLs must never appear in test set"

    # Specific Apna College isolation test
    assert train_df["url"].str.contains("apnacollege.in").sum() == 0
    assert val_df["url"].str.contains("apnacollege.in").sum() == 0
    assert test_df["url"].str.contains("apnacollege.in").sum() == 0
    assert ood_df["url"].str.contains("apnacollege.in").sum() >= 2


def test_gate_g4_cross_split_disjointness(dataset_splits):
    """G4: Train, Val, and Test splits must be completely disjoint."""
    train_df, val_df, test_df, _ = dataset_splits
    train_set = set(train_df["normalized_url"])
    val_set = set(val_df["normalized_url"])
    test_set = set(test_df["normalized_url"])

    assert len(train_set.intersection(val_set)) == 0, "Train and Val must be disjoint"
    assert len(train_set.intersection(test_set)) == 0, "Train and Test must be disjoint"
    assert len(val_set.intersection(test_set)) == 0, "Val and Test must be disjoint"


def test_gate_g5_legitimate_domain_diversity(dataset_splits):
    """G5: Legitimate registered domains must exceed 50 (no monoculture)."""
    train_df, val_df, test_df, _ = dataset_splits
    full_df = pd.concat([train_df, val_df, test_df])
    legit_domains = full_df[full_df["label"] == 0]["registered_domain"].nunique()
    assert legit_domains > 50, f"Expected >50 legitimate registered domains, got {legit_domains}"


def test_gate_g6_lms_and_complex_coverage(dataset_splits):
    """G6: LMS and complex structural URLs are represented in dataset."""
    train_df, val_df, test_df, _ = dataset_splits
    full_df = pd.concat([train_df, val_df, test_df])
    lms_count = (full_df["source_category"] == "Legitimate_LMS").sum()
    saas_count = (full_df["source_category"] == "Legitimate_Developer_SaaS").sum()
    assert lms_count > 1000, "LMS dataset category must be well-represented"
    assert saas_count > 1000, "Developer/SaaS dataset category must be well-represented"


def test_gate_g7_public_suffix_extraction():
    """G7: Multi-level ccTLD public suffix resolution behaves correctly."""
    assert extract_registered_domain("https://www.apnacollege.in/path-player") == "apnacollege.in"
    assert extract_registered_domain("portal.service.co.uk") == "service.co.uk"
    assert extract_registered_domain("https://swayam.gov.in/courses") == "swayam.gov.in"
    assert extract_registered_domain("192.168.1.100") == "192.168.1.100"


def test_gate_g8_feature_distribution_non_degeneracy():
    """G8: Feature distributions for length and digits overlap realistically."""
    feat_path = os.path.join(REPORTS_DIR, "url_dataset_feature_distribution.json")
    with open(feat_path, "r") as f:
        feats = json.load(f)
    assert feats["url_length"]["legit_max"] > 100, "Legitimate URLs must include long URLs"
    assert feats["num_digits"]["legit_max"] > 10, "Legitimate URLs must include digit-rich URLs (UUIDs/hashes)"


def test_gate_g9_sha256_integrity(manifest):
    """G9: Manifest SHA-256 hashes match actual files on disk."""
    for split_key, split_meta in manifest["files"].items():
        actual_path = os.path.join(BASE_DIR, "..", split_meta["path"])
        assert os.path.exists(actual_path), f"File {split_meta['path']} must exist"
        computed_hash = sha256_file(actual_path)
        assert computed_hash == split_meta["sha256"], f"SHA256 mismatch for {split_meta['path']}"


def test_gate_g10_zero_models_trained_in_phase_c(manifest):
    """G10: Compliance rule: 0 models trained in Phase C."""
    assert manifest["phase_c_compliance"]["models_trained"] == 0


def test_gate_g11_zero_risk_engine_modifications(manifest):
    """G11: Compliance rule: zero risk engine modifications."""
    assert manifest["phase_c_compliance"]["risk_engine_modified"] is False


def test_gate_g12_baseline_model_preserved():
    """G12: Baseline model v1.0.0 is preserved in immutable directory."""
    baseline_dir = os.path.join(MODELS_DIR, "url_phishing", "v1.0.0")
    assert os.path.exists(baseline_dir), "v1.0.0 baseline directory must exist"
    model_file = os.path.join(baseline_dir, "model.joblib")
    assert os.path.exists(model_file), "model.joblib must exist in v1.0.0"
