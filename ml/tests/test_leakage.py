"""
Tests for Data Leakage Prevention
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.leakage_checks import check_dataset_leakage

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(ML_ROOT, "datasets", "processed")


def test_url_dataset_zero_leakage():
    train_path = os.path.join(PROCESSED_DIR, "url_train.csv")
    val_path = os.path.join(PROCESSED_DIR, "url_val.csv")
    test_path = os.path.join(PROCESSED_DIR, "url_test_frozen.csv")

    assert os.path.exists(train_path)
    assert os.path.exists(val_path)
    assert os.path.exists(test_path)

    report = check_dataset_leakage(train_path, val_path, test_path, text_column="url")
    assert report["leakage_detected"] is False
    assert report["status"] == "PASS"


def test_text_dataset_zero_leakage():
    train_path = os.path.join(PROCESSED_DIR, "text_train.csv")
    val_path = os.path.join(PROCESSED_DIR, "text_val.csv")
    test_path = os.path.join(PROCESSED_DIR, "text_test_frozen.csv")

    assert os.path.exists(train_path)
    assert os.path.exists(val_path)
    assert os.path.exists(test_path)

    report = check_dataset_leakage(train_path, val_path, test_path, text_column="text")
    assert report["leakage_detected"] is False
    assert report["status"] == "PASS"
