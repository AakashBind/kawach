"""
Data Leakage Audit Engine
Ensures zero data contamination across Train, Validation, and Frozen Test partitions.
"""

import pandas as pd


def check_dataset_leakage(train_csv: str, val_csv: str, test_csv: str, text_column: str = "url") -> dict:
    """Verifies that no input strings leak across splits."""
    df_train = pd.read_csv(train_csv)
    df_val = pd.read_csv(val_csv)
    df_test = pd.read_csv(test_csv)

    set_train = set(df_train[text_column].astype(str).str.strip().str.lower())
    set_val = set(df_val[text_column].astype(str).str.strip().str.lower())
    set_test = set(df_test[text_column].astype(str).str.strip().str.lower())

    train_val_overlap = len(set_train.intersection(set_val))
    train_test_overlap = len(set_train.intersection(set_test))
    val_test_overlap = len(set_val.intersection(set_test))

    total_overlap = train_val_overlap + train_test_overlap + val_test_overlap
    passed = (total_overlap == 0)

    report = {
        "leakage_detected": not passed,
        "train_val_overlap_count": train_val_overlap,
        "train_test_overlap_count": train_test_overlap,
        "val_test_overlap_count": val_test_overlap,
        "train_samples": len(df_train),
        "val_samples": len(df_val),
        "test_samples": len(df_test),
        "status": "PASS" if passed else "FAIL"
    }

    return report
