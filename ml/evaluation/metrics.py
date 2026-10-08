"""
Model Evaluation & Metrics Calculation Engine
Calculates:
- Accuracy, Precision, Recall, F1
- Confusion Matrix (TN, FP, FN, TP)
- False Positive Rate (FPR), False Negative Rate (FNR)
- ROC-AUC, PR-AUC
- Latency per prediction (milliseconds)
"""

import time
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, precision_recall_curve, auc
)


def compute_comprehensive_metrics(y_true, y_pred, y_proba=None, inference_times=None) -> dict:
    """Computes all required audit metrics accurately from actual predictions."""
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    fpr = float(fp / max(1, (fp + tn)))
    fnr = float(fn / max(1, (fn + tp)))

    roc_auc = None
    pr_auc = None
    if y_proba is not None:
        try:
            roc_auc = float(roc_auc_score(y_true, y_proba))
            precision_vals, recall_vals, _ = precision_recall_curve(y_true, y_proba)
            pr_auc = float(auc(recall_vals, precision_vals))
        except Exception:
            pass

    avg_latency_ms = None
    if inference_times and len(inference_times) > 0:
        avg_latency_ms = float(np.mean(inference_times) * 1000)

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "pr_auc": round(pr_auc, 4) if pr_auc is not None else None,
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        },
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "average_latency_ms": round(avg_latency_ms, 2) if avg_latency_ms is not None else None,
        "sample_count": len(y_true)
    }
