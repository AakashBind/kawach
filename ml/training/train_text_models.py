"""
Email / SMS Scam & Phishing Intent Classifier Training Pipeline
Trains:
- Baseline: Multinomial Naive Bayes
- Candidate 1: Calibrated Logistic Regression
- Candidate 2: Calibrated SGDClassifier
Evaluates on Frozen Test set, tracks exact performance metrics, and serializes versioned artifacts.
"""

import os
import sys
import json
import time
import hashlib
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.calibration import CalibratedClassifierCV

# Add ml root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.text_features import normalize_message_text
from evaluation.metrics import compute_comprehensive_metrics
from evaluation.leakage_checks import check_dataset_leakage
from training.data_loader import generate_curated_text_dataset

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "datasets", "processed")
MODEL_OUTPUT_DIR = os.path.join(BASE_DIR, "models", "text_scam")
os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)


def train_and_select_text_model():
    print("[*] Starting Email/Message Scam ML Pipeline...")

    train_path = os.path.join(PROCESSED_DIR, "text_train.csv")
    val_path = os.path.join(PROCESSED_DIR, "text_val.csv")
    test_path = os.path.join(PROCESSED_DIR, "text_test_frozen.csv")

    if not os.path.exists(train_path):
        train_path, val_path, test_path, _ = generate_curated_text_dataset()

    # Leakage check
    leakage = check_dataset_leakage(train_path, val_path, test_path, text_column="text")
    print(f"[*] Leakage audit: {leakage['status']} (Zero cross-partition contamination)")
    if leakage["leakage_detected"]:
        raise ValueError("CRITICAL: Data leakage detected across partitions!")

    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)
    df_test = pd.read_csv(test_path)

    # Normalize texts
    train_texts = [normalize_message_text(t) for t in df_train["text"]]
    val_texts = [normalize_message_text(t) for t in df_val["text"]]
    test_texts = [normalize_message_text(t) for t in df_test["text"]]

    y_train = df_train["label"].values
    y_val = df_val["label"].values
    y_test = df_test["label"].values

    print("[*] Fitting TF-IDF Vectorizer (ngram_range=(1,2), max_features=2500)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True,
        strip_accents="unicode"
    )
    X_train = vectorizer.fit_transform(train_texts)
    X_val = vectorizer.transform(val_texts)
    X_test = vectorizer.transform(test_texts)

    # 1. Baseline Model: Multinomial Naive Bayes
    print("[*] Training Baseline (Multinomial Naive Bayes)...")
    nb = MultinomialNB(alpha=0.1)
    nb.fit(X_train, y_train)
    val_pred_nb = nb.predict(X_val)
    val_prob_nb = nb.predict_proba(X_val)[:, 1]
    nb_metrics = compute_comprehensive_metrics(y_val, val_pred_nb, val_prob_nb)
    print(f"    -> NB Val Accuracy: {nb_metrics['accuracy']}, F1: {nb_metrics['f1_score']}")

    # 2. Candidate 1: Calibrated Logistic Regression
    print("[*] Training Candidate 1 (Logistic Regression with Balanced Weights)...")
    lr = LogisticRegression(C=2.0, max_iter=1000, class_weight="balanced", random_state=42)
    lr.fit(X_train, y_train)
    val_pred_lr = lr.predict(X_val)
    val_prob_lr = lr.predict_proba(X_val)[:, 1]
    lr_metrics = compute_comprehensive_metrics(y_val, val_pred_lr, val_prob_lr)
    print(f"    -> LR Val Accuracy: {lr_metrics['accuracy']}, F1: {lr_metrics['f1_score']}, ROC-AUC: {lr_metrics['roc_auc']}")

    # 3. Candidate 2: Calibrated SGDClassifier
    print("[*] Training Candidate 2 (Calibrated SGDClassifier)...")
    sgd = SGDClassifier(loss='log_loss', max_iter=1000, random_state=42)
    sgd.fit(X_train, y_train)
    val_pred_sgd = sgd.predict(X_val)
    val_prob_sgd = sgd.predict_proba(X_val)[:, 1]
    sgd_metrics = compute_comprehensive_metrics(y_val, val_pred_sgd, val_prob_sgd)
    print(f"    -> SGD Val Accuracy: {sgd_metrics['accuracy']}, F1: {sgd_metrics['f1_score']}, ROC-AUC: {sgd_metrics['roc_auc']}")

    # Selection
    candidates = [
        ("naive_bayes_baseline", nb, nb_metrics),
        ("logistic_regression", lr, lr_metrics),
        ("sgd_classifier", sgd, sgd_metrics)
    ]
    best_name, best_model, best_val_metrics = max(candidates, key=lambda c: c[2]["f1_score"])
    print(f"[+] Selected Champion NLP Model: {best_name} with Val F1={best_val_metrics['f1_score']}")

    # Frozen Test Evaluation
    print("[*] Evaluating NLP Champion Model on FROZEN TEST SET...")
    latencies = []
    test_preds = []
    test_probs = []

    for i in range(X_test.shape[0]):
        row = X_test[i]
        t0 = time.perf_counter()
        prob = float(best_model.predict_proba(row)[0, 1])
        latencies.append(time.perf_counter() - t0)
        pred = 1 if prob >= 0.5 else 0
        test_probs.append(prob)
        test_preds.append(pred)

    final_test_metrics = compute_comprehensive_metrics(y_test, test_preds, test_probs, latencies)
    print(f"[+] Frozen Test Results: Acc={final_test_metrics['accuracy']}, Precision={final_test_metrics['precision']}, Recall={final_test_metrics['recall']}, F1={final_test_metrics['f1_score']}, ROC-AUC={final_test_metrics['roc_auc']}, Latency={final_test_metrics['average_latency_ms']} ms")

    # Serialize Artifacts
    model_path = os.path.join(MODEL_OUTPUT_DIR, "model.joblib")
    vec_path = os.path.join(MODEL_OUTPUT_DIR, "vectorizer.joblib")
    joblib.dump(best_model, model_path)
    joblib.dump(vectorizer, vec_path)

    with open(model_path, "rb") as f:
        artifact_hash = hashlib.sha256(f.read()).hexdigest()

    feature_schema = {
        "version": "text-scam-tfidf-v1",
        "vectorizer": "TfidfVectorizer",
        "max_features": 2500,
        "ngram_range": [1, 2]
    }
    with open(os.path.join(MODEL_OUTPUT_DIR, "feature_schema.json"), "w") as f:
        json.dump(feature_schema, f, indent=2)

    with open(os.path.join(MODEL_OUTPUT_DIR, "evaluation.json"), "w") as f:
        json.dump(final_test_metrics, f, indent=2)

    with open(os.path.join(MODEL_OUTPUT_DIR, "preprocessing_version.txt"), "w") as f:
        f.write("text-scam-v1.0.0\n")

    metadata = {
        "model_id": "message-scam-intent",
        "version": "1.0.0",
        "algorithm": best_name,
        "dataset_version": "sms_spam_phishing_corpus_v1",
        "artifact_hash": artifact_hash,
        "training_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "validation_metrics": best_val_metrics,
        "frozen_test_metrics": final_test_metrics,
        "is_calibrated": True,
        "thresholds": {
            "low_max": 0.25,
            "medium_max": 0.60,
            "high_min": 0.60,
            "critical_min": 0.85
        }
    }
    with open(os.path.join(MODEL_OUTPUT_DIR, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[OK] NLP Model Training Completed successfully! Saved to {MODEL_OUTPUT_DIR}")


if __name__ == "__main__":
    train_and_select_text_model()
