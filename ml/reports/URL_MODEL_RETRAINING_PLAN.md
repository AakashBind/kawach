# URL Phishing Model Retraining & Calibration Plan
**Document Version:** 1.1.0-PLAN  
**Date:** 2026-10-04  
**Status:** Audit Completed — Pending Review Prior to Execution  

---

## 1. Baseline Model Audit (Version 1.0.0)

| Field | Baseline Implementation Value |
|---|---|
| **Model ID** | `url-phishing` |
| **Model Version** | `1.0.0` (Preserved in `ml/models/url_phishing/v1.0.0/`) |
| **Algorithm** | `LogisticRegression(max_iter=1000, random_state=42)` |
| **Artifact Path** | `ml/models/url_phishing/model.joblib` |
| **Artifact SHA-256** | `3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49` |
| **Dataset Snapshot** | `url_uci_phiusiil_benchmark_v1` (7,881 total raw records) |
| **License** | CC BY 4.0 |
| **Class Balance** | 1,881 Legitimate (23.9%) / 6,000 Phishing (76.1%) |
| **Split Strategy** | Stratified 70% Train (5,516) / 15% Val (1,182) / 15% Frozen Test (1,183) |
| **Reproduced Test Metrics** | Accuracy: `1.0000`, Precision: `1.0000`, Recall: `1.0000`, F1: `1.0000`, ROC-AUC: `1.0000` |
| **Observed Regression Failure** | `https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit` $\rightarrow$ Score `0.9957` (False Positive) |

---

## 2. Confirmed Root Cause of False Positive

1. **Severe Underrepresentation of Complex Benign URLs:**
   - In baseline dataset `v1.0.0`, legitimate samples consisted almost entirely of shallow, short paths (mean length: 32 chars, mean digits: 0.1).
   - Phishing samples featured long queries and hex session hashes.
2. **Unscaled Linear Feature Weights:**
   - In unscaled `LogisticRegression`, `url_length` ($\beta = +0.2955$) and `num_digits` ($\beta = +0.8801$) became dominant linear proxies for phishing.
   - For a legitimate URL with 14 hexadecimal characters and 94 chars total length, the model added $+40.10$ to the logit, forcing probability to $99.57\%$.
3. **Risk Engine Critical Floor Amplification:**
   - The backend assigned `severity: 'critical'` when ML probability exceeded `0.80`, which triggered a hard risk floor of `85 / 100`.

---

## 3. Dataset Expansion & Diversity Strategy

### 3.1 Legitimate Dataset Representation
We will enrich the legitimate dataset partition with real-world, permissible public datasets and authenticated benign corpora covering:
- **E-learning & LMS Platforms:** Deep video player routes, course slugs, unit ObjectIDs (`courseid=...`, `unit=24hexChar`, `lesson=...`).
- **Cloud & SaaS Applications:** Long path hierarchies, query tokens, API endpoints, UUIDs (`/api/v2/items/550e8400-e29b-41d4-a716-446655440000`).
- **E-commerce & Content Hubs:** Multi-parameter search queries, tracking parameters (`?category=books&sort=asc&page=3&ref=header`).
- **Target Distribution:** 12,000+ balanced instances (50% verified Benign / 50% verified Phishing).

---

## 4. Feature Engineering & Preprocessing Improvements

1. **Normalized & Contextual Feature Transforms:**
   - Add `digit_ratio_path`: Ratio of digits specifically in the path component.
   - Add `digit_ratio_query`: Ratio of digits specifically in the query component.
   - Add `has_hex_object_id`: Detection of 24-character hexadecimal IDs (distinguishing path-based data identifiers from random hostname entropy).
   - Add `has_uuid`: Regex detection of standard RFC 4122 UUIDs.
   - Add `query_param_count`: Explicit count of distinct query keys.
2. **Feature Scaling:**
   - Incorporate `StandardScaler` / `RobustScaler` within pipeline to prevent single magnitude features from blowing up linear coefficients.

---

## 5. Candidate Models & Benchmarking Protocol

We will train and compare 4 distinct candidates on identical stratified splits (`random_state=42`):
- **Candidate A:** Unscaled Logistic Regression Baseline (v1.0.0 reference)
- **Candidate B:** Standardized & Regularized Logistic Regression (`L2` penalty with GridSearch C)
- **Candidate C:** Random Forest Classifier (`n_estimators=150`, `max_depth=14`, `class_weight='balanced'`)
- **Candidate D:** XGBoost Classifier (`n_estimators=150`, `learning_rate=0.08`, `max_depth=6`, `subsample=0.85`)

---

## 6. Probability Calibration & Threshold Strategy

1. **Validation Calibration:** Apply `CalibratedClassifierCV(method='sigmoid', cv=3)` to output well-calibrated posterior probabilities.
2. **Operating Thresholds:**
   - `LOW`: $P(\text{Phishing}) < 0.35$
   - `MEDIUM`: $0.35 \le P(\text{Phishing}) < 0.70$
   - `HIGH`: $0.70 \le P(\text{Phishing}) < 0.90$
   - `CRITICAL`: $P(\text{Phishing}) \ge 0.90$ + Corroborating Deterministic Signal

---

## 7. Risk Engine Decoupling

- **ML Signal Isolation:** A standalone ML prediction $\ge 0.70$ will be assigned `severity: 'high'` (contributing $+25$ points), not `critical`.
- **Critical Severity Requirement:** `severity: 'critical'` will strictly require **either** active deterministic violation (e.g. IP-host, credential harvesting form to external domain, brand domain mismatch) **or** calibrated ML probability $\ge 0.95$ alongside secondary structural flags.

---

## 8. Regression Suite & Validation Gates

Regression test suite (`ml/tests/test_regression.py`):
1. `https://www.apnacollege.in/start` (Legitimate shallow)
2. `https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit` (Legitimate deep query)
3. `https://github.com/torvalds/linux/commit/80564ee3ba42f8812b1c7a8b4081c7e9bb519e96` (Legitimate git hash)
4. `http://192.168.1.1/paypal/verify.php` (Phishing IP host)
5. `http://apple-id-verify.security-alert99.tk/login` (Phishing brand spoof)

---

## 9. Integration Gates (Prior to Production Activation)
- [ ] Leakage audit zero overlap
- [ ] Frozen test evaluation report generated
- [ ] All 12 Pytest tests + new regression tests pass
- [ ] Backend integration tests pass
- [ ] No hardcoded domain/URL rules
- [ ] All metrics generated strictly by executable code
