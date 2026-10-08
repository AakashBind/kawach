# LIVE URL SCANNER V1/V2 FORENSIC AUDIT REPORT (PHASE E.1.1)

## Executive Summary
A read-only forensic audit was executed to determine whether the active live URL Scanner in the PS5 AI Scam & Phishing Detection Platform runs **URL Phishing Model v2.0.0**, **v1.0.0**, or an incorrect/stale artifact.

### Audit Verdict: **LIVE SCANNER USES V2.0.0 (VERIFIED)**
The live runtime pipeline from Frontend UI $\rightarrow$ Backend Gateway $\rightarrow$ ML Microservice $\rightarrow$ Feature Extraction $\rightarrow$ Model Inference $\rightarrow$ Unified Risk Engine $\rightarrow$ SQLite Persistence is demonstrably executing **URL Phishing Model v2.0.0** (`b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156`).

On the diagnostic regression target URL:
`https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit`
- **Live ML Calibrated Probability**: `0.000672` (`0.0672%` phishing)
- **Live ML Raw Score**: `0.000036`
- **Live Platform Risk Score**: `2 / 100` (`LOW` Risk, `LEGITIMATE`)
- **Active Detector Tag**: `url-phishing-2.0.0`

In contrast, the immutable v1.0.0 baseline was directly evaluated and produced `0.995687` (`99.57%` phishing), proving that v1.0.0 is not executing in the live scanner.

---

## Live Request Path & Architecture Trace

| Step | Component / Layer | Source File & Function | Operation / Data Transferred |
| :--- | :--- | :--- | :--- |
| **1** | Frontend UI | `frontend/src/pages/ScannerPage.tsx` (`handleScan`) | Captures user input URL string |
| **2** | Frontend API Service | `frontend/src/services/api.ts` (`ApiService.scanUrl`) | Dispatches `POST /api/v1/scans/url` payload |
| **3** | Backend Router | `backend/src/routes/scanRoutes.ts` (`scanRouter.post('/url')`) | Validates URL format with Zod and enforces rate limits |
| **4** | Backend Analyzer | `backend/src/services/urlAnalyzer.ts` (`analyzeUrl`) | Coordinates lexical heuristic checks & ML microservice call |
| **5** | Backend ML Client | `backend/src/services/mlClient.ts` (`MLClient.inferUrl`) | Dispatches HTTP request `POST /inference/url` |
| **6** | Python ML Microservice | `ml/service/app.py` (`infer_url`) | Validates global `URL_MODEL` state and receives payload |
| **7** | Feature Extractor | `ml/features/url_features.py` (`extract_url_features`) | Deterministically extracts exact 31-feature numerical vector |
| **8** | ML Inference | `ml/service/app.py` (`URL_MODEL.predict_proba`) | Executes calibrated XGBoost classifier v2.0.0 |
| **9** | Unified Risk Engine | `backend/src/services/riskEngine.ts` (`calculateUnifiedRisk`) | Aggregates ML evidence and heuristic signals into composite score |
| **10** | Database Persistence | `backend/src/routes/scanRoutes.ts` (`persistScan`) | Stores scan & evidence records in SQLite database |
| **11** | Frontend Presentation | `frontend/src/pages/ResultPage.tsx` | Renders risk gauge, score (`2`), and active detector tags |

---

## Model Loading Evidence & SHA-256 Verification

```python
# ml/service/app.py load_artifacts()
url_dir = os.path.join(ML_ROOT, "models", "url_phishing")
url_model_path = os.path.join(url_dir, "model.joblib")
actual_hash = compute_sha256(url_model_path)
# Verified against expected hash b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156
```

### Artifact Hash Audit Table

| Artifact Target | File Path | Expected SHA-256 | Actual Live SHA-256 | Match |
| :--- | :--- | :--- | :--- | :--- |
| **v1.0.0 Baseline** | `ml/models/url_phishing/v1.0.0/model.joblib` | `3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49` | `3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49` | **YES** |
| **v2.0.0 Production** | `ml/models/url_phishing/v2.0.0/model.joblib` | `b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156` | `b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156` | **YES** |
| **Active Root Model** | `ml/models/url_phishing/model.joblib` | `b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156` | `b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156` | **YES** |

---

## V1 vs V2 Determination

### Direct Comparison on Diagnostic Target URL
Target: `https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit`

| Pipeline | Model Artifact SHA | Raw Probability | Calibrated Prob | Class | Risk Score | Risk Level |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Direct v1.0.0 Evaluation** | `3fef...4c49` | `0.995687` | N/A (uncalibrated) | `phishing` (1) | `85+` | `CRITICAL` (FP) |
| **Direct v2.0.0 Evaluation** | `b22a...9156` | `0.000036` | `0.000672` | `legitimate` (0) | `2` | `LOW` (Correct) |
| **Live Scanner Endpoint** | `b22a...9156` | `0.000036` | `0.000672` | `legitimate` (0) | `2` | `LOW` (Correct) |

### Conclusion: **Category A: LIVE SCANNER USES V2.0.0**

---

## Live Scanner Response Payload (Raw JSON)

```json
{
  "model_id": "url-phishing",
  "model_version": "2.0.0",
  "detector_version": "url-detector-2.0.0",
  "score": 0.000672,
  "raw_score": 0.000036,
  "calibrated_probability": 0.000672,
  "calibrated": true,
  "predicted_class": "legitimate",
  "top_signals": [],
  "features": {
    "url_length": 94,
    "hostname_length": 18,
    "path_length": 12,
    "query_length": 55,
    "num_dots": 2,
    "num_hyphens": 3,
    "num_underscores": 0,
    "num_slashes": 3,
    "num_questionmarks": 1,
    "num_equal_signs": 2,
    "num_at_symbols": 0,
    "num_percent_encoded": 0,
    "num_digits": 14,
    "num_digits_hostname": 0,
    "digit_ratio_url": 0.1489,
    "digit_ratio_hostname": 0.0,
    "has_ip_address": 0,
    "is_https": 1,
    "subdomain_depth": 1,
    "has_suspicious_tld": 0,
    "suspicious_token_count": 0,
    "suspicious_token_in_host": 0,
    "suspicious_token_in_path": 0,
    "url_entropy": 4.8278,
    "hostname_entropy": 3.3502,
    "has_non_standard_port": 0,
    "path_depth": 1,
    "has_double_slash_path": 0,
    "has_at_symbol": 0,
    "consecutive_consonants_max": 3,
    "longest_token_length": 28
  },
  "feature_extraction_time_ms": 0.158,
  "model_inference_time_ms": 6.096,
  "processing_time_ms": 6.26,
  "errors": []
}
```

---

## Detector Metadata & Unified Risk Engine Trace

1. **Detector Version Metadata**:
   - `ml/service/app.py`: `model_version: "2.0.0"`, `detector_version: "url-detector-2.0.0"`
   - `backend/src/services/urlAnalyzer.ts`: appends `url-phishing-2.0.0` to `modelVersions`.
   - `backend/src/database/migrations.ts`: records `url-phishing v2.0.0` in `model_metadata`.
   - The label `url-phishing-1.0.0` is completely absent from the live inference path.
2. **Unified Risk Score Computation**:
   - Initial base score: `10`
   - Benign ML signal deduction: $-8 \times \text{confidence} (0.9993) = -7.9944$
   - Total calculated score: $\text{round}(10 - 7.9944) = 2 / 100$
   - Category mapping: Score $< 25 \longrightarrow \mathbf{LOW}$ Risk.

---

## Control Tests Verification

| Target URL | Purpose | ML Calibrated Prob | ML Raw Score | Risk Score | Risk Level |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `https://www.apnacollege.in/start` | Control 1 (Benign simple) | `0.000672` (`0.067%`) | `0.000048` | `2 / 100` | **LOW** |
| `https://www.google.com/search?q=cybersecurity+defense` | Control 2 (Benign search) | `0.000685` (`0.068%`) | `0.001273` | `2 / 100` | **LOW** |

---

## Root Cause, Severity & Required Fix

- **Discrepancy Found**: **NONE**. The live URL Scanner is operating strictly on Model v2.0.0 with accurate metadata and verified cryptographic hashes.
- **Severity**: **NONE (HEALTHY)**.
- **Required Fix**: **NO CHANGES REQUIRED**.

---

## Final Governance Audit Summary

- **Models Retrained**: `0`
- **Models Modified**: `0`
- **Dataset Modified**: `0`
- **Risk Engine Modified**: `0`
- **Frontend Modified**: `0`
- **Backend Modified**: `0`
- **Hardcoded Predictions Added**: `0`
- **Tests Removed / Disabled**: `0`
- **Security Controls Weakened**: `0`
- **Audit Status**: **COMPLETE — VERIFIED**
