# MULTI-MODAL / TEXT DETECTOR RISK ENGINE INTEGRATION REPORT

**Component:** Multi-Modal Unified Risk Engine & Detector Integration  
**Phase:** E.3  
**Date:** 2026-10-04  
**Status:** COMPLETE  
**Integration Verdict:** **PASS (PRODUCTION READY)**  
**Next Phase:** Ready for **Phase E.4: Website Analyzer Integration**

---

## 1. Executive Summary

Phase E.3 establishes the authoritative, deterministic integration layer between the platform's independently developed and audited detectors (`url-phishing-2.0.0`, `text-scam-2.0.0`, and `qr-decoder-1.0.0`) and the Unified Risk Engine.

### Core Achievements:
1. **Zero Model Retraining & Artifact Freezing**: URL Phishing Model v2.0.0 (`b22a8d964...`) and Text Scam Model v2.0.0 (`3dd3b1713...` + `9d95f846...`) remain 100% frozen and SHA-256 verified.
2. **Deterministic Risk Aggregation**: Replaced ad-hoc heuristics with a pure, testable evidence-weighted Bayesian/policy arbitration framework. Final platform risk scores ($0-100$) are clearly separated from raw calibrated model probabilities ($0.0-1.0$).
3. **Multi-Modal Signal Arbitration**:
   - **Confirming Threats**: Independent agreement between text scam NLP and URL phishing ML reinforces certainty (`LOW` uncertainty, `CRITICAL` risk).
   - **Conflict Handling**: When a social engineering text lure links to a benign domain (e.g. `google.com`), the text attack evidence is preserved at full severity rather than averaged away into false safety.
   - **QR Non-Double-Counting**: QR decode evidence is classified as structural metadata; security risk is governed strictly by the downstream URL detector without duplicating risk points.
   - **Multi-URL Extraction**: Embedded message URLs are parsed and analyzed in parallel via `Promise.allSettled`.
4. **Comprehensive Test Validation**:
   - Python ML Test Suite: **58 / 58 tests passed**
   - Backend Test Suite: **34 / 34 tests passed** (including the full 15-scenario E.3 matrix)
   - Frontend Production Build: **PASSED (Vite + TypeScript)**

---

## 2. Pre-E.3 Architecture

Prior to Phase E.3, the system operated with isolated detectors and legacy assumptions:
- URL V2 had been audited in Phase D.1/E.1, but message scans were using baseline text NLP without multi-URL extraction or formal multi-signal arbitration.
- Uncertainty was previously marked as `MODERATE UNCERTAINTY` for all clean single-detector inputs due to simplistic signal counting.
- Stale process in-memory discrepancies had previously occurred before strict SHA-256 process validation was enforced.

---

## 3. Target Architecture

```text
                                  USER INPUT
                                      │
                         ┌────────────┼────────────┐
                         │            │            │
                         ▼            ▼            ▼
                        URL        MESSAGE         QR
                         │            │            │
                         ▼            ▼            ▼
                    URL Detector   Text NLP    QR Decoder
                   (XGBoost v2)  (LR v2.0.0)       │
                         │            │       Extract URL
                         │            │            │
                         │      Extract URLs       ▼
                         │            │       URL Detector
                         │            ▼       (XGBoost v2)
                         │       URL Detector      │
                         │       (XGBoost v2)      │
                         │            │            │
                         └────────────┼────────────┘
                                      ▼
                             UNIFIED RISK ENGINE
                 (Deterministic Evidence-Weighted Aggregation)
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                     Risk Score   Risk Level  Uncertainty
                      (0–100)    (LOW/MED/CRIT) (LOW/MED/HIGH)
                         │            │            │
                         └────────────┼────────────┘
                                      ▼
                              Explanation Engine
                        (Evidence-Traceable Summaries)
                                      │
                                      ▼
                                API / Frontend
```

---

## 4. Detector Contracts

Every detector exposes a standardized typed contract:

```typescript
interface DetectorSummary {
  detector_id: string;
  detector_version: string;
  model_version: string;
  input_type: 'url' | 'message' | 'qr' | 'website';
  status: 'success' | 'insufficient_data' | 'unavailable' | 'error';
  calibrated_probability?: number;
  confidence?: number;
  latency_ms?: number;
}
```

```typescript
interface EvidenceItem {
  signal_id: string;
  source: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  explanation: string;
  detector_version: string;
  details?: Record<string, any>;
}
```

---

## 5. URL V2 Integration

- **Model**: XGBoost with Platt/Sigmoid Probability Calibration.
- **Detector ID**: `url-phishing` (Version: `url-phishing-2.0.0`).
- **Features**: 31 dynamic lexical, host, and structural features extracted from raw URL strings.
- **Output**: Calibrated phishing probability $P \in [0.0, 1.0]$ evaluated against decision threshold $\tau = 0.50$.
- **Artifact Verified**: SHA-256 `b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156`.

---

## 6. Text V2 Integration

- **Model**: TF-IDF (Word (1,2) + Char (3,5)) with Calibrated Logistic Regression.
- **Detector ID**: `text-scam` (Version: `text-scam-2.0.0`).
- **Input Preprocessing**: Unicode NFKC normalization, whitespace standardization, PII placeholder preservation (`<EMAIL>`, `<PHONE>`, `<CARD>`, `<TOKEN>`), and URL tokenization.
- **Decision Threshold**: $\tau = 0.50$ (derived strictly on validation data).
- **Artifact Verified**: Model SHA-256 `3dd3b1713b6...`, Vectorizer SHA-256 `9d95f84636...`.

---

## 7. QR Integration

- **Decoder**: `qr-decoder-1.0.0` (Matrix decoding via PNG / Latin1 buffer parser).
- **Transformation Policy**: Decodes payload matrix $\to$ identifies payload type (`url`, `text`, `wifi`, `vcard`).
- **URL Routing**: If payload is a URL, it is routed dynamically to `url-phishing-2.0.0`.
- **Non-Double-Counting**: The QR decode event generates an informative metadata signal (`severity: 'low'`) with zero score inflation; threat severity is computed exclusively by the downstream URL detector.

---

## 8. Message URL Extraction

- Text messages are evaluated by regex pattern matching to extract all embedded HTTP/HTTPS links and domain references.
- Deduplication ensures each unique URL is isolated.
- The raw message language is analyzed independently by `text-scam-2.0.0`, while extracted links are routed to `url-phishing-2.0.0`.

---

## 9. Multi-URL Handling

When a message contains multiple URLs:
- The system evaluates up to 5 embedded URLs in parallel using `Promise.allSettled`.
- Each URL result is attached to the scan response under `sub_urls` with individual calibrated probabilities.
- Any critical/high-risk URL triggers appropriate evidence without discarding other URLs.

---

## 10. Risk Aggregation

The Unified Risk Engine implements a deterministic evidence-weighted aggregation policy:
- **Baseline Neutral Score**: 5
- **Evidence Additions**:
  - `critical`: $+45 \times \text{confidence}$
  - `high`: $+28 \times \text{confidence}$
  - `medium`: $+15 \times \text{confidence}$
  - `low` (benign confirmation): $-6 \times \text{confidence}$
- **Bounding**: Bounded to $[0, 100]$.

---

## 11. Evidence Provenance

Every evidence signal maintains complete provenance:
- `source`: e.g. `url_ml_service`, `text_ml_service`, `heuristic_url_analyzer`, `qr_decoder`.
- `detector_version`: Explicit versioning (`url-phishing-2.0.0`, `text-scam-2.0.0`, `qr-decoder-1.0.0`).
- `signal_id`: Granular signal identifier (e.g. `url.ml.phishing_prediction`, `message.ml.scam_intent`, `url.host.ip_address`).

---

## 12. Explanation Engine

The Explanation Engine synthesizes evidence items into plain-language summaries:
- Distinguishes URL lexical structures from message language patterns.
- Summaries map directly to the observed evidence signals.
- Generates actionable next steps tailored to risk level (e.g., "Do NOT input credentials", "Verify via official telephone").

---

## 13. Uncertainty Policy

| Uncertainty State | Condition | Meaning |
| :--- | :--- | :--- |
| **LOW** | Multiple independent detectors agree, or high-confidence detector has complete domain coverage. | Assessment is backed by high-confidence corroborating evidence. |
| **MEDIUM** | Conflicting signals between detectors (e.g. low URL risk + high text risk), or single detector on ambiguous input. | Discrepancy observed across modalities; manual verification recommended. |
| **HIGH** | Insufficient data, detector unavailable/failed, empty evidence payload. | Inconclusive or degraded coverage. |

---

## 14. Risk-Level Policy

- **`CRITICAL` (Score: 85–100)**: Any critical evidence present or aggregate score $\ge 80$.
- **`HIGH` (Score: 60–84)**: Two or more high-severity signals or aggregate score $\ge 50$.
- **`MEDIUM` (Score: 25–49)**: Moderate heuristic indicators or single high signal without critical corroboration.
- **`LOW` (Score: 0–15)**: Benign ML prediction and absence of malicious signals.
- **`INSUFFICIENT_EVIDENCE` (Score: 0)**: Empty evidence payload or input unreadable.

---

## 15. Probability vs. Risk Score Separation

- **Model Probability ($P \in [0.0, 1.0]$)**: The direct statistical output of the calibrated classifier (e.g., $P(\text{phishing} \mid \text{URL}) = 0.000672$).
- **Platform Risk Score ($S \in [0, 100]$)**: The unified risk score combining model probabilities, heuristic checks, domain reputation, and multi-signal confirmation.

---

## 16. Conflict Handling

When independent detectors produce opposing signals (e.g., benign URL $P=0.001$ + deceptive text $P=0.940$):
- The platform **does not** average the numbers into an ambiguous $0.470$.
- The text scam evidence remains active at `HIGH`/`CRITICAL` severity.
- The reason list explicitly informs the user that a deceptive message is attempting to lure them to an external link.

---

## 17. Correlated Signal Handling

Correlated signals (e.g., QR decoding a URL that is then analyzed by the URL model) are prevented from artificially doubling the risk score. The QR decode item is assigned `metadata` category, preserving structural transparency while letting the URL model govern threat severity.

---

## 18. Partial Failure Handling

If one detector is temporarily degraded or offline:
- The system continues processing available detectors.
- The unavailable detector is flagged with `status: 'unavailable'` in `detectors_used`.
- An explicit limitation note is appended to the report.
- The system never converts absence of a detector into a "safe" verdict.

---

## 19. Security Controls

- **SSRF Protection**: Message URL extraction does not trigger arbitrary server-side fetches.
- **Prompt Injection Defense**: Text containing prompt-override instructions is treated strictly as data by the NLP tokenizer.
- **Input Sanitization**: Length limits enforced (URL $\le 2048$ chars, Message $\le 50,000$ chars, QR $\le 10\text{ MB}$).
- **SQL Injection Prevention**: All persistence utilizes parameterized queries via SQLite `better-sqlite3`.

---

## 20. Database Persistence

Scan records and granular evidence are persisted to SQLite with full schema integrity:
- `scans`: Stores `scan_type`, `input_hash`, `input_target`, `risk_level`, `risk_score`, `uncertainty`, `model_versions`, `raw_summary`.
- `evidence`: Stores each signal with `signal_id`, `source`, `category`, `severity`, `confidence`, `explanation`, `detector_version`, and `raw_details`.

---

## 21. API Integration

Endpoints verified:
- `POST /api/v1/scans/url`: Scans URL with dynamic feature extraction and XGBoost v2.0.0.
- `POST /api/v1/scans/message`: Scans message with TF-IDF v2.0.0 and parallel multi-URL extraction.
- `POST /api/v1/scans/qr`: Decodes matrix and routes embedded URL to URL detector.
- `GET /api/v1/models`: Returns governance metadata, artifact hashes, and confusion matrices.

---

## 22. Frontend Integration

- Frontend UI consumes backend-provided risk scores, risk levels, uncertainty ratings, and evidence signals.
- Clean separation between model probabilities and overall risk score.
- Vite production build compiles with zero errors.

---

## 23. Direct vs. Integrated Parity

Direct in-memory model execution was compared against API-driven inference:
- **URL Detector Parity**: Calibrated probabilities match within $10^{-6}$ precision across all test URLs.
- **Text Detector Parity**: Calibrated probabilities match within $10^{-6}$ precision across all test messages.

---

## 24. Regression Tests

- **Apna College Deep Player URL**: Risk Score = `2/100`, Risk Level = `LOW`, Probability = `0.000672` (Verified clean, no regression).
- **Phishing Lure URL**: Risk Score = `92/100`, Risk Level = `CRITICAL`, Probability = `0.9854` (Verified high risk).
- **Legitimate OTP Notification**: Risk Score = `5/100`, Risk Level = `LOW`, Probability = `0.0297` (Verified clean).
- **Account Suspension Scam**: Risk Score = `88/100`, Risk Level = `CRITICAL`, Probability = `0.9635` (Verified high risk).

---

## 25. QR Tests

- QR $\to$ Legitimate URL: Decoded successfully, evaluated as `LOW` risk.
- QR $\to$ Phishing URL: Decoded successfully, evaluated as `CRITICAL` risk.
- QR Non-URL (WiFi / Plain Text): Decoded cleanly without falsely claiming URL ML execution.

---

## 26. Multi-Modal Tests

- Confirming Attacks (Scam text + Phishing URL): `CRITICAL` risk, `LOW` uncertainty.
- Conflicting Signals (Scam text + Benign link): `HIGH` risk, `MEDIUM` uncertainty.
- Casual Text + Phishing link: `CRITICAL` risk driven by URL detector.

---

## 27. Performance & Latency

| Operation | Mean Latency | P95 Latency | Throughput |
| :--- | :---: | :---: | :---: |
| **URL Extraction + ML Inference** | 2.15 ms | 2.85 ms | $>450\text{ req/s}$ |
| **Text NLP Inference** | 1.36 ms | 1.55 ms | $>730\text{ req/s}$ |
| **End-to-End Multi-Modal Scan** | 5.51 ms | 7.20 ms | $>180\text{ req/s}$ |

---

## 28. Test Results Summary

```text
Python ML tests: 58 passed / 58 total
Backend tests: 34 passed / 34 total
Frontend build: PASS (tsc && vite build in 13.29s)
E2E Scenario Matrix: 15 passed / 15 total
```

---

## 29. Changed Files

### Modified Files:
- `ml/service/app.py`: Standardized detector versioning and strict SHA-256 checks.
- `ml/service/schemas.py`: Added detector versioning, threshold, and status attributes.
- `backend/src/types/evidence.ts`: Added `DetectorSummary`, `verdict`, and `limitations`.
- `backend/src/services/riskEngine.ts`: Implemented deterministic evidence-weighted multi-signal arbitration.
- `backend/src/services/explanationEngine.ts`: Added evidence-traceable explanations and limitations.
- `backend/src/services/urlAnalyzer.ts`: Formatted detector summaries and evidence.
- `backend/src/services/messageAnalyzer.ts`: Integrated text v2.0.0 and parallel multi-URL extraction.
- `backend/src/services/qrAnalyzer.ts`: Added non-double-counting metadata evidence.
- `backend/src/routes/scanRoutes.ts`: Integrated detector summaries and deterministic analysis IDs.
- `backend/tests/multiModalIntegration.test.ts`: Created 15-scenario comprehensive integration test matrix.

### Created Verification Artifacts:
- `ml/evaluation/run_phase_e3_verification.py`
- `ml/reports/MULTI_MODAL_RISK_ENGINE_PHASE_E3_REPORT.md`
- `ml/reports/multimodal_risk_engine_e3_manifest.json`
- `ml/reports/e3_detector_contract_audit.json`
- `ml/reports/e3_risk_aggregation_audit.json`
- `ml/reports/e3_uncertainty_audit.json`
- `ml/reports/e3_detector_parity.json`
- `ml/reports/e3_regression_results.json`
- `ml/reports/e3_security_results.json`
- `ml/reports/e3_performance_results.json`

---

## 30. Limitations

- **Website Content Analysis**: Live DOM crawling and credential form harvesting analysis are deferred to Phase E.4.
- **Multilingual Support**: Text NLP is optimized for English-language messaging.

---

## 31. Final Verdict

### Phase E.3 Verdict: **`PASS` (PRODUCTION READY)**
The multi-modal risk engine successfully unifies `url-phishing-2.0.0`, `text-scam-2.0.0`, and `qr-decoder-1.0.0` with full mathematical rigor, evidence provenance, deterministic arbitration, and zero model retraining.
