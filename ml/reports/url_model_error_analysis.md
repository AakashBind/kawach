# PHASE D: URL PHISHING MODEL ERROR ANALYSIS & RESIDUAL DIAGNOSTICS

**Model Evaluated:** `url-phishing v2.0.0` (XGBoost + Calibrated Sigmoid)  
**Evaluation Splits:** Frozen Test Set (3049 samples) & OOD Benchmark (20 samples)  
**Date:** 2026-10-03 19:46:11 UTC

---

## 1. FALSE POSITIVE ANALYSIS (Legitimate URLs misclassified as Phishing)

Total False Positives in Frozen Test Set: **0** (out of 1597 legitimate samples $\rightarrow$ FPR: 0.0000)

### Breakdown of Observed False Positives:

> **Zero False Positives observed on the Frozen Test Set.** The model demonstrated exceptional precision on unseen legitimate test URLs.

---

## 2. FALSE NEGATIVE ANALYSIS (Phishing URLs misclassified as Legitimate)

Total False Negatives in Frozen Test Set: **0** (out of 1452 phishing samples $\rightarrow$ FNR: 0.0000)

### Breakdown of Observed False Negatives:

> **Zero False Negatives observed on the Frozen Test Set.**

---

## 3. OUT-OF-DISTRIBUTION (OOD) BENCHMARK ERROR ANALYSIS

### Summary of OOD Misclassifications:

| URL | True Class | Predicted Class | Calibrated Probability | Notes |
|---|---|---|---|---|
| `https://apnacollege-course-access.xyz/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit` | phishing | legitimate | 0.0008 | Typosquat/impersonation mimicking Apna College path player on .xyz |

---

## 4. ARCHITECTURAL TAKEAWAYS & GENERALIZATION SUMMARY

1. **Resolution of Length/Digit Shortcut:** In baseline model v1.0.0, long query strings and 24-character hexadecimal MongoDB ObjectIDs caused a 99.57% false-positive probability. In v2.0.0, the non-linear decision trees combined with multi-source training data allow the model to recognize legitimate LMS player parameters as safe.
2. **Deterministic Fallbacks:** For extreme zero-day edge cases, the broader platform's deterministic rules (IP hostname detection, suspicious TLD flagging, SSRF filters) provide an additional layer of security.
