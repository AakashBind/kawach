# URL Dataset Generalization Audit

## 1. Executive Summary
This forensic audit investigated the true generalization capacity and benchmark validity of the baseline URL phishing detection model (`url-phishing v1.0.0`). 

**Key Findings:**
1. **The 100.0% frozen-test accuracy reported by Model 1.0.0 is an artifact of severe shortcut learning rather than robust generalization.**
2. A single feature, `url_length`, alone achieves **$98.73\%$ accuracy** and **$0.9994$ ROC-AUC** on the baseline dataset. `num_digits` alone achieves **$97.63\%$ accuracy**.
3. **Severe Benign Domain & Structural Monoculture:** All 1,881 legitimate samples originated from just **30 standard domains** with shallow, short paths (mean length: 35.1 chars, mean digits: 0.29). No legitimate deep LMS players, course slugs, UUIDs, or MongoDB ObjectIDs existed in the baseline dataset.
4. **Out-of-Distribution (OOD) Collapse:** When evaluated against real-world complex legitimate URLs (LMS video players, SaaS consoles, Jira tickets, cloud URLs), Model 1.0.0 accuracy collapses from **$100.0\%$ to $64.0\%$**, with an unacceptable **$46.67\%$ False Positive Rate (FPR)**.
5. **Retraining Readiness:** The dataset is classified as **`NOT READY — DATA QUALITY ISSUE REMAINS`**. Retraining without expanding legitimate complex URL coverage will merely reproduce the same failure mode.

---

## 2. Dataset Provenance
- **Dataset Identifier:** `url_uci_phiusiil_benchmark_v1`
- **Source:** UCI Machine Learning Repository (Phishing Websites ID 327 & PhiUSIIL ID 967 benchmarks)
- **Official URL:** `https://archive.ics.uci.edu/dataset/327/phishing`
- **License:** Creative Commons Attribution 4.0 International (`CC BY 4.0`)
- **Access Date:** 2026-10-03
- **Raw Snapshot SHA-256:** `cb7e0eff529a7d932dca56adc8f37c4a5acc840ac2a4ac03f086ba38e9643105`

---

## 3. Current Dataset Composition
- **Total Raw Samples:** `7,881`
- **Deduplicated Samples:** `7,881`
- **Legitimate Samples (0):** `1,881` ($23.87\%$)
- **Phishing Samples (1):** `6,000` ($76.13\%$)
- **Partitions:**
  - **Training Set (70%):** 5,516 samples (1,317 Legit / 4,199 Phish)
  - **Validation Set (15%):** 1,182 samples (282 Legit / 900 Phish)
  - **Frozen Test Set (15%):** 1,183 samples (282 Legit / 901 Phish)

---

## 4. Domain Overlap
- **Total Registered Domains in Dataset:** `4,871`
- **Train Domains:** `3,450`
- **Validation Domains:** `834`
- **Test Domains:** `840`
- **Cross-Partition Domain Overlap:**
  - **Train $\cap$ Test Domains:** `126` shared domains ($15.0\%$ of test domains)
  - **Train $\cap$ Val Domains:** `127` shared domains ($15.2\%$ of val domains)
  - **Val $\cap$ Test Domains:** `109` shared domains ($13.0\%$ of test domains)
- **Significance:** In the baseline stratified split, all 30 legitimate domains appeared concurrently in train, validation, and test partitions, enabling domain memorization.

---

## 5. Domain-Label Analysis & Purity
- **100% Legitimate Domains:** `30` domains ($0.6\%$ of all domains)
- **100% Phishing Domains:** `4,841` domains ($99.4\%$ of all domains)
- **Mixed Domains (having both legit & phishing URLs):** `0` ($0.0\%$)
- **Audit Takeaway:** $100\%$ of the baseline dataset can be perfectly predicted purely by memorizing domain identities because zero domain ambiguity exists.

---

## 6. Exact Duplicate Analysis
- **Train $\cap$ Train Duplicates:** `0` (Deduplication verified)
- **Train $\cap$ Validation Duplicates:** `0`
- **Train $\cap$ Test Duplicates:** `0`
- **Validation $\cap$ Test Duplicates:** `0`
- **Status:** PASS (Zero literal URL cross-partition contamination).

---

## 7. Near-Duplicate Analysis
- Heuristic near-duplicate audit (URLs sharing identical domain and path structure, differing only by numerical parameters):
  - **Observed Near-Duplicate Volume:** `38.9%` of samples in the validation and test sets share identical parameterized path structures with training records.

---

## 8. Template Leakage
- **Total Unique Structural Templates:** `5,244`
- **Test Samples with Matching Training Template:** `460 / 1,183` ($38.88\%$)
- **Impact:** Synthetic campaign generation patterns (e.g. `domain/brand/verify-account.php?id=<NUM>`) allowed the classifier to match structural templates seen in training.

---

## 9. Synthetic / Data Artifact Investigation
Inspection of feature statistics reveals a profound synthetic generation artifact:
1. **URL Length Separation:**
   - Legitimate URLs: Max length `58` chars (Mean: `35.1` chars)
   - Phishing URLs: Min length `48` chars, Max `114` chars (Mean: `77.3` chars)
2. **Digit Count Separation:**
   - Legitimate URLs: Mean `0.29` digits (Median: `0.0`, Max: `4.0`)
   - Phishing URLs: Mean `7.75` digits (Median: `6.0`, Max: `16.0`)
3. **Hyphen Count Separation:**
   - Legitimate URLs: Mean `0.15` hyphens (Max: `1.0`)
   - Phishing URLs: Mean `3.53` hyphens (Max: `6.0`)

---

## 10. Feature Distribution Analysis

| Feature Name | Legit Mean (Std) | Phish Mean (Std) | Legit Min/Max | Phish Min/Max | Artifact Risk |
|---|---|---|---|---|---|
| `url_length` | 35.11 (8.61) | 77.31 (16.66) | 14.0 / 58.0 | 48.0 / 114.0 | **CRITICAL SHORTCUT** |
| `num_digits` | 0.29 (1.04) | 7.75 (4.25) | 0.0 / 4.0 | 2.0 / 16.0 | **CRITICAL SHORTCUT** |
| `num_hyphens` | 0.15 (0.36) | 3.53 (1.49) | 0.0 / 1.0 | 1.0 / 6.0 | **HIGH SHORTCUT** |
| `query_length` | 1.34 (4.72) | 17.09 (22.21) | 0.0 / 18.0 | 0.0 / 61.0 | **MODERATE** |
| `is_https` | 0.86 (0.35) | 0.20 (0.40) | 0.0 / 1.0 | 0.0 / 1.0 | Moderate |
| `url_entropy` | 3.82 (0.31) | 4.41 (0.28) | 2.85 / 4.25 | 3.60 / 5.12 | Moderate |

---

## 11. Model Coefficient Analysis (Logistic Regression v1.0.0)

| Feature | Coefficient ($\beta$) | Absolute Impact | Interpretation |
|---|---|---|---|
| `num_digits` | `+0.8801` | **Highest per-unit weight** | $+0.88$ logit per digit. 14 digits add $+12.32$ to logit! |
| `num_digits_hostname` | `+0.8486` | High | Penalizes IP or numbered hosts |
| `num_hyphens` | `+0.7375` | High | $+0.74$ logit per hyphen |
| `suspicious_token_count` | `+0.5197` | High | Penalizes security/banking keywords |
| `url_length` | `+0.2955` | **Dominant Magnitude** | Unscaled! 94 chars adds $+27.78$ to logit! |
| `path_length` | `-0.3719` | Moderate Negative | Compensatory path term |
| `longest_token_length` | `-0.5435` | Moderate Negative | Decreases logit for long single words |
| `Intercept` | `-0.3201` | Baseline | Near zero baseline bias |

---

## 12. Single-Feature Diagnostic Experiments

| Single Feature Model | Test Accuracy | Test F1-Score | Test ROC-AUC | Diagnostic Verdict |
|---|---|---|---|---|
| **`url_length` only** | **$98.73\%$** | **$0.9917$** | **$0.9994$** | **Flawed Dataset Shortcut** |
| **`num_digits` only** | **$97.63\%$** | **$0.9846$** | **$0.9810$** | **Flawed Dataset Shortcut** |
| **`num_hyphens` only** | **$96.20\%$** | **$0.9756$** | **$0.9934$** | **Flawed Dataset Shortcut** |
| `query_length` only | $76.16\%$ | $0.8647$ | $0.7577$ | Weak standalone |
| `is_https` only | $79.54\%$ | $0.8530$ | $0.8133$ | Weak standalone |
| `subdomain_depth` only | $76.16\%$ | $0.8647$ | $0.6858$ | Weak standalone |

---

## 13. Legitimate URL Diversity Audit
- **Current Legitimate Diversity:** Severely deficient.
- Consists entirely of basic root/about pages from 30 popular domains.
- Total absence of:
  - Course players (`path-player`, `lecture/`, `assignments/`)
  - Hexadecimal MongoDB ObjectIDs (`68dbea2c4069da29a90e18bfUnit`)
  - UUIDs (`550e8400-e29b-41d4-a716-446655440000`)
  - Multi-key query parameters (`?courseid=...&unit=...&session=...`)
  - Cloud / SaaS consoles (AWS, GCP, Jira, Canvas)

---

## 14. Phishing URL Diversity Audit
- **Current Phishing Diversity:** Good coverage of synthetic lures and classic phishing archetypes (IP hosts, `@` symbol credential tricks, suspicious TLDs, token spoofing).
- **Limitation:** Strong structural bias toward long URLs with digits and hyphens, creating an artificial divide against legitimate samples.

---

## 15. Out-of-Distribution (OOD) Evaluation

Evaluating Model 1.0.0 on a 25-sample OOD suite (15 complex real-world benign URLs + 10 real phishing URLs):

| Evaluation Set | Samples | Accuracy | Precision | Recall | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|
| **Frozen Test Benchmark** | 1,183 | $100.0\%$ | $100.0\%$ | $100.0\%$ | $1.0000$ | $0.00\%$ | $0.00\%$ |
| **Real-World OOD Suite** | 25 | **$64.00\%$** | **$53.33\%$** | **$80.00\%$** | **$0.6400$** | **$46.67\%$** | **$20.00\%$** |

### OOD False Positives (Legitimate URLs misclassified as Phishing by Model 1.0.0):
1. `https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit` $\rightarrow$ **$99.57\%$ Phishing**
2. `https://aws.amazon.com/console/home?region=us-east-1#services-overview-2026` $\rightarrow$ **$99.94\%$ Phishing**
3. `https://jira.atlassian.com/browse/CONFSERVER-58492?focusedCommentId=1948291...` $\rightarrow$ **$100.00\%$ Phishing**
4. `https://www.amazon.com/dp/B08N5WRWNW?ref_=cm_sw_r_cp_ud_dp_8W94EZJ8219K&th=1` $\rightarrow$ **$99.41\%$ Phishing**
5. `https://console.cloud.google.com/bigquery?project=my-data-warehouse-2026...` $\rightarrow$ **$100.00\%$ Phishing**
6. `https://canvas.instructure.com/courses/1948291/assignments/9482019...` $\rightarrow$ **$99.99\%$ Phishing**
7. `https://youtube.com/watch?v=dQw4w9WgXcQ&t=42s&feature=shared` $\rightarrow$ **$51.34\%$ Phishing**

---

## 16. Calibration Audit
- On the in-distribution frozen test set, Brier score is `0.000000` because the model outputs extreme probabilities ($0.0000$ or $1.0000$).
- On OOD data, the model displays severe overconfidence: outputting $>99.9\%$ confidence on completely legitimate URLs due to linear unscaled logit escalation.

---

## 17. Apna College Case Study
- **URL 1 (`/start`):** `url_length=32`, `num_digits=0`, `num_hyphens=0` $\rightarrow$ Logit: `-9.9334` $\rightarrow P(\text{Phishing}) = 0.000049$ (LOW)
- **URL 2 (`/path-player?...`):** `url_length=94`, `num_digits=14`, `num_hyphens=3` $\rightarrow$ Logit: `+5.4417` $\rightarrow P(\text{Phishing}) = 0.995687$ (CRITICAL)
- **Diagnosis:** The 14 hexadecimal characters in `68dbea2c4069da29a90e18bfUnit` and 94 character length pushed the unscaled logistic regression into extreme saturation.

---

## 18. Legitimate URL Coverage Matrix

| Category | Current Coverage in Baseline | Required Coverage for Robust ML | Gap Description |
|---|---|---|---|
| **Homepage** | 100% | 20% | Overrepresented; dominates benign class |
| **Shallow Paths** | 100% | 25% | Overrepresented; all paths $<20$ chars |
| **Deep Query URLs** | 0% | 30% | **Critical Gap**: Zero multi-query benign URLs |
| **UUID URLs** | 0% | 15% | **Critical Gap**: Zero UUID-based SaaS links |
| **Hex ID / ObjectID URLs**| 0% | 15% | **Critical Gap**: Zero MongoDB/Hex ID routes |
| **Education / LMS** | 0% | 20% | **Critical Gap**: Zero video/course player links |
| **E-commerce / Catalog**| 0% | 20% | **Critical Gap**: Zero faceted search/product URLs |
| **SaaS / Cloud Dashboards**| 0% | 15% | **Critical Gap**: Zero AWS/GCP/Jira/Console URLs |
| **Documentation / APIs**| 10% | 20% | Moderate Gap: Only shallow docs present |

---

## 19. Phishing Coverage Matrix

| Category | Coverage in Baseline | Evidence / Status |
|---|---|---|
| **Credential Phishing** | 80% | High coverage of login/signin lures |
| **Brand Impersonation** | 85% | Covers PayPal, BofA, Wells Fargo, Netflix |
| **IP-Host Phishing** | 40% | Synthetic IP hosts included |
| **Long Phishing URLs** | 95% | Heavily represented (mean length: 77 chars) |
| **Query-based Phishing**| 70% | High coverage of session/token query strings |
| **Short / Homograph Phish**| 10% | Low coverage of short deceptive domains |

---

## 20. Recommended Dataset Composition & Split Strategy

### Recommended Dataset Expansion:
- **Balanced 12,000+ Sample Dataset:**
  - **6,000 Legitimate URLs:** 
    - 2,000 Standard Homepages & Docs
    - 1,500 Deep LMS & Course Player Links (with ObjectIDs, slugs, lesson IDs)
    - 1,500 E-commerce & Multi-Query Links
    - 1,000 Cloud / SaaS / Git / API UUID Links
  - **6,000 Phishing URLs:** 
    - Ingested from verified UCI PhiUSIIL, PhishTank, and URLhaus corpora (CC BY 4.0 / Open Data).

### Recommended Split Strategy:
- **Domain-Grouped Stratified Partitioning:** URLs sharing the same registered domain must stay within the same partition (Train, Val, or Test) to eliminate domain memorization and force the model to learn structural and lexical patterns.

---

## 21. Retraining Readiness Decision & Limitations

### **FINAL DECISION: `NOT READY — DATA QUALITY ISSUE REMAINS`**
*Retraining on the existing baseline dataset without first injecting complex legitimate URL diversity would simply reproduce the single-feature length/digit shortcut.*

### Documented Limitations:
1. Model 1.0.0 cannot distinguish hexadecimal identifiers from random phishing tokens due to absence of complex benign examples in its training set.
2. Unscaled linear models are unsuited for raw count features without normalization and feature scaling (`StandardScaler`).
3. Domain-grouped splitting must be applied to prevent benchmark score inflation.
