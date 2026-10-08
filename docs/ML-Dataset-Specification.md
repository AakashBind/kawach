# ML & Dataset Specification — V1 Web Application
# PS5 — AI Scam & Phishing Detection Platform

**Version:** 1.0.0 — Engineering Source of Truth for Genuine Machine Learning  
**Mandate:** Zero fake AI, zero hardcoded predictions, zero fabricated metrics. Every metric originates from frozen test set evaluation.

---

## 1. Machine Learning Scope

| Component | ML Status | Algorithm / Architecture | Provenance & Dataset |
|---|---|---|---|
| **URL Phishing Classifier** | Genuine ML | Supervised Ensemble: Random Forest + Gradient Boosting | UCI Phishing Websites (ID 327) & PhiUSIIL URL benchmark (11,000+ verified rows, CC BY 4.0) |
| **Message Scam Classifier** | Genuine ML | NLP Pipeline: TF-IDF Vectorizer + Calibrated Logistic Regression / LinearSVC | UCI SMS Spam / Phishing Collection (5,574+ labeled messages, CC BY 4.0) |
| **Deterministic Heuristic Rules** | Rule-based | Regex, lexical parsers, TLD risk tables, IP address detectors | Explicitly labeled as Rule-based (not AI) |
| **QR Decoder** | Computer Vision / Lib | Deterministic Matrix Decoder | Standard open-source QR decoder |
| **Website DOM Inspector** | Parser | HTML token & form analyzer | Deterministic DOM inspector |
| **Unified Risk Engine** | Expert System | Weighted Evidence Aggregator | Controlled, versioned multi-signal engine |

---

## 2. Dataset Governance & Ingestion Pipelines

### 2.1 URL Phishing Dataset Registry
- **Source:** UCI Machine Learning Repository (Phishing Websites & PhiUSIIL)
- **License:** Creative Commons Attribution 4.0 International (CC BY 4.0)
- **Feature Set (30+ Dimensions):**
  1. `url_length`: Total character count
  2. `hostname_length`: Length of authority
  3. `path_length`: Length of path
  4. `num_dots`: Dot count
  5. `num_hyphens`: Hyphen count
  6. `num_slashes`: Directory slash count
  7. `num_questionmarks`: Query symbol count
  8. `num_at_symbols`: '@' credential spoof count
  9. `num_percent`: Percent encoding count
  10. `num_digits`: Digit count
  11. `has_ip_address`: Boolean (1 if hostname is IPv4/IPv6)
  12. `subdomain_depth`: Number of sub-domain levels
  13. `is_https`: Boolean (1 if scheme is https)
  14. `has_suspicious_tld`: Boolean (.tk, .ml, .cf, .gq, .xyz, .top, .work, etc.)
  15. `suspicious_token_count`: Count of security/banking keywords in path/query (login, verify, update, secure, account, bank, signin, token, free, bonus)
  16. `entropy`: Shannon entropy of the URL string
  17. `has_port`: Non-standard port present
  18. `path_depth`: Path segments count
  ... [Up to 30 documented deterministic numeric features]

### 2.2 Message Scam Dataset Registry
- **Source:** UCI SMS Spam Collection & Public Phishing Email Corpus
- **License:** CC BY 4.0
- **Classes:** `0 = Legitimate / Ham`, `1 = Scam / Phishing Intent`
- **Features:** 2,500 Max Features TF-IDF (unigrams + bigrams), sublinear term frequency scaling, entity indicator flags (has_url, has_phone, has_money_currency, has_urgency_word).

---

## 3. Data Leakage & Reproducibility Safeguards
1. **Deduplication:** Strict deduplication on canonicalized inputs prior to splitting.
2. **Stratified Train / Val / Test Partition:**
   - 70% Training
   - 15% Validation (hyperparameter search & threshold calibration)
   - 15% Frozen Test Set (used solely for final report generation; never seen during tuning)
3. **Seed Control:** `random_state=42` throughout all splits and model training.
4. **Artifact Checksums:** Generated artifacts (`model.joblib`, `vectorizer.joblib`, `feature_schema.json`) are hashed with SHA-256 and committed with metadata.
