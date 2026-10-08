# Architecture Design Document
# PS5 — AI Scam & Phishing Detection Platform

```
+-------------------------------------------------------------------------------+
|                             CLIENT BROWSER                                    |
|   React 18 + Vite + TypeScript + Tailwind CSS Single Page Application         |
|   - Modality Selector (URL / Message / QR / Website)                          |
|   - Unified Result Dashboard (Risk Gauge, Evidence Cards, Uncertainty View)    |
|   - Scan History, Fraud Reporting, Model Governance Dashboard                 |
+-------------------------------------------------------------------------------+
                                      |
                                      | HTTPS / REST JSON (/api/v1)
                                      v
+-------------------------------------------------------------------------------+
|                       NODE.JS / EXPRESS ORCHESTRATOR API                      |
|                                                                               |
|  [Security & Middleware]                                                      |
|   - Rate Limiter (express-rate-limit)                                         |
|   - Security Headers (Helmet, Strict CSP, CORS)                               |
|   - JWT & Argon2 Authentication & Authorization Guard                         |
|   - Zod Schema Validation & Safe File Upload Inspector                        |
|                                                                               |
|  [Core Domain Engines]                                                        |
|   - URL Analyzer (Lexical + Hostname + Deterministic Rules)                   |
|   - Message Analyzer (Entity Extractor + Sub-URL Dispatcher)                  |
|   - QR Analyzer (Safe Image Stream Decoder)                                   |
|   - Defensive Website Analyzer (SSRF-Safe Fetcher, HTML Form/DOM Inspector)   |
|   - Unified Risk Engine (Evidence Aggregation, Uncertainty Metric, Scoring)   |
|   - Explanation Engine (Signal ID -> Plain Language Taxonomy)                 |
+-------------------------------------------------------------------------------+
           |                                                      |
           | HTTP REST (Port 8000)                                | SQL / ACID
           v                                                      v
+------------------------------------+   +--------------------------------------+
|     PYTHON FASTAPI ML SERVICE      |   |          RELATIONAL DATABASE         |
|                                    |   |          (SQLite3 / PostgreSQL)      |
|  [Inference & Pipelines]           |   |                                      |
|   - 30+ URL Feature Extractor      |   |  - users (auth, roles)               |
|   - URL Phishing Model (v1.0.0)    |   |  - scans (metadata, scores, level)   |
|   - TF-IDF + NLP Intent Classifier |   |  - evidence (signals, source, value) |
|   - Model Metadata & Provenance    |   |  - reports (fraud submissions)       |
|   - Health & Version Telemetry     |   |  - feedback (FP/FN ground truth)     |
+------------------------------------+   |  - model_metadata (governance)       |
                                         |  - audit_events (security logs)      |
                                         +--------------------------------------+
```

## 1. Unified Evidence Contract
Every detector normalizes observations into a standardized Evidence item:
```json
{
  "signal_id": "website.form.credential_harvesting",
  "source": "website_analyzer",
  "category": "credential_collection",
  "severity": "high",
  "value": true,
  "confidence": 0.92,
  "explanation_key": "credential_form_detected",
  "detector_version": "website-1.0.0",
  "details": {
    "action_url": "http://evil-collector.com/login",
    "password_inputs": 1,
    "domain_mismatch": true
  }
}
```

## 2. Risk Engine Aggregation Logic
1. **Model Score Baseline:** URL model and NLP model outputs contribute to baseline risk points (0–100 scale).
2. **Deterministic Rules Modulation:**
   - IP-in-hostname: +25 points (HIGH severity)
   - Brand impersonation mismatch: +35 points (CRITICAL severity)
   - Uncredentialed password form over HTTP / mismatched target: +35 points
   - Urgency + Payment request in message: +25 points
   - Obfuscated/punycode domain: +20 points
3. **Uncertainty Quantification:**
   - Evaluates signal alignment vs contradiction.
   - Computes data completeness (e.g. if website unreachable, uncertainty increases).
4. **Risk Level Categorization:**
   - `0 - 24`: **LOW** (No significant threats detected)
   - `25 - 59`: **MEDIUM** (Elevated indicators, proceed with caution)
   - `60 - 84`: **HIGH** (Strong phishing/scam patterns, do not provide credentials)
   - `85 - 100`: **CRITICAL** (Active malicious attack confirmed by multiple signals)
   - Fallback: **INSUFFICIENT_EVIDENCE** if primary inputs cannot be parsed or analyzers fail.
