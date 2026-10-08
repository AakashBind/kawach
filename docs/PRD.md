# Product Requirements Document (PRD)
# PS5 — AI Scam & Phishing Detection Platform (V1 Web Application)

**Document Type:** Production-oriented Master PRD / Implementation Contract  
**Scope:** V1 Web Application (Level 2 Multimodal Detection)  
**Status:** Approved Engineering Source of Truth  
**Target Delivery:** Genuinely functional, zero-cost, end-to-end production-quality security web platform.

---

## 1. Executive Summary
The AI Scam & Phishing Detection Platform is an intelligent, multi-layered cybersecurity system designed to protect everyday internet users, enterprise employees, and digital consumers from rapidly evolving phishing attacks, social engineering ploys, malicious QR codes, and fraudulent websites.

Unlike superficial scanners that provide binary or fabricated verdicts, this platform combines:
1. **Real Supervised Machine Learning** (trained tabular URL phishing models & NLP scam-intent classifiers).
2. **Deterministic Security Signal Analyzers** (lexical analysis, IP-host detection, encoding anomalies, form harvesting inspection).
3. **Defensive Website Analysis** (sandboxed HTTP fetching with strict SSRF controls, DOM/form extraction without script execution).
4. **QR Code Safe Decoding & Payload Routing**.
5. **A Unified Versioned Risk Engine** that synthesizes multi-source evidence into an explainable risk assessment (LOW, MEDIUM, HIGH, CRITICAL, INSUFFICIENT_EVIDENCE) accompanied by calibrated confidence, uncertainty metrics, and actionable remediation steps.

---

## 2. Product Vision & Principles
- **Genuine AI / Real ML:** Never hardcode predictions or simulate AI with keywords. Predictions must originate from traceable, trained model artifacts.
- **Multimodal by Design:** Support URL, Email/Message, QR Code, and Website scanning in a unified interface.
- **Explainability First:** Always communicate *why* a verdict was reached. Separate raw evidence from synthesized conclusions.
- **Zero-Cost Development:** Built entirely on open-source libraries, free public datasets with permissible licenses (CC BY 4.0), and local execution without paid external API lock-in.
- **Security & Privacy by Design:** Data minimization, zero credential storage, strict SSRF defenses, robust input validation, and clear authorization boundaries.

---

## 3. Target User Personas & Workflows

### 3.1 General Consumers & Students
- **Goal:** Quickly verify suspicious SMS messages, emails, UPI/payment links, or QR codes received on social media/chat apps.
- **Workflow:** Paste message or URL / upload QR -> Instant scan -> Plain-language explanation + clear action guidance (e.g., "Do not enter passwords").

### 3.2 Enterprise Employees & IT Security Teams
- **Goal:** Inspect suspicious links or phishing lure emails before clicking or reporting to SOC.
- **Workflow:** Paste full email text with headers -> Comprehensive multi-signal evidence breakdown -> Export shareable fraud report.

### 3.3 Security Auditors & Model Reviewers
- **Goal:** Verify system integrity, review model provenance, check confusion matrices, evaluate datasets, and verify anti-fake-AI controls.
- **Workflow:** Open Model Governance Dashboard -> Inspect model cards, live evaluation metrics, SHA-256 hashes, and dataset manifests.

---

## 4. Functional Requirements (P0 - Mandatory Level 2 Scope)

| Feature ID | Feature Name | Description | Priority |
|---|---|---|---|
| **FR-01** | Unified Multi-Scanner UI | Tabbed/segmented interface supporting URL, Email/Message, QR Image, and Website targets. | P0 |
| **FR-02** | Real ML URL Phishing Classifier | Feature extraction (30+ lexical, host, structural features) + trained model inference. | P0 |
| **FR-03** | Real NLP Scam/Intent Classifier | Text preprocessing, entity extraction (monetary, urgency, credential triggers), and intent scoring. | P0 |
| **FR-04** | QR Code Analyzer | Safe image upload, magic byte validation, dimension limits, payload decoding, and recursive URL routing. | P0 |
| **FR-05** | Defensive Website Analyzer | SSRF-safe HTTP request, response limits, HTML parsing, login/payment form detection, redirect inspection. | P0 |
| **FR-06** | Unified Risk Engine | Structured evidence ingestion, deterministic rule combination, uncertainty computation, risk level (LOW/MED/HIGH/CRITICAL/INSUFFICIENT_EVIDENCE). | P0 |
| **FR-07** | Explainable Evidence Engine | Ranked reasons, human-readable evidence cards, mapped signal IDs, model version transparency. | P0 |
| **FR-08** | Scan History & Deletion | Persisted history for authenticated/guest sessions with search, filter, and privacy deletion. | P0 |
| **FR-09** | Structured Fraud Reporting | Exportable/submittable fraud incident reports linked to scan evidence. | P0 |
| **FR-10** | Feedback & Ground Truth Loop | User false-positive / false-negative reporting stored in separate audit tables (no unvalidated auto-retraining). | P0 |
| **FR-11** | Model Governance & Audit View | Publicly accessible model card, reproducible metrics, confusion matrix, dataset provenance viewer. | P0 |
| **FR-12** | Authentication & Account Security | Argon2/bcrypt password hashing, JWT/session security, rate limiting, and IDOR protection. | P0 |

---

## 5. Non-Goals (V1 Out of Scope)
- No operating system-level kernel drivers or real-time packet filtering.
- No headless browser JavaScript execution (defensive HTTP parsing only to prevent client-side exploits).
- No paid threat intelligence API dependencies (VirusTotal, Shodan, etc.).
- No automatic submission of user credentials into third-party sites.
