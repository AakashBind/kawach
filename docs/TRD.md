# Technical Requirements Document (TRD)
# PS5 — AI Scam & Phishing Detection Platform (V1 Web Application)

**Document Purpose:** Engineering implementation contract derived from the PS5 PRD.  
**Scope:** V1 Web Application only. Level 2 Multimodal Detection.  
**Constraint:** $0 development spend, reproducible ML pipelines, security-first architecture.

---

## 1. Technical Stack Overview

| Layer | Technology | Justification |
|---|---|---|
| **Frontend** | React 18 + Vite + TypeScript | High performance, strict type safety, modular architecture |
| **Styling & UI** | Tailwind CSS + Lucide Icons | Accessible, responsive, serious cybersecurity design system |
| **Backend API** | Node.js + Express + TypeScript | Lightweight, fast REST API orchestration, robust ecosystem |
| **ML & Inference** | Python 3.14 + FastAPI + scikit-learn + XGBoost | Industry standard for tabular & NLP inference, reproducible artifacts |
| **Database** | SQLite3 via Better-SQLite3 / Prisma-compatible SQL | Local relational consistency, zero-cost, ACID transactions, migrations |
| **QR Engine** | Node.js / Python QR parsing (safe decoding without execution) | Safe byte matrix decoding, payload normalization |
| **Testing** | Vitest / Jest + Supertest (Backend), Pytest (Python ML) | Fast unit, integration, SSRF, and ML fixture testing |

---

## 2. System Service Boundaries

1. **Frontend (Port 5173 / Production Build):**
   - Renders UI, validates client inputs, handles state, renders evidence cards and risk indicators.
   - Never makes security verdict decisions locally.
2. **Node.js API Gateway / Orchestrator (Port 5000):**
   - Handles client authentication, rate limiting, request validation, SSRF filtering, database persistence, fraud reporting, and orchestrates calls to the Python ML inference service.
3. **Python ML & Inference Service (Port 8000):**
   - Hosts the trained URL Phishing Classifier and Message Scam Intent Classifier.
   - Extracts 30+ URL features and NLP entities on demand.
   - Returns structured predictions, probability scores, and top feature contributions.
4. **Database (Local SQLite File / Storage):**
   - Persists user accounts, scan results, evidence items, fraud reports, feedback records, model metadata, and audit events.

---

## 3. Multimodal Analysis Pipelines

### 3.1 URL Request Lifecycle
`POST /api/v1/scans/url` -> Validate scheme & length -> SSRF security check -> Extract 30+ lexical/host features -> Call Python ML Service -> Evaluate deterministic heuristic signals (IP hostname, suspicious TLD, excessive subdomains) -> Evidence generation -> Unified Risk Engine -> DB persistence -> Formatted JSON response.

### 3.2 Email/Message Request Lifecycle
`POST /api/v1/scans/message` -> Validate length -> Text preprocessing -> Extract embedded URLs, phone numbers, crypto addresses, payment handles -> Run NLP scam-intent classifier -> Recursively analyze extracted URLs -> Aggregate evidence -> Unified Risk Engine -> Persist & return.

### 3.3 QR Code Request Lifecycle
`POST /api/v1/scans/qr` -> Validate MIME type & file size (max 5MB) -> Safe memory decoding -> Extract payload -> If URL: route to URL pipeline -> If text/other: sanitize & display payload metadata -> Persist & return.

### 3.4 Website Request Lifecycle
`POST /api/v1/scans/website` -> Validate URL -> SSRF DNS & IP checks (block loopback, RFC 1918, link-local) -> Safe HTTP fetch with 5s timeout & 2MB max response -> Parse HTML DOM -> Detect credential/payment forms, external form actions, brand vs domain mismatches -> URL ML inference -> Aggregate evidence -> Unified Risk Engine -> Persist & return.

---

## 4. Performance & Operational Targets
- URL ML Local Inference: `< 50 ms`
- Message NLP Inference: `< 100 ms`
- QR Image Safe Decode: `< 150 ms`
- Website SSRF-Safe Fetch & Parse: `< 2.5 s` (bounded by 5.0 s hard timeout)
- Overall Scan API Response: `< 300 ms` for URL/Message/QR; `< 3.0 s` for Website.
- Zero Memory Leaks during continuous scan runs.
