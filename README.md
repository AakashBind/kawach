# PS5 — AI Scam & Phishing Detection Platform

A Level 2 multimodal cybersecurity web application that detects phishing URLs, deceptive SMS/email lures, malicious QR codes, and fraudulent websites.

---

## 🚀 Key Architectural Features
- **Supervised Machine Learning:** 
  - URL Phishing Tabular Classifier (trained XGBoost with 31 lexical & structural dimensions).
  - Message Scam & Social Engineering Classifier (NLP TF-IDF + Calibrated Classifier).
  - Frozen test set evaluation metrics with SHA-256 cryptographic provenance.
- **Multimodal Analyzers:**
  - **URL Scanner:** Lexical, IP-host, TLD risk, and subdomain depth extraction.
  - **Message/Email Scanner:** Natural language intent, artificial urgency cues, payment requests, and recursive embedded link auditing.
  - **QR Code Scanner:** In-memory byte decoding, MIME/dimension validation, and payload routing.
  - **Website Crawler:** SSRF-shielded HTTP inspection detecting credential harvesting forms, third-party submission targets, and page title brand spoofing.
- **Unified Risk & Explanation Engine:**
  - Standardized evidence contract across all detectors.
  - Calibrated 0–100 Product Risk Score and Risk Level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `INSUFFICIENT_EVIDENCE`).
  - Uncertainty Quantification (`LOW`, `MEDIUM`, `HIGH`).
  - Actionable security guidance and ranked evidence breakdown.
- **Security & Privacy by Design:**
  - Strict SSRF protection (blocking RFC 1918, link-local, cloud metadata, IPv6 loopback, and DNS rebinding).
  - Role-based data isolation for authenticated reports and scan history.
  - IP-based rate limiting, strict CORS, Helmet security headers.

---

## 📁 Repository Structure
```
ps5-scam-shield/
├── backend/                     # Node.js + Express + TypeScript API Gateway (Port 5000)
│   ├── data/                    # SQLite database directory (auto-created on startup)
│   ├── src/
│   │   ├── database/            # SQLite schema, WAL mode, migrations
│   │   ├── middleware/          # JWT auth, SSRF guards, rate limiters, error handling
│   │   ├── services/            # URL, Message, QR, Website analyzers & Unified Risk Engine
│   │   └── routes/              # REST v1 endpoints (/scans, /reports, /feedback, /models)
│   └── tests/                   # Jest + Supertest test suite (112 tests)
├── frontend/                    # React 18 + Vite + TypeScript + Tailwind CSS SPA (Port 5173)
│   ├── src/
│   │   ├── components/          # RiskGauge, RiskBadge, EvidenceCard, CyberBackground, Modals
│   │   ├── pages/               # Scanner, Result, History, Reports, Models, Education, Auth
│   │   └── services/            # API client & auth session management
│   └── vite.config.ts           # Configured with host: true for LAN / mobile testing
├── ml/                          # Machine Learning Pipelines & FastAPI Microservice (Port 8000)
│   ├── datasets/                # Manifests, raw and processed dataset splits
│   ├── features/                # 31 URL feature extractors, entity & text normalizers
│   ├── models/                  # Serialized artifacts (model.joblib, metadata, checksums)
│   ├── service/                 # FastAPI inference service
│   └── tests/                   # Pytest automated test suite
├── docs/                        # Architecture, PRD, and Mobile Audit Documentation
├── requirements.txt             # Python ML requirements
├── package.json                 # Root workspace scripts
└── .gitignore                   # Comprehensive gitignore
```

---

## 🛠️ Step-by-Step Quick Start Guide (For Any Cloned Environment)

### 1. Prerequisites
- **Node.js**: v18+ (tested on Node v20/v22)
- **Python**: 3.10+ (tested on Python 3.10–3.14)
- **Git**

---

### 2. Fast Setup (From Root)

#### Step A: Install All Node Dependencies
```bash
npm run install:all
```
*(Or install individually: `cd backend && npm install`, then `cd ../frontend && npm install`)*

#### Step B: Install Python ML Dependencies
```bash
pip install -r requirements.txt
```

#### Step C: Environment Configuration (Optional)
The backend comes pre-configured with default fallbacks. To customize:
```bash
cp .env.example .env
```

---

### 3. Running the Services

You can run the three services in separate terminals:

#### Terminal 1 — Python ML Service (Port 8000)
```bash
uvicorn ml.service.app:app --host 127.0.0.1 --port 8000 --reload
```
*(Or from root: `npm run dev:ml`)*

#### Terminal 2 — Backend API Gateway (Port 5000)
```bash
npm run dev:backend
```
*(Or `cd backend && npm run dev`)*
> Note: The backend will automatically initialize the SQLite database and seed model metadata on its first start.

#### Terminal 3 — Frontend Web Application (Port 5173)
```bash
npm run dev:frontend
```
*(Or `cd frontend && npm run dev`)*

Open your browser at **`http://localhost:5173`** (or access from your mobile phone via your local network IP `http://<your-ip>:5173`).

---

### 4. Running Automated Tests

#### Backend Test Suite (112 Tests)
```bash
npm run test:backend
```
*(Or `cd backend && npm test`)*

#### Python ML Test Suite
```bash
pytest ml/tests
```

---

## 🧪 Quick Test Scenarios to Try
1. **Phishing URL Scan:** Paste `http://192.168.1.1/paypal-account-verification-alert99.tk/login.php` -> Flags **CRITICAL** risk with lexical, IP-host, and ML model evidence.
2. **Benign URL Scan:** Paste `https://www.google.com` -> Flags **LOW** risk with calibrated benign confidence.
3. **Scam SMS/Email Scan:** Paste *"URGENT: Your Wells Fargo account has been suspended! Verify your credentials immediately at http://wellsfargo-verify-login.xyz"* -> Flags **HIGH/CRITICAL** risk with NLP intent & URL evidence.
4. **QR Code Scanner:** Upload any QR code image -> Decodes payload in-memory without server image storage.
5. **SSRF Guard Protection:** Scan `http://169.254.169.254/latest/meta-data/` or `http://127.0.0.1` -> Defensively blocks internal network access.
