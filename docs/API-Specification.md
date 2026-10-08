# REST API Specification (v1)
# PS5 — AI Scam & Phishing Detection Platform

Base URL: `/api/v1`  
Protocol: `HTTPS / JSON`  
Authentication: `Bearer <JWT>` in `Authorization` header for protected routes.

---

## 1. Authentication Endpoints

### 1.1 Register User
- **Method:** `POST /api/v1/auth/register`
- **Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```
- **Response `201 Created`:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "usr_94a73e8f",
      "email": "user@example.com",
      "role": "user"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### 1.2 Login User
- **Method:** `POST /api/v1/auth/login`
- **Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```
- **Response `200 OK`:**
```json
{
  "success": true,
  "data": {
    "user": { "id": "usr_94a73e8f", "email": "user@example.com", "role": "user" },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### 1.3 Current User Info
- **Method:** `GET /api/v1/auth/me` (Protected)
- **Response `200 OK`:** Returns authenticated user profile.

---

## 2. Scan Endpoints (Core Multimodal Analyzers)

### 2.1 Scan URL
- **Method:** `POST /api/v1/scans/url`
- **Request Body:**
```json
{
  "url": "http://paypal-verification-alert99.tk/login.php"
}
```
- **Response `200 OK`:**
```json
{
  "success": true,
  "data": {
    "scan_id": "scn_5091aefc",
    "scan_type": "url",
    "target": "http://paypal-verification-alert99.tk/login.php",
    "risk_level": "HIGH",
    "risk_score": 88,
    "uncertainty": "LOW",
    "summary": "High risk phishing indicators detected including brand spoofing tokens and high ML model classification.",
    "reasons": [
      "URL lexical structure matches known phishing patterns with 94.2% confidence",
      "Brand token 'paypal' present in unverified third-level subdomain",
      "Suspicious high-risk TLD (.tk) commonly associated with malicious campaigns"
    ],
    "evidence": [
      {
        "signal_id": "url.ml.phishing_prediction",
        "source": "url_ml_service",
        "category": "machine_learning",
        "severity": "high",
        "confidence": 0.942,
        "explanation": "Supervised tabular Random Forest model classified URL features as phishing",
        "detector_version": "url-phishing-1.0.0"
      },
      {
        "signal_id": "url.lexical.brand_mismatch",
        "source": "heuristic_url_analyzer",
        "category": "impersonation",
        "severity": "high",
        "confidence": 0.89,
        "explanation": "Target brand token 'paypal' in unverified hostname",
        "detector_version": "url-heuristic-1.0.0"
      }
    ],
    "model_versions": ["url-phishing-1.0.0"],
    "created_at": "2026-10-03T18:30:00.000Z"
  }
}
```

### 2.2 Scan Email / Message
- **Method:** `POST /api/v1/scans/message`
- **Request Body:**
```json
{
  "message": "URGENT: Your bank account will be suspended within 24 hours. Update your PIN now at http://secure-bank-login.xyz or send $500 fine via UPI.",
  "context": "sms"
}
```
- **Response `200 OK`:** Returns aggregated NLP scam intent classification, extracted entities (monetary, urgency, links), and sub-URL analysis.

### 2.3 Scan QR Code
- **Method:** `POST /api/v1/scans/qr`
- **Content-Type:** `multipart/form-data`
- **Form Field:** `image` (PNG, JPG, WebP max 5MB)
- **Response `200 OK`:** Returns decoded payload, payload type (URL, raw text, wifi, vcard), and subsequent URL scan if payload is a link.

### 2.4 Scan Website (Defensive HTTP Analyzer)
- **Method:** `POST /api/v1/scans/website`
- **Request Body:**
```json
{
  "url": "https://example.com"
}
```
- **Response `200 OK`:** Returns SSRF-safe page analysis, HTML title, meta tags, password/payment forms detected, external action endpoints, and URL risk assessment.

---

## 3. History & Deletion

- `GET /api/v1/scans`: List past scans (paginated, query filters for `type`, `risk_level`, `search`).
- `GET /api/v1/scans/:id`: Get full scan details and evidence list.
- `DELETE /api/v1/scans/:id`: Delete a specific scan.
- `DELETE /api/v1/scans`: Clear all user scans (Privacy control).

---

## 4. Fraud Reporting & Feedback

- `POST /api/v1/reports`: Submit an incident report linked to a scan.
- `GET /api/v1/reports`: List user reports.
- `POST /api/v1/feedback`: Submit FP/FN feedback (`scan_id`, `feedback_type`, `user_comments`).

---

## 5. Model Governance & Health

- `GET /api/v1/models`: Returns list of trained models, artifact hashes, dataset versions, real confusion matrix, precision, recall, F1, ROC-AUC.
- `GET /api/v1/health`: Returns API, database, and Python ML service health.
