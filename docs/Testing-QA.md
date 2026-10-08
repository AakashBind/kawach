# Testing, Quality Assurance & Verification Plan
# PS5 — AI Scam & Phishing Detection Platform

## 1. Test Pyramid & Automation Strategy

1. **Python ML & Pipeline Tests (`pytest`):**
   - Feature extraction schema and deterministic consistency.
   - Leakage prevention (zero cross-partition URL or domain overlaps).
   - Artifact loading, model signature verification, inference latency `< 100ms`.
   - Frozen test fixture evaluations (positive phishing, negative legitimate).
2. **Backend Unit & Integration Tests (Jest / Vitest / Supertest):**
   - URL Normalization & Lexical parser tests.
   - SSRF Protection Unit Tests (blocking private IPs, IPv6 link-local, cloud metadata addresses, redirection attacks).
   - Risk Engine Aggregation & Uncertainty Calculation tests.
   - API Endpoint Contract tests (`/scans/url`, `/scans/message`, `/scans/qr`, `/scans/website`, `/reports`, `/feedback`).
   - Authentication, password hashing, and IDOR boundary tests.
3. **End-to-End Multimodal User Journey Scenarios:**
   - **Scenario A:** URL scan -> Real ML inference -> Evidence -> Risk Score & Reasons -> DB save -> UI display.
   - **Scenario B:** Scam message with embedded link -> Entity extraction -> NLP classifier -> Sub-URL scan -> Unified score.
   - **Scenario C:** QR code image upload -> In-memory decode -> Route URL to URL scanner -> UI result.
   - **Scenario D:** Website scan -> SSRF guard -> Fetch HTML -> Login form detection -> Mismatch analysis -> Result.
   - **Scenario E:** User submits False Positive feedback -> Verified persisted in feedback table without auto-retraining.
   - **Scenario F:** Adversarial/malformed inputs (SSRF attack, huge file, malicious scripts) -> Graceful safe error response.
