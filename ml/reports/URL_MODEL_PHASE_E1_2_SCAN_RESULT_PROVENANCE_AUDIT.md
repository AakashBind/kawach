# LIVE SCAN RESULT PROVENANCE & STALE V1 RESULT AUDIT REPORT (PHASE E.1.2)

## Executive Summary
A comprehensive read-only forensic audit was conducted to investigate why the browser `ResultPage` was displaying:
- **Risk Score**: `85 / 100`
- **Risk Level**: `CRITICAL`
- **ML score**: `99.6% phishing`
- **Detector Version**: `url-phishing-1.0.0`

for the Apna College deep course-player URL (`https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit`), whereas Phase E.1 / E.1.1 offline and test-client evaluations verified that the codebase on disk produces:
- **Calibrated Probability**: `0.000672` (`0.0672%`)
- **Risk Score**: `2 / 100` (`LOW`)
- **Detector Version**: `url-phishing-2.0.0`

### Root Cause Finding: **Category G — Stale Daemon Processes Running in Memory**
The divergence was caused by **stale background server processes (PID 6380 on Port 8000 and PID 18216 on Port 5000)** started at `00:08:27` (prior to Phase D retraining, D.1 audit, and E.1 integration). Because FastAPI loads model artifacts into memory once at process startup, PID 6380 has remained running with the initial in-memory **v1.0.0** model in RAM.

The codebase and model artifacts on disk are 100% correctly configured for **v2.0.0** (`b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156`).

---

## Observed Contradiction

| Dimension | Browser ResultPage / Live Port 5000 | Fresh Codebase on Disk (Phase E.1) |
| :--- | :--- | :--- |
| **Model Version** | `1.0.0` | `2.0.0` |
| **Detector Version** | `url-phishing-1.0.0` | `url-phishing-2.0.0` |
| **ML Score** | `0.9957` (99.6% phishing) | `0.000672` (0.067% phishing) |
| **Platform Risk Score** | `85 / 100` | `2 / 100` |
| **Risk Level** | `CRITICAL` | `LOW` |
| **Executive Verdict** | `PHISHING` | `LEGITIMATE` |

---

## Process & Network Port Audit

A live process inspection of TCP listening ports on the operating system revealed:

| Port | Bound Process | Process Name | PID | Start Time (Local) | Current Memory State |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **8000** | `127.0.0.1:8000` | `python.exe` (FastAPI ML Service) | `6380` | `04-10-2026 00:08:27` | **STALE (Holding v1.0.0 in RAM)** |
| **5000** | `[::]:5000` | `node.exe` (Express Backend) | `18216` | `04-10-2026 00:08:42` | **STALE (Holding old handlers)** |
| **5173** | `[::1]:5173` | `node.exe` (Vite Frontend Dev) | `18028` | `04-10-2026 00:08:51` | Active Dev Server |

### Live Port Query Output
A live HTTP POST request dispatched to `http://127.0.0.1:8000/inference/url` (PID 6380) returned:
```json
{
  "model_id": "url-phishing",
  "model_version": "1.0.0",
  "detector_version": "url-detector-1.0.0",
  "score": 0.9957,
  "calibrated": true,
  "predicted_class": "phishing"
}
```
This proves that PID 6380 was launched before Phase D retraining and was never recycled to reload the updated `ml/models/url_phishing/model.joblib` artifact from disk.

---

## Frontend, API & ResultPage Trace

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant Vite as Vite Proxy (:5173 / PID 18028)
    participant Backend as Express Backend (:5000 / PID 18216)
    participant ML as ML Service (:8000 / PID 6380)
    participant DB as SQLite (scam_shield.db)

    User->>Vite: POST /api/v1/scans/url (Apna College URL)
    Vite->>Backend: Proxy POST /api/v1/scans/url
    Backend->>ML: POST http://127.0.0.1:8000/inference/url
    Note over ML: Stale Process PID 6380<br/>(Holding v1.0.0 in RAM)
    ML-->>Backend: score: 0.9957, model_version: "1.0.0"
    Note over Backend: Risk Engine computes 85 / CRITICAL
    Backend->>DB: INSERT scan ana_musuey22_egxc2 (v1.0.0, 85, CRITICAL)
    Backend-->>Vite: { success: true, data: { risk_score: 85, risk_level: "CRITICAL", model_versions: ["url-phishing-1.0.0"] } }
    Vite-->>User: Renders ResultPage with 85/100, CRITICAL, url-phishing-1.0.0
```

---

## POST Response vs GET Response Comparison

| Field | POST Response (`/api/v1/scans/url` on Port 5000) | GET Response (`/api/v1/scans/:id` on Port 5000) | Identical? |
| :--- | :--- | :--- | :--- |
| **Scan ID** | `ana_musuey22_egxc2` | `ana_musuey22_egxc2` | YES |
| **Model Version** | `["url-phishing-1.0.0"]` | `["url-phishing-1.0.0"]` | YES |
| **Detector Version** | `url-phishing-1.0.0` | `url-phishing-1.0.0` | YES |
| **Calibrated Prob / Score** | `0.9957` | `0.9957` | YES |
| **Predicted Class** | `phishing` | `phishing` | YES |
| **Risk Score** | `85` | `85` | YES |
| **Risk Level** | `CRITICAL` | `CRITICAL` | YES |
| **Evidence Signal** | `url.ml.phishing_prediction` | `url.ml.phishing_prediction` | YES |

The POST and GET endpoints are 100% consistent with each other. Both faithfully transmit the data emitted by the running in-memory process PID 6380.

---

## Database Record Trace (SQLite: `scam_shield.db`)

Inspecting the database confirmed:
1. `ana_musuey22_egxc2` (persisted at 2026-10-03 20:26:58 via live Port 5000) stored `["url-phishing-1.0.0"]`, `score: 85`, `CRITICAL`.
2. Scans generated during automated tests (where test runners instantiated fresh in-process Python/Node runtimes) stored `["url-phishing-2.0.0"]`, `score: 2`, `LOW`.

---

## V1 Reference Audit in Source Files

Every occurrence of `url-phishing-1.0.0` or `v1.0.0` was classified:
- **`ml/models/url_phishing/v1.0.0/`**: Immutable historical benchmark archive (Category A — ACCEPTABLE).
- **`ml/tests/test_url_model_v2.py`**: Regression baseline test fixture (Category B — ACCEPTABLE).
- **`backend/src/services/urlAnalyzer.ts`**: Dynamic string `url-phishing-${mlRes.model_version}` based on ML service response (Category D/E — Resolved on disk to v2.0.0).
- **`ml/service/app.py`**: Configured to load v2.0.0 with SHA-256 validation (Category D — Verified on disk).

There are **zero hardcoded v1.0.0 strings** or mock fallbacks forcing the result.

---

## Exact Point of Divergence

The point of divergence is **Process State Memory vs Disk State**:
- **Disk State**: `ml/models/url_phishing/model.joblib` is SHA-256 `b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156` (v2.0.0).
- **Live Memory State**: `python.exe` (PID 6380) running since `00:08:27` holds the old model instance loaded before v2.0.0 was trained.

---

## Root Cause Classification

# **Category G — Duplicate / Stale Background Service Processes Running in Memory**

---

## Severity & Recommended Fix

### Severity: **Operational / Process Management (Low architectural risk; Zero model risk)**
The ML model v2.0.0, risk engine, backend code, and frontend code on disk are fully functional, verified, and passing all automated test suites.

### Recommended Fix (To be executed when instructed):
1. Gracefully terminate stale background server processes:
   - Terminate PID 6380 (stale Python ML service on port 8000).
   - Terminate PID 18216 (stale Node backend service on port 5000).
2. Restart the ML microservice (`uvicorn ml.service.app:app --port 8000`) so it executes `load_artifacts()` and loads the verified v2.0.0 artifact.
3. Restart the Backend service (`npm run dev` or `node dist/server.js` on port 5000).
4. Re-run browser scan on `https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit` to confirm live browser rendering displays `2 / 100 LOW` with `url-phishing-2.0.0`.

---

## Final Governance Audit Summary

- **Models Retrained**: `0`
- **Models Modified**: `0`
- **Dataset Modified**: `0`
- **Risk Engine Modified**: `0`
- **Frontend Modified**: `0`
- **Backend Modified**: `0`
- **Database Modified**: `0`
- **Hardcoded Predictions Added**: `0`
- **Tests Removed / Disabled**: `0`
- **Security Controls Weakened**: `0`
- **Audit Status**: **COMPLETE — VERIFIED**
