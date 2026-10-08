# Error Handling & Resilience Specification
# PS5 — AI Scam & Phishing Detection Platform

## 1. Unified Error Contract

All error responses across all REST API endpoints conform strictly to the following JSON structure:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_INPUT | SSRF_BLOCKED | MODEL_UNAVAILABLE | FILE_TOO_LARGE | UNSUPPORTED_MEDIA | UNAUTHORIZED | FORBIDDEN | RATE_LIMIT_EXCEEDED | INTERNAL_ERROR",
    "message": "Human-readable safe explanation without sensitive stack traces",
    "request_id": "req_84f93a102b",
    "timestamp": "2026-10-03T18:30:00.000Z",
    "details": []
  }
}
```

## 2. Failure Handling Rules
1. **Model Service Down / Unreachable:**
   - Fallback gracefully: The backend marks the ML evidence as `unavailable` or `insufficient_evidence`.
   - The unified risk engine elevates the `uncertainty` level to `HIGH` and warns the user rather than inventing a mock prediction.
2. **SSRF Target Blocked:**
   - Immediately reject request with HTTP 400 (`SSRF_BLOCKED`) and log security audit event.
3. **QR Decode Failure (Blurry / Non-QR image):**
   - Return clean 422 with explanation "Unable to locate or decode valid QR matrix in the submitted image. Please ensure good lighting and contrast."
4. **Website Timeout / DNS Failure:**
   - Return 200 with `website_analyzer` evidence noting `site_unreachable_or_timed_out` with neutral score impact and medium uncertainty.
