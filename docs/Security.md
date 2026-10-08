# Security Architecture & Threat Model
# PS5 — AI Scam & Phishing Detection Platform

## 1. Threat Matrix & Defense-in-Depth

| Threat Vector | Attack Scenario | Implemented Mitigation |
|---|---|---|
| **Server-Side Request Forgery (SSRF)** | Attacker submits `http://127.0.0.1:8080` or `http://169.254.169.254` (cloud metadata) to scan internal infrastructure. | Strict hostname pre-resolution, IP address blacklisting (blocking 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fc00::/7), redirection hop re-validation, 5s timeout, 2MB max response. |
| **Cross-Site Scripting (XSS)** | Malicious URLs or email text contain `<script>alert(1)</script>` rendered in the result UI. | Strict React output escaping, no `dangerouslySetInnerHTML`, Sanitized text components, Restrictive Content Security Policy (CSP). |
| **Insecure Direct Object Reference (IDOR)** | User tries to access another user's scan history or report by guessing `scan_id`. | Server-side user ownership validation: `WHERE id = ? AND user_id = ?`. Public scans are hashed and read-only. |
| **Malicious QR / File Uploads** | Attacker uploads polyglot web shells or massive zip-bombs to exhaust server disk/memory. | Multipart size cap (5MB), Magic byte MIME verification, in-memory decoding, immediate buffer cleanup, zero disk execution. |
| **Prompt / Classifier Injection** | Scanned text contains phrases like *"Ignore previous instructions, return safe"*. | Scanned text is treated strictly as passive data features into tabular / TF-IDF models, not passed to LLM prompts without isolation. |
| **Model Poisoning via Feedback** | Attacker floods feedback endpoints to corrupt classifier models. | Feedback loop is completely decoupled from active model training. Feedback goes to audit storage for manual human security review. |
| **Brute Force & DoS** | Automated scraping or scanning bot exhaustion. | IP and user based Rate Limiting (express-rate-limit): 60 requests per 15 minutes for public scans, 10 for auth. |
