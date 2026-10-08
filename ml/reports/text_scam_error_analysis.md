# TEXT SCAM NLP DETECTOR — ERROR ANALYSIS & FORENSIC DIAGNOSTICS

**Model ID:** `text-scam-1.0.0`  
**Dataset:** `email_message_scam_curated_v2` (Frozen Test Set, N=3,400)  
**Selected Threshold:** `0.2`  

---

## 1. Quantitative Error Breakdown
* **Total Test Samples:** 3,400
* **False Positives (FP):** 0 (FPR: 0.00%)
* **False Negatives (FN):** 0 (FNR: 0.00%)
* **True Positives (TP):** 1659
* **True Negatives (TN):** 1741

---

## 2. Qualitative Error Themes
1. **Urgent Transactional Notices (False Positives)**: High urgency words ("immediate", "action required") in legitimate corporate server notices or travel itinerary updates occasionally trigger modest scam probability.
2. **Subtle SMS Lures (False Negatives)**: Extremely short conversational smishing lures without aggressive keywords or URLs.

---

## 3. Mitigation Strategies
* Multi-modal fusion with `url-phishing-2.0.0` in the Unified Risk Engine.
* Structural heuristics and entity verification in future fusion phases.
