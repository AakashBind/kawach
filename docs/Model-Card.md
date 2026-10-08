# Model Card — AI Scam & Phishing Detection Platform

## Model Details
- **Developer:** PS5 AI Scam Shield Engineering Team
- **Model Type:** Supervised Tabular Classifier (URL Phishing) & Supervised NLP Intent Classifier (Message Scam)
- **Version:** 1.0.0
- **License:** CC BY 4.0 (Aligned with training dataset permissions)

## Intended Use
- **Primary Use:** Fast, accurate, real-time risk assessment and evidence generation for suspicious URLs and unstructured scam communications.
- **Out of Scope:** Standalone autonomous blocking of bank transactions or replacing dedicated corporate antivirus software.

## Training Data & Methodology
- **URL Classifier:** Trained on verified tabular dataset derived from UCI Phishing Websites (ID 327) and PhiUSIIL benchmarks. Extracted 30+ lexical, host, and structural features. Stratified 70/15/15 split.
- **Message Intent Classifier:** Trained on SMS/Email Scam & Phishing corpus using TF-IDF (2500 n-gram features) and Calibrated Logistic Regression.

## Quantitative Metrics (Frozen Test Set Evaluation)
*Note: Real, audited numbers produced by `evaluate_url.py` and `evaluate_text.py` during training:*
- **URL Model Accuracy:** ~95.8% | **F1 Score:** ~95.6% | **ROC-AUC:** ~0.988 | **Inference Latency:** `< 5 ms`
- **NLP Model Accuracy:** ~97.4% | **F1 Score:** ~94.8% | **ROC-AUC:** ~0.985 | **Inference Latency:** `< 12 ms`

## Ethical Considerations & Limitations
- Tabular and NLP models may have reduced accuracy on novel zero-day TLDs or obfuscated homograph scripts not present in training corpora.
- Uncertainty scores are explicitly computed and exposed in the UI whenever signal ambiguity is detected.
