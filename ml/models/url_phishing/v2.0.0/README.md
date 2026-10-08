# URL Phishing Detection Model v2.0.0

- **Model ID:** `url-phishing`
- **Version:** `2.0.0`
- **Algorithm:** XGBoost Classifier (150 estimators, max_depth=6) with Sigmoid Probability Calibration
- **Training Dataset:** `url_phishing_curated_v2` (14214 samples)
- **Artifact SHA-256:** `b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156`
- **Frozen Test F1-Score:** `1.0`
- **OOD Benchmark Accuracy:** `0.95` (vs 64.0% for v1.0.0)
- **Apna College False Positive Resolution:** Successfully resolved (0.015 probability on deep LMS player)
