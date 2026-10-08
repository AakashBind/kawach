import sqlite3
import json

db_path = 'backend/data/scam_shield.db'
conn = sqlite3.connect(db_path)
cur = conn.cursor()

print("=" * 80)
print("HISTORICAL SCANS FOR APNA COLLEGE IN DATABASE")
print("=" * 80)

cur.execute("SELECT id, input_target, risk_level, risk_score, model_versions, created_at FROM scans WHERE input_target LIKE '%apnacollege%' ORDER BY created_at DESC")
rows = cur.fetchall()
for r in rows:
    print(f"Scan ID: {r[0]} | Date: {r[5]} | Level: {r[2]} | Score: {r[3]} | Version: {r[4]}")
    print(f"  Target: {r[1]}")
    cur.execute("SELECT signal_id, confidence, detector_version, explanation, raw_details FROM evidence WHERE scan_id = ?", (r[0],))
    evs = cur.fetchall()
    for ev in evs:
        print(f"    - Signal: {ev[0]} | Conf: {ev[1]} | Detector: {ev[2]}")
        print(f"      Explanation: {ev[3]}")
    print("-" * 80)
