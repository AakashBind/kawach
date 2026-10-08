import sqlite3
import json
import os

db_candidates = [
    'backend/data/scam_shield.db',
    'data/scam_shield.db',
    'backend/scam_shield.db'
]
db_path = None
for c in db_candidates:
    if os.path.exists(c):
        db_path = c
        break

print(f"Using DB path: {db_path}")

if db_path and os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    print("\n--- ALL SCANS IN DATABASE ---")
    cur.execute("SELECT id, scan_type, input_target, risk_level, risk_score, uncertainty, model_versions, raw_summary, created_at FROM scans ORDER BY created_at DESC")
    rows = cur.fetchall()
    print(f"Total scans count: {len(rows)}")
    for r in rows:
        print(f"\n[SCAN] ID: {r[0]}")
        print(f"  Type: {r[1]}")
        print(f"  Target: {r[2]}")
        print(f"  Risk Level: {r[3]} | Risk Score: {r[4]} | Uncertainty: {r[5]}")
        print(f"  Model Versions: {r[6]}")
        print(f"  Summary: {r[7]}")
        print(f"  Created At: {r[8]}")
        
        # Evidence
        cur.execute("SELECT id, signal_id, source, category, severity, confidence, explanation, detector_version, raw_details FROM evidence WHERE scan_id = ?", (r[0],))
        ev_rows = cur.fetchall()
        print(f"  Evidence ({len(ev_rows)} items):")
        for ev in ev_rows:
            print(f"    - [{ev[1]}] (sev: {ev[4]}, conf: {ev[5]}, det: {ev[7]}): {ev[6]}")
            if ev[8]:
                print(f"      Details: {ev[8]}")
else:
    print("Database file not found in candidate paths.")
