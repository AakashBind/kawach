CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    scan_type TEXT NOT NULL, -- 'url' | 'message' | 'qr' | 'website'
    input_hash TEXT NOT NULL,
    input_target TEXT NOT NULL,
    risk_level TEXT NOT NULL, -- 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INSUFFICIENT_EVIDENCE'
    risk_score INTEGER NOT NULL,
    uncertainty TEXT NOT NULL, -- 'LOW' | 'MEDIUM' | 'HIGH'
    model_versions TEXT NOT NULL, -- JSON array
    raw_summary TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    signal_id TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'low' | 'medium' | 'high' | 'critical'
    confidence REAL NOT NULL,
    explanation TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    raw_details TEXT, -- JSON
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    scan_id TEXT,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'submitted',
    evidence_summary TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS feedback (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    feedback_type TEXT NOT NULL, -- 'false_positive' | 'false_negative' | 'correct'
    user_comments TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS model_metadata (
    id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL,
    version TEXT NOT NULL,
    dataset_version TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    metrics TEXT NOT NULL, -- JSON
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_id TEXT,
    event_type TEXT NOT NULL,
    ip_hash TEXT,
    payload TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_scan_id ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_feedback_scan_id ON feedback(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id);
