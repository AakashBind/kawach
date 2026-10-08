import { EvidenceItem, RiskLevel, UncertaintyLevel } from './evidence.js';

export type ScanType = 'url' | 'message' | 'qr' | 'website';

export interface ScanRecord {
  id: string;
  user_id: string | null;
  scan_type: ScanType;
  input_hash: string;
  input_target: string;
  risk_level: RiskLevel;
  risk_score: number;
  uncertainty: UncertaintyLevel;
  model_versions: string; // JSON string array
  raw_summary: string | null;
  created_at: string;
}

export interface UserRecord {
  id: string;
  email: string;
  password_hash: string;
  role: string;
  created_at: string;
}

export interface ReportRecord {
  id: string;
  user_id: string | null;
  scan_id: string | null;
  category: string;
  description: string;
  status: 'submitted' | 'under_review' | 'resolved';
  evidence_summary: string | null;
  created_at: string;
}

export interface FeedbackRecord {
  id: string;
  scan_id: string;
  feedback_type: 'false_positive' | 'false_negative' | 'correct';
  user_comments: string | null;
  created_at: string;
}

export interface ModelMetadataRecord {
  id: string;
  model_id: string;
  version: string;
  dataset_version: string;
  artifact_hash: string;
  metrics: string; // JSON string
  is_active: number;
  created_at: string;
}
