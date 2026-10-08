export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INSUFFICIENT_EVIDENCE';
export type UncertaintyLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type ScanType = 'url' | 'message' | 'qr' | 'website';

export interface EvidenceItem {
  id?: string;
  signal_id: string;
  source: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  explanation: string;
  detector_version: string;
  details?: Record<string, any>;
}

export interface ScanResultData {
  id?: string;
  scan_id: string;
  scan_type: ScanType;
  target: string;
  input_target?: string;
  raw_summary?: string | null;
  risk_level: RiskLevel;
  risk_score: number;
  uncertainty: UncertaintyLevel;
  summary: string;
  reasons: string[];
  evidence: EvidenceItem[];
  model_versions: string[] | string;
  recommended_actions: string[];
  generated_at: string;
  created_at?: string;
  analysis_id: string;
  entities?: any;
  sub_urls?: any[];
  page_title?: string;
  forms_detected?: number;
  password_fields?: number;
  payload_type?: string;
}

export interface User {
  id: string;
  email: string;
  role: string;
}

export interface ModelMetadata {
  model_id: string;
  version: string;
  dataset_version: string;
  artifact_hash: string;
  algorithm?: string;
  is_active?: boolean;
  training_samples?: number;
  validation_samples?: number;
  frozen_test_samples?: number;
  ood_samples?: number;
  vectorizer_hash?: string;
  feature_count?: string | number;
  evaluation_scope?: string;
  license_info?: string;
  full_metadata?: any;
  metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1_score?: number;
    roc_auc?: number;
    average_latency_ms?: number;
    confusion_matrix?: {
      true_negatives?: number;
      false_positives?: number;
      false_negatives?: number;
      true_positives?: number;
      tn?: number;
      fp?: number;
      fn?: number;
      tp?: number;
    };
  };
}

export interface DeterministicComponent {
  component_id: string;
  name: string;
  version: string;
  technology: string;
  type: string;
  ml_training: string;
  pipeline: string;
  status: string;
}

export interface GovernanceData {
  registered_models: ModelMetadata[];
  active_models: ModelMetadata[];
  archived_models: ModelMetadata[];
  deterministic_components: DeterministicComponent[];
  live_service_metadata: any[];
  governance_disclaimers: string[];
}

export interface FraudReport {
  id: string;
  user_id: string | null;
  scan_id: string | null;
  category: string;
  description: string;
  status: 'submitted' | 'under_review' | 'resolved';
  evidence_summary: string | null;
  created_at: string;
}
