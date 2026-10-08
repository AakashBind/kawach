export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface EvidenceItem {
  id?: string;
  signal_id: string;
  source: string;
  category: string;
  severity: Severity;
  confidence: number;
  explanation: string;
  detector_version: string;
  details?: Record<string, any>;
}

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INSUFFICIENT_EVIDENCE';
export type UncertaintyLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export interface DetectorSummary {
  detector_id: string;
  detector_version: string;
  model_version: string;
  input_type: 'url' | 'message' | 'qr' | 'website';
  status: 'success' | 'insufficient_data' | 'unavailable' | 'error' | 'blocked_ssrf' | 'fetch_error' | 'timeout';
  calibrated_probability?: number;
  confidence?: number;
  latency_ms?: number;
}

export interface UnifiedRiskResult {
  risk_level: RiskLevel;
  risk_score: number; // 0 to 100
  uncertainty: UncertaintyLevel;
  verdict: 'LIKELY_SAFE' | 'SUSPICIOUS' | 'LIKELY_SCAM' | 'HIGH_RISK' | 'INSUFFICIENT_EVIDENCE';
  summary: string;
  reasons: string[];
  evidence: EvidenceItem[];
  model_versions: string[];
  detectors_used: DetectorSummary[];
  recommended_actions: string[];
  limitations: string[];
  generated_at: string;
  analysis_id: string;
}
