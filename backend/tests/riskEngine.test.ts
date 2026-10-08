import { calculateUnifiedRisk } from '../src/services/riskEngine';
import { EvidenceItem } from '../src/types/evidence';

describe('Unified Risk Engine Tests', () => {
  test('should return INSUFFICIENT_EVIDENCE when no evidence provided', () => {
    const result = calculateUnifiedRisk([], ['url-model-1.0.0']);
    expect(result.risk_level).toBe('INSUFFICIENT_EVIDENCE');
    expect(result.uncertainty).toBe('HIGH');
  });

  test('should compute CRITICAL risk when critical evidence is present', () => {
    const evidence: EvidenceItem[] = [
      {
        signal_id: 'website.form.mismatched_action_target',
        source: 'website_analyzer',
        category: 'credential_theft',
        severity: 'critical',
        confidence: 0.95,
        explanation: 'Form submits credentials to evil external host',
        detector_version: 'website-1.0.0'
      }
    ];

    const result = calculateUnifiedRisk(evidence, ['website-1.0.0']);
    expect(result.risk_level).toBe('CRITICAL');
    expect(result.risk_score).toBeGreaterThanOrEqual(85);
    expect(result.reasons.length).toBeGreaterThan(0);
    expect(result.recommended_actions.length).toBeGreaterThan(0);
  });

  test('should compute LOW risk when only benign low-severity evidence is present', () => {
    const evidence: EvidenceItem[] = [
      {
        signal_id: 'url.ml.benign_prediction',
        source: 'url_ml_service',
        category: 'machine_learning',
        severity: 'low',
        confidence: 0.98,
        explanation: 'ML classified URL features as benign',
        detector_version: 'url-phishing-1.0.0'
      }
    ];

    const result = calculateUnifiedRisk(evidence, ['url-phishing-1.0.0']);
    expect(result.risk_level).toBe('LOW');
    expect(result.risk_score).toBeLessThanOrEqual(25);
  });
});
