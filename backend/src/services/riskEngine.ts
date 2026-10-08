import crypto from 'crypto';
import { EvidenceItem, RiskLevel, UncertaintyLevel, UnifiedRiskResult, DetectorSummary } from '../types/evidence.js';
import { generateExplanationsAndActions } from './explanationEngine.js';

export function calculateRiskScore(evidence: EvidenceItem[]): {
  score: number;
  hasCritical: boolean;
  highCount: number;
  mediumCount: number;
  lowCount: number;
} {
  if (!evidence || evidence.length === 0) {
    return { score: 0, hasCritical: false, highCount: 0, mediumCount: 0, lowCount: 0 };
  }

  let accumulatedScore = 5; // Clean baseline
  let hasCritical = false;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const item of evidence) {
    const weight = typeof item.confidence === 'number' ? Math.max(0.1, Math.min(1.0, item.confidence)) : 0.8;
    
    // QR metadata should not inflate security risk
    if (item.source === 'qr_decoder' && item.category === 'metadata') {
      continue;
    }

    switch (item.severity) {
      case 'critical':
        accumulatedScore += 45 * weight;
        hasCritical = true;
        break;
      case 'high':
        accumulatedScore += 28 * weight;
        highCount++;
        break;
      case 'medium':
        accumulatedScore += 15 * weight;
        mediumCount++;
        break;
      case 'low':
        accumulatedScore -= 6 * weight;
        lowCount++;
        break;
    }
  }

  const boundedScore = Math.max(0, Math.min(100, Math.round(accumulatedScore)));
  return { score: boundedScore, hasCritical, highCount, mediumCount, lowCount };
}

export function determineRiskLevel(
  rawScore: number,
  hasCritical: boolean,
  highCount: number,
  mediumCount: number
): { riskLevel: RiskLevel; finalScore: number } {
  let riskLevel: RiskLevel;
  let finalScore = rawScore;

  if (hasCritical || finalScore >= 80) {
    riskLevel = 'CRITICAL';
    finalScore = Math.max(85, finalScore);
  } else if (finalScore >= 50 || highCount >= 2) {
    riskLevel = 'HIGH';
    finalScore = Math.max(60, finalScore);
  } else if (finalScore >= 20 || mediumCount >= 1 || highCount === 1) {
    riskLevel = 'MEDIUM';
    finalScore = Math.max(25, Math.min(49, finalScore));
  } else {
    riskLevel = 'LOW';
    finalScore = Math.min(15, finalScore);
  }

  return { riskLevel, finalScore };
}

export function determineUncertainty(
  evidence: EvidenceItem[],
  riskLevel: RiskLevel,
  lowCount: number,
  highCount: number,
  hasCritical: boolean,
  detectorsUsed: DetectorSummary[] = []
): UncertaintyLevel {
  const totalSignals = evidence.filter(e => !(e.source === 'qr_decoder' && e.category === 'metadata')).length;

  if (totalSignals === 0 || riskLevel === 'INSUFFICIENT_EVIDENCE') {
    return 'HIGH';
  }

  // Check if any detector encountered an error/unavailable status
  const hasUnavailableDetector = detectorsUsed.some(d => d.status === 'unavailable' || d.status === 'error');
  if (hasUnavailableDetector && riskLevel !== 'CRITICAL') {
    return 'HIGH';
  }

  // Conflicting signals: strong positive threat + strong negative benign signal
  if (lowCount > 0 && (highCount > 0 || hasCritical)) {
    return 'MEDIUM';
  }

  // Multiple independent agreeing detectors
  if (totalSignals >= 2 && (riskLevel === 'CRITICAL' || riskLevel === 'HIGH')) {
    return 'LOW';
  }

  if (totalSignals >= 1 && riskLevel === 'LOW') {
    return 'LOW';
  }

  if (totalSignals <= 1 && riskLevel === 'MEDIUM') {
    return 'MEDIUM';
  }

  return 'LOW';
}

export function calculateUnifiedRisk(
  evidence: EvidenceItem[],
  modelVersions: string[],
  detectorsUsed: DetectorSummary[] = [],
  analysisId?: string
): UnifiedRiskResult {
  const deterministicId = analysisId || `ana_${crypto.createHash('sha256').update(JSON.stringify(evidence) + Date.now().toString()).digest('hex').substring(0, 16)}`;
  const now = new Date().toISOString();

  if (!evidence || evidence.length === 0) {
    return {
      risk_level: 'INSUFFICIENT_EVIDENCE',
      risk_score: 0,
      uncertainty: 'HIGH',
      verdict: 'INSUFFICIENT_EVIDENCE',
      summary: 'Insufficient evidence was collected to establish a reliable risk rating.',
      reasons: ['No conclusive heuristic or machine learning signals were extracted from the submitted input.'],
      evidence: [],
      model_versions: modelVersions,
      detectors_used: detectorsUsed,
      recommended_actions: ['Exercise caution and verify the destination or message source through independent channels.'],
      limitations: ['Analysis failed or returned insufficient signal payload.'],
      generated_at: now,
      analysis_id: deterministicId
    };
  }

  const { score, hasCritical, highCount, mediumCount, lowCount } = calculateRiskScore(evidence);
  const { riskLevel, finalScore } = determineRiskLevel(score, hasCritical, highCount, mediumCount);
  const uncertainty = determineUncertainty(evidence, riskLevel, lowCount, highCount, hasCritical, detectorsUsed);

  let verdict: 'LIKELY_SAFE' | 'SUSPICIOUS' | 'LIKELY_SCAM' | 'HIGH_RISK' | 'INSUFFICIENT_EVIDENCE';
  switch (riskLevel) {
    case 'CRITICAL':
      verdict = 'HIGH_RISK';
      break;
    case 'HIGH':
      verdict = 'LIKELY_SCAM';
      break;
    case 'MEDIUM':
      verdict = 'SUSPICIOUS';
      break;
    case 'LOW':
      verdict = 'LIKELY_SAFE';
      break;
    default:
      verdict = 'INSUFFICIENT_EVIDENCE';
  }

  const { summary, reasons, actions, limitations } = generateExplanationsAndActions(
    riskLevel,
    finalScore,
    evidence,
    modelVersions
  );

  return {
    risk_level: riskLevel,
    risk_score: finalScore,
    uncertainty,
    verdict,
    summary,
    reasons,
    evidence,
    model_versions: modelVersions,
    detectors_used: detectorsUsed,
    recommended_actions: actions,
    limitations,
    generated_at: now,
    analysis_id: deterministicId
  };
}
