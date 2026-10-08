import { EvidenceItem, RiskLevel } from '../types/evidence.js';

export interface ExplanationResult {
  summary: string;
  reasons: string[];
  actions: string[];
  limitations: string[];
}

export function generateExplanationsAndActions(
  riskLevel: RiskLevel,
  riskScore: number,
  evidence: EvidenceItem[],
  modelVersions: string[] = []
): ExplanationResult {
  const reasons: string[] = [];
  const actions: string[] = [];
  const limitations: string[] = [];

  // Sort evidence by severity (critical > high > medium > low) and then confidence
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const sorted = [...evidence].sort((a, b) => {
    const sDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    if (sDiff !== 0) return sDiff;
    return (b.confidence || 0) - (a.confidence || 0);
  });

  for (const item of sorted) {
    if (item.severity !== 'low') {
      reasons.push(item.explanation);
    }
  }

  if (reasons.length === 0) {
    reasons.push('No malicious indicators, abnormal lexical structures, or social engineering patterns were detected.');
  }

  // Summary and Actions based on Risk Level
  let summary = '';
  switch (riskLevel) {
    case 'CRITICAL':
      summary = `Critical risk detected (${riskScore}/100). High-confidence indicators of active phishing, credential theft, or scam lure identified.`;
      actions.push('Do NOT open the link, download attachments, or input passwords/financial details.');
      actions.push('Report this incident immediately to your organization security team or anti-fraud provider.');
      actions.push('If sensitive credentials were submitted, change your passwords immediately from a verified clean device.');
      break;

    case 'HIGH':
      summary = `High risk detected (${riskScore}/100). Strong suspicious indicators correlate with known scam or phishing campaigns.`;
      actions.push('Avoid interacting with buttons, payment requests, or embedded links.');
      actions.push('Independently verify the sender or domain through official bookmarks or telephone lines.');
      actions.push('Do not share one-time verification codes (OTP) or private account details.');
      break;

    case 'MEDIUM':
      summary = `Moderate risk observed (${riskScore}/100). Anomalies, conflicting signals, or elevated indicators require caution.`;
      actions.push('Proceed with caution and verify the exact destination URL and certificate before proceeding.');
      actions.push('Ensure the communication originated from the legitimate provider portal.');
      break;

    case 'LOW':
      summary = `Low observed risk (${riskScore}/100). No significant malicious indicators detected across analyzed signals.`;
      actions.push('Standard safe browsing practices apply. Continue to verify sensitive requests through official channels.');
      break;

    case 'INSUFFICIENT_EVIDENCE':
    default:
      summary = 'Analysis was inconclusive due to unavailable signals or unreadable input format.';
      actions.push('Verify the destination manually or re-submit with additional context.');
      break;
  }

  // Limitations identification
  const hasUrlModel = modelVersions.some(v => v.includes('url-phishing') || v.includes('url-detector'));
  const hasTextModel = modelVersions.some(v => v.includes('text-scam') || v.includes('message-scam'));
  const hasWebsiteAnalysis = modelVersions.some(v => v.includes('website-analyzer'));

  if (hasUrlModel && !hasWebsiteAnalysis) {
    limitations.push('URL evaluation is based on dynamic lexical and host features. Destination web page contents were not crawled.');
  }
  if (hasTextModel && !hasUrlModel) {
    limitations.push('Assessment evaluates natural language and social engineering patterns. Destination links were not independently analyzed.');
  }
  if (!hasUrlModel && !hasTextModel) {
    limitations.push('Full automated machine learning models were unavailable for this input; assessment relies on local heuristics.');
  }

  return {
    summary,
    reasons: reasons.slice(0, 5),
    actions,
    limitations
  };
}
