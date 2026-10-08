import { EvidenceItem, DetectorSummary } from '../types/evidence.js';
import { MLClient } from './mlClient.js';
import { analyzeUrl } from './urlAnalyzer.js';

const URGENCY_REGEX = /\b(urgently?|immediate(ly)?|within 24 hours|within 48 hours|act now|expires?|suspended?|locked|terminate|final warning|deadline|hurry)\b/i;
const CREDENTIAL_REGEX = /\b(passwords?|passcodes?|pin|credentials?|ssn|social security|kyc|log\s*in|sign\s*in|unlock your account|verify your (?:account|identity)|confirm (?:that )?it was you|(?:reply with|send|share|provide|enter|submit)\s+(?:the|your)?\s*(?:verification\s*code|code|otp))\b/i;
const PAYMENT_REGEX = /\b(bank account|credit card|debit card|cvv|wire transfer|western union|gift card|itunes card|bitcoin|crypto|upi|paytm|gpay|phonepe|refund|claim prize|lottery|winner)\b/i;
const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"]+|(?:\b[a-zA-Z0-9.-]+\.(?:com|org|net|xyz|tk|ml|cf|gq|info|top|app)\b[^\s<>"]*)/gi;

export async function analyzeMessage(
  message: string,
  context: string = 'generic'
): Promise<{
  evidence: EvidenceItem[];
  nlpScore: number | null;
  extractedEntities: Record<string, any>;
  subUrlResults: any[];
  modelVersions: string[];
  detectorsUsed: DetectorSummary[];
}> {
  const evidence: EvidenceItem[] = [];
  const modelVersions: string[] = [];
  const detectorsUsed: DetectorSummary[] = [];
  const subUrlResults: any[] = [];
  let nlpScore: number | null = null;

  // 1. Extract URLs and Local Intent Cues
  const matchedUrls = message.match(URL_REGEX) || [];
  const uniqueUrls = Array.from(new Set(matchedUrls));
  const hasUrgency = URGENCY_REGEX.test(message);
  const hasCredentials = CREDENTIAL_REGEX.test(message);
  const hasPayment = PAYMENT_REGEX.test(message);

  const localEntities = {
    extracted_urls: uniqueUrls,
    intent_signals: {
      has_urgency: hasUrgency,
      has_credential_request: hasCredentials,
      has_payment_request: hasPayment
    }
  };

  let extractedEntities: Record<string, any> = localEntities;

  // 2. Execute NLP Text Model (text-scam-2.0.0)
  const mlRes = await MLClient.inferMessage(message, context);
  if (mlRes) {
    nlpScore = mlRes.score;
    extractedEntities = mlRes.entities || localEntities;
    const modelVer = mlRes.model_version || '2.0.0';
    const detectorVer = mlRes.detector_version || `text-scam-${modelVer}`;
    if (!modelVersions.includes(detectorVer)) {
      modelVersions.push(detectorVer);
    }

    detectorsUsed.push({
      detector_id: mlRes.model_id || 'text-scam',
      detector_version: detectorVer,
      model_version: modelVer,
      input_type: 'message',
      status: 'success',
      calibrated_probability: mlRes.calibrated_probability ?? mlRes.score,
      confidence: mlRes.score >= 0.5 ? mlRes.score : (1 - mlRes.score),
      latency_ms: mlRes.processing_time_ms
    });

    if (mlRes.score >= 0.50) {
      evidence.push({
        signal_id: 'message.ml.scam_intent',
        source: 'text_ml_service',
        category: 'machine_learning',
        severity: mlRes.score >= 0.85 ? 'critical' : 'high',
        confidence: mlRes.score,
        explanation: `NLP Scam Intent Classifier (v${modelVer}) identified social engineering, fraudulent lure, or phishing intent patterns with ${(mlRes.score * 100).toFixed(2)}% calibrated probability.`,
        detector_version: detectorVer,
        details: { score: mlRes.score, processing_time_ms: mlRes.processing_time_ms }
      });
    } else {
      evidence.push({
        signal_id: 'message.ml.benign_intent',
        source: 'text_ml_service',
        category: 'machine_learning',
        severity: 'low',
        confidence: 1 - mlRes.score,
        explanation: `NLP Scam Intent Classifier (v${modelVer}) found natural conversational patterns with low scam intent probability (${((1 - mlRes.score) * 100).toFixed(2)}% legitimate confidence).`,
        detector_version: detectorVer,
        details: { score: mlRes.score, processing_time_ms: mlRes.processing_time_ms }
      });
    }
  } else {
    modelVersions.push('text-scam-2.0.0');
    detectorsUsed.push({
      detector_id: 'text-scam',
      detector_version: 'text-scam-2.0.0',
      model_version: '2.0.0',
      input_type: 'message',
      status: 'unavailable',
      confidence: 0
    });
  }

  // 3. Add Intent Evidence from Extracted Signals (grounded in actual input text)
  if (extractedEntities.intent_signals?.has_urgency) {
    evidence.push({
      signal_id: 'message.intent.urgency',
      source: 'message_intent_analyzer',
      category: 'social_engineering',
      severity: 'medium',
      confidence: 0.85,
      explanation: 'Artificial urgency cues detected pressuring rapid compliance without verification.',
      detector_version: 'message-heuristic-1.0.0'
    });
  }

  if (extractedEntities.intent_signals?.has_credential_request) {
    const msgLower = message.toLowerCase();
    let credExplanation = 'Direct solicitation of sensitive credentials or account verification observed.';
    
    if (msgLower.includes('verification code') || msgLower.includes('otp') || msgLower.includes('code sent to your phone')) {
      credExplanation = 'Request for a verification code or OTP confirmation detected in message.';
    } else if (msgLower.includes('password') || msgLower.includes('passcode') || msgLower.includes('pin')) {
      credExplanation = 'Direct solicitation of account passwords or PIN credentials observed in message.';
    } else if (msgLower.includes('login') || msgLower.includes('sign in') || msgLower.includes('unlock your account') || msgLower.includes('verify your account')) {
      credExplanation = 'Account access verification or login confirmation prompt detected.';
    }

    evidence.push({
      signal_id: 'message.intent.credential_harvesting',
      source: 'message_intent_analyzer',
      category: 'credential_theft',
      severity: 'high',
      confidence: 0.90,
      explanation: credExplanation,
      detector_version: 'message-heuristic-1.0.0'
    });
  }

  if (extractedEntities.intent_signals?.has_payment_request) {
    evidence.push({
      signal_id: 'message.intent.payment_request',
      source: 'message_intent_analyzer',
      category: 'financial_fraud',
      severity: 'high',
      confidence: 0.88,
      explanation: 'Suspicious payment, wire transfer, cryptocurrency, or gift card request identified.',
      detector_version: 'message-heuristic-1.0.0'
    });
  }

  // 4. Parallel Multi-URL Analysis for Embedded Links
  const urlsToAnalyze = uniqueUrls.slice(0, 5);
  if (urlsToAnalyze.length > 0) {
    const urlAnalysisPromises = urlsToAnalyze.map(u => analyzeUrl(u));
    const settledResults = await Promise.allSettled(urlAnalysisPromises);

    for (let i = 0; i < settledResults.length; i++) {
      const res = settledResults[i];
      const url = urlsToAnalyze[i];

      if (res.status === 'fulfilled') {
        const urlData = res.value;
        subUrlResults.push({ url, ...urlData });

        for (const ev of urlData.evidence) {
          evidence.push({
            ...ev,
            explanation: `[Embedded Link (${url})]: ${ev.explanation}`
          });
        }

        for (const v of urlData.modelVersions) {
          if (!modelVersions.includes(v)) modelVersions.push(v);
        }

        for (const d of urlData.detectorsUsed) {
          detectorsUsed.push(d);
        }
      } else {
        subUrlResults.push({ url, error: res.reason?.message || 'URL evaluation failed' });
        detectorsUsed.push({
          detector_id: 'url-phishing',
          detector_version: 'url-phishing-2.0.0',
          model_version: '2.0.0',
          input_type: 'url',
          status: 'error',
          confidence: 0
        });
      }
    }
  }

  return { evidence, nlpScore, extractedEntities, subUrlResults, modelVersions, detectorsUsed };
}
