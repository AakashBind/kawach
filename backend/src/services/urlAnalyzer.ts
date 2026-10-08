import { URL } from 'url';
import { EvidenceItem, DetectorSummary } from '../types/evidence.js';
import { MLClient } from './mlClient.js';

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'loan', 'click', 'link',
  'bid', 'stream', 'download', 'win', 'racing', 'accountant', 'date', 'faith',
  'review', 'party', 'trade', 'science', 'cricket', 'zip', 'mov'
]);

const BRAND_TARGETS = [
  'paypal', 'bankofamerica', 'wellsfargo', 'chase', 'netflix', 'apple',
  'microsoft', 'google', 'amazon', 'binance', 'coinbase', 'facebook', 'instagram'
];

export async function analyzeUrl(rawUrl: string): Promise<{
  evidence: EvidenceItem[];
  mlScore: number | null;
  modelVersions: string[];
  detectorsUsed: DetectorSummary[];
}> {
  const evidence: EvidenceItem[] = [];
  const modelVersions: string[] = [];
  const detectorsUsed: DetectorSummary[] = [];
  let mlScore: number | null = null;

  let parsed: URL;
  try {
    const formatted = rawUrl.startsWith('http://') || rawUrl.startsWith('https://') ? rawUrl : `http://${rawUrl}`;
    parsed = new URL(formatted);
  } catch {
    detectorsUsed.push({
      detector_id: 'url-parser',
      detector_version: 'url-parser-1.0.0',
      model_version: '1.0.0',
      input_type: 'url',
      status: 'insufficient_data',
      confidence: 0
    });
    return { evidence, mlScore, modelVersions, detectorsUsed };
  }

  const hostname = parsed.hostname.toLowerCase();
  const hostParts = hostname.split('.');
  const tld = hostParts.length > 0 ? hostParts[hostParts.length - 1] : '';

  // 1. IP in Hostname Signal
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipRegex.test(hostname)) {
    evidence.push({
      signal_id: 'url.host.ip_address',
      source: 'heuristic_url_analyzer',
      category: 'suspicious_host',
      severity: 'high',
      confidence: 0.95,
      explanation: 'URL uses a raw IP address as its host instead of a registered domain name.',
      detector_version: 'url-heuristic-1.0.0',
      details: { hostname }
    });
  }

  // 2. Suspicious TLD Signal
  if (SUSPICIOUS_TLDS.has(tld)) {
    evidence.push({
      signal_id: 'url.domain.suspicious_tld',
      source: 'heuristic_url_analyzer',
      category: 'domain_reputation',
      severity: 'medium',
      confidence: 0.80,
      explanation: `URL utilizes high-risk top-level domain (.${tld}) frequently leveraged in disposable phishing lures.`,
      detector_version: 'url-heuristic-1.0.0',
      details: { tld }
    });
  }

  // 3. Excessive Subdomain Depth
  if (!ipRegex.test(hostname) && hostParts.length > 3) {
    evidence.push({
      signal_id: 'url.domain.excessive_subdomains',
      source: 'heuristic_url_analyzer',
      category: 'domain_structure',
      severity: 'medium',
      confidence: 0.75,
      explanation: `URL contains anomalous subdomain nesting depth (${hostParts.length - 2} levels).`,
      detector_version: 'url-heuristic-1.0.0',
      details: { subdomain_count: hostParts.length - 2 }
    });
  }

  // 4. Target Brand Impersonation in Host/Path
  for (const brand of BRAND_TARGETS) {
    if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.org`) && !hostname.endsWith(`${brand}.net`)) {
      evidence.push({
        signal_id: 'url.brand.impersonation',
        source: 'heuristic_url_analyzer',
        category: 'impersonation',
        severity: 'high',
        confidence: 0.90,
        explanation: `Target brand name '${brand}' was detected inside an unaffiliated third-party host '${hostname}'.`,
        detector_version: 'url-heuristic-1.0.0',
        details: { brand, hostname }
      });
      break;
    }
  }

  // 5. Credential / @ Obfuscation
  if (rawUrl.includes('@')) {
    evidence.push({
      signal_id: 'url.obfuscation.at_symbol',
      source: 'heuristic_url_analyzer',
      category: 'obfuscation',
      severity: 'high',
      confidence: 0.92,
      explanation: "URL utilizes '@' symbol credential syntax to disguise actual destination server.",
      detector_version: 'url-heuristic-1.0.0'
    });
  }

  // 6. Real ML Model Inference (XGBoost v2.0.0)
  const mlRes = await MLClient.inferUrl(rawUrl);
  if (mlRes) {
    mlScore = mlRes.score;
    const modelVer = mlRes.model_version || '2.0.0';
    const detectorVer = `url-phishing-${modelVer}`;
    modelVersions.push(detectorVer);

    detectorsUsed.push({
      detector_id: mlRes.model_id || 'url-phishing',
      detector_version: detectorVer,
      model_version: modelVer,
      input_type: 'url',
      status: 'success',
      calibrated_probability: mlRes.calibrated_probability ?? mlRes.score,
      confidence: mlRes.score >= 0.5 ? mlRes.score : (1 - mlRes.score),
      latency_ms: mlRes.processing_time_ms
    });

    if (mlRes.score >= 0.5) {
      evidence.push({
        signal_id: 'url.ml.phishing_prediction',
        source: 'url_ml_service',
        category: 'machine_learning',
        severity: mlRes.score >= 0.8 ? 'critical' : 'high',
        confidence: mlRes.score,
        explanation: `Supervised machine learning model (XGBoost v${modelVer}) evaluated 31 dynamic lexical/host features and flagged this URL as phishing (${(mlRes.score * 100).toFixed(2)}% calibrated probability).`,
        detector_version: detectorVer,
        details: {
          score: mlRes.score,
          raw_score: mlRes.raw_score,
          calibrated_probability: mlRes.calibrated_probability ?? mlRes.score,
          features: mlRes.features,
          top_signals: mlRes.top_signals,
          processing_time_ms: mlRes.processing_time_ms
        }
      });
    } else {
      evidence.push({
        signal_id: 'url.ml.benign_prediction',
        source: 'url_ml_service',
        category: 'machine_learning',
        severity: 'low',
        confidence: 1 - mlRes.score,
        explanation: `Supervised machine learning model (XGBoost v${modelVer}) evaluated 31 dynamic lexical/host features and found benign structural characteristics (${((1 - mlRes.score) * 100).toFixed(2)}% legitimate confidence).`,
        detector_version: detectorVer,
        details: {
          score: mlRes.score,
          raw_score: mlRes.raw_score,
          calibrated_probability: mlRes.calibrated_probability ?? mlRes.score,
          features: mlRes.features,
          processing_time_ms: mlRes.processing_time_ms
        }
      });
    }
  } else {
    detectorsUsed.push({
      detector_id: 'url-phishing',
      detector_version: 'url-phishing-2.0.0',
      model_version: '2.0.0',
      input_type: 'url',
      status: 'unavailable',
      confidence: 0
    });
  }

  return { evidence, mlScore, modelVersions, detectorsUsed };
}
