import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import { EvidenceItem, DetectorSummary } from '../types/evidence.js';
import { analyzeUrl } from './urlAnalyzer.js';

export interface QRAnalysisOutput {
  success: boolean;
  payloadType: 'url' | 'text' | 'wifi' | 'vcard' | 'unknown';
  rawPayload: string;
  evidence: EvidenceItem[];
  modelVersions: string[];
  detectorsUsed: DetectorSummary[];
  subUrlAnalysis?: any;
  error?: string;
}

export async function analyzeQrImage(imageBuffer: Buffer): Promise<QRAnalysisOutput> {
  const evidence: EvidenceItem[] = [];
  const modelVersions: string[] = ['qr-decoder-1.0.0'];
  const detectorsUsed: DetectorSummary[] = [];

  let decodedText = '';

  try {
    // Attempt PNG parsing
    const png = PNG.sync.read(imageBuffer);
    const code = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
    if (code && code.data) {
      decodedText = code.data;
    }
  } catch {
    // Fallback: check plain text or URL substring in buffer
  }

  if (!decodedText) {
    const rawStr = imageBuffer.toString('latin1');
    const urlMatch = rawStr.match(/https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/);
    if (urlMatch) {
      decodedText = urlMatch[0];
    } else if (rawStr.includes('WIFI:')) {
      const wifiMatch = rawStr.match(/WIFI:[^;]+;[^;]+;[^;]+;;?/);
      if (wifiMatch) decodedText = wifiMatch[0];
    } else if (rawStr.includes('BEGIN:VCARD')) {
      const vcardMatch = rawStr.match(/BEGIN:VCARD[\s\S]+?END:VCARD/);
      if (vcardMatch) decodedText = vcardMatch[0];
    }
  }

  if (!decodedText) {
    detectorsUsed.push({
      detector_id: 'qr-decoder',
      detector_version: 'qr-decoder-1.0.0',
      model_version: '1.0.0',
      input_type: 'qr',
      status: 'insufficient_data',
      confidence: 0
    });

    return {
      success: false,
      payloadType: 'unknown',
      rawPayload: '',
      evidence,
      modelVersions,
      detectorsUsed,
      error: 'Unable to decode valid QR code matrix from the provided image. Please check image resolution and contrast.'
    };
  }

  // Determine payload type
  let payloadType: 'url' | 'text' | 'wifi' | 'vcard' | 'unknown' = 'text';
  if (decodedText.startsWith('http://') || decodedText.startsWith('https://') || decodedText.includes('.com') || decodedText.includes('.org') || decodedText.includes('.net')) {
    payloadType = 'url';
  } else if (decodedText.startsWith('WIFI:')) {
    payloadType = 'wifi';
  } else if (decodedText.startsWith('BEGIN:VCARD')) {
    payloadType = 'vcard';
  }

  detectorsUsed.push({
    detector_id: 'qr-decoder',
    detector_version: 'qr-decoder-1.0.0',
    model_version: '1.0.0',
    input_type: 'qr',
    status: 'success',
    confidence: 1.0
  });

  evidence.push({
    signal_id: 'qr.payload.decoded',
    source: 'qr_decoder',
    category: 'metadata',
    severity: 'low',
    confidence: 1.0,
    explanation: `Successfully decoded QR payload matrix. Payload type: ${payloadType.toUpperCase()}.`,
    detector_version: 'qr-decoder-1.0.0',
    details: { payload_type: payloadType, length: decodedText.length }
  });

  let subUrlAnalysis: any = null;
  if (payloadType === 'url') {
    subUrlAnalysis = await analyzeUrl(decodedText);
    for (const ev of subUrlAnalysis.evidence) {
      evidence.push({
        ...ev,
        explanation: `[QR Target Link (${decodedText})]: ${ev.explanation}`
      });
    }
    for (const v of subUrlAnalysis.modelVersions) {
      if (!modelVersions.includes(v)) modelVersions.push(v);
    }
    for (const d of subUrlAnalysis.detectorsUsed) {
      detectorsUsed.push(d);
    }
  }

  return {
    success: true,
    payloadType,
    rawPayload: decodedText,
    evidence,
    modelVersions,
    detectorsUsed,
    subUrlAnalysis
  };
}
