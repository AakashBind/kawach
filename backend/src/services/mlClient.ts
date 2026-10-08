import axios from 'axios';
import { CONFIG } from '../config.js';

export interface MLUrlResponse {
  model_id: string;
  model_version: string;
  detector_version: string;
  score: number;
  raw_score?: number;
  calibrated_probability?: number;
  calibrated: boolean;
  threshold?: number;
  predicted_class: string;
  top_signals: Array<{ signal: string; severity: string; weight: number }>;
  features: Record<string, any>;
  feature_extraction_time_ms?: number;
  model_inference_time_ms?: number;
  processing_time_ms: number;
  analysis_status?: string;
  errors: string[];
}

export interface MLMessageResponse {
  model_id: string;
  model_version: string;
  detector_version: string;
  score: number;
  raw_score?: number;
  calibrated_probability?: number;
  calibrated: boolean;
  threshold?: number;
  predicted_class: string;
  entities: {
    extracted_urls: string[];
    extracted_emails: string[];
    extracted_phones: string[];
    monetary_amounts: string[];
    crypto_wallets: string[];
    intent_signals: {
      has_urgency: boolean;
      urgency_triggers: string[];
      has_credential_request: boolean;
      credential_triggers: string[];
      has_payment_request: boolean;
      payment_triggers: string[];
      has_authority_impersonation: boolean;
      authority_triggers: string[];
    };
  };
  signals: Array<{ type: string; triggers: string[] }>;
  processing_time_ms: number;
  analysis_status?: string;
  errors: string[];
}

export class MLClient {
  private static baseUrl = CONFIG.ML_SERVICE_URL;

  public static async inferUrl(url: string): Promise<MLUrlResponse | null> {
    try {
      const resp = await axios.post<MLUrlResponse>(`${this.baseUrl}/inference/url`, { url }, { timeout: 4000 });
      return resp.data;
    } catch (err: any) {
      console.warn(`[MLClient] URL Inference service unavailable: ${err.message}`);
      return null;
    }
  }

  public static async inferMessage(message: string, context: string = 'generic'): Promise<MLMessageResponse | null> {
    try {
      const resp = await axios.post<MLMessageResponse>(`${this.baseUrl}/inference/message`, { message, context }, { timeout: 4000 });
      return resp.data;
    } catch (err: any) {
      console.warn(`[MLClient] Message Inference service unavailable: ${err.message}`);
      return null;
    }
  }

  public static async getModelsMetadata(): Promise<any> {
    try {
      const resp = await axios.get(`${this.baseUrl}/models/metadata`, { timeout: 3000 });
      return resp.data;
    } catch (err: any) {
      console.warn(`[MLClient] Model metadata fetch failed: ${err.message}`);
      return null;
    }
  }

  public static async checkHealth(): Promise<boolean> {
    try {
      const resp = await axios.get(`${this.baseUrl}/health`, { timeout: 2000 });
      return resp.data?.status === 'healthy';
    } catch {
      return false;
    }
  }
}
