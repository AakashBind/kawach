import axios from 'axios';
import { AuthService } from './auth';
import { ScanResultData, ModelMetadata, FraudReport, User, GovernanceData } from '../types';

const API_BASE = '/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Attach JWT token automatically
apiClient.interceptors.request.use((config) => {
  const token = AuthService.getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const ApiService = {
  // Scans
  async scanUrl(url: string): Promise<ScanResultData> {
    const res = await apiClient.post('/scans/url', { url });
    return res.data.data;
  },

  async scanMessage(message: string, context: string = 'generic'): Promise<ScanResultData> {
    const res = await apiClient.post('/scans/message', { message, context });
    return res.data.data;
  },

  async scanQr(file: File): Promise<ScanResultData> {
    const formData = new FormData();
    formData.append('image', file);
    const res = await apiClient.post('/scans/qr', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data.data;
  },

  async scanWebsite(url: string): Promise<ScanResultData> {
    const res = await apiClient.post('/scans/website', { url });
    return res.data.data;
  },

  async getScans(filters?: { type?: string; risk_level?: string; search?: string }): Promise<ScanResultData[]> {
    const res = await apiClient.get('/scans', { params: filters });
    return res.data.data.scans;
  },

  async getScanDetails(id: string): Promise<{ scan: ScanResultData; evidence: any[] }> {
    const res = await apiClient.get(`/scans/${id}`);
    return res.data.data;
  },

  async deleteScan(id: string): Promise<void> {
    await apiClient.delete(`/scans/${id}`);
  },

  async clearAllScans(): Promise<void> {
    await apiClient.delete('/scans');
  },

  // Reports & Feedback
  async submitReport(data: { scan_id?: string; category: string; description: string; evidence_summary?: string }): Promise<any> {
    const res = await apiClient.post('/reports', data);
    return res.data.data;
  },

  async getReports(): Promise<FraudReport[]> {
    const res = await apiClient.get('/reports');
    return res.data.data.reports;
  },

  async submitFeedback(data: { scan_id: string; feedback_type: 'false_positive' | 'false_negative' | 'correct'; user_comments?: string }): Promise<any> {
    const res = await apiClient.post('/feedback', data);
    return res.data.data;
  },

  // Model Governance
  async getModels(): Promise<GovernanceData> {
    const res = await apiClient.get('/models');
    return res.data.data;
  },

  // Health
  async getHealth(): Promise<any> {
    const res = await apiClient.get('/health');
    return res.data;
  },

  // Auth
  async register(email: string, password: string): Promise<{ user: User; token: string }> {
    const res = await apiClient.post('/auth/register', { email, password });
    return res.data.data;
  },

  async login(email: string, password: string): Promise<{ user: User; token: string }> {
    const res = await apiClient.post('/auth/login', { email, password });
    return res.data.data;
  },

  async getMe(): Promise<User> {
    const res = await apiClient.get('/auth/me');
    return res.data.data.user;
  }
};
