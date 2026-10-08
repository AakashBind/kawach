import request from 'supertest';
import { app } from '../src/app.js';
import { db } from '../src/database/db.js';
import { runMigrations } from '../src/database/migrations.js';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

describe('Message Scanner — Runtime Model Provenance & Evidence Grounding Audit', () => {
  beforeAll(() => {
    runMigrations();
  });

  const TEXT_V2_EXPECTED_MODEL_SHA = '3dd3b1713b667c64d3acb190be6673ea284efb88a9f69d4434dc1ed07e9c952c';
  const TEXT_V2_EXPECTED_VEC_SHA = '9d95f84636b0f289cb46fbe29c93a2b33f4de1ab54315684fe283d26c25a15e6';

  describe('1. Model Artifact Cryptographic Integrity Check', () => {
    it('Text Scam v2.0.0 model artifact matches authoritative SHA-256', () => {
      const modelPath = path.resolve(__dirname, '../../ml/models/text_scam/v2.0.0/model.joblib');
      const hash = crypto.createHash('sha256').update(fs.readFileSync(modelPath)).digest('hex');
      expect(hash).toBe(TEXT_V2_EXPECTED_MODEL_SHA);
    });

    it('Text Scam v2.0.0 vectorizer artifact matches authoritative SHA-256', () => {
      const vecPath = path.resolve(__dirname, '../../ml/models/text_scam/v2.0.0/vectorizer.joblib');
      const hash = crypto.createHash('sha256').update(fs.readFileSync(vecPath)).digest('hex');
      expect(hash).toBe(TEXT_V2_EXPECTED_VEC_SHA);
    });
  });

  describe('2. Model Governance & Registry Validation', () => {
    it('GET /api/v1/models exposes text-scam-2.0.0 as ACTIVE and V1 as ARCHIVED', async () => {
      const res = await request(app).get('/api/v1/models');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const activeModels = res.body.data.active_models;
      const archivedModels = res.body.data.archived_models;

      // Ensure active text model is v2.0.0
      const activeTextModel = activeModels.find((m: any) => m.model_id.includes('text-scam') || m.model_id === 'text-scam');
      expect(activeTextModel).toBeDefined();
      expect(activeTextModel.version).toBe('2.0.0');
      expect(activeTextModel.is_active).toBe(true);
      expect(activeTextModel.artifact_hash).toBe(TEXT_V2_EXPECTED_MODEL_SHA);

      // Ensure no V1 model is in active models
      const activeV1 = activeModels.find((m: any) => m.version === '1.0.0' || m.model_id.includes('1.0.0') || m.model_id === 'message-scam-intent');
      expect(activeV1).toBeUndefined();

      // Ensure V1 exists in archived models
      const archivedText = archivedModels.find((m: any) => m.version === '1.0.0' && m.model_id.includes('text-scam'));
      expect(archivedText).toBeDefined();
      expect(archivedText.is_active).toBe(false);
    });
  });

  describe('3. Required Regression Scenarios', () => {
    it('Case A: Job-offer style message does NOT emit unsupported payment evidence', async () => {
      const jobMsg = 'Hi, we found your profile and would like to offer you a part-time work-from-home position with flexible hours and high daily pay. Contact our hiring manager on Telegram @career_recruiter to begin.';
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: jobMsg, context: 'sms' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const data = res.body.data;

      // Active model must be text-scam-2.0.0
      expect(data.model_versions).toContain('text-scam-2.0.0');
      expect(data.model_versions).not.toContain('message-scam-1.0.0');
      expect(data.model_versions).not.toContain('text-scam-1.0.0');

      // Check evidence signals: must NOT contain message.intent.payment_request
      const paymentEvidence = data.evidence.find((e: any) => e.signal_id === 'message.intent.payment_request');
      expect(paymentEvidence).toBeUndefined();

      // Risk score is generated dynamically by Risk Engine
      expect(typeof data.risk_score).toBe('number');
      expect(data.risk_score).toBeGreaterThanOrEqual(0);
      expect(data.risk_score).toBeLessThanOrEqual(100);
    });

    it('Case B: Genuine payment request message emits grounded payment evidence if present', async () => {
      const payMsg = 'Your account has been selected. Pay 2000 processing fee through bitcoin wire transfer or gift card to claim prize.';
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: payMsg, context: 'sms' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const data = res.body.data;

      expect(data.model_versions).toContain('text-scam-2.0.0');
      const payEvidence = data.evidence.find((e: any) => e.signal_id === 'message.intent.payment_request');
      expect(payEvidence).toBeDefined();
      expect(payEvidence.category).toBe('financial_fraud');
      expect(payEvidence.severity).toBe('high');
    });

    it('Case C: Legitimate message emits no payment or credential harvesting evidence', async () => {
      const legitMsg = 'Hi, are we still meeting tomorrow at 10 AM? Please bring the project documents.';
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: legitMsg, context: 'sms' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const data = res.body.data;

      expect(data.risk_level).toBe('LOW');
      expect(data.risk_score).toBeLessThanOrEqual(25);
      expect(data.model_versions).toContain('text-scam-2.0.0');

      const fakePayment = data.evidence.find((e: any) => e.signal_id === 'message.intent.payment_request');
      const fakeCred = data.evidence.find((e: any) => e.signal_id === 'message.intent.credential_harvesting');
      expect(fakePayment).toBeUndefined();
      expect(fakeCred).toBeUndefined();
    });

    it('Case D: Verification code request message emits accurate grounded verification evidence', async () => {
      const verifMsg = "Hi, this is regarding your recent account activity. We noticed a login from a new device and need to confirm that it was you. If you don't recognize it, please reply with the verification code sent to your phone so we can secure the account.";
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: verifMsg, context: 'sms' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const data = res.body.data;

      expect(data.model_versions).toContain('text-scam-2.0.0');
      const credEvidence = data.evidence.find((e: any) => e.signal_id === 'message.intent.credential_harvesting');
      expect(credEvidence).toBeDefined();
      expect(credEvidence.explanation).toContain('verification code');
    });
  });
});
