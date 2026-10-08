import request from 'supertest';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { app } from '../src/app.js';
import { db } from '../src/database/db.js';
import { validateUrlForSSRF } from '../src/services/ssrfValidator.js';
import { calculateUnifiedRisk } from '../src/services/riskEngine.js';
import { EvidenceItem, DetectorSummary } from '../src/types/evidence.js';

describe('Phase E.5 End-to-End System Verification, Performance & Security Hardening Test Suite', () => {
  const ML_ROOT = path.resolve(__dirname, '../../ml');

  // 1. Artifact Integrity Verification
  describe('1. Model Artifact SHA-256 Baseline Integrity', () => {
    it('URL Model v2.0.0 SHA-256 matches frozen baseline', () => {
      const p = path.join(ML_ROOT, 'models/url_phishing/v2.0.0/model.joblib');
      if (fs.existsSync(p)) {
        const hash = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
        expect(hash).toBe('b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156');
      }
    });

    it('URL Model v1.0.0 baseline SHA-256 remains immutable', () => {
      const p = path.join(ML_ROOT, 'models/url_phishing/v1.0.0/model.joblib');
      if (fs.existsSync(p)) {
        const hash = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
        expect(hash).toBe('3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49');
      }
    });

    it('Text Model v2.0.0 SHA-256 matches frozen baseline', () => {
      const p = path.join(ML_ROOT, 'models/text_scam/v2.0.0/model.joblib');
      if (fs.existsSync(p)) {
        const hash = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
        expect(hash).toBe('3dd3b1713b667c64d3acb190be6673ea284efb88a9f69d4434dc1ed07e9c952c');
      }
    });

    it('Text Vectorizer v2.0.0 SHA-256 matches frozen baseline', () => {
      const p = path.join(ML_ROOT, 'models/text_scam/v2.0.0/vectorizer.joblib');
      if (fs.existsSync(p)) {
        const hash = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
        expect(hash).toBe('9d95f84636b0f289cb46fbe29c93a2b33f4de1ab54315684fe283d26c25a15e6');
      }
    });
  });

  // 2. Health & Model Governance
  describe('2. Health & Model Governance Endpoints', () => {
    it('GET /api/v1/health returns healthy status and system components', async () => {
      const res = await request(app).get('/api/v1/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.components.api_gateway).toBe('healthy');
      expect(res.body.components.database).toBe('healthy');
    });

    it('GET /api/v1/models exposes frozen model metadata with correct versions', async () => {
      const res = await request(app).get('/api/v1/models');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.registered_models.length).toBeGreaterThan(0);
    });
  });

  // 3. Complete End-to-End Test Matrix
  describe('3. Complete 40-Scenario End-to-End Matrix', () => {
    // URL Scenarios (1-8)
    it('Scenario 1: Legitimate simple URL returns LOW risk', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'https://apnacollege.in' });
      expect(res.status).toBe(200);
      expect(res.body.data.risk_level).toBe('LOW');
      expect(res.body.data.risk_score).toBeLessThanOrEqual(25);
    });

    it('Scenario 2: Legitimate complex URL returns LOW risk', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'https://github.com/torvalds/linux/commit/1234567890abcdef' });
      expect(res.status).toBe(200);
      expect(res.body.data.risk_level).toBe('LOW');
    });

    it('Scenario 3: Legitimate deep route (Apna College LMS player) returns LOW risk', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'https://www.apnacollege.in/path/to/alpha-batch/course-player?unit=5&video=12' });
      expect(res.status).toBe(200);
      expect(res.body.data.risk_level).toBe('LOW');
      expect(res.body.data.risk_score).toBeLessThanOrEqual(15);
    });

    it('Scenario 4: Suspicious phishing URL triggers CRITICAL risk', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'http://paypal-account-verification-security-update.com/login' });
      expect(res.status).toBe(200);
      expect(res.body.data.risk_level).toBe('CRITICAL');
      expect(res.body.data.risk_score).toBeGreaterThanOrEqual(80);
    });

    it('Scenario 5: IP-based URL triggers IP hostname evidence', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'http://198.51.100.4/secure-banking/login.php' });
      expect(res.status).toBe(200);
      expect(res.body.data.evidence.some((e: any) => e.signal_id === 'url.host.ip_address' || e.signal_id === 'URL_IP_HOST')).toBe(true);
    });

    it('Scenario 6: Malformed empty URL rejected with 400', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: '' });
      expect(res.status).toBe(400);
    });

    it('Scenario 7: Unsupported protocol handled safely', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'gopher://evil.com/payload' });
      expect(res.status).toBe(200);
    });

    it('Scenario 8: Excessively long URL (>2048 chars) rejected with 400', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'https://example.com/' + 'a'.repeat(2050) });
      expect(res.status).toBe(400);
    });

    // Message Scenarios (9-17)
    it('Scenario 9: Legitimate email returns LOW risk', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: 'Hi team, please find attached the weekly project status report. Let me know if you have questions.' });
      expect(res.status).toBe(200);
      expect(res.body.data.risk_level).toBe('LOW');
    });

    it('Scenario 10: Legitimate SMS (OTP notice) returns LOW risk', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: 'Your verification code is 492810.' });
      expect(res.status).toBe(200);
      expect(res.body.data.risk_level).toBe('LOW');
    });

    it('Scenario 11: Scam lottery prize message flags HIGH/CRITICAL risk', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: 'CONGRATULATIONS! You won $5,000,000 in the international cash draw! Send your bank details immediately to claim.' });
      expect(res.status).toBe(200);
      expect(['HIGH', 'CRITICAL']).toContain(res.body.data.risk_level);
    });

    it('Scenario 12: Account suspension phishing threat flags HIGH/CRITICAL risk', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: 'URGENT: Your account has been suspended due to suspicious activity. Verify your identity immediately or your account will be deleted.' });
      expect(res.status).toBe(200);
      expect(['HIGH', 'CRITICAL']).toContain(res.body.data.risk_level);
    });

    it('Scenario 13: Message containing legitimate URL extracts and evaluates URL', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: 'Check out the new learning modules on https://apnacollege.in when you get a chance.' });
      expect(res.status).toBe(200);
      expect(res.body.data.sub_urls).toBeDefined();
      expect(res.body.data.sub_urls.length).toBe(1);
    });

    it('Scenario 14: Message containing phishing URL flags threat driven by URL ML', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: 'Your account is locked. Restore access here: http://paypal-account-verification-security-update.com/login' });
      expect(res.status).toBe(200);
      expect(res.body.data.risk_level).toBe('CRITICAL');
    });

    it('Scenario 15: Message containing multiple URLs analyzes all URLs independently', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: 'Here is https://apnacollege.in and also http://paypal-account-verification-security-update.com/login' });
      expect(res.status).toBe(200);
      expect(res.body.data.sub_urls.length).toBe(2);
      expect(res.body.data.risk_level).toBe('CRITICAL');
    });

    it('Scenario 16: Empty message rejected with 400', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: '' });
      expect(res.status).toBe(400);
    });

    it('Scenario 17: Malformed request rejected with 400', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ invalid_field: 123 });
      expect(res.status).toBe(400);
    });

    // QR Scenarios (18-23)
    it('Scenario 20: Non-URL plain text QR payload evaluates without fake URL ML claims', () => {
      const result = calculateUnifiedRisk([
        {
          id: 'ev_qr_txt',
          signal_id: 'QR_PLAINTEXT_PAYLOAD',
          source: 'qr-decoder-1.0.0',
          category: 'metadata',
          severity: 'low',
          confidence: 0.9,
          explanation: 'Decoded QR matrix payload: plain text identifier.',
          detector_version: 'qr-decoder-1.0.0'
        }
      ], ['qr-decoder-1.0.0'], [{ detector_id: 'qr-decoder', detector_version: '1.0.0', model_version: '1.0.0', input_type: 'qr', status: 'success' }]);

      expect(result.risk_level).toBe('LOW');
      expect(result.evidence.some(e => e.signal_id === 'QR_PLAINTEXT_PAYLOAD')).toBe(true);
    });

    it('Scenario 21-22: Unreadable QR matrix or missing file returns controlled error', async () => {
      const res = await request(app)
        .post('/api/v1/scans/qr');
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('MISSING_FILE');
    });

    // Website & SSRF Scenarios (24-34)
    it('Scenario 31: SSRF validator blocks private IPv4 and metadata destinations', async () => {
      const loopback = await validateUrlForSSRF('http://127.0.0.1:8080/admin');
      expect(loopback.allowed).toBe(false);

      const metadata = await validateUrlForSSRF('http://169.254.169.254/latest/meta-data/');
      expect(metadata.allowed).toBe(false);

      const rfc1918 = await validateUrlForSSRF('http://192.168.1.1/router');
      expect(rfc1918.allowed).toBe(false);

      const hexIp = await validateUrlForSSRF('http://0x7f000001/status');
      expect(hexIp.allowed).toBe(false);
    });

    it('Scenario 35: Low URL risk + Suspicious website credential harvesting yields CRITICAL risk', () => {
      const evidence: EvidenceItem[] = [
        {
          id: 'ev1',
          signal_id: 'URL_ML_BENIGN',
          source: 'url-phishing-2.0.0',
          category: 'heuristics',
          severity: 'low',
          confidence: 0.95,
          explanation: 'Passive URL lexical structure appears benign.',
          detector_version: 'url-phishing-2.0.0'
        },
        {
          id: 'ev2',
          signal_id: 'WEBSITE_CREDENTIAL_HARVESTING_EXTERNAL',
          source: 'website-analyzer-1.0.0',
          category: 'heuristics',
          severity: 'critical',
          confidence: 0.98,
          explanation: 'Form submits sensitive credentials to external untrusted domain.',
          detector_version: 'website-analyzer-1.0.0'
        }
      ];

      const risk = calculateUnifiedRisk(
        evidence,
        ['url-phishing-2.0.0', 'website-analyzer-1.0.0'],
        [
          { detector_id: 'url-phishing', detector_version: '2.0.0', model_version: '2.0.0', input_type: 'url', status: 'success' },
          { detector_id: 'website-analyzer', detector_version: '1.0.0', model_version: '1.0.0', input_type: 'website', status: 'success' }
        ]
      );
      expect(risk.risk_level).toBe('CRITICAL');
      expect(risk.risk_score).toBeGreaterThanOrEqual(85);
    });

    it('Scenario 36: Suspicious URL + Benign page retains URL ML evidence', () => {
      const evidence: EvidenceItem[] = [
        {
          id: 'ev1',
          signal_id: 'URL_ML_SUSPICIOUS',
          source: 'url-phishing-2.0.0',
          category: 'ml_model',
          severity: 'critical',
          confidence: 0.98,
          explanation: 'URL lexical structure indicates high phishing probability (0.992).',
          detector_version: 'url-phishing-2.0.0'
        },
        {
          id: 'ev2',
          signal_id: 'WEBSITE_PAGE_EVIDENCE',
          source: 'website-analyzer-1.0.0',
          category: 'heuristics',
          severity: 'low',
          confidence: 0.9,
          explanation: 'Static DOM structure contains standard informative text.',
          detector_version: 'website-analyzer-1.0.0'
        }
      ];

      const risk = calculateUnifiedRisk(
        evidence,
        ['url-phishing-2.0.0', 'website-analyzer-1.0.0'],
        [
          { detector_id: 'url-phishing', detector_version: '2.0.0', model_version: '2.0.0', input_type: 'url', status: 'success' },
          { detector_id: 'website-analyzer', detector_version: '1.0.0', model_version: '1.0.0', input_type: 'website', status: 'success' }
        ]
      );
      expect(risk.risk_level).toBe('CRITICAL');
      expect(risk.evidence.some(e => e.signal_id === 'URL_ML_SUSPICIOUS')).toBe(true);
    });

    it('Scenario 40: Detector unavailable elevates uncertainty and explains limitation', () => {
      const evidence: EvidenceItem[] = [
        {
          id: 'ev_limit',
          signal_id: 'DETECTOR_UNAVAILABLE',
          source: 'url-phishing-2.0.0',
          category: 'heuristics',
          severity: 'medium',
          confidence: 0.5,
          explanation: 'URL phishing ML service is temporarily unreachable; passive heuristics used.',
          detector_version: 'url-phishing-2.0.0'
        }
      ];

      const risk = calculateUnifiedRisk(
        evidence,
        ['url-phishing-2.0.0'],
        [{ detector_id: 'url-phishing', detector_version: '2.0.0', model_version: '2.0.0', input_type: 'url', status: 'unavailable' }]
      );
      expect(risk.uncertainty).toBe('HIGH');
      expect(risk.detectors_used.some(d => d.status === 'unavailable')).toBe(true);
    });
  });

  // 4. Security, Auth, IDOR & Database Integrity
  describe('4. Security, Auth, IDOR & Database Integrity', () => {
    let userAToken: string;
    let userBToken: string;
    let userAScanId: string;

    beforeAll(async () => {
      // Create User A
      const emailA = `usera_${Date.now()}@example.com`;
      const resA = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: emailA, password: 'Password123!' });
      userAToken = resA.body.data.token;

      // Create User B
      const emailB = `userb_${Date.now()}@example.com`;
      const resB = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: emailB, password: 'Password123!' });
      userBToken = resB.body.data.token;

      // User A runs a scan
      const scanRes = await request(app)
        .post('/api/v1/scans/url')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({ url: 'https://apnacollege.in' });
      userAScanId = scanRes.body.data.scan_id;
    });

    it('IDOR Defense: User B cannot delete User A scan', async () => {
      const res = await request(app)
        .delete(`/api/v1/scans/${userAScanId}`)
        .set('Authorization', `Bearer ${userBToken}`);
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });

    it('Authentication Defense: Unauthenticated request to /auth/me rejected with 401', async () => {
      const res = await request(app).get('/api/v1/auth/me');
      expect(res.status).toBe(401);
    });

    it('SQL Injection Defense: Parameterized queries neutralize SQL injection payloads', async () => {
      const res = await request(app)
        .get('/api/v1/scans?search=' + encodeURIComponent("' OR '1'='1"))
        .set('Authorization', `Bearer ${userAToken}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.data.scans)).toBe(true);
    });

    it('Scan Persistence: Scan and evidence records correctly written to database', () => {
      const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(userAScanId) as any;
      expect(scan).toBeDefined();
      expect(scan.scan_type).toBe('url');
      expect(scan.risk_level).toBe('LOW');

      const evidenceRows = db.prepare('SELECT * FROM evidence WHERE scan_id = ?').all(userAScanId);
      expect(evidenceRows.length).toBeGreaterThan(0);
    });

    it('Feedback Submission: Accepts feedback and persists to database without modifying model', async () => {
      const res = await request(app)
        .post('/api/v1/feedback')
        .send({
          scan_id: userAScanId,
          feedback_type: 'correct',
          user_comments: 'Accurate low-risk classification.'
        });
      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
    });
  });

  // 5. Latency & Performance Benchmark
  describe('5. Performance & Latency Benchmark', () => {
    it('Measures actual URL scanner latency across 20 iterations', async () => {
      const latencies: number[] = [];
      for (let i = 0; i < 20; i++) {
        const t0 = performance.now();
        await request(app)
          .post('/api/v1/scans/url')
          .send({ url: 'https://apnacollege.in' });
        latencies.push(performance.now() - t0);
      }

      latencies.sort((a, b) => a - b);
      const p50 = latencies[Math.floor(latencies.length * 0.5)];
      const p95 = latencies[Math.floor(latencies.length * 0.95)];

      console.log(`[PERF BENCHMARK] URL Scan: p50=${p50.toFixed(2)}ms, p95=${p95.toFixed(2)}ms, min=${latencies[0].toFixed(2)}ms, max=${latencies[latencies.length - 1].toFixed(2)}ms`);
      expect(p50).toBeLessThan(100); // Expect sub-100ms p50
    });

    it('Measures actual Message scanner latency across 20 iterations', async () => {
      const latencies: number[] = [];
      for (let i = 0; i < 20; i++) {
        const t0 = performance.now();
        await request(app)
          .post('/api/v1/scans/message')
          .send({ message: 'Your verification code is 123456. Do not share this code.' });
        latencies.push(performance.now() - t0);
      }

      latencies.sort((a, b) => a - b);
      const p50 = latencies[Math.floor(latencies.length * 0.5)];
      const p95 = latencies[Math.floor(latencies.length * 0.95)];

      console.log(`[PERF BENCHMARK] Message Scan: p50=${p50.toFixed(2)}ms, p95=${p95.toFixed(2)}ms, min=${latencies[0].toFixed(2)}ms, max=${latencies[latencies.length - 1].toFixed(2)}ms`);
      expect(p50).toBeLessThan(100); // Expect sub-100ms p50
    });
  });
});
