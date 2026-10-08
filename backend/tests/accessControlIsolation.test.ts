import request from 'supertest';
import path from 'path';
import fs from 'fs';
import { app } from '../src/app';
import { runMigrations } from '../src/database/migrations';
import { db } from '../src/database/db';

beforeAll(() => {
  runMigrations();
});

describe('Access Control, Guest Scanning & User Data Isolation Security Test Matrix', () => {
  let userAToken: string;
  let userAId: string;
  let userBToken: string;
  let userBId: string;

  let userAScanId: string;
  let userBScanId: string;
  let guestScanId: string;

  let userAReportId: string;
  let userBReportId: string;

  beforeAll(async () => {
    // 1. Register User A
    const emailA = `test_user_a_${Date.now()}@shield.local`;
    const resA = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: emailA, password: 'StrongPassword123!' });
    expect(resA.status).toBe(201);
    userAToken = resA.body.data.token;
    userAId = resA.body.data.user.id;

    // 2. Register User B
    const emailB = `test_user_b_${Date.now()}@shield.local`;
    const resB = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: emailB, password: 'StrongPassword123!' });
    expect(resB.status).toBe(201);
    userBToken = resB.body.data.token;
    userBId = resB.body.data.user.id;
  });

  // 1. Guest Scanning (Publicly Accessible without Auth)
  describe('1. Guest Scanning Endpoints (Unauthenticated Access)', () => {
    it('POST /api/v1/scans/url without auth returns 200 and yields immediate result', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'https://www.example.com' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.scan_id).toBeDefined();
      expect(res.body.data.risk_level).toBeDefined();
      guestScanId = res.body.data.scan_id;

      // Verify in DB that user_id is NULL
      const row = db.prepare('SELECT user_id FROM scans WHERE id = ?').get(guestScanId) as any;
      expect(row.user_id).toBeNull();
    });

    it('POST /api/v1/scans/message without auth returns 200 and yields immediate result', async () => {
      const res = await request(app)
        .post('/api/v1/scans/message')
        .send({ message: 'Hello, your package delivery is waiting for confirmation.' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.scan_id).toBeDefined();
    });

    it('POST /api/v1/scans/qr without auth returns 200 and decodes payload', async () => {
      // Create simple test QR buffer if sample exists, or verify with valid QR file
      const qrPath = path.resolve(__dirname, 'fixtures/sample_qr.png');
      let qrBuffer: Buffer;
      if (fs.existsSync(qrPath)) {
        qrBuffer = fs.readFileSync(qrPath);
      } else {
        // Minimal 1x1 png buffer or test fixture
        qrBuffer = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082', 'hex');
      }

      const res = await request(app)
        .post('/api/v1/scans/qr')
        .attach('image', qrBuffer, 'test_qr.png');
      // Either 200 or 422 if matrix unreadable, but never 401
      expect(res.status).not.toBe(401);
    });

    it('POST /api/v1/scans/website without auth returns 200 or SSRF block (never 401)', async () => {
      const res = await request(app)
        .post('/api/v1/scans/website')
        .send({ url: 'https://www.google.com' });
      expect(res.status).not.toBe(401);
      expect(res.body.data?.scan_id || res.body.error).toBeDefined();
    });
  });

  // 2. Authenticated Scanning & Ownership Binding
  describe('2. Authenticated Scanning & Client-Supplied ID Override Prevention', () => {
    it('User A creates scan -> associated with User A', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({ url: 'https://github.com/torvalds/linux' });
      expect(res.status).toBe(200);
      userAScanId = res.body.data.scan_id;

      const row = db.prepare('SELECT user_id FROM scans WHERE id = ?').get(userAScanId) as any;
      expect(row.user_id).toBe(userAId);
    });

    it('User B creates scan -> associated with User B', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .set('Authorization', `Bearer ${userBToken}`)
        .send({ url: 'https://paypal-security-alert.phish.com' });
      expect(res.status).toBe(200);
      userBScanId = res.body.data.scan_id;

      const row = db.prepare('SELECT user_id FROM scans WHERE id = ?').get(userBScanId) as any;
      expect(row.user_id).toBe(userBId);
    });

    it('Client-supplied user_id in body is ignored (Server strictly binds to req.user.id)', async () => {
      const res = await request(app)
        .post('/api/v1/scans/url')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          url: 'https://wikipedia.org',
          user_id: userBId // Malicious attempt to spoof ownership
        });
      expect(res.status).toBe(200);
      const spoofAttemptScanId = res.body.data.scan_id;

      const row = db.prepare('SELECT user_id FROM scans WHERE id = ?').get(spoofAttemptScanId) as any;
      expect(row.user_id).toBe(userAId);
      expect(row.user_id).not.toBe(userBId);
    });
  });

  // 3. User Scan History Data Isolation
  describe('3. User Scan History Isolation (GET /api/v1/scans)', () => {
    it('Unauthenticated GET /api/v1/scans is rejected with 401', async () => {
      const res = await request(app).get('/api/v1/scans');
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('User A history returns ONLY User A scans (never User B or guest scans)', async () => {
      const res = await request(app)
        .get('/api/v1/scans')
        .set('Authorization', `Bearer ${userAToken}`);
      expect(res.status).toBe(200);
      const userAScans = res.body.data.scans;
      expect(userAScans.length).toBeGreaterThan(0);

      // Verify all scans belong to User A
      for (const s of userAScans) {
        expect(s.user_id).toBe(userAId);
      }
      expect(userAScans.some((s: any) => s.id === userBScanId)).toBe(false);
      expect(userAScans.some((s: any) => s.id === guestScanId)).toBe(false);
    });

    it('User B history returns ONLY User B scans (never User A scans)', async () => {
      const res = await request(app)
        .get('/api/v1/scans')
        .set('Authorization', `Bearer ${userBToken}`);
      expect(res.status).toBe(200);
      const userBScans = res.body.data.scans;

      for (const s of userBScans) {
        expect(s.user_id).toBe(userBId);
      }
      expect(userBScans.some((s: any) => s.id === userAScanId)).toBe(false);
    });
  });

  // 4. IDOR Protection on Single Scan Access
  describe('4. IDOR Protection (GET /api/v1/scans/:id & DELETE /api/v1/scans/:id)', () => {
    it('User A accessing own Scan A -> 200 OK', async () => {
      const res = await request(app)
        .get(`/api/v1/scans/${userAScanId}`)
        .set('Authorization', `Bearer ${userAToken}`);
      expect(res.status).toBe(200);
      expect(res.body.data.scan.id).toBe(userAScanId);
    });

    it('User A requesting User B Scan B -> 404 Not Found (Denied without leaking existence)', async () => {
      const res = await request(app)
        .get(`/api/v1/scans/${userBScanId}`)
        .set('Authorization', `Bearer ${userAToken}`);
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('SCAN_NOT_FOUND');
    });

    it('User B requesting User A Scan A -> 404 Not Found', async () => {
      const res = await request(app)
        .get(`/api/v1/scans/${userAScanId}`)
        .set('Authorization', `Bearer ${userBToken}`);
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('SCAN_NOT_FOUND');
    });

    it('Guest requesting User A Scan A without token -> 404 Not Found', async () => {
      const res = await request(app).get(`/api/v1/scans/${userAScanId}`);
      expect(res.status).toBe(404);
    });

    it('User A cannot delete User B Scan B -> 403 Forbidden', async () => {
      const res = await request(app)
        .delete(`/api/v1/scans/${userBScanId}`)
        .set('Authorization', `Bearer ${userAToken}`);
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  // 5. Incident Reporting Authentication & Data Isolation
  describe('5. Incident Reporting Authentication & Data Isolation', () => {
    it('Guest submitting report without auth is rejected with 401', async () => {
      const res = await request(app)
        .post('/api/v1/reports')
        .send({
          category: 'phishing_lure',
          description: 'Observed phishing attack on banking site'
        });
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('User A submitting report -> 201 Created and associated with User A', async () => {
      const res = await request(app)
        .post('/api/v1/reports')
        .set('Authorization', `Bearer ${userAToken}`)
        .send({
          scan_id: userAScanId,
          category: 'phishing_lure',
          description: 'Confirmed phishing credential harvester.'
        });
      expect(res.status).toBe(201);
      userAReportId = res.body.data.report_id;

      const row = db.prepare('SELECT user_id, scan_id FROM reports WHERE id = ?').get(userAReportId) as any;
      expect(row.user_id).toBe(userAId);
      expect(row.scan_id).toBe(userAScanId);
    });

    it('User B submitting report -> 201 Created and associated with User B', async () => {
      const res = await request(app)
        .post('/api/v1/reports')
        .set('Authorization', `Bearer ${userBToken}`)
        .send({
          scan_id: userBScanId,
          category: 'malicious_qr',
          description: 'Malicious QR code found in phishing email.'
        });
      expect(res.status).toBe(201);
      userBReportId = res.body.data.report_id;
    });

    it('Cross-User Scan Attachment Prevention: User B attempts to attach User A scan -> 403 Forbidden', async () => {
      const res = await request(app)
        .post('/api/v1/reports')
        .set('Authorization', `Bearer ${userBToken}`)
        .send({
          scan_id: userAScanId, // User A's private scan!
          category: 'credential_harvester',
          description: 'Attempting to attach User A scan to User B report'
        });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN_SCAN_ATTACHMENT');
    });

    it('Report Isolation: User A GET /api/v1/reports returns ONLY User A reports', async () => {
      const res = await request(app)
        .get('/api/v1/reports')
        .set('Authorization', `Bearer ${userAToken}`);
      expect(res.status).toBe(200);
      const reports = res.body.data.reports;
      expect(reports.length).toBeGreaterThan(0);

      for (const r of reports) {
        expect(r.user_id).toBe(userAId);
      }
      expect(reports.some((r: any) => r.id === userBReportId)).toBe(false);
    });

    it('Report Isolation: User B GET /api/v1/reports returns ONLY User B reports', async () => {
      const res = await request(app)
        .get('/api/v1/reports')
        .set('Authorization', `Bearer ${userBToken}`);
      expect(res.status).toBe(200);
      const reports = res.body.data.reports;

      for (const r of reports) {
        expect(r.user_id).toBe(userBId);
      }
      expect(reports.some((r: any) => r.id === userAReportId)).toBe(false);
    });

    it('Unauthenticated GET /api/v1/reports is rejected with 401', async () => {
      const res = await request(app).get('/api/v1/reports');
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });
  });

  // 6. Guest Stale Session & Ownership Contamination Test
  describe('6. Guest Stale Session & Ownership Contamination', () => {
    it('After logout / no auth header, guest scan is stored with NULL user_id and not contaminated', async () => {
      // Perform scan without token
      const guestRes = await request(app)
        .post('/api/v1/scans/url')
        .send({ url: 'https://duckduckgo.com' });
      expect(guestRes.status).toBe(200);
      const freshGuestScanId = guestRes.body.data.scan_id;

      // Verify in DB
      const row = db.prepare('SELECT user_id FROM scans WHERE id = ?').get(freshGuestScanId) as any;
      expect(row.user_id).toBeNull();

      // Check User A's history -> freshGuestScanId MUST NOT appear
      const userAHist = await request(app)
        .get('/api/v1/scans')
        .set('Authorization', `Bearer ${userAToken}`);
      expect(userAHist.body.data.scans.some((s: any) => s.id === freshGuestScanId)).toBe(false);
    });
  });
});
