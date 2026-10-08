import request from 'supertest';
import { app } from '../src/app';
import { runMigrations } from '../src/database/migrations';

beforeAll(() => {
  runMigrations();
});

describe('Backend API Endpoints Integration Tests', () => {
  test('GET /api/v1/health should return health status', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
    expect(res.body.components.database).toBe('healthy');
  });

  test('POST /api/v1/auth/register and /login flow', async () => {
    const testEmail = `test_${Date.now()}@example.com`;
    const password = 'StrongPassword123!';

    // Register
    const regRes = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: testEmail, password });
    expect(regRes.status).toBe(201);
    expect(regRes.body.success).toBe(true);
    expect(regRes.body.data.token).toBeDefined();

    // Login
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: testEmail, password });
    expect(loginRes.status).toBe(200);
    expect(loginRes.body.data.token).toBeDefined();
  });

  test('POST /api/v1/scans/url should scan suspicious URL', async () => {
    const res = await request(app)
      .post('/api/v1/scans/url')
      .send({ url: 'http://192.168.1.1/paypal-verification-alert.tk/login' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.scan_id).toBeDefined();
    expect(res.body.data.risk_score).toBeGreaterThan(0);
    expect(res.body.data.evidence.length).toBeGreaterThan(0);
  });

  test('POST /api/v1/scans/message should scan scam text', async () => {
    const res = await request(app)
      .post('/api/v1/scans/message')
      .send({
        message: 'URGENT: Your account will be locked in 24 hours. Send $500 to restore access at http://paypal-alert.tk',
        context: 'sms'
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.entities).toBeDefined();
    expect(res.body.data.evidence.length).toBeGreaterThan(0);
  });

  test('GET /api/v1/models should return model governance metadata and confusion matrix', async () => {
    const res = await request(app).get('/api/v1/models');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.registered_models.length).toBeGreaterThan(0);

    const urlModel = res.body.data.registered_models.find((m: any) => m.model_id === 'url-phishing');
    expect(urlModel).toBeDefined();
    expect(urlModel.version).toBe('2.0.0');
    expect(urlModel.metrics).toBeDefined();
    expect(urlModel.metrics.confusion_matrix).toBeDefined();

    const cm = urlModel.metrics.confusion_matrix;
    const tn = cm.true_negatives ?? cm.tn;
    const fp = cm.false_positives ?? cm.fp;
    const fn = cm.false_negatives ?? cm.fn;
    const tp = cm.true_positives ?? cm.tp;

    expect(tn).toBe(1597);
    expect(fp).toBe(0);
    expect(fn).toBe(0);
    expect(tp).toBe(1452);
  });

  test('POST /api/v1/feedback should accept scan feedback', async () => {
    const scanRes = await request(app)
      .post('/api/v1/scans/url')
      .send({ url: 'https://www.google.com' });

    const scanId = scanRes.body.data.scan_id;

    const fbRes = await request(app)
      .post('/api/v1/feedback')
      .send({
        scan_id: scanId,
        feedback_type: 'correct',
        user_comments: 'Clean and legitimate website.'
      });

    expect(fbRes.status).toBe(201);
    expect(fbRes.body.success).toBe(true);
  });
});
