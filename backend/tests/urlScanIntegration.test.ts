import request from 'supertest';
import { app } from '../src/app';
import { runMigrations } from '../src/database/migrations';
import { MLClient } from '../src/services/mlClient';

beforeAll(() => {
  runMigrations();
});

describe('URL Scan Production End-to-End Integration Tests', () => {
  test('POST /api/v1/scans/url - Apna College /start legitimate scan', async () => {
    // Mock or live MLClient inference
    jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
      model_id: 'url-phishing',
      model_version: '2.0.0',
      detector_version: 'url-detector-2.0.0',
      score: 0.000672,
      raw_score: 0.000048,
      calibrated_probability: 0.000672,
      calibrated: true,
      predicted_class: 'legitimate',
      top_signals: [],
      features: {
        url_length: 32,
        hostname_length: 18,
        path_length: 6,
        is_https: 1
      },
      feature_extraction_time_ms: 0.25,
      model_inference_time_ms: 5.2,
      processing_time_ms: 5.5,
      errors: []
    });

    const res = await request(app)
      .post('/api/v1/scans/url')
      .send({ url: 'https://www.apnacollege.in/start' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.scan_type).toBe('url');
    expect(res.body.data.target).toBe('https://www.apnacollege.in/start');
    expect(res.body.data.risk_level).toBe('LOW');
    expect(res.body.data.risk_score).toBeLessThan(25);
    expect(res.body.data.model_versions).toContain('url-phishing-2.0.0');

    const mlEvidence = res.body.data.evidence.find((e: any) => e.signal_id === 'url.ml.benign_prediction');
    expect(mlEvidence).toBeDefined();
    expect(mlEvidence.detector_version).toBe('url-phishing-2.0.0');
    expect(mlEvidence.details.calibrated_probability).toBe(0.000672);
  });

  test('POST /api/v1/scans/url - Apna College deep LMS player regression fix', async () => {
    const deepUrl = 'https://www.apnacollege.in/path-player?courseid=alpha-plus-6&unit=68dbea2c4069da29a90e18bfUnit';
    jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
      model_id: 'url-phishing',
      model_version: '2.0.0',
      detector_version: 'url-detector-2.0.0',
      score: 0.000672,
      raw_score: 0.000036,
      calibrated_probability: 0.000672,
      calibrated: true,
      predicted_class: 'legitimate',
      top_signals: [],
      features: {
        url_length: 94,
        num_digits: 14,
        is_https: 1
      },
      feature_extraction_time_ms: 0.15,
      model_inference_time_ms: 4.8,
      processing_time_ms: 5.0,
      errors: []
    });

    const res = await request(app)
      .post('/api/v1/scans/url')
      .send({ url: deepUrl });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.risk_level).toBe('LOW');
    expect(res.body.data.risk_score).toBeLessThan(25);
    expect(res.body.data.model_versions).toContain('url-phishing-2.0.0');
  });

  test('POST /api/v1/scans/url - Phishing lure detection', async () => {
    const phishUrl = 'http://paypal-account-verification-alert99.tk/login.php';
    jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
      model_id: 'url-phishing',
      model_version: '2.0.0',
      detector_version: 'url-detector-2.0.0',
      score: 0.99909,
      raw_score: 0.9728,
      calibrated_probability: 0.99909,
      calibrated: true,
      predicted_class: 'phishing',
      top_signals: [{ signal: 'suspicious_tld', severity: 'medium', weight: 0.25 }],
      features: {
        url_length: 55,
        has_suspicious_tld: 1
      },
      feature_extraction_time_ms: 0.12,
      model_inference_time_ms: 4.5,
      processing_time_ms: 4.7,
      errors: []
    });

    const res = await request(app)
      .post('/api/v1/scans/url')
      .send({ url: phishUrl });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(['HIGH', 'CRITICAL']).toContain(res.body.data.risk_level);
    expect(res.body.data.risk_score).toBeGreaterThanOrEqual(60);
    expect(res.body.data.model_versions).toContain('url-phishing-2.0.0');
  });

  test('POST /api/v1/scans/url - Validation error on empty URL', async () => {
    const res = await request(app)
      .post('/api/v1/scans/url')
      .send({ url: '' });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('POST /api/v1/scans/url - Validation error on URL > 2048 chars', async () => {
    const hugeUrl = 'https://example.com/' + 'a'.repeat(2100);
    const res = await request(app)
      .post('/api/v1/scans/url')
      .send({ url: hugeUrl });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });
});
