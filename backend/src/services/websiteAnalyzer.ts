import axios, { AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import { URL } from 'url';
import { EvidenceItem, DetectorSummary } from '../types/evidence.js';
import { validateUrlForSSRF } from './ssrfValidator.js';
import { analyzeUrl } from './urlAnalyzer.js';
import { CONFIG } from '../config.js';

export interface RedirectHop {
  url: string;
  statusCode?: number;
  location?: string;
  domainChanged?: boolean;
  protocolDowngrade?: boolean;
}

export interface PageIdentity {
  title: string;
  metaDescription?: string;
  canonicalUrl?: string;
  headings: string[];
}

export interface FormsSummary {
  totalForms: number;
  passwordForms: number;
  paymentLikeForms: number;
  externalActionForms: number;
  insecureActionForms: number;
}

export interface WebsiteAnalysisOutput {
  success: boolean;
  status: 'success' | 'blocked_ssrf' | 'timeout' | 'fetch_error' | 'parse_error' | 'insufficient_data';
  requestedUrl: string;
  finalUrl?: string;
  httpStatus?: number;
  contentType?: string;
  pageIdentity?: PageIdentity;
  formsSummary?: FormsSummary;
  redirectChain: RedirectHop[];
  externalFormActions?: string[];
  evidence: EvidenceItem[];
  modelVersions: string[];
  detectorsUsed: DetectorSummary[];
  limitations: string[];
  latencyMs?: number;
  error?: string;
}

const BRAND_TARGETS: Record<string, string[]> = {
  paypal: ['paypal.com'],
  'bank of america': ['bankofamerica.com'],
  'wells fargo': ['wellsfargo.com'],
  chase: ['chase.com'],
  apple: ['apple.com', 'icloud.com'],
  netflix: ['netflix.com'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
  google: ['google.com', 'accounts.google.com'],
  amazon: ['amazon.com']
};

const EXECUTABLE_EXTENSIONS = /\.(exe|scr|bat|cmd|msi|apk|vbs|ps1|hta)$/i;
const PAYMENT_INPUT_PATTERN = /(card[-_]?num|credit[-_]?card|cvv|cvc|expir|card[-_]?holder|upi[-_]?id|bank[-_]?acc)/i;

/**
 * Extracts registrable domain e.g. login.example.co.uk -> example.co.uk
 */
function getRegistrableDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname;
  // Handle double TLDs like co.uk, com.au, org.in
  const secondLast = parts[parts.length - 2];
  if (['co', 'com', 'org', 'net', 'edu', 'gov'].includes(secondLast) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Safely fetches webpage with bounded multi-hop redirects and continuous SSRF re-validation.
 */
async function safeFetchWebpage(initialUrl: string): Promise<{
  html: string;
  finalUrl: string;
  httpStatus: number;
  contentType: string;
  redirectChain: RedirectHop[];
  ssrfBlockedHop?: string;
}> {
  let currentUrl = initialUrl;
  const redirectChain: RedirectHop[] = [];
  const maxHops = 3;

  for (let hop = 0; hop <= maxHops; hop++) {
    // 1. SSRF check at EVERY hop
    const ssrfCheck = await validateUrlForSSRF(currentUrl);
    if (!ssrfCheck.allowed) {
      return {
        html: '',
        finalUrl: currentUrl,
        httpStatus: 0,
        contentType: '',
        redirectChain,
        ssrfBlockedHop: ssrfCheck.reason
      };
    }

    // 2. Fetch with manual redirect control
    let response: AxiosResponse<any>;
    try {
      response = await axios.get(currentUrl, {
        timeout: CONFIG.WEBSITE_FETCH_TIMEOUT_MS || 4000,
        maxContentLength: CONFIG.WEBSITE_MAX_RESPONSE_BYTES || 2097152, // 2MB limit
        maxRedirects: 0, // Manual redirect handling for continuous SSRF validation
        validateStatus: (status) => status >= 200 && status < 400,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PS5ScamShieldSecurityAudit/2.0',
          'Accept': 'text/html,application/xhtml+xml',
          'Accept-Language': 'en-US,en;q=0.9'
        }
      });
    } catch (err: any) {
      // Check if it's a redirect status code (3xx)
      if (err.response && [301, 302, 303, 307, 308].includes(err.response.status)) {
        const locationHeader = err.response.headers['location'];
        if (!locationHeader) {
          throw new Error(`Redirect status ${err.response.status} returned without Location header`);
        }

        const nextUrl = new URL(locationHeader, currentUrl).toString();
        const prevHost = new URL(currentUrl).hostname;
        const nextHost = new URL(nextUrl).hostname;
        const domainChanged = prevHost !== nextHost;
        const protocolDowngrade = currentUrl.startsWith('https://') && nextUrl.startsWith('http://');

        redirectChain.push({
          url: currentUrl,
          statusCode: err.response.status,
          location: nextUrl,
          domainChanged,
          protocolDowngrade
        });

        currentUrl = nextUrl;
        continue;
      }
      throw err;
    }

    // Successfully reached final page
    const contentType = String(response.headers['content-type'] || 'text/html');
    const html = typeof response.data === 'string' ? response.data : '';

    return {
      html,
      finalUrl: currentUrl,
      httpStatus: response.status,
      contentType,
      redirectChain
    };
  }

  throw new Error(`Exceeded maximum allowed redirects (${maxHops})`);
}

/**
 * Executes comprehensive, passive, deterministic website security analysis.
 */
export async function analyzeWebsite(targetUrl: string): Promise<WebsiteAnalysisOutput> {
  const t0 = Date.now();
  const evidence: EvidenceItem[] = [];
  const modelVersions: string[] = ['website-dom-2.0.0'];
  const detectorsUsed: DetectorSummary[] = [];
  const limitations: string[] = [];

  // Step 1: Initial SSRF Validation
  const initialSsrf = await validateUrlForSSRF(targetUrl);
  if (!initialSsrf.allowed) {
    evidence.push({
      signal_id: 'website.security.ssrf_blocked',
      source: 'website_analyzer',
      category: 'security_violation',
      severity: 'critical',
      confidence: 1.0,
      explanation: `Website scan blocked by SSRF defense policy: ${initialSsrf.reason}`,
      detector_version: 'website-dom-2.0.0',
      details: { url: targetUrl, reason: initialSsrf.reason }
    });

    detectorsUsed.push({
      detector_id: 'website-analyzer',
      detector_version: 'website-dom-2.0.0',
      model_version: '2.0.0',
      input_type: 'website',
      status: 'blocked_ssrf',
      confidence: 1.0,
      latency_ms: Date.now() - t0
    });

    limitations.push('Destination URL belongs to an internal, private, or restricted network zone and cannot be accessed.');

    return {
      success: false,
      status: 'blocked_ssrf',
      requestedUrl: targetUrl,
      redirectChain: [],
      evidence,
      modelVersions,
      detectorsUsed,
      limitations,
      latencyMs: Date.now() - t0,
      error: `SSRF_BLOCKED: ${initialSsrf.reason}`
    };
  }

  // Step 2: Concurrently evaluate URL ML v2.0.0
  const urlScan = await analyzeUrl(targetUrl);
  for (const ev of urlScan.evidence) {
    evidence.push(ev);
  }
  for (const v of urlScan.modelVersions) {
    if (!modelVersions.includes(v)) modelVersions.push(v);
  }
  for (const d of urlScan.detectorsUsed) {
    detectorsUsed.push(d);
  }

  // Step 3: Safe HTTP Fetch with Continuous SSRF Redirect Checks
  let fetchResult: {
    html: string;
    finalUrl: string;
    httpStatus: number;
    contentType: string;
    redirectChain: RedirectHop[];
    ssrfBlockedHop?: string;
  };

  try {
    fetchResult = await safeFetchWebpage(targetUrl);
  } catch (err: any) {
    evidence.push({
      signal_id: 'website.fetch.timeout_or_unreachable',
      source: 'website_analyzer',
      category: 'network',
      severity: 'medium',
      confidence: 0.70,
      explanation: `Target website was unreachable, timed out, or connection failed: ${err.message}`,
      detector_version: 'website-dom-2.0.0',
      details: { requested_url: targetUrl, error: err.message }
    });

    detectorsUsed.push({
      detector_id: 'website-analyzer',
      detector_version: 'website-dom-2.0.0',
      model_version: '2.0.0',
      input_type: 'website',
      status: 'fetch_error',
      confidence: 0,
      latency_ms: Date.now() - t0
    });

    limitations.push('Webpage could not be fetched due to network timeout or connection refusal. Assessment is based on URL structure.');

    return {
      success: true,
      status: 'fetch_error',
      requestedUrl: targetUrl,
      redirectChain: [],
      evidence,
      modelVersions,
      detectorsUsed,
      limitations,
      latencyMs: Date.now() - t0,
      error: err.message
    };
  }

  // Check if any redirect hop triggered SSRF violation
  if (fetchResult.ssrfBlockedHop) {
    evidence.push({
      signal_id: 'website.redirect.ssrf_redirect_blocked',
      source: 'website_analyzer',
      category: 'security_violation',
      severity: 'critical',
      confidence: 1.0,
      explanation: `Redirect hop attempted to route into restricted/private network: ${fetchResult.ssrfBlockedHop}`,
      detector_version: 'website-dom-2.0.0',
      details: { redirect_chain: fetchResult.redirectChain, reason: fetchResult.ssrfBlockedHop }
    });

    detectorsUsed.push({
      detector_id: 'website-analyzer',
      detector_version: 'website-dom-2.0.0',
      model_version: '2.0.0',
      input_type: 'website',
      status: 'blocked_ssrf',
      confidence: 1.0,
      latency_ms: Date.now() - t0
    });

    limitations.push('Redirect chain contained restricted internal network destination.');

    return {
      success: false,
      status: 'blocked_ssrf',
      requestedUrl: targetUrl,
      finalUrl: fetchResult.finalUrl,
      redirectChain: fetchResult.redirectChain,
      evidence,
      modelVersions,
      detectorsUsed,
      limitations,
      latencyMs: Date.now() - t0,
      error: `SSRF_BLOCKED: ${fetchResult.ssrfBlockedHop}`
    };
  }

  // Record Redirect Chain Evidence
  if (fetchResult.redirectChain.length > 0) {
    const domainChangedHops = fetchResult.redirectChain.filter(r => r.domainChanged);
    const protocolDowngrades = fetchResult.redirectChain.filter(r => r.protocolDowngrade);

    if (protocolDowngrades.length > 0) {
      evidence.push({
        signal_id: 'website.redirect.protocol_downgrade',
        source: 'website_analyzer',
        category: 'security_violation',
        severity: 'high',
        confidence: 0.90,
        explanation: 'Insecure protocol downgrade detected: redirect routed from HTTPS to unencrypted HTTP.',
        detector_version: 'website-dom-2.0.0',
        details: { redirect_chain: fetchResult.redirectChain }
      });
    }

    if (domainChangedHops.length >= 2) {
      evidence.push({
        signal_id: 'website.redirect.multiple_cross_domain',
        source: 'website_analyzer',
        category: 'suspicious_redirect',
        severity: 'medium',
        confidence: 0.75,
        explanation: `Multiple cross-domain redirects (${domainChangedHops.length} domain hops) observed before reaching final destination.`,
        detector_version: 'website-dom-2.0.0',
        details: { hops: domainChangedHops.map(h => ({ from: h.url, to: h.location })) }
      });
    }
  }

  // Step 4: Safe HTML Parsing with Cheerio (No Script Execution)
  const $ = cheerio.load(fetchResult.html);
  const rawTitle = $('title').first().text().trim();
  const pageTitle = rawTitle.length > 150 ? rawTitle.substring(0, 147) + '...' : (rawTitle || 'No Title Found');
  const metaDesc = $('meta[name="description"]').attr('content')?.trim();
  const canonicalUrl = $('link[rel="canonical"]').attr('href')?.trim();

  const headings: string[] = [];
  $('h1, h2').slice(0, 5).each((_i, el) => {
    const txt = $(el).text().trim().replace(/\s+/g, ' ');
    if (txt) headings.push(txt.length > 100 ? txt.substring(0, 97) + '...' : txt);
  });

  const pageIdentity: PageIdentity = {
    title: pageTitle,
    metaDescription: metaDesc ? (metaDesc.length > 200 ? metaDesc.substring(0, 197) + '...' : metaDesc) : undefined,
    canonicalUrl,
    headings
  };

  // Step 5: Form & Credential Field Inspection
  const forms = $('form');
  const formsCount = forms.length;
  let passwordCount = 0;
  let paymentLikeCount = 0;
  let externalActionCount = 0;
  let insecureActionCount = 0;
  const externalActions: string[] = [];

  const finalUrlParsed = new URL(fetchResult.finalUrl);
  const pageRegistrableDomain = getRegistrableDomain(finalUrlParsed.hostname);

  forms.each((_i, el) => {
    const formEl = $(el);
    const action = formEl.attr('action')?.trim();
    const method = (formEl.attr('method') || 'GET').toUpperCase();

    // Check inputs inside this form
    const hasPassword = formEl.find('input[type="password"]').length > 0;
    if (hasPassword) passwordCount += formEl.find('input[type="password"]').length;

    let formHasPayment = false;
    formEl.find('input').each((_j, inp) => {
      const name = ($(inp).attr('name') || '').toLowerCase();
      const id = ($(inp).attr('id') || '').toLowerCase();
      const placeholder = ($(inp).attr('placeholder') || '').toLowerCase();
      if (PAYMENT_INPUT_PATTERN.test(name) || PAYMENT_INPUT_PATTERN.test(id) || PAYMENT_INPUT_PATTERN.test(placeholder)) {
        formHasPayment = true;
      }
    });
    if (formHasPayment) paymentLikeCount++;

    // Analyze form destination action
    if (action) {
      if (action.startsWith('http://') || action.startsWith('https://')) {
        try {
          const actionParsed = new URL(action);
          const actionRegistrableDomain = getRegistrableDomain(actionParsed.hostname);

          if (actionRegistrableDomain && actionRegistrableDomain !== pageRegistrableDomain) {
            externalActionCount++;
            externalActions.push(action);
          }

          if (action.startsWith('http://') && fetchResult.finalUrl.startsWith('https://')) {
            insecureActionCount++;
          }
        } catch {}
      }
    }
  });

  const formsSummary: FormsSummary = {
    totalForms: formsCount,
    passwordForms: passwordCount > 0 ? 1 : 0,
    paymentLikeForms: paymentLikeCount,
    externalActionForms: externalActionCount,
    insecureActionForms: insecureActionCount
  };

  // Signal: Credential Harvesting Inputs
  if (passwordCount > 0) {
    evidence.push({
      signal_id: 'website.form.credential_harvesting',
      source: 'website_analyzer',
      category: 'credential_theft',
      severity: 'high',
      confidence: 0.88,
      explanation: `Observed ${passwordCount} password/credential input fields on page.`,
      detector_version: 'website-dom-2.0.0',
      details: { password_fields: passwordCount, form_count: formsCount }
    });
  }

  // Signal: Form submits credentials or payment data to an external mismatched origin
  if (externalActionCount > 0 && (passwordCount > 0 || paymentLikeCount > 0)) {
    evidence.push({
      signal_id: 'website.form.mismatched_action_target',
      source: 'website_analyzer',
      category: 'credential_theft',
      severity: 'critical',
      confidence: 0.96,
      explanation: `High-risk form action detected: form with credential/payment inputs submits data to mismatched external origin (${externalActions[0]}).`,
      detector_version: 'website-dom-2.0.0',
      details: { external_endpoints: externalActions, page_domain: pageRegistrableDomain }
    });
  }

  // Signal: Insecure HTTP Form Action from HTTPS page
  if (insecureActionCount > 0) {
    evidence.push({
      signal_id: 'website.form.insecure_http_action',
      source: 'website_analyzer',
      category: 'security_violation',
      severity: 'high',
      confidence: 0.90,
      explanation: 'Insecure data submission: form submits input over unencrypted HTTP protocol from an HTTPS origin.',
      detector_version: 'website-dom-2.0.0',
      details: { insecure_form_count: insecureActionCount }
    });
  }

  // Step 6: Brand / Claimed Identity Mismatch Analysis
  const titleText = (pageTitle + ' ' + headings.join(' ')).toLowerCase();
  for (const [brand, officialDomains] of Object.entries(BRAND_TARGETS)) {
    if (titleText.includes(brand)) {
      const matchesOfficial = officialDomains.some(d => pageRegistrableDomain === d || pageRegistrableDomain.endsWith(`.${d}`));
      if (!matchesOfficial) {
        evidence.push({
          signal_id: 'website.brand.identity_mismatch',
          source: 'website_analyzer',
          category: 'impersonation',
          severity: 'high',
          confidence: 0.92,
          explanation: `Page title and content claim to be '${brand.toUpperCase()}', but the destination domain '${pageRegistrableDomain}' does not belong to authorized brand domains.`,
          detector_version: 'website-dom-2.0.0',
          details: { claimed_brand: brand, actual_domain: pageRegistrableDomain, expected_domains: officialDomains }
        });
        break;
      }
    }
  }

  // Step 7: Executable Download Link Inspection
  let executableLinksCount = 0;
  $('a[href]').each((_i, el) => {
    const href = $(el).attr('href') || '';
    if (EXECUTABLE_EXTENSIONS.test(href)) {
      executableLinksCount++;
    }
  });

  if (executableLinksCount > 0) {
    evidence.push({
      signal_id: 'website.download.executable_payload',
      source: 'website_analyzer',
      category: 'malware_distribution',
      severity: 'high',
      confidence: 0.85,
      explanation: `Detected ${executableLinksCount} direct download links to executable binary files (.exe, .scr, .msi, .apk).`,
      detector_version: 'website-dom-2.0.0',
      details: { executable_count: executableLinksCount }
    });
  }

  // Step 8: Suspicious Hidden Iframes
  let hiddenIframesCount = 0;
  $('iframe').each((_i, el) => {
    const width = $(el).attr('width');
    const height = $(el).attr('height');
    const style = ($(el).attr('style') || '').toLowerCase();
    if (width === '0' || height === '0' || style.includes('display:none') || style.includes('visibility:hidden')) {
      hiddenIframesCount++;
    }
  });

  if (hiddenIframesCount > 0) {
    evidence.push({
      signal_id: 'website.dom.hidden_iframe',
      source: 'website_analyzer',
      category: 'obfuscation',
      severity: 'medium',
      confidence: 0.80,
      explanation: `Observed ${hiddenIframesCount} hidden zero-pixel iframe elements on page.`,
      detector_version: 'website-dom-2.0.0',
      details: { hidden_iframes: hiddenIframesCount }
    });
  }

  detectorsUsed.push({
    detector_id: 'website-analyzer',
    detector_version: 'website-dom-2.0.0',
    model_version: '2.0.0',
    input_type: 'website',
    status: 'success',
    confidence: 1.0,
    latency_ms: Date.now() - t0
  });

  limitations.push('Website analysis is based on static HTML inspection without browser JavaScript execution.');

  return {
    success: true,
    status: 'success',
    requestedUrl: targetUrl,
    finalUrl: fetchResult.finalUrl,
    httpStatus: fetchResult.httpStatus,
    contentType: fetchResult.contentType,
    pageIdentity,
    formsSummary,
    redirectChain: fetchResult.redirectChain,
    externalFormActions: externalActions,
    evidence,
    modelVersions,
    detectorsUsed,
    limitations,
    latencyMs: Date.now() - t0
  };
}
