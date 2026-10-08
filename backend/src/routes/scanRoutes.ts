import { Router, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import { db } from '../database/db.js';
import { optionalAuth, requireAuth, AuthenticatedRequest } from '../middleware/auth.js';
import { qrUpload } from '../middleware/upload.js';
import { scanRateLimiter } from '../middleware/rateLimiter.js';
import { analyzeUrl } from '../services/urlAnalyzer.js';
import { analyzeMessage } from '../services/messageAnalyzer.js';
import { analyzeQrImage } from '../services/qrAnalyzer.js';
import { analyzeWebsite } from '../services/websiteAnalyzer.js';
import { calculateUnifiedRisk } from '../services/riskEngine.js';
import { AuditService } from '../services/auditService.js';
import { EvidenceItem, UnifiedRiskResult } from '../types/evidence.js';

export const scanRouter = Router();

const UrlScanSchema = z.object({
  url: z.string().min(1, 'URL is required').max(2048, 'URL length cannot exceed 2048 characters')
});

const MessageScanSchema = z.object({
  message: z.string().min(1, 'Message is required').max(50000, 'Message cannot exceed 50,000 characters'),
  context: z.string().optional()
});

const WebsiteScanSchema = z.object({
  url: z.string().min(1, 'Website URL is required').max(2048)
});

function persistScan(
  userId: string | null,
  scanType: 'url' | 'message' | 'qr' | 'website',
  rawInput: string,
  riskResult: UnifiedRiskResult,
  ip: string
) {
  const scanId = riskResult.analysis_id || `scn_${crypto.createHash('sha256').update(rawInput + Date.now().toString()).digest('hex').substring(0, 16)}`;
  const inputHash = crypto.createHash('sha256').update(rawInput).digest('hex');
  const sanitizedTarget = rawInput.length > 200 ? rawInput.substring(0, 197) + '...' : rawInput;

  const insertScan = db.prepare(`
    INSERT INTO scans (id, user_id, scan_type, input_hash, input_target, risk_level, risk_score, uncertainty, model_versions, raw_summary)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertScan.run(
    scanId,
    userId,
    scanType,
    inputHash,
    sanitizedTarget,
    riskResult.risk_level,
    riskResult.risk_score,
    riskResult.uncertainty,
    JSON.stringify(riskResult.model_versions),
    riskResult.summary
  );

  const insertEvidence = db.prepare(`
    INSERT INTO evidence (id, scan_id, signal_id, source, category, severity, confidence, explanation, detector_version, raw_details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const ev of riskResult.evidence) {
    const evId = `evi_${crypto.createHash('sha256').update(scanId + ev.signal_id + (ev.details ? JSON.stringify(ev.details) : '')).digest('hex').substring(0, 16)}`;
    insertEvidence.run(
      evId,
      scanId,
      ev.signal_id,
      ev.source,
      ev.category,
      ev.severity,
      ev.confidence,
      ev.explanation,
      ev.detector_version,
      ev.details ? JSON.stringify(ev.details) : null
    );
  }

  AuditService.logEvent(userId, `SCAN_${scanType.toUpperCase()}`, ip, {
    scan_id: scanId,
    risk_level: riskResult.risk_level,
    risk_score: riskResult.risk_score
  });

  return scanId;
}

// 1. Scan URL
scanRouter.post('/url', scanRateLimiter, optionalAuth, async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { url } = UrlScanSchema.parse(req.body);
    const { evidence, modelVersions, detectorsUsed } = await analyzeUrl(url);
    const riskResult = calculateUnifiedRisk(evidence, modelVersions, detectorsUsed);
    const scanId = persistScan(req.user?.id || null, 'url', url, riskResult, req.ip || '');

    res.json({
      success: true,
      data: {
        scan_id: scanId,
        scan_type: 'url',
        target: url,
        ...riskResult
      }
    });
  } catch (err) {
    next(err);
  }
});

// 2. Scan Message
scanRouter.post('/message', scanRateLimiter, optionalAuth, async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { message, context } = MessageScanSchema.parse(req.body);
    const { evidence, modelVersions, extractedEntities, subUrlResults, detectorsUsed } = await analyzeMessage(message, context || 'generic');
    const riskResult = calculateUnifiedRisk(evidence, modelVersions, detectorsUsed);
    const scanId = persistScan(req.user?.id || null, 'message', message, riskResult, req.ip || '');

    res.json({
      success: true,
      data: {
        scan_id: scanId,
        scan_type: 'message',
        target: message.length > 80 ? message.substring(0, 77) + '...' : message,
        entities: extractedEntities,
        sub_urls: subUrlResults,
        ...riskResult
      }
    });
  } catch (err) {
    next(err);
  }
});

// 3. Scan QR
scanRouter.post('/qr', scanRateLimiter, optionalAuth, qrUpload.single('image'), async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (!req.file) {
      res.status(400).json({
        success: false,
        error: { code: 'MISSING_FILE', message: 'QR image file is required (PNG, JPG, or WebP).' }
      });
      return;
    }

    const qrResult = await analyzeQrImage(req.file.buffer);
    if (!qrResult.success) {
      res.status(422).json({
        success: false,
        error: { code: 'QR_DECODE_FAILED', message: qrResult.error || 'Failed to decode QR matrix.' }
      });
      return;
    }

    const riskResult = calculateUnifiedRisk(qrResult.evidence, qrResult.modelVersions, qrResult.detectorsUsed);
    const scanId = persistScan(req.user?.id || null, 'qr', qrResult.rawPayload, riskResult, req.ip || '');

    res.json({
      success: true,
      data: {
        scan_id: scanId,
        scan_type: 'qr',
        target: qrResult.rawPayload,
        payload_type: qrResult.payloadType,
        ...riskResult
      }
    });
  } catch (err) {
    next(err);
  }
});

// 4. Scan Website
scanRouter.post('/website', scanRateLimiter, optionalAuth, async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { url } = WebsiteScanSchema.parse(req.body);
    const siteResult = await analyzeWebsite(url);
    const riskResult = calculateUnifiedRisk(siteResult.evidence, siteResult.modelVersions, siteResult.detectorsUsed);
    const scanId = persistScan(req.user?.id || null, 'website', url, riskResult, req.ip || '');

    if (!siteResult.success && siteResult.status === 'blocked_ssrf') {
      res.status(422).json({
        success: false,
        error: { code: 'SSRF_BLOCKED', message: siteResult.error || 'Destination blocked by SSRF defense policy.' },
        data: {
          scan_id: scanId,
          scan_type: 'website',
          target: url,
          status: siteResult.status,
          redirect_chain: siteResult.redirectChain,
          ...riskResult
        }
      });
      return;
    }

    res.json({
      success: true,
      data: {
        scan_id: scanId,
        scan_type: 'website',
        target: url,
        status: siteResult.status,
        final_url: siteResult.finalUrl,
        page_title: siteResult.pageIdentity?.title || 'No Title Found',
        page_identity: siteResult.pageIdentity,
        forms_summary: siteResult.formsSummary,
        forms_detected: siteResult.formsSummary?.totalForms || 0,
        password_fields: siteResult.formsSummary?.passwordForms || 0,
        redirect_chain: siteResult.redirectChain,
        external_form_actions: siteResult.externalFormActions,
        ...riskResult
      }
    });
  } catch (err) {
    next(err);
  }
});

// 5. List User Scan History (Private to Authenticated User)
scanRouter.get('/', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const page = parseInt(req.query.page as string, 10) || 1;
  const limit = parseInt(req.query.limit as string, 10) || 20;
  const offset = (page - 1) * limit;
  const scanType = req.query.type as string;
  const riskLevel = req.query.risk_level as string;
  const search = req.query.search as string;

  let query = 'SELECT * FROM scans WHERE user_id = ?';
  const params: any[] = [userId];

  if (scanType) {
    query += ' AND scan_type = ?';
    params.push(scanType);
  }
  if (riskLevel) {
    query += ' AND risk_level = ?';
    params.push(riskLevel);
  }
  if (search) {
    query += ' AND input_target LIKE ?';
    params.push(`%${search}%`);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const scans = db.prepare(query).all(...params);
  res.json({ success: true, data: { scans, page, limit } });
});

// 6. Get Scan Details with Evidence (Strict Authorization & IDOR Protection)
scanRouter.get('/:id', optionalAuth, (req: AuthenticatedRequest, res: Response): void => {
  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(req.params.id) as any;
  if (!scan) {
    res.status(404).json({ success: false, error: { code: 'SCAN_NOT_FOUND', message: 'Scan result not found' } });
    return;
  }

  // If scan is owned by a user, only that authenticated user can retrieve it
  if (scan.user_id) {
    if (!req.user || req.user.id !== scan.user_id) {
      res.status(404).json({ success: false, error: { code: 'SCAN_NOT_FOUND', message: 'Scan result not found' } });
      return;
    }
  } else {
    // Anonymous scan: If an unauthenticated client tries to harvest arbitrary scan IDs, reject
    if (!req.user) {
      res.status(404).json({ success: false, error: { code: 'SCAN_NOT_FOUND', message: 'Scan result not found' } });
      return;
    }
  }

  const evidence = db.prepare('SELECT * FROM evidence WHERE scan_id = ? ORDER BY created_at ASC').all(req.params.id) as any[];
  const formattedEvidence: EvidenceItem[] = evidence.map(e => ({
    id: e.id,
    signal_id: e.signal_id,
    source: e.source,
    category: e.category,
    severity: e.severity,
    confidence: e.confidence,
    explanation: e.explanation,
    detector_version: e.detector_version,
    details: e.raw_details ? JSON.parse(e.raw_details) : undefined
  }));

  res.json({
    success: true,
    data: {
      scan,
      evidence: formattedEvidence
    }
  });
});

// 7. Delete Scan (IDOR protected, requires Auth)
scanRouter.delete('/:id', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(req.params.id) as any;
  if (!scan) {
    res.status(404).json({ success: false, error: { code: 'SCAN_NOT_FOUND', message: 'Scan not found' } });
    return;
  }

  if (scan.user_id !== req.user!.id) {
    res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Unauthorized to delete this scan' } });
    return;
  }

  db.prepare('DELETE FROM scans WHERE id = ?').run(req.params.id);
  res.json({ success: true, message: 'Scan successfully deleted.' });
});

// 8. Delete All Scans (Privacy Clear, requires Auth)
scanRouter.delete('/', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  db.prepare('DELETE FROM scans WHERE user_id = ?').run(req.user!.id);
  res.json({ success: true, message: 'Scan history cleared.' });
});
