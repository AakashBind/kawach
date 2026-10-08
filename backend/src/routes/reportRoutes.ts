import { Router, Response, NextFunction } from 'express';
import { z } from 'zod';
import { db } from '../database/db.js';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth.js';
import { AuditService } from '../services/auditService.js';

export const reportRouter = Router();

const ReportSchema = z.object({
  scan_id: z.string().optional(),
  category: z.string().min(1, 'Category is required'),
  description: z.string().min(5, 'Please provide a detailed description (at least 5 characters)'),
  evidence_summary: z.string().optional()
});

// 1. Submit Fraud & Incident Report (Requires Authentication)
reportRouter.post('/', requireAuth, (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  try {
    const { scan_id, category, description, evidence_summary } = ReportSchema.parse(req.body);
    const userId = req.user!.id;

    // Cross-user scan attachment prevention:
    // If a scan_id is attached to this report, verify it belongs to the authenticated user
    if (scan_id) {
      const referencedScan = db.prepare('SELECT id, user_id FROM scans WHERE id = ?').get(scan_id) as any;
      if (referencedScan && referencedScan.user_id && referencedScan.user_id !== userId) {
        res.status(403).json({
          success: false,
          error: {
            code: 'FORBIDDEN_SCAN_ATTACHMENT',
            message: 'Referenced scan does not belong to the authenticated user.'
          }
        });
        return;
      }
    }

    const reportId = `rep_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;

    db.prepare(`
      INSERT INTO reports (id, user_id, scan_id, category, description, status, evidence_summary)
      VALUES (?, ?, ?, ?, ?, 'submitted', ?)
    `).run(reportId, userId, scan_id || null, category, description, evidence_summary || null);

    AuditService.logEvent(userId, 'FRAUD_REPORT_SUBMITTED', req.ip || '', { report_id: reportId, category, scan_id });

    res.status(201).json({
      success: true,
      data: {
        report_id: reportId,
        status: 'submitted',
        message: 'Fraud incident report recorded successfully.'
      }
    });
  } catch (err) {
    next(err);
  }
});

// 2. Get Incident Reports (Requires Authentication - User's Own Reports Only)
reportRouter.get('/', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const reports = db.prepare('SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(userId);
  res.json({ success: true, data: { reports } });
});

