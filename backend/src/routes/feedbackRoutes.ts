import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { db } from '../database/db.js';
import { AuditService } from '../services/auditService.js';

export const feedbackRouter = Router();

const FeedbackSchema = z.object({
  scan_id: z.string().min(1, 'Scan ID is required'),
  feedback_type: z.enum(['false_positive', 'false_negative', 'correct']),
  user_comments: z.string().max(1000).optional()
});

feedbackRouter.post('/', (req: Request, res: Response, next: NextFunction): void => {
  try {
    const { scan_id, feedback_type, user_comments } = FeedbackSchema.parse(req.body);
    const feedbackId = `fb_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;

    db.prepare(`
      INSERT INTO feedback (id, scan_id, feedback_type, user_comments)
      VALUES (?, ?, ?, ?)
    `).run(feedbackId, scan_id, feedback_type, user_comments || null);

    AuditService.logEvent(null, 'USER_FEEDBACK_SUBMITTED', req.ip || '', { feedback_id: feedbackId, scan_id, feedback_type });

    res.status(201).json({
      success: true,
      data: {
        feedback_id: feedbackId,
        message: 'Feedback recorded for manual security review. Thank you for improving detection accuracy.'
      }
    });
  } catch (err) {
    next(err);
  }
});
