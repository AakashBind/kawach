import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { db } from '../database/db.js';
import { CONFIG } from '../config.js';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth.js';
import { authRateLimiter } from '../middleware/rateLimiter.js';
import { AuditService } from '../services/auditService.js';

export const authRouter = Router();

const AuthSchema = z.object({
  email: z.string().email('Invalid email address format'),
  password: z.string().min(8, 'Password must be at least 8 characters long')
});

authRouter.post('/register', authRateLimiter, (req: Request, res: Response, next: NextFunction): void => {
  try {
    const { email, password } = AuthSchema.parse(req.body);
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (existing) {
      res.status(400).json({
        success: false,
        error: { code: 'EMAIL_ALREADY_EXISTS', message: 'An account with this email already exists.' }
      });
      return;
    }

    const userId = `usr_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(password, salt);

    db.prepare('INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)').run(
      userId,
      email.toLowerCase(),
      passwordHash,
      'user'
    );

    const token = jwt.sign({ id: userId, email: email.toLowerCase(), role: 'user' }, CONFIG.JWT_SECRET, {
      expiresIn: '7d'
    });

    AuditService.logEvent(userId, 'USER_REGISTERED', req.ip || '', { email: email.toLowerCase() });

    res.status(201).json({
      success: true,
      data: {
        user: { id: userId, email: email.toLowerCase(), role: 'user' },
        token
      }
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/login', authRateLimiter, (req: Request, res: Response, next: NextFunction): void => {
  try {
    const { email, password } = AuthSchema.parse(req.body);
    const user = db.prepare('SELECT id, email, password_hash, role FROM users WHERE email = ?').get(email.toLowerCase()) as any;
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      AuditService.logEvent(null, 'LOGIN_FAILED', req.ip || '', { email: email.toLowerCase() });
      res.status(401).json({
        success: false,
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' }
      });
      return;
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, CONFIG.JWT_SECRET, {
      expiresIn: '7d'
    });

    AuditService.logEvent(user.id, 'LOGIN_SUCCESS', req.ip || '', { email: user.email });

    res.json({
      success: true,
      data: {
        user: { id: user.id, email: user.email, role: user.role },
        token
      }
    });
  } catch (err) {
    next(err);
  }
});

authRouter.get('/me', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const user = db.prepare('SELECT id, email, role, created_at FROM users WHERE id = ?').get(req.user!.id) as any;
  if (!user) {
    res.status(404).json({ success: false, error: { code: 'USER_NOT_FOUND', message: 'User not found' } });
    return;
  }
  res.json({ success: true, data: { user } });
});
