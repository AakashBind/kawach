import { db } from '../database/db.js';
import crypto from 'crypto';

export class AuditService {
  public static logEvent(actorId: string | null, eventType: string, ip: string, payload: Record<string, any> = {}) {
    try {
      const ipHash = crypto.createHash('sha256').update(ip || 'unknown').digest('hex').substring(0, 16);
      const id = `aud_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
      const stmt = db.prepare(`
        INSERT INTO audit_events (id, actor_id, event_type, ip_hash, payload)
        VALUES (?, ?, ?, ?, ?)
      `);
      stmt.run(id, actorId, eventType, ipHash, JSON.stringify(payload));
    } catch (err: any) {
      console.warn(`[AuditService] Failed to log audit event: ${err.message}`);
    }
  }
}
