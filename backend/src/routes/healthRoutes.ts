import { Router, Request, Response } from 'express';
import { db } from '../database/db.js';
import { MLClient } from '../services/mlClient.js';

export const healthRouter = Router();

healthRouter.get('/', async (_req: Request, res: Response): Promise<void> => {
  let dbHealthy = false;
  try {
    const row = db.prepare('SELECT 1 as alive').get();
    dbHealthy = !!row;
  } catch {
    dbHealthy = false;
  }

  const mlHealthy = await MLClient.checkHealth();

  const isAllHealthy = dbHealthy;
  const status = isAllHealthy ? 'healthy' : 'degraded';

  res.status(isAllHealthy ? 200 : 503).json({
    status,
    timestamp: new Date().toISOString(),
    components: {
      api_gateway: 'healthy',
      database: dbHealthy ? 'healthy' : 'unreachable',
      python_ml_service: mlHealthy ? 'healthy' : 'unavailable'
    }
  });
});
