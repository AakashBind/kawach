import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';

export function errorHandler(err: any, req: Request, res: Response, _next: NextFunction): void {
  const requestId = (req.headers['x-request-id'] as string) || `req_${Date.now().toString(36)}`;

  if (err instanceof ZodError) {
    res.status(400).json({
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request payload failed schema validation.',
        request_id: requestId,
        timestamp: new Date().toISOString(),
        details: err.errors.map(e => ({ path: e.path.join('.'), message: e.message }))
      }
    });
    return;
  }

  const statusCode = err.status || err.statusCode || 500;
  const errorCode = err.code || (statusCode === 400 ? 'INVALID_REQUEST' : 'INTERNAL_SERVER_ERROR');

  res.status(statusCode).json({
    success: false,
    error: {
      code: errorCode,
      message: err.message || 'An unexpected error occurred processing your request.',
      request_id: requestId,
      timestamp: new Date().toISOString()
    }
  });
}
