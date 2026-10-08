import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

export const CONFIG = {
  PORT: process.env.PORT ? parseInt(process.env.PORT, 10) : 5000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  DATABASE_PATH: process.env.DATABASE_PATH || path.join(process.cwd(), 'data', 'scam_shield.db'),
  ML_SERVICE_URL: process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000',
  JWT_SECRET: process.env.JWT_SECRET || 'ps5_super_secure_jwt_secret_dev_2026_production_zero_cost',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d',
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
  MAX_UPLOAD_BYTES: 5 * 1024 * 1024, // 5MB
  WEBSITE_FETCH_TIMEOUT_MS: 5000, // 5 seconds
  WEBSITE_MAX_RESPONSE_BYTES: 2 * 1024 * 1024, // 2MB
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 mins
  RATE_LIMIT_MAX_REQUESTS: 120
};
