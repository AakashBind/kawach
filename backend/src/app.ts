import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { authRouter } from './routes/authRoutes.js';
import { scanRouter } from './routes/scanRoutes.js';
import { reportRouter } from './routes/reportRoutes.js';
import { feedbackRouter } from './routes/feedbackRoutes.js';
import { modelRouter } from './routes/modelRoutes.js';
import { healthRouter } from './routes/healthRoutes.js';
import { errorHandler } from './middleware/errorHandler.js';
import { CONFIG } from './config.js';

export const app = express();

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow API usage across clients
}));

app.use(cors({
  origin: CONFIG.CORS_ORIGIN,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-request-id']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// REST API v1 Routes
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/scans', scanRouter);
app.use('/api/v1/reports', reportRouter);
app.use('/api/v1/feedback', feedbackRouter);
app.use('/api/v1/models', modelRouter);
app.use('/api/v1/health', healthRouter);

// Global Error Handler
app.use(errorHandler);
