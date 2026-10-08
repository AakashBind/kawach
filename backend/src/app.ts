import express from 'express';
import path from 'path';
import fs from 'fs';
import cors from 'cors';
import helmet from 'helmet';
import { authRouter } from './routes/authRoutes.js';
import { scanRouter } from './routes/scanRoutes.js';
import { reportRouter } from './routes/reportRoutes.js';
import { feedbackRouter } from './routes/feedbackRoutes.js';
import { modelRouter } from './routes/modelRoutes.js';
import { healthRouter } from './routes/healthRoutes.js';
import { assistantRouter } from './routes/assistantRoutes.js';
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
app.use('/api/v1/assistant', assistantRouter);

// Frontend static serving for production unified deployment
const clientDistCandidates = [
  path.resolve(process.cwd(), '../frontend/dist'),
  path.resolve(process.cwd(), 'frontend/dist'),
  path.resolve(process.cwd(), 'public'),
  path.resolve(__dirname, '../../frontend/dist')
];
const clientDist = clientDistCandidates.find(p => fs.existsSync(p));
if (clientDist) {
  app.use(express.static(clientDist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    res.sendFile(path.join(clientDist, 'index.html'));
  });
}

// Global Error Handler
app.use(errorHandler);
