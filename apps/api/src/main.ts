/**
 * SecureScan AI - API Gateway Entry Point
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { logger } from '@securescan/logger';
import { authRouter } from './routes/auth.routes.js';
import { orgRouter } from './routes/org.routes.js';
import { assetRouter } from './routes/asset.routes.js';
import { scanRouter } from './routes/scan.routes.js';
import { findingRouter } from './routes/finding.routes.js';
import { aiRouter } from './routes/ai.routes.js';
import { reportRouter } from './routes/report.routes.js';

dotenv.config();

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Promise Rejection caught', { reason: String(reason) });
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception caught', { error: err.message, stack: err.stack });
});

const app = express();
const PORT = process.env.PORT || 4000;

// Security Middleware
app.use(
  cors({
    origin: (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000').split(','),
    credentials: true,
  })
);

app.use(express.json({ limit: '5mb' }));

// Request Logging
app.use((req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  res.on('finish', () => {
    logger.info(`${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - start}ms`);
  });
  next();
});

// Health Checks
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/ready', (_req: Request, res: Response) => {
  res.json({ status: 'ready', uptime: process.uptime() });
});

// API Routes
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/organizations', orgRouter);
app.use('/api/v1/assets', assetRouter);
app.use('/api/v1/scans', scanRouter);
app.use('/api/v1/findings', findingRouter);
app.use('/api/v1/ai', aiRouter);
app.use('/api/v1/reports', reportRouter);

// Centralized Error Handler (RFC 7807 Problem Details)
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error('Unhandled API Error', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
  });

  res.status(500).json({
    type: 'https://securescan.ai/errors/internal-error',
    title: 'Internal Server Error',
    status: 500,
    detail: process.env.NODE_ENV === 'development' ? err.message : 'An unexpected error occurred.',
  });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    logger.info(`SecureScan AI API Gateway listening on port ${PORT}`);
  });
}

export default app;
