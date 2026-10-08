import { Router, Request, Response } from 'express';
import { db } from '../database/db.js';
import { MLClient } from '../services/mlClient.js';

export const modelRouter = Router();

modelRouter.get('/', async (_req: Request, res: Response): Promise<void> => {
  const dbModels = db.prepare('SELECT * FROM model_metadata ORDER BY is_active DESC, created_at DESC').all() as any[];
  const remoteMeta = await MLClient.getModelsMetadata();

  const formatted = dbModels.map(m => {
    let parsedMetrics: any = {};
    try {
      parsedMetrics = typeof m.metrics === 'string' ? JSON.parse(m.metrics) : m.metrics;
    } catch {
      parsedMetrics = {};
    }

    return {
      model_id: m.model_id,
      version: m.version,
      dataset_version: m.dataset_version,
      artifact_hash: m.artifact_hash,
      is_active: m.is_active === 1,
      metrics: parsedMetrics.frozen_test_metrics || parsedMetrics,
      full_metadata: parsedMetrics,
      created_at: m.created_at
    };
  });

  const activeModels = formatted.filter(m => m.is_active);
  const archivedModels = formatted.filter(m => !m.is_active);

  const deterministicComponents = [
    {
      component_id: 'qr-decoder',
      name: 'QR Matrix Decoder',
      version: '1.0.0',
      technology: 'jsQR deterministic matrix decoder',
      type: 'Deterministic Decoder',
      ml_training: 'None (No ML Model)',
      pipeline: 'QR Image -> Matrix Decoding -> Payload Extraction -> URL Phishing ML v2.0.0 -> Unified Risk Engine',
      status: 'Active & Verified'
    },
    {
      component_id: 'website-analyzer',
      name: 'Deterministic Website Analyzer',
      version: '1.0.0',
      technology: 'Cheerio static DOM AST + Safe Network Fetcher + SSRF Validator',
      type: 'Deterministic Security Analyzer',
      ml_training: 'None (Deterministic Subsystem)',
      pipeline: 'Input URL -> SSRF Validation -> Safe Multi-Hop Fetch -> Form & Brand Mismatch Inspection -> Unified Risk Engine',
      status: 'Active & Verified'
    },
    {
      component_id: 'risk-engine',
      name: 'Unified Risk Engine',
      version: '1.0.0',
      technology: 'Deterministic Evidence Aggregator & Calibrated Uncertainty Arbiter',
      type: 'Deterministic Decision Engine',
      ml_training: 'None (Multi-Signal Arbitration)',
      pipeline: 'Multi-Modal Evidence Signals -> Severity Weighting -> Calibrated Uncertainty -> Final Risk Score (0-100)',
      status: 'Active & Verified'
    }
  ];

  res.json({
    success: true,
    data: {
      registered_models: formatted,
      active_models: activeModels,
      archived_models: archivedModels,
      deterministic_components: deterministicComponents,
      live_service_metadata: remoteMeta?.models || [],
      governance_disclaimers: [
        'Evaluation metrics are benchmark results from documented frozen test and out-of-distribution datasets. They do not represent a guarantee of universal real-world detection accuracy.',
        'QR decoding, Website Analysis, and the Unified Risk Engine are deterministic security components, not independently trained ML classifiers.'
      ]
    }
  });
});
