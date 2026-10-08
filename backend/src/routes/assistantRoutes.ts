import { Router, Request, Response } from 'express';
import { GeminiService } from '../services/geminiService.js';
import { z } from 'zod';

export const assistantRouter = Router();

const chatRequestSchema = z.object({
  message: z.string().min(1).max(2000),
  history: z.array(
    z.object({
      role: z.enum(['user', 'assistant', 'model']),
      content: z.string().max(4000)
    })
  ).optional()
});

assistantRouter.post('/chat', async (req: Request, res: Response): Promise<void> => {
  try {
    const parseResult = chatRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid message or history format',
          details: parseResult.error.errors
        }
      });
      return;
    }

    const { message, history } = parseResult.data;
    const reply = await GeminiService.askSecurityCopilot(message, history || []);

    res.json({
      success: true,
      data: {
        reply,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error: any) {
    console.error('[AssistantRoute Error]:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to process security copilot query'
      }
    });
  }
});
