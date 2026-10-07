/**
 * SecureScan AI - AI Security Analyst Endpoints
 */

import { Router, Request, Response } from 'express';
import { prisma } from '@securescan/database';
import { authMiddleware } from '../middleware/auth.js';
import { createAIProvider, promptSanitizer } from '@securescan/ai';
import { FindingResult, Severity } from '@securescan/types';

export const aiRouter = Router();

aiRouter.use(authMiddleware);

const aiProvider = createAIProvider(
  process.env.AI_PROVIDER || 'mock',
  process.env.OPENAI_API_KEY,
  process.env.OPENAI_MODEL
);

/**
 * POST /api/v1/ai/findings/:id/explain
 * Generates an on-demand AI explanation and developer patch
 */
aiRouter.post('/findings/:id/explain', async (req: Request, res: Response) => {
  const id = String(req.params.id);

  const finding = await prisma.finding.findFirst({
    where: {
      id,
      organizationId: req.tenant!.organizationId,
    },
    include: {
      evidence: true,
      aiAnalysis: true,
      asset: true,
    },
  });

  if (!finding) {
    res.status(404).json({
      code: 'FINDING_NOT_FOUND',
      message: 'Finding not found.',
    });
    return;
  }

  // Return existing analysis if already present
  if (finding.aiAnalysis) {
    res.json({ analysis: finding.aiAnalysis });
    return;
  }

  const contentHash = promptSanitizer.computeFindingHash(
    finding.ruleId,
    finding.severity,
    finding.evidence?.summary || finding.title
  );

  const findingAdapter: FindingResult = {
    ruleId: finding.ruleId,
    title: finding.title,
    category: finding.category as any,
    severity: finding.severity as unknown as Severity,
    confidence: 'CONFIRMED',
    description: finding.description,
    impact: finding.impact,
    remediation: finding.remediation,
    evidence: {
      summary: finding.evidence?.summary || '',
      details: (finding.evidence?.details as Record<string, unknown>) || {},
    },
    fingerprint: finding.fingerprint,
  };

  const aiResult = await aiProvider.generateRemediation({
    finding: findingAdapter,
    targetUrl: finding.asset.targetUrl,
  });

  const createdAnalysis = await prisma.aIAnalysis.create({
    data: {
      findingId: finding.id,
      contentHash,
      plainExplanation: aiResult.plainExplanation,
      businessImpact: aiResult.businessImpact,
      technicalExplanation: aiResult.technicalExplanation,
      developerFix: aiResult.developerFix,
      validationSteps: aiResult.validationSteps as any,
      priorityReasoning: aiResult.priorityReasoning,
      tokenUsage: aiResult.tokenUsage as any,
    },
  });

  res.json({ analysis: createdAnalysis });
});

/**
 * POST /api/v1/ai/qna
 * Answers security posture questions scoped strictly to organization findings
 */
aiRouter.post('/qna', async (req: Request, res: Response) => {
  const { question } = req.body;

  if (!question) {
    res.status(400).json({
      code: 'VALIDATION_ERROR',
      message: 'Question is required.',
    });
    return;
  }

  const org = await prisma.organization.findUnique({
    where: { id: req.tenant!.organizationId },
    select: { name: true },
  });

  // Pull tenant findings only
  const tenantFindings = await prisma.finding.findMany({
    where: {
      organizationId: req.tenant!.organizationId,
      status: 'OPEN',
    },
    take: 20,
    orderBy: { severity: 'desc' },
  });

  const adaptedFindings: FindingResult[] = tenantFindings.map((f: any) => ({
    ruleId: f.ruleId,
    title: f.title,
    category: f.category as any,
    severity: f.severity as unknown as Severity,
    confidence: 'CONFIRMED',
    description: f.description,
    impact: f.impact,
    remediation: f.remediation,
    evidence: { summary: '', details: {} },
    fingerprint: f.fingerprint,
  }));

  const answer = await aiProvider.answerSecurityQuestion({
    question: promptSanitizer.sanitizeUntrustedInput(question),
    contextFindings: adaptedFindings,
    organizationName: org?.name || 'Organization',
  });

  res.json({ qna: answer });
});
