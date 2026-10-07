/**
 * SecureScan AI - Finding Management Endpoints
 */

import { Router, Request, Response } from 'express';
import { prisma, FindingStatus, Severity, OrgRole } from '@securescan/database';
import { authMiddleware, requireRole } from '../middleware/auth.js';

export const findingRouter = Router();

findingRouter.use(authMiddleware);

/**
 * GET /api/v1/findings
 * Multi-filtered findings query
 */
findingRouter.get('/', async (req: Request, res: Response) => {
  const { severity, status, assetId, search } = req.query;

  const whereClause: Record<string, unknown> = {
    organizationId: req.tenant!.organizationId,
  };

  if (severity && typeof severity === 'string') {
    whereClause.severity = severity as Severity;
  }

  if (status && typeof status === 'string') {
    whereClause.status = status as FindingStatus;
  }

  if (assetId && typeof assetId === 'string') {
    whereClause.assetId = assetId;
  }

  if (search && typeof search === 'string') {
    whereClause.OR = [
      { title: { contains: search, mode: 'insensitive' } },
      { description: { contains: search, mode: 'insensitive' } },
      { ruleId: { contains: search, mode: 'insensitive' } },
    ];
  }

  const findings = await prisma.finding.findMany({
    where: whereClause,
    include: {
      asset: { select: { id: true, targetUrl: true } },
      evidence: { select: { summary: true } },
      aiAnalysis: { select: { id: true, plainExplanation: true } },
    },
    orderBy: [{ severity: 'desc' }, { createdAt: 'desc' }],
    take: 100,
  });

  res.json({ findings });
});

/**
 * GET /api/v1/findings/:id
 */
findingRouter.get('/:id', async (req: Request, res: Response) => {
  const id = String(req.params.id);

  const finding = await prisma.finding.findFirst({
    where: {
      id,
      organizationId: req.tenant!.organizationId,
    },
    include: {
      asset: true,
      scan: { select: { id: true, createdAt: true, scannerVersion: true } },
      evidence: true,
      aiAnalysis: true,
      rule: true,
    },
  });

  if (!finding) {
    res.status(404).json({
      code: 'FINDING_NOT_FOUND',
      message: 'Finding not found.',
    });
    return;
  }

  res.json({ finding });
});

/**
 * PATCH /api/v1/findings/:id/status
 * Manages finding lifecycle transitions
 */
findingRouter.patch('/:id/status', requireRole([OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER]), async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const { status, justification } = req.body;

  if (!status || !Object.values(FindingStatus).includes(status)) {
    res.status(400).json({
      code: 'INVALID_STATUS',
      message: `Status must be one of: ${Object.values(FindingStatus).join(', ')}`,
    });
    return;
  }

  const finding = await prisma.finding.findFirst({
    where: {
      id,
      organizationId: req.tenant!.organizationId,
    },
  });

  if (!finding) {
    res.status(404).json({
      code: 'FINDING_NOT_FOUND',
      message: 'Finding not found.',
    });
    return;
  }

  const updated = await prisma.finding.update({
    where: { id: finding.id },
    data: { status: status as FindingStatus },
  });

  // Audit log
  await prisma.auditLog.create({
    data: {
      organizationId: req.tenant!.organizationId,
      userId: req.user!.id,
      action: 'FINDING_STATUS_CHANGED',
      resourceType: 'FINDING',
      resourceId: finding.id,
      ipAddress: req.ip,
      metadata: {
        previousStatus: finding.status,
        newStatus: status,
        justification: justification || 'User action',
      },
    },
  });

  res.json({
    message: `Finding status updated to ${status}.`,
    finding: updated,
  });
});
