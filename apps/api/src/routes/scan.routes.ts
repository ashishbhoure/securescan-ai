/**
 * SecureScan AI - Scan Orchestration Endpoints
 */

import { Router, Request, Response } from 'express';
import { prisma, ScanStatus, OrgRole } from '@securescan/database';
import { authMiddleware, requireRole } from '../middleware/auth.js';
import { scanRunnerService } from '../services/scan-runner.js';

export const scanRouter = Router();

scanRouter.use(authMiddleware);

/**
 * GET /api/v1/scans
 */
scanRouter.get('/', async (req: Request, res: Response) => {
  const scans = await prisma.scan.findMany({
    where: {
      organizationId: req.tenant!.organizationId,
    },
    include: {
      asset: { select: { id: true, targetUrl: true, type: true } },
      _count: { select: { findings: true } },
    },
    orderBy: { createdAt: 'desc' },
    take: 50,
  });

  res.json({ scans });
});

/**
 * GET /api/v1/scans/:id
 */
scanRouter.get('/:id', async (req: Request, res: Response) => {
  const id = String(req.params.id);

  const scan = await prisma.scan.findFirst({
    where: {
      id,
      organizationId: req.tenant!.organizationId,
    },
    include: {
      asset: true,
      riskScore: true,
      findings: {
        include: {
          evidence: true,
          aiAnalysis: true,
        },
        orderBy: [{ severity: 'desc' }, { createdAt: 'asc' }],
      },
    },
  });

  if (!scan) {
    res.status(404).json({
      code: 'SCAN_NOT_FOUND',
      message: 'Scan record not found.',
    });
    return;
  }

  res.json({ scan });
});

/**
 * POST /api/v1/scans
 * Triggers an asynchronous security assessment
 */
scanRouter.post('/', requireRole([OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER]), async (req: Request, res: Response) => {
  const { assetId } = req.body;

  if (!assetId) {
    res.status(400).json({
      code: 'VALIDATION_ERROR',
      message: 'Asset ID is required to start a scan.',
    });
    return;
  }

  const asset = await prisma.asset.findFirst({
    where: {
      id: assetId,
      organizationId: req.tenant!.organizationId,
    },
    include: {
      authorizations: true,
    },
  });

  if (!asset) {
    res.status(404).json({
      code: 'ASSET_NOT_FOUND',
      message: 'Asset not found.',
    });
    return;
  }

  // Safety Requirement: Target Authorization must exist
  if (asset.authorizations.length === 0 && asset.verificationStatus !== 'VERIFIED') {
    res.status(403).json({
      code: 'TARGET_NOT_AUTHORIZED',
      message: 'This target has not been confirmed for authorized testing. Please authorize the asset before scanning.',
    });
    return;
  }

  // Create Scan Record
  const scan = await prisma.scan.create({
    data: {
      organizationId: req.tenant!.organizationId,
      assetId: asset.id,
      triggeredByUserId: req.user!.id,
      status: ScanStatus.QUEUED,
    },
  });

  // Audit Log
  await prisma.auditLog.create({
    data: {
      organizationId: req.tenant!.organizationId,
      userId: req.user!.id,
      action: 'SCAN_QUEUED',
      resourceType: 'SCAN',
      resourceId: scan.id,
      ipAddress: req.ip,
      metadata: { targetUrl: asset.targetUrl },
    },
  });

  // Launch async runner non-blocking
  setImmediate(() => {
    scanRunnerService.runScan(scan.id).catch((err) => {
      console.error(`Unhandled error in background scan ${scan.id}:`, err);
    });
  });

  res.status(202).json({
    message: 'Scan has been successfully queued.',
    scan: {
      id: scan.id,
      status: scan.status,
      targetUrl: asset.targetUrl,
      createdAt: scan.createdAt,
    },
  });
});
