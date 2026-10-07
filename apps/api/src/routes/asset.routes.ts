/**
 * SecureScan AI - Asset Management & Target Authorization Endpoints
 */

import { Router, Request, Response } from 'express';
import { prisma, AssetStatus, VerificationMethod, OrgRole } from '@securescan/database';
import { authMiddleware, requireRole } from '../middleware/auth.js';
import { validateTargetUrl, isPrivateOrReservedIp } from '@securescan/scanner-core';

export const assetRouter = Router();

assetRouter.use(authMiddleware);

/**
 * GET /api/v1/assets
 */
assetRouter.get('/', async (req: Request, res: Response) => {
  const assets = await prisma.asset.findMany({
    where: {
      organizationId: req.tenant!.organizationId,
    },
    include: {
      project: { select: { id: true, name: true } },
      authorizations: {
        select: { id: true, method: true, authorizedAt: true, confirmedOwnership: true },
        take: 1,
      },
    },
    orderBy: { createdAt: 'desc' },
  });

  res.json({ assets });
});

/**
 * POST /api/v1/assets
 */
assetRouter.post('/', requireRole([OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER]), async (req: Request, res: Response) => {
  const { targetUrl, type = 'WEBSITE', projectId } = req.body;

  if (!targetUrl) {
    res.status(400).json({
      code: 'VALIDATION_ERROR',
      message: 'Target URL is required.',
    });
    return;
  }

  // 1. SSRF URL validation
  try {
    const parsed = validateTargetUrl(targetUrl);
    if (isPrivateOrReservedIp(parsed.hostname)) {
      res.status(400).json({
        code: 'PROHIBITED_TARGET',
        message: 'Scanning private IP addresses or internal networks is strictly prohibited.',
      });
      return;
    }
  } catch (err) {
    res.status(400).json({
      code: 'INVALID_TARGET_URL',
      message: (err as Error).message,
    });
    return;
  }

  // 2. Check Plan Quota
  const org = await prisma.organization.findUnique({
    where: { id: req.tenant!.organizationId },
    include: { _count: { select: { assets: true } } },
  });

  if (org && org._count.assets >= org.maxAssets) {
    res.status(403).json({
      code: 'ASSET_LIMIT_EXCEEDED',
      message: `Your current plan allows a maximum of ${org.maxAssets} assets. Please upgrade to add more targets.`,
    });
    return;
  }

  // 3. Resolve Project
  let targetProjectId = projectId;
  if (!targetProjectId) {
    const defaultProject = await prisma.project.findFirst({
      where: { organizationId: req.tenant!.organizationId },
    });
    if (!defaultProject) {
      const createdProj = await prisma.project.create({
        data: {
          organizationId: req.tenant!.organizationId,
          name: 'Main Infrastructure',
        },
      });
      targetProjectId = createdProj.id;
    } else {
      targetProjectId = defaultProject.id;
    }
  }

  const asset = await prisma.asset.create({
    data: {
      organizationId: req.tenant!.organizationId,
      projectId: targetProjectId,
      type,
      targetUrl,
      status: AssetStatus.PENDING_VERIFICATION,
      verificationStatus: 'UNVERIFIED',
    },
  });

  // Audit log
  await prisma.auditLog.create({
    data: {
      organizationId: req.tenant!.organizationId,
      userId: req.user!.id,
      action: 'ASSET_CREATED',
      resourceType: 'ASSET',
      resourceId: asset.id,
      ipAddress: req.ip,
      metadata: { targetUrl, type },
    },
  });

  res.status(201).json({ asset });
});

/**
 * POST /api/v1/assets/:id/authorize
 * Confirms explicit ownership/authorization to scan target
 */
assetRouter.post('/:id/authorize', requireRole([OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER]), async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const { confirmedOwnership, method = 'CONFIRMATION_CHECK' } = req.body;

  if (!confirmedOwnership) {
    res.status(400).json({
      code: 'AUTHORIZATION_REQUIRED',
      message: 'You must explicitly confirm that you own or have legal authorization to test this target.',
    });
    return;
  }

  const asset = await prisma.asset.findFirst({
    where: {
      id,
      organizationId: req.tenant!.organizationId,
    },
  });

  if (!asset) {
    res.status(404).json({
      code: 'ASSET_NOT_FOUND',
      message: 'Asset not found.',
    });
    return;
  }

  // Record Authorization
  const authRecord = await prisma.assetAuthorization.create({
    data: {
      assetId: asset.id,
      organizationId: req.tenant!.organizationId,
      userId: req.user!.id,
      method: method as VerificationMethod,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'],
      confirmedOwnership: true,
    },
  });

  // Update Asset Status to VERIFIED & ACTIVE
  const updatedAsset = await prisma.asset.update({
    where: { id: asset.id },
    data: {
      status: AssetStatus.ACTIVE,
      verificationStatus: 'VERIFIED',
    },
  });

  // Audit Log
  await prisma.auditLog.create({
    data: {
      organizationId: req.tenant!.organizationId,
      userId: req.user!.id,
      action: 'TARGET_AUTHORIZED',
      resourceType: 'ASSET',
      resourceId: asset.id,
      ipAddress: req.ip,
      metadata: {
        authorizationId: authRecord.id,
        targetUrl: asset.targetUrl,
        method,
      },
    },
  });

  res.json({
    message: 'Target authorization confirmed successfully.',
    asset: updatedAsset,
    authorization: authRecord,
  });
});
