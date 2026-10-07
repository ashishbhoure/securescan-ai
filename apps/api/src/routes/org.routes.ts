/**
 * SecureScan AI - Organization & Team Management Endpoints
 */

import { Router, Request, Response } from 'express';
import { prisma } from '@securescan/database';
import { authMiddleware } from '../middleware/auth.js';

export const orgRouter = Router();

orgRouter.use(authMiddleware);

/**
 * GET /api/v1/organizations/current
 */
orgRouter.get('/current', async (req: Request, res: Response) => {
  const org = await prisma.organization.findUnique({
    where: { id: req.tenant!.organizationId },
    include: {
      members: {
        include: {
          user: { select: { id: true, email: true, name: true } },
        },
      },
      _count: {
        select: {
          assets: true,
          scans: true,
          findings: true,
        },
      },
    },
  });

  if (!org) {
    res.status(404).json({ code: 'ORG_NOT_FOUND', message: 'Organization not found.' });
    return;
  }

  res.json({ organization: org, userRole: req.tenant!.role });
});

/**
 * GET /api/v1/organizations/stats
 * Main dashboard aggregated security metrics
 */
orgRouter.get('/stats', async (req: Request, res: Response) => {
  const orgId = req.tenant!.organizationId;

  const [assetCount, openFindings, recentScans] = await Promise.all([
    prisma.asset.count({ where: { organizationId: orgId } }),
    prisma.finding.groupBy({
      by: ['severity'],
      where: { organizationId: orgId, status: 'OPEN' },
      _count: { _all: true },
    }),
    prisma.scan.findMany({
      where: { organizationId: orgId },
      orderBy: { createdAt: 'desc' },
      take: 5,
      include: { asset: { select: { targetUrl: true } } },
    }),
  ]);

  const severityCounts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  for (const item of openFindings) {
    severityCounts[item.severity] = item._count._all;
  }

  // Calculate overall organization posture average
  const scoredAssets = await prisma.asset.findMany({
    where: { organizationId: orgId, lastScore: { not: null } },
    select: { lastScore: true },
  });

  const avgScore =
    scoredAssets.length > 0
      ? Math.round(
          scoredAssets.reduce((acc: number, curr: any) => acc + (curr.lastScore || 0), 0) /
            scoredAssets.length
        )
      : 100;

  res.json({
    metrics: {
      overallScore: avgScore,
      totalAssets: assetCount,
      criticalFindings: severityCounts.CRITICAL,
      highFindings: severityCounts.HIGH,
      mediumFindings: severityCounts.MEDIUM,
      lowFindings: severityCounts.LOW,
      infoFindings: severityCounts.INFO,
      recentScans,
    },
  });
});
