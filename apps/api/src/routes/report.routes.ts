/**
 * SecureScan AI - Security Report Generation Endpoints
 */

import { Router, Request, Response } from 'express';
import { prisma } from '@securescan/database';
import { authMiddleware } from '../middleware/auth.js';

export const reportRouter = Router();

reportRouter.use(authMiddleware);

/**
 * POST /api/v1/reports
 * Compiles a structured executive security assessment report
 */
reportRouter.post('/', async (req: Request, res: Response) => {
  const { scanId } = req.body;

  if (!scanId) {
    res.status(400).json({
      code: 'VALIDATION_ERROR',
      message: 'Scan ID is required to generate a report.',
    });
    return;
  }

  const scan = await prisma.scan.findFirst({
    where: {
      id: scanId,
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

  const reportTitle = `Security Posture Assessment — ${scan.asset.targetUrl}`;

  const report = await prisma.report.create({
    data: {
      organizationId: req.tenant!.organizationId,
      scanId: scan.id,
      title: reportTitle,
    },
  });

  // Record Audit
  await prisma.auditLog.create({
    data: {
      organizationId: req.tenant!.organizationId,
      userId: req.user!.id,
      action: 'REPORT_DOWNLOADED',
      resourceType: 'REPORT',
      resourceId: report.id,
      ipAddress: req.ip,
    },
  });

  res.status(201).json({
    report: {
      id: report.id,
      title: report.title,
      generatedAt: report.generatedAt,
      metadata: {
        targetUrl: scan.asset.targetUrl,
        score: scan.overallScore,
        grade: scan.grade,
        scannerVersion: scan.scannerVersion,
        totalFindings: scan.findings.length,
      },
      disclaimer:
        'This automated assessment does not constitute a complete penetration test or guarantee that an asset is completely secure. It assesses discoverable surface configurations and deterministic posture indicators.',
      executiveSummary: {
        score: scan.overallScore,
        grade: scan.grade,
        criticalCount: scan.riskScore?.criticalCount || 0,
        highCount: scan.riskScore?.highCount || 0,
        mediumCount: scan.riskScore?.mediumCount || 0,
        lowCount: scan.riskScore?.lowCount || 0,
      },
      findings: scan.findings,
    },
  });
});
