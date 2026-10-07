/**
 * SecureScan AI - Standalone Scan Worker Daemon
 * Consumes and executes queued security assessments in an isolated worker process.
 */

import dotenv from 'dotenv';
import { prisma, ScanStatus, Severity } from '@securescan/database';
import { ScannerPipeline } from '@securescan/scanner-core';
import { RuleEngine, RiskScoreEngine } from '@securescan/security-rules';
import { createAIProvider, promptSanitizer } from '@securescan/ai';
import { logger } from '@securescan/logger';
import { AssetType } from '@securescan/types';

dotenv.config();

const pipeline = new ScannerPipeline();
const ruleEngine = new RuleEngine();
const scoreEngine = new RiskScoreEngine();
const aiProvider = createAIProvider(
  process.env.AI_PROVIDER || 'mock',
  process.env.OPENAI_API_KEY,
  process.env.OPENAI_MODEL
);

let isRunning = true;

async function processNextQueuedScan() {
  const scan = await prisma.scan.findFirst({
    where: { status: ScanStatus.QUEUED },
    include: {
      asset: {
        include: { authorizations: true },
      },
    },
    orderBy: { createdAt: 'asc' },
  });

  if (!scan) return;

  const workerLog = logger.withContext({
    scanId: scan.id,
    assetId: scan.assetId,
    organizationId: scan.organizationId,
    module: 'worker-daemon',
  });

  workerLog.info(`Worker picked up scan for ${scan.asset.targetUrl}`);

  // Safety Verification Check
  if (scan.asset.authorizations.length === 0 && scan.asset.verificationStatus !== 'VERIFIED') {
    workerLog.warn('Scan aborted by worker: target not authorized');
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: ScanStatus.FAILED, completedAt: new Date() },
    });
    return;
  }

  const startTime = Date.now();
  await prisma.scan.update({
    where: { id: scan.id },
    data: { status: ScanStatus.RUNNING, startedAt: new Date() },
  });

  try {
    const evidence = await pipeline.execute({
      scanId: scan.id,
      assetId: scan.assetId,
      organizationId: scan.organizationId,
      targetUrl: scan.asset.targetUrl,
      assetType: scan.asset.type as unknown as AssetType,
    });

    const findingResults = ruleEngine.evaluate(evidence);
    const riskBreakdown = scoreEngine.calculate(findingResults);

    for (const fr of findingResults) {
      await prisma.securityRule.upsert({
        where: { id: fr.ruleId },
        update: {},
        create: {
          id: fr.ruleId,
          name: fr.title,
          category: fr.category,
          severity: fr.severity as Severity,
          description: fr.description,
          impact: fr.impact,
          remediationTemplate: fr.remediation,
        },
      });

      const findingRecord = await prisma.finding.create({
        data: {
          organizationId: scan.organizationId,
          scanId: scan.id,
          assetId: scan.assetId,
          ruleId: fr.ruleId,
          title: fr.title,
          category: fr.category,
          severity: fr.severity as Severity,
          confidence: fr.confidence,
          description: fr.description,
          impact: fr.impact,
          remediation: fr.remediation,
          fingerprint: fr.fingerprint,
          evidence: {
            create: {
              summary: fr.evidence.summary,
              details: fr.evidence.details as any,
            },
          },
        },
      });

      // AI Remediation
      const contentHash = promptSanitizer.computeFindingHash(
        fr.ruleId,
        fr.severity,
        fr.evidence.summary
      );

      const existingAnalysis = await prisma.aIAnalysis.findFirst({
        where: { contentHash },
      });

      if (existingAnalysis) {
        await prisma.aIAnalysis.create({
          data: {
            findingId: findingRecord.id,
            contentHash,
            plainExplanation: existingAnalysis.plainExplanation,
            businessImpact: existingAnalysis.businessImpact,
            technicalExplanation: existingAnalysis.technicalExplanation,
            developerFix: existingAnalysis.developerFix,
            validationSteps: existingAnalysis.validationSteps as any,
            priorityReasoning: existingAnalysis.priorityReasoning,
          },
        });
      } else {
        try {
          const aiResult = await aiProvider.generateRemediation({
            finding: fr,
            targetUrl: scan.asset.targetUrl,
            technologies: evidence.technologies?.map((t) => t.name),
          });

          await prisma.aIAnalysis.create({
            data: {
              findingId: findingRecord.id,
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
        } catch (aiErr) {
          workerLog.warn('Worker skipped AI for finding', {
            error: (aiErr as Error).message,
          });
        }
      }
    }

    // Persist score
    await prisma.riskScore.create({
      data: {
        scanId: scan.id,
        overallScore: riskBreakdown.overallScore,
        grade: riskBreakdown.grade,
        criticalCount: riskBreakdown.criticalCount,
        highCount: riskBreakdown.highCount,
        mediumCount: riskBreakdown.mediumCount,
        lowCount: riskBreakdown.lowCount,
        infoCount: riskBreakdown.infoCount,
        deductions: riskBreakdown.riskDeductions as any,
      },
    });

    const durationMs = Date.now() - startTime;
    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: ScanStatus.COMPLETED,
        overallScore: riskBreakdown.overallScore,
        grade: riskBreakdown.grade,
        durationMs,
        completedAt: new Date(),
      },
    });

    await prisma.asset.update({
      where: { id: scan.assetId },
      data: {
        lastScanAt: new Date(),
        lastScore: riskBreakdown.overallScore,
      },
    });

    workerLog.info('Scan completed by worker daemon', {
      score: riskBreakdown.overallScore,
      durationMs,
    });
  } catch (err) {
    workerLog.error('Scan failed in worker daemon', {
      error: (err as Error).message,
    });

    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: ScanStatus.FAILED,
        completedAt: new Date(),
        durationMs: Date.now() - startTime,
      },
    });
  }
}

async function loop() {
  logger.info('SecureScan AI Worker Daemon initialized. Polling for queued scans...');
  while (isRunning) {
    try {
      await processNextQueuedScan();
    } catch (err) {
      logger.error('Worker loop error', { error: (err as Error).message });
    }
    // Sleep 2 seconds before next poll
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

process.on('SIGTERM', () => {
  isRunning = false;
  logger.info('Worker daemon received SIGTERM, draining...');
});

loop();
