/**
 * SecureScan AI - Async Scan Execution Service
 * Orchestrates scanner pipeline, rule evaluation, risk scoring, and AI analysis.
 */

import { prisma, ScanStatus, Severity } from '@securescan/database';
import { ScannerPipeline } from '@securescan/scanner-core';
import { RuleEngine, RiskScoreEngine } from '@securescan/security-rules';
import { createAIProvider, promptSanitizer } from '@securescan/ai';
import { logger } from '@securescan/logger';
import { AssetType } from '@securescan/types';

export class ScanRunnerService {
  private pipeline = new ScannerPipeline();
  private ruleEngine = new RuleEngine();
  private scoreEngine = new RiskScoreEngine();
  private aiProvider = createAIProvider(
    process.env.AI_PROVIDER || 'mock',
    process.env.OPENAI_API_KEY,
    process.env.OPENAI_MODEL
  );

  public async runScan(scanId: string): Promise<void> {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        asset: {
          include: {
            authorizations: true,
          },
        },
      },
    });

    if (!scan) {
      logger.error('Scan not found for execution', { scanId });
      return;
    }

    const scanLog = logger.withContext({
      scanId,
      assetId: scan.assetId,
      organizationId: scan.organizationId,
    });

    // Verify Target Authorization
    if (scan.asset.authorizations.length === 0 && scan.asset.verificationStatus !== 'VERIFIED') {
      scanLog.error('Scan aborted: Asset lacks explicit target authorization record');
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: ScanStatus.FAILED,
          completedAt: new Date(),
        },
      });
      return;
    }

    const startTime = Date.now();
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: ScanStatus.RUNNING,
        startedAt: new Date(),
      },
    });

    try {
      scanLog.info('Executing scan pipeline...');
      const evidence = await this.pipeline.execute({
        scanId: scan.id,
        assetId: scan.assetId,
        organizationId: scan.organizationId,
        targetUrl: scan.asset.targetUrl,
        assetType: scan.asset.type as unknown as AssetType,
      });

      // 1. Evaluate Evidence with Rule Engine
      scanLog.info('Evaluating evidence against security rules catalog...');
      const findingResults = this.ruleEngine.evaluate(evidence);

      // 2. Compute Risk Score & Deductions
      const riskBreakdown = this.scoreEngine.calculate(findingResults);

      // 3. Persist Findings & Evidence to Database
      for (const fr of findingResults) {
        // Ensure rule exists in DB
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

        // 4. Generate AI Remediation with Deduplication & Caching
        const contentHash = promptSanitizer.computeFindingHash(
          fr.ruleId,
          fr.severity,
          fr.evidence.summary
        );

        // Check if cached AI analysis exists
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
          // Request new analysis from AI provider
          try {
            const aiResult = await this.aiProvider.generateRemediation({
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
            scanLog.warn('AI analysis skipped for finding', {
              findingId: findingRecord.id,
              error: (aiErr as Error).message,
            });
          }
        }
      }

      // 5. Persist Risk Score
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

      // 6. Complete Scan & Update Asset Posture
      const durationMs = Date.now() - startTime;
      await prisma.scan.update({
        where: { id: scanId },
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

      // Record Audit Log
      await prisma.auditLog.create({
        data: {
          organizationId: scan.organizationId,
          userId: scan.triggeredByUserId,
          action: 'SCAN_COMPLETED',
          resourceType: 'SCAN',
          resourceId: scan.id,
          metadata: {
            score: riskBreakdown.overallScore,
            findingsCount: findingResults.length,
            durationMs,
          },
        },
      });

      scanLog.info('Scan completed successfully', {
        score: riskBreakdown.overallScore,
        findingsCount: findingResults.length,
      });
    } catch (err) {
      scanLog.error('Scan execution encountered fatal error', {
        error: (err as Error).message,
      });

      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: ScanStatus.FAILED,
          completedAt: new Date(),
          durationMs: Date.now() - startTime,
        },
      });
    }
  }
}

export const scanRunnerService = new ScanRunnerService();
