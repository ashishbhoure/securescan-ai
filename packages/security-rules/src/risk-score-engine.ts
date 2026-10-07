/**
 * SecureScan AI - Risk Scoring Engine
 * Computes non-linear 0-100 posture scores with critical vulnerability caps.
 */

import { FindingResult, RiskScoreBreakdown, Severity } from '@securescan/types';

export class RiskScoreEngine {
  public calculate(findings: FindingResult[]): RiskScoreBreakdown {
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let infoCount = 0;

    const riskDeductions: RiskScoreBreakdown['riskDeductions'] = [];

    let totalDeduction = 0;

    for (const finding of findings) {
      let deduction = 0;

      switch (finding.severity) {
        case Severity.CRITICAL:
          criticalCount++;
          deduction = 35;
          break;
        case Severity.HIGH:
          highCount++;
          deduction = 15;
          break;
        case Severity.MEDIUM:
          mediumCount++;
          deduction = 6;
          break;
        case Severity.LOW:
          lowCount++;
          deduction = 2;
          break;
        case Severity.INFO:
        default:
          infoCount++;
          deduction = 0;
          break;
      }

      if (deduction > 0) {
        totalDeduction += deduction;
        riskDeductions.push({
          ruleId: finding.ruleId,
          severity: finding.severity,
          deductionPoints: deduction,
          reason: finding.title,
        });
      }
    }

    let calculatedScore = Math.max(0, 100 - totalDeduction);

    // Critical Cap: A single critical vulnerability guarantees the score cannot exceed 49 (High/Critical risk)
    if (criticalCount > 0 && calculatedScore > 49) {
      calculatedScore = 49;
    } else if (highCount > 0 && calculatedScore > 74) {
      // A high vulnerability guarantees score cannot exceed 74 (Moderate risk)
      calculatedScore = 74;
    }

    let grade: 'A' | 'B' | 'C' | 'D' | 'F';
    if (calculatedScore >= 90) {
      grade = 'A';
    } else if (calculatedScore >= 75) {
      grade = 'B';
    } else if (calculatedScore >= 60) {
      grade = 'C';
    } else if (calculatedScore >= 40) {
      grade = 'D';
    } else {
      grade = 'F';
    }

    return {
      overallScore: calculatedScore,
      grade,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      riskDeductions,
    };
  }
}
