import { describe, it, expect } from 'vitest';
import { RuleEngine } from '../src/rule-engine.js';
import { RiskScoreEngine } from '../src/risk-score-engine.js';
import { AggregatedScanEvidence, Severity } from '@securescan/types';

describe('Security Rule Engine & Risk Scoring', () => {
  it('should detect missing HSTS and lack of CSP', () => {
    const engine = new RuleEngine();
    const evidence: AggregatedScanEvidence = {
      scanId: 'scan-123',
      targetUrl: 'https://test-site.com',
      scannedAt: new Date(),
      http: {
        requestUrl: 'https://test-site.com',
        finalUrl: 'https://test-site.com',
        statusCode: 200,
        redirectChain: [],
        responseHeaders: {}, // Empty headers -> all security headers missing
      },
    };

    const findings = engine.evaluate(evidence);
    const ruleIds = findings.map((f) => f.ruleId);

    expect(ruleIds).toContain('SEC-HDR-001'); // Missing HSTS
    expect(ruleIds).toContain('SEC-HDR-002'); // Missing CSP
    expect(ruleIds).toContain('SEC-HDR-004'); // Missing nosniff
    expect(ruleIds).toContain('SEC-HDR-005'); // Missing clickjacking defense
  });

  it('should correctly cap score when a critical vulnerability is present', () => {
    const engine = new RuleEngine();
    const scorer = new RiskScoreEngine();

    const evidence: AggregatedScanEvidence = {
      scanId: 'scan-456',
      targetUrl: 'https://expired-tls.com',
      scannedAt: new Date(),
      tls: {
        authorized: false,
        protocol: 'TLSv1.3',
        validFrom: '2023-01-01',
        validTo: '2023-12-31',
        daysRemaining: -100,
        isExpired: true,
        hostnameMismatch: false,
        supportsInsecureProtocols: [],
        issuer: {},
        subject: {},
        sans: [],
      },
      http: {
        requestUrl: 'https://expired-tls.com',
        finalUrl: 'https://expired-tls.com',
        statusCode: 200,
        redirectChain: [],
        responseHeaders: {
          'strict-transport-security': 'max-age=31536000',
          'content-security-policy': "default-src 'self'",
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'no-referrer',
        },
      },
    };

    const findings = engine.evaluate(evidence);
    const expiredCertFinding = findings.find((f) => f.ruleId === 'SEC-TLS-002');
    expect(expiredCertFinding).toBeDefined();
    expect(expiredCertFinding?.severity).toBe(Severity.CRITICAL);

    const score = scorer.calculate(findings);
    expect(score.criticalCount).toBe(1);
    expect(score.overallScore).toBeLessThanOrEqual(49); // Critical cap enforced!
    expect(['D', 'F']).toContain(score.grade);
  });

  it('should award 100 Grade A to perfectly hardened targets', () => {
    const scorer = new RiskScoreEngine();
    const score = scorer.calculate([]);

    expect(score.overallScore).toBe(100);
    expect(score.grade).toBe('A');
    expect(score.criticalCount).toBe(0);
    expect(score.highCount).toBe(0);
  });
});
