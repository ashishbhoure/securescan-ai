/**
 * SecureScan AI - Resilient In-Memory Development Datastore
 * Automatically activated when PostgreSQL is offline or unreachable.
 * Ensures zero-friction development and prevents API crashes.
 */

import * as crypto from 'crypto';

export class InMemoryDataStore {
  public users: any[] = [];
  public organizations: any[] = [];
  public organizationMembers: any[] = [];
  public projects: any[] = [];
  public assets: any[] = [];
  public assetAuthorizations: any[] = [];
  public scans: any[] = [];
  public findings: any[] = [];
  public findingEvidences: any[] = [];
  public securityRules: any[] = [];
  public riskScores: any[] = [];
  public aIAnalyses: any[] = [];
  public reports: any[] = [];
  public auditLogs: any[] = [];

  constructor() {
    this.seedDefaults();
  }

  private seedDefaults() {
    const demoPasswordHash = crypto.createHash('sha256').update('SecureScan123!').digest('hex');

    // 1. User
    const demoUser = {
      id: 'usr-demo-001',
      email: 'demo@securescan.ai',
      name: 'Security Architect',
      passwordHash: demoPasswordHash,
      isEmailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.users.push(demoUser);

    // 2. Organization
    const demoOrg = {
      id: 'org-demo-001',
      name: 'Acme Cyber Labs',
      slug: 'securescan-demo',
      planTier: 'PRO',
      maxAssets: 25,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.organizations.push(demoOrg);

    // 3. Membership
    this.organizationMembers.push({
      id: 'mem-demo-001',
      organizationId: demoOrg.id,
      userId: demoUser.id,
      role: 'OWNER',
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // 4. Project
    const demoProject = {
      id: 'proj-demo-001',
      organizationId: demoOrg.id,
      name: 'Main Infrastructure',
      description: 'Production web properties and cloud portals',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.projects.push(demoProject);

    // 5. Asset
    const demoAsset = {
      id: 'asset-demo-001',
      organizationId: demoOrg.id,
      projectId: demoProject.id,
      type: 'WEBSITE',
      targetUrl: 'https://example.com',
      status: 'ACTIVE',
      verificationStatus: 'VERIFIED',
      lastScanAt: new Date(),
      lastScore: 82,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.assets.push(demoAsset);

    // 6. Asset Authorization
    this.assetAuthorizations.push({
      id: 'auth-demo-001',
      assetId: demoAsset.id,
      organizationId: demoOrg.id,
      userId: demoUser.id,
      method: 'CONFIRMATION_CHECK',
      authorizedAt: new Date(),
      ipAddress: '127.0.0.1',
      confirmedOwnership: true,
    });

    // 7. Initial Completed Scan
    const demoScan = {
      id: 'scan-demo-001',
      organizationId: demoOrg.id,
      assetId: demoAsset.id,
      triggeredByUserId: demoUser.id,
      status: 'COMPLETED',
      overallScore: 82,
      grade: 'B',
      durationMs: 1840,
      scannerVersion: '1.0.0',
      createdAt: new Date(Date.now() - 3600000),
      startedAt: new Date(Date.now() - 3600000),
      completedAt: new Date(Date.now() - 3598000),
    };
    this.scans.push(demoScan);

    // 8. Seed Findings
    const findingsData = [
      {
        id: 'fnd-001',
        ruleId: 'SEC-HDR-001',
        title: 'Missing Strict-Transport-Security (HSTS) Header',
        category: 'SECURITY_HEADERS',
        severity: 'MEDIUM',
        description: 'The HTTP response lacks the Strict-Transport-Security header, allowing unencrypted initial HTTP connections.',
        impact: 'Users are vulnerable to SSL-stripping attacks on insecure networks.',
        remediation: 'Configure: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        summary: 'Strict-Transport-Security header is missing from HTTPS response',
      },
      {
        id: 'fnd-002',
        ruleId: 'SEC-HDR-002',
        title: 'Missing Content-Security-Policy (CSP) Header',
        category: 'SECURITY_HEADERS',
        severity: 'MEDIUM',
        description: 'The response does not declare a Content-Security-Policy header, leaving client-side execution unrestrained.',
        impact: 'Significantly increases the risk of successful Cross-Site Scripting (XSS) and data injection attacks.',
        remediation: 'Configure a strong Content-Security-Policy declaring trusted script origins.',
        summary: 'Content-Security-Policy header is missing',
      },
      {
        id: 'fnd-003',
        ruleId: 'SEC-HDR-004',
        title: 'Missing X-Content-Type-Options Header',
        category: 'SECURITY_HEADERS',
        severity: 'LOW',
        description: 'The response lacks X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff response bodies.',
        impact: 'Untrusted user uploads can be executed as HTML/JavaScript in older user agents.',
        remediation: 'Add the header: X-Content-Type-Options: nosniff',
        summary: 'X-Content-Type-Options: nosniff header is missing',
      },
      {
        id: 'fnd-004',
        ruleId: 'SEC-HDR-005',
        title: 'Missing Clickjacking Protection',
        category: 'SECURITY_HEADERS',
        severity: 'MEDIUM',
        description: 'Neither X-Frame-Options nor CSP frame-ancestors is present to restrict embedding in iframes.',
        impact: 'Malicious third-party sites can frame the application to conduct Clickjacking.',
        remediation: 'Configure: X-Frame-Options: DENY (or SAMEORIGIN), or use CSP frame-ancestors.',
        summary: 'Neither X-Frame-Options nor CSP frame-ancestors is present',
      },
    ];

    for (const item of findingsData) {
      const fnd = {
        id: item.id,
        organizationId: demoOrg.id,
        scanId: demoScan.id,
        assetId: demoAsset.id,
        ruleId: item.ruleId,
        title: item.title,
        category: item.category,
        severity: item.severity,
        status: 'OPEN',
        confidence: 'CONFIRMED',
        description: item.description,
        impact: item.impact,
        remediation: item.remediation,
        fingerprint: crypto.createHash('sha256').update(item.ruleId).digest('hex'),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      this.findings.push(fnd);

      const ev = {
        id: `ev-${item.id}`,
        findingId: item.id,
        summary: item.summary,
        details: { verifiedUrl: demoAsset.targetUrl, statusCode: 200 },
        createdAt: new Date(),
      };
      this.findingEvidences.push(ev);

      this.aIAnalyses.push({
        id: `ai-${item.id}`,
        findingId: item.id,
        contentHash: item.ruleId,
        plainExplanation: `We detected "${item.title}". Your server does not declare mandatory browser defense controls.`,
        businessImpact: 'Leaving this control unconfigured exposes end users to browser-level manipulation and violates SOC 2 & ISO 27001 hardening baselines.',
        technicalExplanation: `The technical check failed: ${item.summary}. Directive ${item.ruleId} must be returned in the HTTP response headers.`,
        developerFix: `Apply this configuration to your web server or middleware:\n\n${item.remediation}`,
        validationSteps: ['Run: curl -I ' + demoAsset.targetUrl, 'Check the response headers for the directive', 'Re-scan with SecureScan AI'],
        priorityReasoning: `Severity is ${item.severity}. Schedule for upcoming sprint remediation.`,
      });
    }

    // Risk score
    this.riskScores.push({
      id: 'rs-demo-001',
      scanId: demoScan.id,
      overallScore: 82,
      grade: 'B',
      criticalCount: 0,
      highCount: 0,
      mediumCount: 3,
      lowCount: 1,
      infoCount: 0,
      deductions: [],
      createdAt: new Date(),
    });
  }
}
