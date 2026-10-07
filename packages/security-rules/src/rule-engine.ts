/**
 * SecureScan AI - Deterministic Security Rule Engine
 * Evaluates scan evidence strictly against verified security rules.
 */

import * as crypto from 'crypto';
import { AggregatedScanEvidence, FindingResult } from '@securescan/types';
import { SECURITY_RULES } from './rules-catalog.js';

export class RuleEngine {
  public evaluate(evidence: AggregatedScanEvidence): FindingResult[] {
    const findings: FindingResult[] = [];

    // 1. Evaluate TLS / SSL Rules
    if (evidence.tls) {
      const tls = evidence.tls;

      // Insecure protocols
      if (tls.supportsInsecureProtocols && tls.supportsInsecureProtocols.length > 0) {
        findings.push(
          this.createFinding('SEC-TLS-001', {
            summary: `Server accepted insecure protocol: ${tls.supportsInsecureProtocols.join(', ')}`,
            details: {
              negotiatedProtocol: tls.protocol,
              insecureProtocols: tls.supportsInsecureProtocols,
              cipher: tls.cipherName,
            },
          })
        );
      }

      // Expired or invalid certificate
      if (tls.isExpired || !tls.authorized) {
        findings.push(
          this.createFinding('SEC-TLS-002', {
            summary: tls.isExpired
              ? `Certificate expired on ${tls.validTo}`
              : 'Certificate is self-signed or from an untrusted authority',
            details: {
              validFrom: tls.validFrom,
              validTo: tls.validTo,
              issuer: tls.issuer,
              subject: tls.subject,
            },
          })
        );
      }

      // Expiring soon (< 14 days, but not already expired)
      if (!tls.isExpired && tls.daysRemaining > 0 && tls.daysRemaining <= 14) {
        findings.push(
          this.createFinding('SEC-TLS-003', {
            summary: `Certificate will expire in ${tls.daysRemaining} days (on ${tls.validTo})`,
            details: {
              daysRemaining: tls.daysRemaining,
              validTo: tls.validTo,
            },
          })
        );
      }

      // Hostname mismatch
      if (tls.hostnameMismatch) {
        findings.push(
          this.createFinding('SEC-TLS-004', {
            summary: 'Certificate CN/SANs do not match requested hostname',
            details: {
              sans: tls.sans,
              subjectCN: tls.subject?.CN,
            },
          })
        );
      }
    }

    // 2. Evaluate HTTP Security Headers
    if (evidence.http) {
      const headers = evidence.http.responseHeaders;
      const isHttps = evidence.http.finalUrl.startsWith('https://');

      // HSTS (relevant on HTTPS)
      if (isHttps && !headers['strict-transport-security']) {
        findings.push(
          this.createFinding('SEC-HDR-001', {
            summary: 'Strict-Transport-Security header is missing from HTTPS response',
            details: {
              finalUrl: evidence.http.finalUrl,
              statusCode: evidence.http.statusCode,
            },
          })
        );
      }

      // Content-Security-Policy
      const csp = headers['content-security-policy'];
      if (!csp) {
        findings.push(
          this.createFinding('SEC-HDR-002', {
            summary: 'Content-Security-Policy header is missing',
            details: {
              statusCode: evidence.http.statusCode,
            },
          })
        );
      } else {
        // Permissive CSP check
        if (/'unsafe-inline'/i.test(csp) || /'unsafe-eval'/i.test(csp)) {
          findings.push(
            this.createFinding('SEC-HDR-003', {
              summary: 'CSP contains unsafe directives (unsafe-inline or unsafe-eval)',
              details: {
                cspHeader: csp,
              },
            })
          );
        }
      }

      // X-Content-Type-Options
      const xcto = headers['x-content-type-options'];
      if (!xcto || xcto.toLowerCase() !== 'nosniff') {
        findings.push(
          this.createFinding('SEC-HDR-004', {
            summary: 'X-Content-Type-Options: nosniff header is missing',
            details: {
              headerValue: xcto || 'none',
            },
          })
        );
      }

      // Clickjacking (X-Frame-Options or frame-ancestors in CSP)
      const xfo = headers['x-frame-options'];
      const hasFrameAncestors = csp ? /frame-ancestors/i.test(csp) : false;
      if (!xfo && !hasFrameAncestors) {
        findings.push(
          this.createFinding('SEC-HDR-005', {
            summary: 'Neither X-Frame-Options nor CSP frame-ancestors is present',
            details: {
              statusCode: evidence.http.statusCode,
            },
          })
        );
      }

      // Referrer-Policy
      const ref = headers['referrer-policy'];
      if (!ref) {
        findings.push(
          this.createFinding('SEC-HDR-006', {
            summary: 'Referrer-Policy header is not explicitly configured',
            details: {
              statusCode: evidence.http.statusCode,
            },
          })
        );
      }

      // Server disclosure
      const server = headers['server'];
      if (server && /\d+\.\d+/.test(server)) {
        findings.push(
          this.createFinding('SEC-EXP-001', {
            summary: `Server header discloses software version: "${server}"`,
            details: {
              serverHeader: server,
            },
          })
        );
      }

      // Powered-by disclosure
      const poweredBy = headers['x-powered-by'];
      if (poweredBy) {
        findings.push(
          this.createFinding('SEC-EXP-002', {
            summary: `X-Powered-By header discloses technology stack: "${poweredBy}"`,
            details: {
              poweredByHeader: poweredBy,
            },
          })
        );
      }
    }

    // 3. Evaluate Cookie Security
    if (evidence.cookies && evidence.cookies.length > 0) {
      for (const cookie of evidence.cookies) {
        if (cookie.isSensitiveLikely && !cookie.hasSecure) {
          findings.push(
            this.createFinding('SEC-CK-001', {
              summary: `Sensitive cookie "${cookie.name}" is missing the Secure flag`,
              details: { cookieName: cookie.name },
            })
          );
        }

        if (cookie.isSensitiveLikely && !cookie.hasHttpOnly) {
          findings.push(
            this.createFinding('SEC-CK-002', {
              summary: `Sensitive cookie "${cookie.name}" is missing the HttpOnly flag`,
              details: { cookieName: cookie.name },
            })
          );
        }

        if (cookie.sameSite === 'Missing') {
          findings.push(
            this.createFinding('SEC-CK-003', {
              summary: `Cookie "${cookie.name}" lacks a SameSite attribute`,
              details: { cookieName: cookie.name },
            })
          );
        }
      }
    }

    // 4. Evaluate DNS Records
    if (evidence.dns) {
      if (!evidence.dns.hasDmarc) {
        findings.push(
          this.createFinding('SEC-DNS-001', {
            summary: `Domain ${evidence.dns.hostname} lacks a DMARC policy record`,
            details: { hostname: evidence.dns.hostname },
          })
        );
      }

      if (!evidence.dns.hasSpf) {
        findings.push(
          this.createFinding('SEC-DNS-002', {
            summary: `Domain ${evidence.dns.hostname} lacks an SPF record`,
            details: { hostname: evidence.dns.hostname },
          })
        );
      }
    }

    return findings;
  }

  private createFinding(
    ruleId: string,
    evidence: { summary: string; details: Record<string, unknown> }
  ): FindingResult {
    const rule = SECURITY_RULES[ruleId];
    if (!rule) {
      throw new Error(`Unknown security rule ID: ${ruleId}`);
    }

    // Calculate deterministic fingerprint for deduplication
    const rawFingerprintData = `${ruleId}:${evidence.summary}:${JSON.stringify(evidence.details)}`;
    const fingerprint = crypto.createHash('sha256').update(rawFingerprintData).digest('hex');

    return {
      ruleId: rule.id,
      title: rule.name,
      category: rule.category,
      severity: rule.severity,
      confidence: 'CONFIRMED',
      description: rule.description,
      impact: rule.impact,
      remediation: rule.remediationTemplate,
      evidence,
      fingerprint,
    };
  }
}
