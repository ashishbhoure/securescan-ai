/**
 * SecureScan AI - Database Seeder
 * Populates security rules catalog, subscription plans, and default seed tenant.
 */

import { PrismaClient, OrgRole, Severity } from '@prisma/client';
import * as crypto from 'crypto';

const prisma = new PrismaClient();

// Inlined or referenced security rules for reliable self-contained seeding
const SEED_RULES = [
  {
    id: 'SEC-TLS-001',
    name: 'Deprecated Insecure TLS Protocol Support',
    category: 'TLS_SSL',
    severity: Severity.HIGH,
    version: '1.0.0',
    description: 'The server negotiates deprecated cryptographic protocols (TLS 1.0, TLS 1.1, or SSLv3).',
    impact: 'Attackers can intercept transit sessions via known cryptographic downgrade attacks.',
    remediationTemplate: 'Disable SSLv3, TLS 1.0, and TLS 1.1. Enforce TLS 1.2 and TLS 1.3 only.',
    cwe: 'CWE-326',
    owaspCategory: 'A02:2021-Cryptographic Failures',
  },
  {
    id: 'SEC-TLS-002',
    name: 'Expired or Untrusted TLS/SSL Certificate',
    category: 'TLS_SSL',
    severity: Severity.CRITICAL,
    version: '1.0.0',
    description: 'The TLS certificate is expired or untrusted.',
    impact: 'Users receive security warnings and sessions are susceptible to MitM interception.',
    remediationTemplate: 'Renew certificate via Let\'s Encrypt or your authorized CA immediately.',
    cwe: 'CWE-295',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
  },
  {
    id: 'SEC-TLS-003',
    name: 'TLS Certificate Expiring Soon',
    category: 'TLS_SSL',
    severity: Severity.MEDIUM,
    version: '1.0.0',
    description: 'The active TLS certificate expires in under 14 days.',
    impact: 'Site risks impending outage and security warnings.',
    remediationTemplate: 'Renew and deploy new TLS certificate prior to expiry date.',
    cwe: 'CWE-298',
  },
  {
    id: 'SEC-TLS-004',
    name: 'TLS Certificate Hostname Mismatch',
    category: 'TLS_SSL',
    severity: Severity.HIGH,
    version: '1.0.0',
    description: 'Certificate CN/SANs do not match the target hostname.',
    impact: 'Client browsers reject the connection.',
    remediationTemplate: 'Deploy a certificate that explicitly lists the target hostname in SANs.',
    cwe: 'CWE-297',
  },
  {
    id: 'SEC-HDR-001',
    name: 'Missing Strict-Transport-Security (HSTS) Header',
    category: 'SECURITY_HEADERS',
    severity: Severity.MEDIUM,
    version: '1.0.0',
    description: 'HTTP response lacks Strict-Transport-Security header.',
    impact: 'Allows SSL-stripping attacks on unencrypted initial connections.',
    remediationTemplate: 'Configure: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    cwe: 'CWE-319',
    owaspCategory: 'A05:2021-Security Misconfiguration',
  },
  {
    id: 'SEC-HDR-002',
    name: 'Missing Content-Security-Policy (CSP) Header',
    category: 'SECURITY_HEADERS',
    severity: Severity.MEDIUM,
    version: '1.0.0',
    description: 'Response does not include a Content-Security-Policy header.',
    impact: 'Increased vulnerability to Cross-Site Scripting (XSS) and code injection.',
    remediationTemplate: 'Configure a strong Content-Security-Policy declaring explicit trusted origins.',
    cwe: 'CWE-1021',
    owaspCategory: 'A05:2021-Security Misconfiguration',
  },
  {
    id: 'SEC-HDR-003',
    name: 'Permissive CSP Unsafe Directive Detected',
    category: 'SECURITY_HEADERS',
    severity: Severity.LOW,
    version: '1.0.0',
    description: 'Content-Security-Policy contains \'unsafe-inline\' or \'unsafe-eval\'.',
    impact: 'Allows injected script snippets to execute despite CSP presence.',
    remediationTemplate: 'Refactor inline scripts to external bundles and adopt cryptographic nonces.',
    cwe: 'CWE-1021',
  },
  {
    id: 'SEC-HDR-004',
    name: 'Missing X-Content-Type-Options Header',
    category: 'SECURITY_HEADERS',
    severity: Severity.LOW,
    version: '1.0.0',
    description: 'Missing X-Content-Type-Options: nosniff header.',
    impact: 'MIME sniffing can lead to script execution from non-script MIME types.',
    remediationTemplate: 'Add header: X-Content-Type-Options: nosniff',
    cwe: 'CWE-79',
  },
  {
    id: 'SEC-HDR-005',
    name: 'Missing Clickjacking Protection',
    category: 'SECURITY_HEADERS',
    severity: Severity.MEDIUM,
    version: '1.0.0',
    description: 'Neither X-Frame-Options nor CSP frame-ancestors is present.',
    impact: 'Attackers can iframe the application to conduct Clickjacking attacks.',
    remediationTemplate: 'Configure: X-Frame-Options: DENY or CSP frame-ancestors \'self\'.',
    cwe: 'CWE-1021',
  },
  {
    id: 'SEC-HDR-006',
    name: 'Missing or Insecure Referrer-Policy',
    category: 'SECURITY_HEADERS',
    severity: Severity.LOW,
    version: '1.0.0',
    description: 'Response lacks an explicit Referrer-Policy.',
    impact: 'Sensitive path URLs may leak across cross-origin requests.',
    remediationTemplate: 'Configure: Referrer-Policy: strict-origin-when-cross-origin',
    cwe: 'CWE-200',
  },
  {
    id: 'SEC-CK-001',
    name: 'Sensitive Cookie Missing Secure Flag',
    category: 'COOKIE_SECURITY',
    severity: Severity.HIGH,
    version: '1.0.0',
    description: 'Session cookie sent without Secure attribute.',
    impact: 'Credentials transmitted unencrypted over plain HTTP.',
    remediationTemplate: 'Add "; Secure" attribute to Set-Cookie header.',
    cwe: 'CWE-614',
  },
  {
    id: 'SEC-CK-002',
    name: 'Sensitive Cookie Missing HttpOnly Flag',
    category: 'COOKIE_SECURITY',
    severity: Severity.HIGH,
    version: '1.0.0',
    description: 'Session cookie accessible via client JavaScript.',
    impact: 'Session tokens can be stolen via XSS.',
    remediationTemplate: 'Add "; HttpOnly" attribute to Set-Cookie header.',
    cwe: 'CWE-1004',
  },
  {
    id: 'SEC-CK-003',
    name: 'Cookie Missing SameSite Attribute',
    category: 'COOKIE_SECURITY',
    severity: Severity.MEDIUM,
    version: '1.0.0',
    description: 'Cookie missing SameSite attribute.',
    impact: 'Elevated risk of Cross-Site Request Forgery (CSRF).',
    remediationTemplate: 'Set "; SameSite=Lax" or "; SameSite=Strict".',
    cwe: 'CWE-352',
  },
  {
    id: 'SEC-EXP-001',
    name: 'Detailed Server Banner Disclosure',
    category: 'INFORMATION_EXPOSURE',
    severity: Severity.LOW,
    version: '1.0.0',
    description: 'Server header exposes software product and version.',
    impact: 'Assists targeted reconnaissance.',
    remediationTemplate: 'Disable server version banner tokens in web server config.',
    cwe: 'CWE-200',
  },
  {
    id: 'SEC-EXP-002',
    name: 'Backend Framework Header Disclosure',
    category: 'INFORMATION_EXPOSURE',
    severity: Severity.LOW,
    version: '1.0.0',
    description: 'X-Powered-By header discloses backend technology.',
    impact: 'Aids attacker reconnaissance.',
    remediationTemplate: 'Disable X-Powered-By header.',
    cwe: 'CWE-200',
  },
  {
    id: 'SEC-DNS-001',
    name: 'Missing DMARC Policy on Domain',
    category: 'DNS_DOMAIN',
    severity: Severity.LOW,
    version: '1.0.0',
    description: 'Domain lacks DMARC DNS record.',
    impact: 'Allows spoofed email impersonation without validation rejection.',
    remediationTemplate: 'Publish TXT record at _dmarc.yourdomain.com.',
    cwe: 'CWE-290',
  },
  {
    id: 'SEC-DNS-002',
    name: 'Missing SPF Record on Domain',
    category: 'DNS_DOMAIN',
    severity: Severity.LOW,
    version: '1.0.0',
    description: 'Domain lacks an SPF DNS record.',
    impact: 'Receiving mail servers cannot verify legitimate senders.',
    remediationTemplate: 'Publish TXT SPF record declaring authorized mail hosts.',
    cwe: 'CWE-290',
  },
];

const SEED_PLANS = [
  {
    name: 'Free Community',
    tier: 'FREE',
    maxAssets: 1,
    maxScansPerMonth: 5,
    priceMonthlyCents: 0,
    isAgency: false,
  },
  {
    name: 'Starter Cloud',
    tier: 'STARTER',
    maxAssets: 5,
    maxScansPerMonth: 30,
    priceMonthlyCents: 2900,
    isAgency: false,
  },
  {
    name: 'Professional',
    tier: 'PRO',
    maxAssets: 25,
    maxScansPerMonth: 200,
    priceMonthlyCents: 9900,
    isAgency: false,
  },
  {
    name: 'Agency Enterprise',
    tier: 'AGENCY',
    maxAssets: 100,
    maxScansPerMonth: 1000,
    priceMonthlyCents: 29900,
    isAgency: true,
  },
];

async function main() {
  console.log('--- Starting SecureScan AI Database Seeder ---');

  // 1. Seed Security Rules
  console.log('Seeding Security Rules Catalog...');
  for (const rule of SEED_RULES) {
    await prisma.securityRule.upsert({
      where: { id: rule.id },
      update: rule,
      create: rule,
    });
  }
  console.log(`Successfully seeded ${SEED_RULES.length} security rules.`);

  // 2. Seed Subscription Plans
  console.log('Seeding Subscription Plans...');
  for (const plan of SEED_PLANS) {
    await prisma.plan.upsert({
      where: { tier: plan.tier },
      update: plan,
      create: plan,
    });
  }
  console.log(`Successfully seeded ${SEED_PLANS.length} subscription plans.`);

  // 3. Seed Default Test User & Organization
  const testEmail = 'demo@securescan.ai';
  // Password hash for 'SecureScan123!' using sha256 (for seed testing convenience; production uses Argon2id)
  const passwordHash = crypto.createHash('sha256').update('SecureScan123!').digest('hex');

  const user = await prisma.user.upsert({
    where: { email: testEmail },
    update: {},
    create: {
      email: testEmail,
      name: 'Security Architect',
      passwordHash,
      isEmailVerified: true,
    },
  });

  const org = await prisma.organization.upsert({
    where: { slug: 'securescan-demo' },
    update: {},
    create: {
      name: 'Acme Cyber Labs',
      slug: 'securescan-demo',
      planTier: 'PRO',
      maxAssets: 25,
      members: {
        create: {
          userId: user.id,
          role: OrgRole.OWNER,
        },
      },
    },
  });

  const project = await prisma.project.create({
    data: {
      organizationId: org.id,
      name: 'Main Infrastructure',
      description: 'Production web properties and cloud portals',
    },
  });

  await prisma.asset.create({
    data: {
      organizationId: org.id,
      projectId: project.id,
      type: 'WEBSITE',
      targetUrl: 'https://example.com',
      status: 'ACTIVE',
      verificationStatus: 'VERIFIED',
    },
  });

  console.log(`Default tenant seeded: Org ID ${org.id}, User ID ${user.id}`);
  console.log('--- Seeding Completed Successfully ---');
}

main()
  .catch((e) => {
    console.error('Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
