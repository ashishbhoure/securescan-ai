/**
 * SecureScan AI - Shared Domain Types & Enums
 */

// ==========================================
// User, Auth & Organization Roles
// ==========================================

export enum OrgRole {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
  MEMBER = 'MEMBER',
  VIEWER = 'VIEWER',
}

export interface UserSession {
  userId: string;
  email: string;
  organizationId: string;
  role: OrgRole;
}

// ==========================================
// Assets & Ownership Verification
// ==========================================

export enum AssetType {
  WEBSITE = 'WEBSITE',
  API = 'API',
  DOMAIN = 'DOMAIN',
}

export enum AssetStatus {
  DISCOVERED = 'DISCOVERED',
  PENDING_VERIFICATION = 'PENDING_VERIFICATION',
  VERIFIED = 'VERIFIED',
  ACTIVE = 'ACTIVE',
  PAUSED = 'PAUSED',
  ARCHIVED = 'ARCHIVED',
}

export enum VerificationMethod {
  CONFIRMATION_CHECK = 'CONFIRMATION_CHECK',
  DNS_TXT = 'DNS_TXT',
  HTTP_TOKEN = 'HTTP_TOKEN',
}

export interface TargetAuthorizationRecord {
  assetId: string;
  organizationId: string;
  userId: string;
  method: VerificationMethod;
  authorizedAt: Date;
  ipAddress: string;
  userAgent?: string;
  confirmedOwnership: boolean;
}

// ==========================================
// Scans & Job Lifecycle
// ==========================================

export enum ScanStatus {
  QUEUED = 'QUEUED',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
}

export interface ScanJobPayload {
  scanId: string;
  assetId: string;
  organizationId: string;
  targetUrl: string;
  assetType: AssetType;
  options?: {
    checkDns?: boolean;
    checkTls?: boolean;
    checkHeaders?: boolean;
    checkCookies?: boolean;
    checkTechnology?: boolean;
    checkExposure?: boolean;
    openApiSpecUrl?: string;
  };
}

// ==========================================
// Findings, Severity & Rules
// ==========================================

export enum Severity {
  INFO = 'INFO',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export enum FindingStatus {
  OPEN = 'OPEN',
  ACKNOWLEDGED = 'ACKNOWLEDGED',
  IN_PROGRESS = 'IN_PROGRESS',
  RESOLVED = 'RESOLVED',
  FALSE_POSITIVE = 'FALSE_POSITIVE',
  ACCEPTED_RISK = 'ACCEPTED_RISK',
}

export enum SecurityCategory {
  TLS_SSL = 'TLS_SSL',
  SECURITY_HEADERS = 'SECURITY_HEADERS',
  COOKIE_SECURITY = 'COOKIE_SECURITY',
  DNS_DOMAIN = 'DNS_DOMAIN',
  INFORMATION_EXPOSURE = 'INFORMATION_EXPOSURE',
  API_SECURITY = 'API_SECURITY',
  MISCONFIGURATION = 'MISCONFIGURATION',
}

export interface SecurityRuleDefinition {
  id: string; // e.g. SEC-HDR-001
  name: string;
  category: SecurityCategory;
  severity: Severity;
  version: string;
  description: string;
  impact: string;
  remediationTemplate: string;
  cwe?: string;
  owaspCategory?: string;
}

// ==========================================
// Evidence Architecture
// ==========================================

export interface HttpEvidence {
  requestUrl: string;
  finalUrl: string;
  statusCode: number;
  redirectChain: string[];
  responseHeaders: Record<string, string>;
  serverHeader?: string;
}

export interface TlsEvidence {
  authorized: boolean;
  protocol: string;
  cipherName?: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  issuer: Record<string, string>;
  subject: Record<string, string>;
  sans: string[];
  isExpired: boolean;
  hostnameMismatch: boolean;
  supportsInsecureProtocols: string[];
}

export interface DnsEvidence {
  hostname: string;
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: string[];
  txtRecords: string[];
  nsRecords: string[];
  hasSpf: boolean;
  hasDmarc: boolean;
  dmarcPolicy?: string;
}

export interface CookieEvidenceItem {
  name: string;
  hasSecure: boolean;
  hasHttpOnly: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None' | 'Missing';
  isSensitiveLikely: boolean;
}

export interface TechnologyEvidenceItem {
  name: string;
  category: string;
  version?: string;
  evidenceSource: 'header' | 'html_meta' | 'script_src' | 'cookie';
}

export interface ExposureEvidenceItem {
  path: string;
  statusCode: number;
  type: string;
  snippetPreview?: string;
}

export interface AggregatedScanEvidence {
  scanId: string;
  targetUrl: string;
  dns?: DnsEvidence;
  tls?: TlsEvidence;
  http?: HttpEvidence;
  cookies?: CookieEvidenceItem[];
  technologies?: TechnologyEvidenceItem[];
  exposures?: ExposureEvidenceItem[];
  scannedAt: Date;
}

// ==========================================
// Finding & Risk Model
// ==========================================

export interface FindingResult {
  ruleId: string;
  title: string;
  category: SecurityCategory;
  severity: Severity;
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  impact: string;
  remediation: string;
  evidence: {
    summary: string;
    details: Record<string, unknown>;
  };
  fingerprint: string;
}

export interface RiskScoreBreakdown {
  overallScore: number; // 0 to 100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  riskDeductions: {
    ruleId: string;
    severity: Severity;
    deductionPoints: number;
    reason: string;
  }[];
}

// ==========================================
// AI Security Analyst Model
// ==========================================

export interface AIAnalysisResult {
  plainExplanation: string;
  businessImpact: string;
  technicalExplanation: string;
  developerFix: string;
  validationSteps: string[];
  priorityReasoning: string;
  tokenUsage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
}

// ==========================================
// Audit Logging
// ==========================================

export enum AuditAction {
  USER_LOGIN = 'USER_LOGIN',
  USER_LOGOUT = 'USER_LOGOUT',
  TARGET_AUTHORIZED = 'TARGET_AUTHORIZED',
  ASSET_CREATED = 'ASSET_CREATED',
  ASSET_DELETED = 'ASSET_DELETED',
  SCAN_QUEUED = 'SCAN_QUEUED',
  SCAN_COMPLETED = 'SCAN_COMPLETED',
  FINDING_STATUS_CHANGED = 'FINDING_STATUS_CHANGED',
  REPORT_DOWNLOADED = 'REPORT_DOWNLOADED',
  API_KEY_CREATED = 'API_KEY_CREATED',
  API_KEY_REVOKED = 'API_KEY_REVOKED',
}

export interface AuditLogEntry {
  organizationId: string;
  userId?: string;
  action: AuditAction;
  resourceType: string;
  resourceId: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}
