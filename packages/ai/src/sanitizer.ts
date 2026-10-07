/**
 * SecureScan AI - Prompt Injection Defense & Input Sanitizer
 * Strips adversarial injection directives and isolates untrusted target data.
 */

import * as crypto from 'crypto';

const INJECTION_PATTERNS = [
  /ignore (all )?(previous|prior) (instructions|directions|prompts)/gi,
  /disregard (all )?(previous|prior) instructions/gi,
  /you are now (an? )?(unrestricted|DAN|jailbreak)/gi,
  /system prompt:/gi,
  /developer mode:/gi,
  /<\/?system>/gi,
  /<\/?instructions>/gi,
];

export class PromptSanitizer {
  /**
   * Sanitizes untrusted text gathered from remote scans before inclusion into LLM prompts
   */
  public sanitizeUntrustedInput(rawInput: string): string {
    if (!rawInput) return '';

    let cleaned = rawInput;

    // Neutralize injection patterns
    for (const pattern of INJECTION_PATTERNS) {
      cleaned = cleaned.replace(pattern, '[BLOCKED_INJECTION_ATTEMPT]');
    }

    // Limit length to prevent context flooding
    const MAX_UNTRUSTED_CHARS = 2000;
    if (cleaned.length > MAX_UNTRUSTED_CHARS) {
      cleaned = cleaned.substring(0, MAX_UNTRUSTED_CHARS) + '... [TRUNCATED]';
    }

    return cleaned;
  }

  /**
   * Wraps untrusted target content in strict XML-style isolation tags
   */
  public wrapUntrustedData(content: string, label = 'untrusted_scan_evidence'): string {
    const cleanContent = this.sanitizeUntrustedInput(content);
    return `<${label}>\n${cleanContent}\n</${label}>`;
  }

  /**
   * Generates a stable cache key hash for AI analysis deduplication
   */
  public computeFindingHash(ruleId: string, severity: string, evidenceSummary: string): string {
    const raw = `${ruleId}:${severity}:${evidenceSummary.trim().toLowerCase()}`;
    return crypto.createHash('sha256').update(raw).digest('hex');
  }
}

export const promptSanitizer = new PromptSanitizer();
