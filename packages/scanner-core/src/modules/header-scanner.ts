/**
 * SecureScan AI - HTTP Security Header & Exposure Scanner
 * Evaluates defense headers and software banner disclosure.
 */

import { HttpEvidence } from '@securescan/types';

export interface HeaderAnalysisResult {
  hasHsts: boolean;
  hstsValue?: string;
  hstsIncludesSubdomains: boolean;
  hstsPreload: boolean;
  hstsMaxAge?: number;

  hasCsp: boolean;
  cspValue?: string;
  cspHasUnsafeInline: boolean;
  cspHasUnsafeEval: boolean;

  hasXContentTypeOptions: boolean;
  xContentTypeOptionsNosniff: boolean;

  hasXFrameOptions: boolean;
  xFrameOptionsValue?: string;

  hasReferrerPolicy: boolean;
  referrerPolicyValue?: string;

  hasPermissionsPolicy: boolean;

  serverHeader?: string;
  poweredByHeader?: string;
}

export class HeaderScanner {
  public analyze(httpEvidence: HttpEvidence): HeaderAnalysisResult {
    const headers = httpEvidence.responseHeaders;

    // HSTS
    const hstsRaw = headers['strict-transport-security'];
    const hasHsts = Boolean(hstsRaw);
    let hstsIncludesSubdomains = false;
    let hstsPreload = false;
    let hstsMaxAge: number | undefined = undefined;

    if (hstsRaw) {
      hstsIncludesSubdomains = /includeSubDomains/i.test(hstsRaw);
      hstsPreload = /preload/i.test(hstsRaw);
      const maxAgeMatch = hstsRaw.match(/max-age=(\d+)/i);
      if (maxAgeMatch) {
        hstsMaxAge = parseInt(maxAgeMatch[1], 10);
      }
    }

    // CSP
    const cspRaw = headers['content-security-policy'];
    const hasCsp = Boolean(cspRaw);
    const cspHasUnsafeInline = cspRaw ? /'unsafe-inline'/i.test(cspRaw) : false;
    const cspHasUnsafeEval = cspRaw ? /'unsafe-eval'/i.test(cspRaw) : false;

    // X-Content-Type-Options
    const xctoRaw = headers['x-content-type-options'];
    const hasXContentTypeOptions = Boolean(xctoRaw);
    const xContentTypeOptionsNosniff = xctoRaw?.toLowerCase() === 'nosniff';

    // X-Frame-Options
    const xfoRaw = headers['x-frame-options'];
    const hasXFrameOptions = Boolean(xfoRaw);

    // Referrer-Policy
    const refPolicy = headers['referrer-policy'];
    const hasReferrerPolicy = Boolean(refPolicy);

    // Permissions-Policy
    const permPolicy = headers['permissions-policy'];
    const hasPermissionsPolicy = Boolean(permPolicy);

    // Exposure
    const serverHeader = headers['server'];
    const poweredByHeader = headers['x-powered-by'];

    return {
      hasHsts,
      hstsValue: hstsRaw,
      hstsIncludesSubdomains,
      hstsPreload,
      hstsMaxAge,

      hasCsp,
      cspValue: cspRaw,
      cspHasUnsafeInline,
      cspHasUnsafeEval,

      hasXContentTypeOptions,
      xContentTypeOptionsNosniff,

      hasXFrameOptions,
      xFrameOptionsValue: xfoRaw,

      hasReferrerPolicy,
      referrerPolicyValue: refPolicy,

      hasPermissionsPolicy,

      serverHeader,
      poweredByHeader,
    };
  }
}
