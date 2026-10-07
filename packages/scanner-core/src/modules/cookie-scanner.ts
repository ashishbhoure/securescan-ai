/**
 * SecureScan AI - Cookie Security Scanner
 * Scrutinizes Set-Cookie attributes, flags missing flags, and redacts values.
 */

import { CookieEvidenceItem } from '@securescan/types';

const SENSITIVE_COOKIE_NAME_PATTERNS = [
  /sess(ion)?/i,
  /auth/i,
  /token/i,
  /jwt/i,
  /id/i,
  /connect\.sid/i,
  /phpsessid/i,
  /jsessionid/i,
  /csrf/i,
  /xsrf/i,
];

export class CookieScanner {
  public analyze(setCookieHeaders: string | string[] | undefined): CookieEvidenceItem[] {
    if (!setCookieHeaders) return [];

    const rawCookies = Array.isArray(setCookieHeaders)
      ? setCookieHeaders
      : [setCookieHeaders];

    const results: CookieEvidenceItem[] = [];

    for (const raw of rawCookies) {
      const parts = raw.split(';').map((p) => p.trim());
      if (parts.length === 0 || !parts[0]) continue;

      const [namePart] = parts;
      const equalsIdx = namePart.indexOf('=');
      const name = equalsIdx > -1 ? namePart.substring(0, equalsIdx).trim() : namePart.trim();

      const lowerParts = parts.map((p) => p.toLowerCase());
      const hasSecure = lowerParts.includes('secure');
      const hasHttpOnly = lowerParts.includes('httponly');

      let sameSite: 'Strict' | 'Lax' | 'None' | 'Missing' = 'Missing';
      for (const p of parts) {
        if (/^samesite=/i.test(p)) {
          const val = p.split('=')[1]?.trim().toLowerCase();
          if (val === 'strict') sameSite = 'Strict';
          else if (val === 'lax') sameSite = 'Lax';
          else if (val === 'none') sameSite = 'None';
        }
      }

      const isSensitiveLikely = SENSITIVE_COOKIE_NAME_PATTERNS.some((pat) => pat.test(name));

      results.push({
        name,
        hasSecure,
        hasHttpOnly,
        sameSite,
        isSensitiveLikely,
      });
    }

    return results;
  }
}
