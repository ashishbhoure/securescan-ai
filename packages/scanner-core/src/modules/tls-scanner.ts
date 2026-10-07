/**
 * SecureScan AI - TLS / SSL Security Scanner
 * Validates certificate chain, expiration horizon, SANs, and TLS protocol negotiation.
 */

import * as tls from 'tls';
import { TlsEvidence } from '@securescan/types';

export class TlsScanner {
  public scan(hostname: string, port = 443, timeoutMs = 8000): Promise<TlsEvidence> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false, // We inspect the certificate authorization manually to capture errors as evidence
          timeout: timeoutMs,
        },
        () => {
          try {
            const cert = socket.getPeerCertificate(true);
            const cipher = socket.getCipher();
            const protocol = socket.getProtocol() || 'UNKNOWN';
            const authorized = socket.authorized;

            if (!cert || Object.keys(cert).length === 0) {
              socket.destroy();
              return resolve({
                authorized: false,
                protocol,
                validFrom: '',
                validTo: '',
                daysRemaining: 0,
                issuer: {},
                subject: {},
                sans: [],
                isExpired: true,
                hostnameMismatch: true,
                supportsInsecureProtocols: [],
              });
            }

            const validToDate = new Date(cert.valid_to);
            const now = new Date();
            const daysRemaining = Math.floor(
              (validToDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
            );
            const isExpired = daysRemaining <= 0;

            // SANs extraction
            const sans: string[] = [];
            if (cert.subjectaltname) {
              sans.push(
                ...cert.subjectaltname
                  .split(',')
                  .map((s) => s.trim().replace(/^DNS:/i, ''))
              );
            }

            // Check hostname match against subject CN or SANs
            const rawCN = cert.subject?.CN;
            const cn = Array.isArray(rawCN) ? rawCN[0] : rawCN;
            const hostnameMatches =
              this.matchHostname(hostname, cn) ||
              sans.some((san) => this.matchHostname(hostname, san));

            const supportsInsecure = [];
            if (['TLSv1', 'TLSv1.1', 'SSLv3'].includes(protocol)) {
              supportsInsecure.push(protocol);
            }

            socket.destroy();

            resolve({
              authorized: authorized && !isExpired && hostnameMatches,
              protocol,
              cipherName: cipher?.name,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              daysRemaining,
              issuer: cert.issuer as unknown as Record<string, string>,
              subject: cert.subject as unknown as Record<string, string>,
              sans,
              isExpired,
              hostnameMismatch: !hostnameMatches,
              supportsInsecureProtocols: supportsInsecure,
            });
          } catch (err) {
            socket.destroy();
            reject(err);
          }
        }
      );

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error(`TLS connection timed out after ${timeoutMs}ms for ${hostname}`));
      });

      socket.on('error', (err) => {
        socket.destroy();
        reject(err);
      });
    });
  }

  private matchHostname(target: string, pattern?: string): boolean {
    if (!pattern) return false;
    const lowerTarget = target.toLowerCase();
    const lowerPattern = pattern.toLowerCase();

    if (lowerTarget === lowerPattern) return true;

    // Wildcard match e.g. *.example.com
    if (lowerPattern.startsWith('*.')) {
      const baseDomain = lowerPattern.substring(2);
      const targetParts = lowerTarget.split('.');
      if (targetParts.length > 1) {
        const targetBase = targetParts.slice(1).join('.');
        return targetBase === baseDomain;
      }
    }

    return false;
  }
}
