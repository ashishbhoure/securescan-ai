/**
 * SecureScan AI - DNS Security Scanner
 * Resolves standard records and evaluates SPF / DMARC posture.
 */

import * as dns from 'dns/promises';
import { DnsEvidence } from '@securescan/types';

export class DnsScanner {
  public async scan(hostname: string): Promise<DnsEvidence> {
    const aRecords: string[] = [];
    const aaaaRecords: string[] = [];
    const mxRecords: string[] = [];
    const txtRecords: string[] = [];
    const nsRecords: string[] = [];

    // Resolve A
    try {
      const res = await dns.resolve4(hostname);
      aRecords.push(...res);
    } catch {
      // Record type may not exist
    }

    // Resolve AAAA
    try {
      const res = await dns.resolve6(hostname);
      aaaaRecords.push(...res);
    } catch {
      // Record type may not exist
    }

    // Resolve MX
    try {
      const res = await dns.resolveMx(hostname);
      mxRecords.push(...res.map((mx) => `${mx.priority} ${mx.exchange}`));
    } catch {
      // Record type may not exist
    }

    // Resolve TXT
    try {
      const res = await dns.resolveTxt(hostname);
      txtRecords.push(...res.map((r) => r.join(' ')));
    } catch {
      // Record type may not exist
    }

    // Resolve NS
    try {
      const res = await dns.resolveNs(hostname);
      nsRecords.push(...res);
    } catch {
      // Record type may not exist
    }

    // Check SPF
    const hasSpf = txtRecords.some((txt) => txt.toLowerCase().startsWith('v=spf1'));

    // Check DMARC
    let hasDmarc = false;
    let dmarcPolicy: string | undefined = undefined;

    try {
      const dmarcTxt = await dns.resolveTxt(`_dmarc.${hostname}`);
      const joinedDmarc = dmarcTxt.map((r) => r.join(' ')).join(' ');
      if (joinedDmarc.toLowerCase().startsWith('v=dmarc1')) {
        hasDmarc = true;
        const match = joinedDmarc.match(/p=([a-zA-Z]+)/i);
        if (match) {
          dmarcPolicy = match[1].toLowerCase();
        }
      }
    } catch {
      // DMARC record may not exist
    }

    return {
      hostname,
      aRecords,
      aaaaRecords,
      mxRecords,
      txtRecords,
      nsRecords,
      hasSpf,
      hasDmarc,
      dmarcPolicy,
    };
  }
}
