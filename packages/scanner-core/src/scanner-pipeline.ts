/**
 * SecureScan AI - Modular Scanner Orchestrator
 * Coordinates safe execution of DNS, TLS, HTTP, Headers, Cookie and Tech scanning modules.
 */

import { AggregatedScanEvidence, ScanJobPayload } from '@securescan/types';
import { logger } from '@securescan/logger';
import { validateTargetUrl } from './ssrf/ip-validator.js';
import { safeHttpGet } from './ssrf/safe-transport.js';
import { DnsScanner } from './modules/dns-scanner.js';
import { TlsScanner } from './modules/tls-scanner.js';
import { HeaderScanner } from './modules/header-scanner.js';
import { CookieScanner } from './modules/cookie-scanner.js';
import { TechnologyScanner } from './modules/tech-scanner.js';

export class ScannerPipeline {
  private dnsScanner = new DnsScanner();
  private tlsScanner = new TlsScanner();
  private headerScanner = new HeaderScanner();
  private cookieScanner = new CookieScanner();
  private techScanner = new TechnologyScanner();

  public async execute(job: ScanJobPayload): Promise<AggregatedScanEvidence> {
    const scanLogger = logger.withContext({
      scanId: job.scanId,
      assetId: job.assetId,
      organizationId: job.organizationId,
    });

    scanLogger.info(`Initiating security scan pipeline for target: ${job.targetUrl}`);

    const parsedUrl = validateTargetUrl(job.targetUrl);
    const hostname = parsedUrl.hostname;
    const isHttps = parsedUrl.protocol === 'https:';

    const evidence: AggregatedScanEvidence = {
      scanId: job.scanId,
      targetUrl: job.targetUrl,
      scannedAt: new Date(),
    };

    // 1. DNS Scanner Module
    try {
      scanLogger.debug('Running DNS scan module', { hostname });
      evidence.dns = await this.dnsScanner.scan(hostname);
    } catch (err) {
      scanLogger.warn('DNS scanner encountered error, continuing remaining modules', {
        error: (err as Error).message,
      });
    }

    // 2. TLS Scanner Module (if HTTPS or standard web)
    if (isHttps || job.options?.checkTls !== false) {
      try {
        scanLogger.debug('Running TLS scan module', { hostname });
        const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : 443;
        evidence.tls = await this.tlsScanner.scan(hostname, port);
      } catch (err) {
        scanLogger.warn('TLS scanner encountered error, continuing remaining modules', {
          error: (err as Error).message,
        });
      }
    }

    // 3. Safe HTTP Transport Module (SSRF-protected + IP pinned)
    try {
      scanLogger.debug('Executing safe HTTP request', { targetUrl: job.targetUrl });
      const httpResponse = await safeHttpGet(job.targetUrl);

      evidence.http = {
        requestUrl: job.targetUrl,
        finalUrl: httpResponse.finalUrl,
        statusCode: httpResponse.statusCode,
        redirectChain: httpResponse.redirectChain,
        responseHeaders: httpResponse.headers,
        serverHeader: httpResponse.headers['server'],
      };

      // 4. Header Scanner
      this.headerScanner.analyze(evidence.http);

      // 5. Cookie Scanner
      const setCookieHeaders = httpResponse.headers['set-cookie'];
      evidence.cookies = this.cookieScanner.analyze(setCookieHeaders);

      // 6. Technology Profiler
      evidence.technologies = this.techScanner.analyze(
        httpResponse.headers,
        httpResponse.body
      );
    } catch (err) {
      scanLogger.error('Safe HTTP transport failed', {
        error: (err as Error).message,
      });
      throw err; // HTTP failure is fatal for posture analysis
    }

    scanLogger.info('Scanner pipeline completed successfully');
    return evidence;
  }
}
