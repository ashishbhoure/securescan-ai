/**
 * SecureScan AI - SSRF-Hardened HTTP Transport with DNS Pinning
 * Prevents DNS rebinding and redirect-to-internal network attacks.
 */

import * as http from 'http';
import * as https from 'https';
import * as dns from 'dns/promises';
import { validateTargetUrl, isPrivateOrReservedIp, SsrfSecurityException } from './ip-validator.js';
import { logger } from '@securescan/logger';

export interface SafeHttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  redirectChain: string[];
}

export interface SafeRequestOptions {
  timeoutMs?: number;
  maxRedirects?: number;
  maxBodyBytes?: number;
}

const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MB max response

/**
 * Executes an SSRF-safe HTTP GET request with IP pinning and redirect auditing
 */
export async function safeHttpGet(
  initialUrl: string,
  options: SafeRequestOptions = {}
): Promise<SafeHttpResponse> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  let currentUrl = initialUrl;
  const redirectChain: string[] = [];

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const parsed = validateTargetUrl(currentUrl);

    // Step 1: Safely resolve hostname
    const resolvedIps = await dns.resolve(parsed.hostname).catch(async () => {
      // Fallback to dns.lookup
      const res = await dns.lookup(parsed.hostname, { all: true });
      return res.map((r) => r.address);
    });

    if (!resolvedIps || resolvedIps.length === 0) {
      throw new SsrfSecurityException(`DNS resolution failed for hostname: ${parsed.hostname}`);
    }

    // Step 2: Validate EVERY resolved IP against SSRF blocklist
    for (const ip of resolvedIps) {
      if (isPrivateOrReservedIp(ip)) {
        logger.warn('SSRF attempt blocked by DNS resolution check', {
          hostname: parsed.hostname,
          blockedIp: ip,
        });
        throw new SsrfSecurityException(`Hostname ${parsed.hostname} resolved to reserved/private IP: ${ip}`);
      }
    }

    const pinnedIp = resolvedIps[0];

    // Step 3: Perform request with pinned IP (connect to IP, set Host header)
    const response = await executePinnedRequest(parsed, pinnedIp, timeoutMs, maxBodyBytes);

    // Step 4: Handle Redirects securely
    if (
      response.statusCode >= 300 &&
      response.statusCode < 400 &&
      response.headers['location']
    ) {
      redirectChain.push(currentUrl);
      const redirectLocation = response.headers['location'];
      const nextUrl = new URL(redirectLocation, currentUrl).toString();

      // Check loop
      if (redirectChain.includes(nextUrl)) {
        throw new Error(`Infinite redirect loop detected to: ${nextUrl}`);
      }

      currentUrl = nextUrl;
      continue;
    }

    return {
      statusCode: response.statusCode,
      headers: response.headers,
      body: response.body,
      finalUrl: currentUrl,
      redirectChain,
    };
  }

  throw new Error(`Exceeded maximum allowed redirects (${maxRedirects})`);
}

function executePinnedRequest(
  parsedUrl: URL,
  pinnedIp: string,
  timeoutMs: number,
  maxBodyBytes: number
): Promise<{ statusCode: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    const isHttps = parsedUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : isHttps ? 443 : 80;

    const requestOptions: https.RequestOptions = {
      host: pinnedIp, // Connect directly to verified IP
      port,
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: {
        Host: parsedUrl.hostname, // Preserve target Host header
        'User-Agent': 'SecureScanAI-SecurityAudit/1.0 (+https://securescan.ai/bot-policy)',
        Accept: 'text/html,application/xhtml+xml,application/json,*/*',
        'Accept-Encoding': 'identity',
        Connection: 'close',
      },
      servername: parsedUrl.hostname, // Required for SNI in TLS
      timeout: timeoutMs,
    };

    const req = client.request(requestOptions, (res) => {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (v !== undefined) {
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
        }
      }

      let body = '';
      let receivedBytes = 0;

      res.on('data', (chunk: Buffer) => {
        receivedBytes += chunk.length;
        if (receivedBytes > maxBodyBytes) {
          req.destroy(new Error(`Response exceeded maximum size limit (${maxBodyBytes} bytes)`));
          return;
        }
        body += chunk.toString('utf-8');
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 0,
          headers,
          body,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error(`HTTP request timed out after ${timeoutMs}ms`));
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.end();
  });
}
