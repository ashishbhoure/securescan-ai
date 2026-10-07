/**
 * SecureScan AI - SSRF Protection Engine & IP Range Validator
 * Blocks loopback, RFC 1918 private, link-local, cloud metadata, and internal IP ranges.
 */

import * as net from 'net';

export class SsrfSecurityException extends Error {
  constructor(message: string) {
    super(`[SSRF_BLOCKED] ${message}`);
    this.name = 'SsrfSecurityException';
  }
}

/**
 * Checks if a given IPv4 or IPv6 address is private, loopback, or cloud metadata.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 0) {
    // Not a valid standard IP string (e.g., might be octal/hex obfuscated, which must be blocked)
    return true;
  }

  if (version === 4) {
    return isPrivateIpv4(ip);
  } else if (version === 6) {
    return isPrivateIpv6(ip);
  }

  return true;
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true;
  }

  const [p0, p1] = parts;

  // 0.0.0.0/8 (Current network)
  if (p0 === 0) return true;

  // 127.0.0.0/8 (Loopback)
  if (p0 === 127) return true;

  // 10.0.0.0/8 (Private RFC 1918)
  if (p0 === 10) return true;

  // 172.16.0.0/12 (Private RFC 1918)
  if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;

  // 192.168.0.0/16 (Private RFC 1918)
  if (p0 === 192 && p1 === 168) return true;

  // 169.254.0.0/16 (Link-Local & Cloud Metadata e.g. 169.254.169.254)
  if (p0 === 169 && p1 === 254) return true;

  // 100.64.0.0/10 (Shared Address Space / CGNAT)
  if (p0 === 100 && p1 >= 64 && p1 <= 127) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (p0 === 192 && p1 === 0 && parts[2] === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1)
  if (p0 === 192 && p1 === 0 && parts[2] === 2) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if (p0 === 198 && p1 === 51 && parts[2] === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (p0 === 203 && p1 === 0 && parts[2] === 113) return true;

  // 224.0.0.0/4 (Multicast)
  if (p0 >= 224 && p0 <= 239) return true;

  // 240.0.0.0/4 (Reserved / Future use)
  if (p0 >= 240) return true;

  // 255.255.255.255 (Broadcast)
  if (p0 === 255) return true;

  return false;
}

function isPrivateIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // IPv6 Loopback (::1)
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;

  // IPv6 Unspecified (::)
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true;

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
  if (normalized.startsWith('::ffff:')) {
    const ipv4Part = normalized.substring('::ffff:'.length);
    if (net.isIPv4(ipv4Part)) {
      return isPrivateIpv4(ipv4Part);
    }
    return true;
  }

  // Link-Local Unicast (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || 
      normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }

  // Unique Local Address / Private (fc00::/7 -> fc00:: to fdff::)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return true;
  }

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) {
    return true;
  }

  return false;
}

/**
 * Validates target hostname and schemes before any network operations.
 */
export function validateTargetUrl(rawUrl: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SsrfSecurityException(`Invalid URL format: ${rawUrl}`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SsrfSecurityException(`Prohibited protocol "${parsed.protocol}". Only HTTP/HTTPS allowed.`);
  }

  const hostname = parsed.hostname.toLowerCase();

  // Disallow localhost and internal DNS names
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.corp') ||
    hostname.endsWith('.home') ||
    hostname.endsWith('.lan')
  ) {
    throw new SsrfSecurityException(`Prohibited internal/local hostname: "${hostname}"`);
  }

  // If hostname is directly an IP, validate it immediately
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new SsrfSecurityException(`Target IP "${hostname}" is private, reserved or loopback.`);
    }
  }

  return parsed;
}
