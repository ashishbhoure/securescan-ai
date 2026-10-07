import { describe, it, expect } from 'vitest';
import { isPrivateOrReservedIp, validateTargetUrl } from '../src/ssrf/ip-validator.js';
import { HeaderScanner } from '../src/modules/header-scanner.js';
import { CookieScanner } from '../src/modules/cookie-scanner.js';

describe('SSRF Protection Engine', () => {
  it('should identify and block loopback IPv4 addresses', () => {
    expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIp('127.1.2.3')).toBe(true);
    expect(isPrivateOrReservedIp('0.0.0.0')).toBe(true);
  });

  it('should identify and block RFC 1918 private IPv4 ranges', () => {
    expect(isPrivateOrReservedIp('10.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIp('10.254.254.254')).toBe(true);
    expect(isPrivateOrReservedIp('172.16.0.1')).toBe(true);
    expect(isPrivateOrReservedIp('172.31.255.255')).toBe(true);
    expect(isPrivateOrReservedIp('192.168.1.1')).toBe(true);
    expect(isPrivateOrReservedIp('192.168.100.254')).toBe(true);
  });

  it('should identify and block Cloud Metadata endpoints (169.254.169.254)', () => {
    expect(isPrivateOrReservedIp('169.254.169.254')).toBe(true);
    expect(isPrivateOrReservedIp('169.254.1.1')).toBe(true);
  });

  it('should identify and block IPv6 loopback and private ranges', () => {
    expect(isPrivateOrReservedIp('::1')).toBe(true);
    expect(isPrivateOrReservedIp('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIp('fe80::1')).toBe(true);
    expect(isPrivateOrReservedIp('fc00::1')).toBe(true);
  });

  it('should allow legitimate public IP addresses', () => {
    expect(isPrivateOrReservedIp('8.8.8.8')).toBe(false);
    expect(isPrivateOrReservedIp('1.1.1.1')).toBe(false);
    expect(isPrivateOrReservedIp('93.184.216.34')).toBe(false); // example.com
  });

  it('should reject prohibited schemes and internal hostnames', () => {
    expect(() => validateTargetUrl('ftp://example.com')).toThrow();
    expect(() => validateTargetUrl('file:///etc/passwd')).toThrow();
    expect(() => validateTargetUrl('http://localhost')).toThrow();
    expect(() => validateTargetUrl('http://app.local')).toThrow();
    expect(() => validateTargetUrl('http://127.0.0.1:8080')).toThrow();
    expect(() => validateTargetUrl('http://169.254.169.254/latest/meta-data/')).toThrow();
  });

  it('should accept valid public URLs', () => {
    const parsed = validateTargetUrl('https://example.com/test?query=1');
    expect(parsed.hostname).toBe('example.com');
    expect(parsed.protocol).toBe('https:');
  });
});

describe('Header & Cookie Security Scanners', () => {
  it('should detect missing vs present HSTS and CSP headers', () => {
    const scanner = new HeaderScanner();
    const result1 = scanner.analyze({
      requestUrl: 'https://example.com',
      finalUrl: 'https://example.com',
      statusCode: 200,
      redirectChain: [],
      responseHeaders: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
      },
    });

    expect(result1.hasHsts).toBe(true);
    expect(result1.hstsIncludesSubdomains).toBe(true);
    expect(result1.hstsPreload).toBe(true);
    expect(result1.hasCsp).toBe(true);
    expect(result1.cspHasUnsafeInline).toBe(false);
    expect(result1.xContentTypeOptionsNosniff).toBe(true);

    const result2 = scanner.analyze({
      requestUrl: 'http://example.com',
      finalUrl: 'http://example.com',
      statusCode: 200,
      redirectChain: [],
      responseHeaders: {
        server: 'Apache/2.4.41 (Ubuntu)',
      },
    });

    expect(result2.hasHsts).toBe(false);
    expect(result2.hasCsp).toBe(false);
    expect(result2.serverHeader).toBe('Apache/2.4.41 (Ubuntu)');
  });

  it('should identify insecure cookie attributes and sensitive tokens', () => {
    const scanner = new CookieScanner();
    const cookies = scanner.analyze([
      'session_id=secret123; Path=/; Secure; HttpOnly; SameSite=Strict',
      'tracking_id=anon456; Path=/',
    ]);

    expect(cookies).toHaveLength(2);
    expect(cookies[0].name).toBe('session_id');
    expect(cookies[0].hasSecure).toBe(true);
    expect(cookies[0].hasHttpOnly).toBe(true);
    expect(cookies[0].sameSite).toBe('Strict');
    expect(cookies[0].isSensitiveLikely).toBe(true);

    expect(cookies[1].name).toBe('tracking_id');
    expect(cookies[1].hasSecure).toBe(false);
    expect(cookies[1].hasHttpOnly).toBe(false);
    expect(cookies[1].sameSite).toBe('Missing');
  });
});
