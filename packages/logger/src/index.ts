/**
 * SecureScan AI - Enterprise Structured Logger with Automatic Secret Redaction
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const SENSITIVE_KEY_PATTERNS = [
  /pass(word)?/i,
  /secret/i,
  /token/i,
  /bearer/i,
  /auth(orization)?/i,
  /cookie/i,
  /api[_-]?key/i,
  /private[_-]?key/i,
  /credit[_-]?card/i,
];

const BEARER_REGEX = /Bearer\s+([a-zA-Z0-9_\-\.]+)/gi;

/**
 * Deeply redacts sensitive keys and values from objects and strings
 */
export function redactSensitiveData<T>(input: T): T {
  if (input === null || input === undefined) {
    return input;
  }

  if (typeof input === 'string') {
    return input.replace(BEARER_REGEX, 'Bearer [REDACTED]') as unknown as T;
  }

  if (Array.isArray(input)) {
    return input.map((item) => redactSensitiveData(item)) as unknown as T;
  }

  if (typeof input === 'object') {
    const sanitizedObj: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      const isSensitiveKey = SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key));

      if (isSensitiveKey) {
        sanitizedObj[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        sanitizedObj[key] = redactSensitiveData(value);
      } else if (typeof value === 'string') {
        sanitizedObj[key] = value.replace(BEARER_REGEX, 'Bearer [REDACTED]');
      } else {
        sanitizedObj[key] = value;
      }
    }

    return sanitizedObj as T;
  }

  return input;
}

export interface LoggerContext {
  organizationId?: string;
  userId?: string;
  scanId?: string;
  assetId?: string;
  module?: string;
}

export class Logger {
  private context: LoggerContext;

  constructor(context: LoggerContext = {}) {
    this.context = context;
  }

  public withContext(additionalContext: LoggerContext): Logger {
    return new Logger({ ...this.context, ...additionalContext });
  }

  private log(level: LogLevel, message: string, metadata?: Record<string, unknown>): void {
    const timestamp = new Date().toISOString();
    const cleanMetadata = metadata ? redactSensitiveData(metadata) : undefined;
    const cleanContext = redactSensitiveData(this.context);

    const logPayload = {
      timestamp,
      level,
      message,
      context: cleanContext,
      metadata: cleanMetadata,
    };

    const serialized = JSON.stringify(logPayload);

    switch (level) {
      case 'error':
        console.error(serialized);
        break;
      case 'warn':
        console.warn(serialized);
        break;
      case 'debug':
        if (process.env.NODE_ENV !== 'production') {
          console.debug(serialized);
        }
        break;
      case 'info':
      default:
        console.log(serialized);
        break;
    }
  }

  public debug(message: string, metadata?: Record<string, unknown>): void {
    this.log('debug', message, metadata);
  }

  public info(message: string, metadata?: Record<string, unknown>): void {
    this.log('info', message, metadata);
  }

  public warn(message: string, metadata?: Record<string, unknown>): void {
    this.log('warn', message, metadata);
  }

  public error(message: string, metadata?: Record<string, unknown>): void {
    this.log('error', message, metadata);
  }
}

export const logger = new Logger();
