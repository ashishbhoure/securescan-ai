import { PrismaClient } from '@prisma/client';
import { InMemoryDataStore } from './memory-store.js';
import { createMockPrismaClient } from './mock-client.js';

export * from '@prisma/client';

const inMemoryStore = new InMemoryDataStore();
const fallbackClient = createMockPrismaClient(inMemoryStore);

let clientInstance: any;

const isExplicitMock = process.env.USE_MOCK_DB === 'true' || process.env.NODE_ENV === 'test';

if (isExplicitMock) {
  clientInstance = fallbackClient;
} else {
  const realPrisma = new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
  });

  let hasFailedOver = false;

  clientInstance = new Proxy(realPrisma, {
    get(target, prop, receiver) {
      if (hasFailedOver) {
        return (fallbackClient as any)[prop];
      }

      const realValue = Reflect.get(target, prop, receiver);
      if (typeof realValue === 'object' && realValue !== null) {
        return new Proxy(realValue, {
          get(modelTarget, modelProp) {
            const method = (modelTarget as any)[modelProp];
            if (typeof method === 'function') {
              return async (...args: any[]) => {
                try {
                  return await method.apply(modelTarget, args);
                } catch (err: any) {
                  if (
                    err.message?.includes("Can't reach database server") ||
                    err.message?.includes('connect ECONNREFUSED') ||
                    err.message?.includes('P1001') ||
                    err.code === 'P1001'
                  ) {
                    if (!hasFailedOver) {
                      console.warn(
                        '\x1b[33m%s\x1b[0m',
                        '⚠️ [SecureScan Database] PostgreSQL unreachable on localhost:5432. Automatically activating resilient in-memory development datastore with pre-seeded demo tenant.'
                      );
                      hasFailedOver = true;
                    }
                    const fallbackModel = (fallbackClient as any)[prop];
                    if (fallbackModel && typeof fallbackModel[modelProp] === 'function') {
                      return await fallbackModel[modelProp](...args);
                    }
                  }
                  throw err;
                }
              };
            }
            return method;
          },
        });
      }
      return realValue;
    },
  });
}

export const prisma = clientInstance;
