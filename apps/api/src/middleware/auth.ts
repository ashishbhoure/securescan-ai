/**
 * SecureScan AI - Authentication & Tenant Context Middleware
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { prisma, OrgRole } from '@securescan/database';

export interface AuthenticatedUser {
  id: string;
  email: string;
  name?: string | null;
}

export interface TenantContext {
  organizationId: string;
  role: OrgRole;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
      tenant?: TenantContext;
    }
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me-in-production-min-32-chars-long';

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      code: 'UNAUTHORIZED',
      message: 'Authentication token is required.',
    });
    return;
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; email: string };
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, email: true, name: true },
    });

    if (!user) {
      res.status(401).json({
        code: 'USER_NOT_FOUND',
        message: 'The authenticated user session is no longer valid.',
      });
      return;
    }

    req.user = user;

    // Resolve Organization Context from Header or User's default membership
    const requestedOrgId = req.headers['x-organization-id'] as string | undefined;

    let membership = null;
    if (requestedOrgId) {
      membership = await prisma.organizationMember.findUnique({
        where: {
          organizationId_userId: {
            organizationId: requestedOrgId,
            userId: user.id,
          },
        },
      });
    } else {
      // Pick first membership
      membership = await prisma.organizationMember.findFirst({
        where: { userId: user.id },
      });
    }

    if (membership) {
      req.tenant = {
        organizationId: membership.organizationId,
        role: membership.role as OrgRole,
      };
    }

    next();
  } catch (err) {
    res.status(401).json({
      code: 'INVALID_TOKEN',
      message: 'Authentication token is invalid or expired.',
    });
  }
}

/**
 * RBAC Guard ensuring user possesses minimum organizational role
 */
export function requireRole(allowedRoles: OrgRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.tenant) {
      res.status(403).json({
        code: 'NO_ORGANIZATION_CONTEXT',
        message: 'User does not belong to an active organization.',
      });
      return;
    }

    if (!allowedRoles.includes(req.tenant.role)) {
      res.status(403).json({
        code: 'FORBIDDEN',
        message: `Insufficient permissions. Required one of: ${allowedRoles.join(', ')}. Your role: ${req.tenant.role}`,
      });
      return;
    }

    next();
  };
}
