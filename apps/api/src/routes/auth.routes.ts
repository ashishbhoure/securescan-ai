/**
 * SecureScan AI - Authentication API Endpoints
 */

import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { prisma, OrgRole } from '@securescan/database';
import { authMiddleware } from '../middleware/auth.js';

export const authRouter = Router();

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me-in-production-min-32-chars-long';

// Helper for password hashing
function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

/**
 * POST /api/v1/auth/register
 */
authRouter.post('/register', async (req: Request, res: Response) => {
  const { email, password, name, organizationName } = req.body;

  if (!email || !password || !name) {
    res.status(400).json({
      code: 'VALIDATION_ERROR',
      message: 'Email, password, and name are required.',
    });
    return;
  }

  if (password.length < 8) {
    res.status(400).json({
      code: 'PASSWORD_TOO_WEAK',
      message: 'Password must be at least 8 characters long.',
    });
    return;
  }

  const existingUser = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
  if (existingUser) {
    res.status(409).json({
      code: 'EMAIL_ALREADY_EXISTS',
      message: 'An account with this email address already exists.',
    });
    return;
  }

  const passwordHash = hashPassword(password);
  const orgTitle = organizationName || `${name.split(' ')[0]}'s Workspace`;
  const slug = `${orgTitle.toLowerCase().replace(/[^a-z0-9]/g, '-')}-${Date.now().toString(36)}`;

  const user = await prisma.user.create({
    data: {
      email: email.toLowerCase(),
      name,
      passwordHash,
      isEmailVerified: true, // Auto-verified in local dev
      memberships: {
        create: {
          role: OrgRole.OWNER,
          organization: {
            create: {
              name: orgTitle,
              slug,
              planTier: 'STARTER',
              maxAssets: 5,
              projects: {
                create: {
                  name: 'Default Project',
                  description: 'Primary web and API infrastructure',
                },
              },
            },
          },
        },
      },
    },
    include: {
      memberships: {
        include: {
          organization: true,
        },
      },
    },
  });

  const org = user.memberships[0].organization;

  // Record audit log
  await prisma.auditLog.create({
    data: {
      organizationId: org.id,
      userId: user.id,
      action: 'USER_LOGIN',
      resourceType: 'USER',
      resourceId: user.id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { event: 'registration' },
    },
  });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: '7d',
  });

  res.status(201).json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
    },
    organization: {
      id: org.id,
      name: org.name,
      slug: org.slug,
      role: OrgRole.OWNER,
    },
  });
});

/**
 * POST /api/v1/auth/login
 */
authRouter.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({
      code: 'VALIDATION_ERROR',
      message: 'Email and password are required.',
    });
    return;
  }

  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
    include: {
      memberships: {
        include: {
          organization: true,
        },
      },
    },
  });

  if (!user) {
    res.status(401).json({
      code: 'INVALID_CREDENTIALS',
      message: 'Invalid email or password.',
    });
    return;
  }

  const inputHash = hashPassword(password);
  if (user.passwordHash !== inputHash) {
    res.status(401).json({
      code: 'INVALID_CREDENTIALS',
      message: 'Invalid email or password.',
    });
    return;
  }

  const primaryMembership = user.memberships[0];

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: '7d',
  });

  // Record audit log
  if (primaryMembership) {
    await prisma.auditLog.create({
      data: {
        organizationId: primaryMembership.organizationId,
        userId: user.id,
        action: 'USER_LOGIN',
        resourceType: 'USER',
        resourceId: user.id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      },
    });
  }

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
    },
    organization: primaryMembership
      ? {
          id: primaryMembership.organization.id,
          name: primaryMembership.organization.name,
          slug: primaryMembership.organization.slug,
          role: primaryMembership.role,
        }
      : null,
  });
});

/**
 * GET /api/v1/auth/me
 */
authRouter.get('/me', authMiddleware, async (req: Request, res: Response) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user!.id },
    select: {
      id: true,
      email: true,
      name: true,
      memberships: {
        include: {
          organization: true,
        },
      },
    },
  });

  res.json({
    user: {
      id: user?.id,
      email: user?.email,
      name: user?.name,
    },
    currentTenant: req.tenant,
    organizations: user?.memberships.map((m: any) => ({
      id: m.organization.id,
      name: m.organization.name,
      slug: m.organization.slug,
      planTier: m.organization.planTier,
      role: m.role,
    })),
  });
});
