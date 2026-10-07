/**
 * SecureScan AI - Resilient Prisma Client Adapter
 * Emulates Prisma model operations against InMemoryDataStore.
 */

import { InMemoryDataStore } from './memory-store.js';

export function createMockPrismaClient(store: InMemoryDataStore) {
  return {
    user: {
      findUnique: async ({ where }: any) => {
        if (where.email) {
          const user = store.users.find((u) => u.email.toLowerCase() === where.email.toLowerCase());
          if (!user) return null;
          const memberships = store.organizationMembers
            .filter((m) => m.userId === user.id)
            .map((m) => ({
              ...m,
              organization: store.organizations.find((o) => o.id === m.organizationId),
            }));
          return { ...user, memberships };
        }
        if (where.id) {
          const user = store.users.find((u) => u.id === where.id);
          if (!user) return null;
          const memberships = store.organizationMembers
            .filter((m) => m.userId === user.id)
            .map((m) => ({
              ...m,
              organization: store.organizations.find((o) => o.id === m.organizationId),
            }));
          return { ...user, memberships };
        }
        return null;
      },
      create: async ({ data, include }: any) => {
        const id = `usr-${Date.now().toString(36)}`;
        const user = {
          id,
          email: data.email,
          name: data.name,
          passwordHash: data.passwordHash,
          isEmailVerified: data.isEmailVerified ?? true,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        store.users.push(user);

        if (data.memberships?.create) {
          const mData = data.memberships.create;
          const orgId = `org-${Date.now().toString(36)}`;
          const org = {
            id: orgId,
            name: mData.organization?.create?.name || 'Workspace',
            slug: mData.organization?.create?.slug || orgId,
            planTier: mData.organization?.create?.planTier || 'STARTER',
            maxAssets: mData.organization?.create?.maxAssets || 5,
            createdAt: new Date(),
            updatedAt: new Date(),
          };
          store.organizations.push(org);

          const membership = {
            id: `mem-${Date.now().toString(36)}`,
            organizationId: org.id,
            userId: user.id,
            role: mData.role || 'OWNER',
            createdAt: new Date(),
            updatedAt: new Date(),
            organization: org,
          };
          store.organizationMembers.push(membership);

          if (include?.memberships) {
            return { ...user, memberships: [membership] };
          }
        }
        return user;
      },
      upsert: async ({ create }: any) => {
        return create;
      },
    },

    organization: {
      findUnique: async ({ where, include }: any) => {
        const org = store.organizations.find((o) => o.id === where.id || o.slug === where.slug);
        if (!org) return null;

        const res: any = { ...org };
        if (include?.members) {
          res.members = store.organizationMembers
            .filter((m) => m.organizationId === org.id)
            .map((m) => ({
              ...m,
              user: store.users.find((u) => u.id === m.userId),
            }));
        }
        if (include?._count) {
          res._count = {
            assets: store.assets.filter((a) => a.organizationId === org.id).length,
            scans: store.scans.filter((s) => s.organizationId === org.id).length,
            findings: store.findings.filter((f) => f.organizationId === org.id).length,
          };
        }
        return res;
      },
      create: async ({ data }: any) => {
        const org = { id: `org-${Date.now().toString(36)}`, ...data, createdAt: new Date() };
        store.organizations.push(org);
        return org;
      },
      upsert: async ({ create }: any) => {
        return create;
      },
    },

    organizationMember: {
      findUnique: async ({ where }: any) => {
        const { organizationId, userId } = where.organizationId_userId || {};
        return (
          store.organizationMembers.find(
            (m) => m.organizationId === organizationId && m.userId === userId
          ) || null
        );
      },
      findFirst: async ({ where }: any) => {
        return store.organizationMembers.find((m) => m.userId === where.userId) || null;
      },
    },

    project: {
      findFirst: async ({ where }: any) => {
        return store.projects.find((p) => p.organizationId === where.organizationId) || null;
      },
      create: async ({ data }: any) => {
        const project = { id: `proj-${Date.now().toString(36)}`, ...data, createdAt: new Date() };
        store.projects.push(project);
        return project;
      },
    },

    asset: {
      findMany: async ({ where }: any) => {
        let list = store.assets.filter((a) => a.organizationId === where.organizationId);
        if (where.lastScore && where.lastScore.not !== null) {
          list = list.filter((a) => a.lastScore !== null && a.lastScore !== undefined);
        }
        return list.map((a) => ({
          ...a,
          project: store.projects.find((p) => p.id === a.projectId),
          authorizations: store.assetAuthorizations.filter((auth) => auth.assetId === a.id),
        }));
      },
      findFirst: async ({ where, include }: any) => {
        const asset = store.assets.find(
          (a) => a.id === where.id && (!where.organizationId || a.organizationId === where.organizationId)
        );
        if (!asset) return null;
        const res: any = { ...asset };
        if (include?.authorizations) {
          res.authorizations = store.assetAuthorizations.filter((auth) => auth.assetId === asset.id);
        }
        return res;
      },
      create: async ({ data }: any) => {
        const asset = {
          id: `asset-${Date.now().toString(36)}`,
          ...data,
          lastScanAt: null,
          lastScore: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        store.assets.push(asset);
        return asset;
      },
      update: async ({ where, data }: any) => {
        const idx = store.assets.findIndex((a) => a.id === where.id);
        if (idx > -1) {
          store.assets[idx] = { ...store.assets[idx], ...data, updatedAt: new Date() };
          return store.assets[idx];
        }
        return null;
      },
      count: async ({ where }: any) => {
        return store.assets.filter((a) => a.organizationId === where.organizationId).length;
      },
    },

    assetAuthorization: {
      create: async ({ data }: any) => {
        const record = { id: `auth-${Date.now().toString(36)}`, ...data, authorizedAt: new Date() };
        store.assetAuthorizations.push(record);
        return record;
      },
    },

    scan: {
      findMany: async ({ where }: any) => {
        return store.scans
          .filter((s) => s.organizationId === where.organizationId)
          .map((s) => ({
            ...s,
            asset: store.assets.find((a) => a.id === s.assetId),
            _count: { findings: store.findings.filter((f) => f.scanId === s.id).length },
          }))
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
      },
      findFirst: async ({ where, include }: any) => {
        const scan = store.scans.find(
          (s) => s.id === where.id && (!where.organizationId || s.organizationId === where.organizationId)
        );
        if (!scan) return null;
        const res: any = { ...scan };
        if (include?.asset) {
          res.asset = store.assets.find((a) => a.id === scan.assetId);
        }
        if (include?.riskScore) {
          res.riskScore = store.riskScores.find((r) => r.scanId === scan.id);
        }
        if (include?.findings) {
          res.findings = store.findings
            .filter((f) => f.scanId === scan.id)
            .map((f) => ({
              ...f,
              evidence: store.findingEvidences.find((e) => e.findingId === f.id),
              aiAnalysis: store.aIAnalyses.find((ai) => ai.findingId === f.id),
            }));
        }
        return res;
      },
      findUnique: async ({ where, include }: any) => {
        const scan = store.scans.find((s) => s.id === where.id);
        if (!scan) return null;
        const res: any = { ...scan };
        if (include?.asset) {
          const asset = store.assets.find((a) => a.id === scan.assetId);
          res.asset = {
            ...asset,
            authorizations: store.assetAuthorizations.filter((auth) => auth.assetId === asset.id),
          };
        }
        return res;
      },
      create: async ({ data }: any) => {
        const scan = {
          id: `scan-${Date.now().toString(36)}`,
          ...data,
          scannerVersion: '1.0.0',
          createdAt: new Date(),
        };
        store.scans.push(scan);
        return scan;
      },
      update: async ({ where, data }: any) => {
        const idx = store.scans.findIndex((s) => s.id === where.id);
        if (idx > -1) {
          store.scans[idx] = { ...store.scans[idx], ...data };
          return store.scans[idx];
        }
        return null;
      },
    },

    finding: {
      findMany: async ({ where }: any) => {
        let list = store.findings.filter((f) => f.organizationId === where.organizationId);
        if (where.status) list = list.filter((f) => f.status === where.status);
        if (where.severity) list = list.filter((f) => f.severity === where.severity);
        if (where.assetId) list = list.filter((f) => f.assetId === where.assetId);
        if (where.OR) {
          list = list.filter((f) =>
            where.OR.some(
              (cond: any) =>
                (cond.title && f.title.toLowerCase().includes(cond.title.contains.toLowerCase())) ||
                (cond.description && f.description.toLowerCase().includes(cond.description.contains.toLowerCase())) ||
                (cond.ruleId && f.ruleId.toLowerCase().includes(cond.ruleId.contains.toLowerCase()))
            )
          );
        }
        return list.map((f) => ({
          ...f,
          asset: store.assets.find((a) => a.id === f.assetId),
          evidence: store.findingEvidences.find((e) => e.findingId === f.id),
          aiAnalysis: store.aIAnalyses.find((ai) => ai.findingId === f.id),
        }));
      },
      findFirst: async ({ where }: any) => {
        const f = store.findings.find(
          (item) => item.id === where.id && (!where.organizationId || item.organizationId === where.organizationId)
        );
        if (!f) return null;
        return {
          ...f,
          asset: store.assets.find((a) => a.id === f.assetId),
          evidence: store.findingEvidences.find((e) => e.findingId === f.id),
          aiAnalysis: store.aIAnalyses.find((ai) => ai.findingId === f.id),
          rule: store.securityRules.find((r) => r.id === f.ruleId) || { cwe: 'CWE-200' },
        };
      },
      create: async ({ data }: any) => {
        const id = `fnd-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
        const { evidence, ...fndFields } = data;
        const finding = { id, ...fndFields, createdAt: new Date(), updatedAt: new Date() };
        store.findings.push(finding);

        if (evidence?.create) {
          store.findingEvidences.push({
            id: `ev-${id}`,
            findingId: id,
            summary: evidence.create.summary,
            details: evidence.create.details,
            createdAt: new Date(),
          });
        }
        return finding;
      },
      update: async ({ where, data }: any) => {
        const idx = store.findings.findIndex((f) => f.id === where.id);
        if (idx > -1) {
          store.findings[idx] = { ...store.findings[idx], ...data, updatedAt: new Date() };
          return store.findings[idx];
        }
        return null;
      },
      groupBy: async ({ by, where }: any) => {
        if (by.includes('severity')) {
          const counts: Record<string, number> = {};
          const matched = store.findings.filter(
            (f) => f.organizationId === where.organizationId && (!where.status || f.status === where.status)
          );
          for (const m of matched) {
            counts[m.severity] = (counts[m.severity] || 0) + 1;
          }
          return Object.entries(counts).map(([sev, count]) => ({
            severity: sev,
            _count: { _all: count },
          }));
        }
        return [];
      },
    },

    securityRule: {
      upsert: async ({ create }: any) => {
        const existing = store.securityRules.find((r) => r.id === create.id);
        if (!existing) store.securityRules.push(create);
        return create;
      },
    },

    riskScore: {
      create: async ({ data }: any) => {
        const rs = { id: `rs-${Date.now().toString(36)}`, ...data, createdAt: new Date() };
        store.riskScores.push(rs);
        return rs;
      },
    },

    aIAnalysis: {
      findFirst: async ({ where }: any) => {
        return store.aIAnalyses.find((ai) => ai.contentHash === where.contentHash) || null;
      },
      create: async ({ data }: any) => {
        const ai = { id: `ai-${Date.now().toString(36)}`, ...data, createdAt: new Date() };
        store.aIAnalyses.push(ai);
        return ai;
      },
    },

    report: {
      create: async ({ data }: any) => {
        const rep = { id: `rep-${Date.now().toString(36)}`, ...data, generatedAt: new Date() };
        store.reports.push(rep);
        return rep;
      },
      findFirst: async ({ where }: any) => {
        return store.reports.find((r) => r.id === where.id) || null;
      },
    },

    auditLog: {
      create: async ({ data }: any) => {
        const log = { id: `audit-${Date.now().toString(36)}`, ...data, createdAt: new Date() };
        store.auditLogs.push(log);
        return log;
      },
    },

    plan: {
      upsert: async ({ create }: any) => {
        return create;
      },
    },

    $disconnect: async () => {},
  };
}
