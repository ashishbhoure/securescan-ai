# SecureScan AI

> **AI-Powered Website, API & Security Posture Scanner for Startups, SMBs, SaaS Companies & Web Agencies**

"Scan your website and APIs, understand your security risks, and get actionable AI-powered remediation guidance."

---

## Key Capabilities

- **100% Deterministic Security Scanning**: Rule-based technical detection across DNS, TLS/SSL certificates, HTTP defense headers, Cookie security attributes, and Information exposure. Zero hallucinated findings.
- **AI Remediation Guidance**: Translates technical CVEs and security flaws into plain-language business impact, prioritized action items, and developer configuration code patches.
- **SSRF Hardening & IP Pinning**: Egress protection blocking RFC 1918 private ranges, loopback, cloud metadata endpoints (e.g. `169.254.169.254`), and defeating DNS rebinding attacks.
- **Authorized Assessment Enforcement**: Requires explicit target ownership confirmation records before scanning.
- **0–100 Security Scoring**: Non-linear risk scoring algorithm heavily weighted against critical vulnerabilities.
- **Audit Logging & Multi-Tenancy**: Built from the ground up with RBAC (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`) and tenant isolation.
- **Executive Security Reports**: Structured reports featuring methodology summaries, findings, and Section 29 compliance disclaimers.

---

## Monorepo Architecture

```
securescan-ai/
├── apps/
│   ├── web/                     # Next.js 14 Web Application (App Router, Tailwind CSS)
│   ├── api/                     # REST API Gateway (/api/v1) with RBAC & Auth
│   └── worker/                  # Standalone BullMQ / Scan Execution Worker Daemon
├── packages/
│   ├── types/                   # Shared TypeScript models, enums & interfaces
│   ├── database/                # PostgreSQL Prisma ORM schema & seeders
│   ├── logger/                  # Pino-based structured logger with secret redaction
│   ├── scanner-core/            # SSRF protection, DNS, TLS, Headers & Cookie scanners
│   ├── security-rules/          # Versioned rule catalog (SEC-*), rule & risk score engines
│   └── ai/                      # AI provider abstraction (OpenAI, Mock) & prompt sanitizer
├── infra/
│   ├── docker-compose.yml       # Local Postgres, Redis, MinIO infrastructure
│   └── docker/                  # Production Dockerfiles
└── docs/                        # Architecture, threat model, API specifications
```

---

## Quick Start (Local Development)

### 1. Prerequisites
- Node.js 20+ / 22+
- pnpm 9+ or npm

### 2. Install Dependencies
```bash
pnpm install
```

### 3. Start Local Infrastructure
```bash
docker compose -f infra/docker-compose.yml up -d
```

### 4. Database Setup & Seed
```bash
pnpm db:generate
pnpm db:push
pnpm db:seed
```

### 5. Launch Development Servers
```bash
pnpm dev
```
- Web Application: `http://localhost:3000`
- API Gateway: `http://localhost:4000/api/v1`

---

## Default Seed Demo Credentials
- **Email:** `demo@securescan.ai`
- **Password:** `SecureScan123!`
- **Organization:** `Acme Cyber Labs` (Role: `OWNER`)

---

## License
Proprietary SaaS — Built for authorized security testing only.
