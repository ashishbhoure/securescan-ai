# SecureScan AI — Security Policy & Safe Scanning Mandate

## 1. Authorized Testing Only
SecureScan AI is strictly an authorized cybersecurity posture and vulnerability intelligence product.

- **Explicit Consent**: Prior to initiating an active assessment against any web property or API, users must confirm ownership or explicit authorization.
- **Audit Records**: Every authorization event logs the User ID, Organization ID, Target URL, IP address, and timestamp.
- **Prohibited Use**: The system rejects scanning of unauthorized third-party websites, competitors, or internal targets.

## 2. Technical Attack Protections
The scanner engine is architected with strict defensive boundaries:
- **SSRF Defense**: The HTTP client resolves DNS and immediately verifies destination IP addresses against RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), link-local (`169.254.0.0/16`), and cloud metadata services (`169.254.169.254`).
- **DNS Rebinding Defense**: The validated IP is pinned directly to the socket connection.
- **Redirect Safeguards**: Redirects are followed with manual step-by-step verification up to a maximum depth of 5. Any redirect to a private address space is immediately blocked.
- **No Destructive Exploits**: The scanner executes non-destructive configuration inspections only. It does not perform denial-of-service, brute-force attacks, persistence, or data modification.

## 3. Data Protection & Secret Redaction
- **Evidence Sanitization**: All authorization headers, bearer tokens, API keys, and sensitive cookies are automatically redacted before logging or database persistence.
- **Tenant Isolation**: All database queries enforce tenant boundaries derived from authenticated session tokens. Cross-tenant access is rejected.
- **AI Prompt Sandboxing**: Target webpage contents are treated as untrusted data and isolated within XML boundary tags to defend against prompt injection attacks.
