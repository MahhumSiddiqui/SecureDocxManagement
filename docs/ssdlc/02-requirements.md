# Phase 2 — Requirements

## Security requirements (mapped to OWASP ASVS themes)
- **Authentication (ASVS V2):** Argon2id hashing, account lockout, enumeration
  resistance, short-lived JWTs with rotating refresh tokens.
- **Access control (ASVS V4):** deny-by-default RBAC plus per-document ACL, enforced
  server-side on every object access.
- **Cryptography (ASVS V6):** AES-256-GCM envelope encryption at rest, TLS in
  transit, SHA-256 integrity digests.
- **Validation & encoding (ASVS V5):** schema validation on every route, magic-byte
  upload verification, context-aware output encoding.
- **Logging (ASVS V7):** hash-chained audit trail of all security-relevant events.

## Abuse cases
Upload of executable content; retrieval of another user''s document by ID
manipulation; privilege escalation via forged role; guessing or reusing share
links; operating undetected through absent logging. Each maps to a demonstrated
vulnerability (VULN-01 to VULN-06).
