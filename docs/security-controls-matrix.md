# Security Controls Matrix — SecureDocs

Each control maps to its implementation and the evidence that verifies it. Status
reflects the secure-mode build.

| Control | Implementation | Verified by | Status |
|---|---|---|---|
| Password hashing (Argon2id) | `auth.controller.ts` — `hashPassword`, cost 19456/2/1 | DB query shows `$argon2id$` prefix; test "logs in / rejects wrong password" | ✅ |
| Account lockout | `auth.controller.ts` — 5 attempts / 15 min | Test "locks after repeated failures" | ✅ |
| Enumeration resistance | `auth.controller.ts` — dummy-hash timing, identical responses | Test "resists account enumeration" | ✅ |
| JWT access tokens (15 min, HS256) | `auth.controller.ts` — `accessToken` | Login returns token; role re-read from DB | ✅ |
| Refresh rotation + reuse detection | `auth.controller.ts` — `/refresh` | Test "rotates refresh tokens and detects reuse" | ✅ |
| CSRF protection (double-submit) | `middleware/csrf.ts`, `sd_csrf` cookie | Manual: upload without token → 403 | ✅ |
| RBAC (deny-by-default) | `permissions.matrix.ts`, `middleware/authorize.ts` | Test "denies standard users admin/audit routes" | ✅ |
| Object-level authorization | `documents.controller.ts` — `findAccess` | Test "refuses IDOR across accounts"; manual 403 | ✅ |
| Startup authorization assertion | route registration in `index.ts` | Server refuses to start if a route lacks `authorize` | ✅ |
| Upload extension allow-list | `upload.pipeline.ts` | Manual: `.exe` → "Disallowed file type" | ✅ |
| Upload magic-byte verification | `upload.pipeline.ts` — `file-type` | Manual: `disguised.pdf` → "Content does not match extension" | ✅ |
| Malware scan (stub) | `scanner.service.ts` | Test "rejects the EICAR signature" | ✅ |
| Encryption at rest (AES-256-GCM) | `crypto.service.ts` — envelope encryption | Manual: stored blob is ciphertext; test "round-trips encrypted content" | ✅ |
| Integrity verification (SHA-256 / GCM) | `crypto.service.ts` | Test "detects GCM tampering" | ✅ |
| Cryptographic erasure on delete | `documents.controller.ts` — `/:id/permanent` | Key row destroyed; download then fails | ✅ |
| Secure share tokens | `share.controller.ts` — CSPRNG, hashed, expiring | Manual: create/use/revoke, 404 after revoke | ✅ |
| Output encoding / XSS | React default escaping | Manual: `<script>` title renders as text | ✅ |
| Security headers (CSP, HSTS) | `helmet` config | Response headers on every request | ✅ |
| CORS restricted to frontend origin | CORS config | `Access-Control-Allow-Origin: 127.0.0.1:5173` | ✅ |
| Rate limiting | `express-rate-limit` | `X-RateLimit-*` headers present | ✅ |
| Hash-chained audit log | `audit.service.ts` | Test "verifies chain, then detects a manual update" | ✅ |
| Response serialization (no data leak) | `serializers.ts` | Test "never exposes persistence-only fields" | ✅ |
| Generic error handling | `middleware/errors.ts` | No stack traces / SQL in responses | ✅ |
| Secrets from environment | `.env`, `config.ts` | No secrets in source; `.env` gitignored | ✅ |
| Localhost-only binding | server bind config | `docker ps` shows `127.0.0.1` | ✅ |

## Test summary

Automated: **12/12 security tests passing** (`apps/api/src/tests/security.test.ts`).
Attack harness: **6/6 exploited vulnerable, 0/6 secure**.