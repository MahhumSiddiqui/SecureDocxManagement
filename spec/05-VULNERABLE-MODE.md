# 05 — Vulnerable Mode

Activated by `SECURE_MODE=false`. Same codebase, selected by a factory at startup.
This is the comparison baseline for the coursework's security analysis, and it runs
only on localhost with synthetic seed data.

## Factory pattern

Each module exports through an `index.ts` that picks an implementation once, at load:

```ts
// modules/documents/index.ts
import { config } from '../../config';
import * as secure from './secure/documents.controller';
import * as vulnerable from './vulnerable/documents.controller';

export const documentsController = config.secureMode ? secure : vulnerable;
```

Both implementations export the same function signatures, so routing is identical.
**The API contract does not change between modes** — the same endpoints, the same
response shapes. Only the internal behaviour differs. This is what makes the
before-and-after comparison controlled.

## Startup banner

When `SECURE_MODE=false`, print in red before the server listens:

```
================================================================
  WARNING — VULNERABLE MODE ACTIVE
  This build contains DELIBERATE security vulnerabilities.
  For isolated laboratory use only. Bound to 127.0.0.1.
  Do not expose this process to any network. Do not use real data.
================================================================
```

Also refuse to start if `NODE_ENV === 'production'` or the bind host is not loopback.

## The six vulnerabilities

Each vulnerable code path carries a comment block:

```ts
// ============================================================
// [VULN-01] Unrestricted File Upload
// CWE-434 | OWASP A04:2021 Insecure Design
// Root cause: file type is decided from client-supplied data.
// Secure version: ../secure/upload.pipeline.ts
// ============================================================
```

---

### VULN-01 — Unrestricted file upload · CWE-434 · OWASP A04

Accept any extension. Trust the client's `Content-Type` header instead of inspecting
magic bytes. Keep the original filename as the storage key. Write into
`apps/api/public/uploads/`, which is served by `express.static`. Skip the scanner.

*Demonstrable effect:* a `.js` or `.html` file uploads successfully and is fetchable
at a predictable URL, with attacker-controlled content served from the app's origin.

### VULN-02 — Insecure direct object reference · CWE-639 · OWASP A01

Accept `Document.legacyId` (the sequential integer) at `GET /documents/:id` and
`/download`. Check only that a valid session exists — no ownership check, no
permission lookup.

*Demonstrable effect:* any authenticated user reads any document by incrementing
the identifier.

### VULN-03 — Broken access control · CWE-285 · OWASP A01

Read the caller's role from an `X-User-Role` request header, falling back to the
token only if absent. Remove the `authorize` middleware from the admin and audit
routes, relying on the frontend hiding those links.

*Demonstrable effect:* a standard user sends `X-User-Role: ADMINISTRATOR` and reaches
the admin console and the full audit log.

### VULN-04 — Cryptographic failures · CWE-311 and CWE-916 · OWASP A02

Store uploaded files as plaintext — no DEK, no `DocumentKey` row. Hash passwords with
unsalted MD5 (`crypto.createHash('md5')`). Login must accept both formats so seeded
Argon2 users still work; comment that this dual-verify exists only to keep the seed
data usable across modes.

*Demonstrable effect:* opening a stored blob in a text editor shows the document
contents; the `passwordHash` column contains MD5 digests recognisable in any
rainbow-table lookup.

### VULN-05 — Insecure share tokens · CWE-330 and CWE-613 · OWASP A02

Generate tokens as `Date.now().toString(36) + counter++`. Store the raw token in
`tokenHash` rather than a hash. Ignore `expiresAt` and `revokedAt` on lookup. No
rate limit on the public route. Return distinct messages for "not found", "expired",
and "revoked".

*Demonstrable effect:* tokens are predictable from a known creation time; revoked
links keep working; distinct error messages confirm which document IDs exist.

### VULN-06 — Insufficient logging · CWE-778 · OWASP A09

Skip audit writes for `AUTH_LOGIN_FAILED`, `ACCESS_DENIED`, `DOC_DOWNLOAD`, and
`SHARE_ACCESS`. For the events still written, omit `prevHash` and `recordHash` (write
empty strings) so there is no chain.

*Demonstrable effect:* the other five attacks run to completion and leave no trace;
`GET /audit/verify` cannot detect a modified record.

---

## Stretch — only if time remains after everything else

**VULN-07 — SQL injection · CWE-89.** The `search` parameter on `GET /documents`
goes through `prisma.$queryRawUnsafe` with the value concatenated in, and `sortBy`
is interpolated without an allow-list. Database errors are returned to the client.

**VULN-08 — Stored XSS · CWE-79.** Document `title` and `originalName` are returned
unescaped and rendered with `dangerouslySetInnerHTML` on the ledger page. CSP is
disabled in vulnerable mode.

Implement these only if sessions 1–3 finish early. Six vulnerabilities already
exceeds the proposal's requirement of five.

---

## Vulnerability register

Produce `docs/vulnerability-register.md`: a table with number, name, CWE, OWASP
category, vulnerable file and line, secure file and line, one-sentence root cause,
and the control that fixes it. Keep the file references accurate — they are checked.