# 04 — Security Controls (secure mode)

## Passwords

Argon2id via the `argon2` package: `memoryCost: 19456` (19 MiB), `timeCost: 2`,
`parallelism: 1`. These are the OWASP Password Storage Cheat Sheet minimums —
say so in a comment, because you will be asked to justify them.

Policy: minimum 12 characters, no composition rules. Check against a hardcoded
array of about 30 common passwords.

Lockout: 5 failed attempts within 15 minutes locks the account for 15 minutes,
counted from the `LoginAttempt` table.

**Enumeration resistance.** When the email is unknown, still run a dummy Argon2
verify against a fixed hash before responding, so the timing matches a real
failure. Comment this — it's a deliberate design decision, not dead code.

## Tokens and sessions

Access token: JWT, HS256, 15-minute expiry, claims `{ sub, email, role, jti }`.
Signed with `JWT_SECRET`. Verified on every request; **role is re-read from the
database, not trusted from the token** — comment on why.

Refresh token: 32 random bytes, base64url. Stored as SHA-256 in `RefreshToken`
with a `familyId`. 7-day expiry. Delivered as cookie `sd_refresh`:
`HttpOnly, Secure, SameSite=Strict, Path=/api/auth`.

Rotation: each refresh issues a new token in the same family and marks the old one
revoked. **Presenting an already-revoked token revokes the entire family** and
writes `AUTH_REFRESH_REUSE` — this is how stolen-token replay is detected.

CSRF: double-submit cookie. `sd_csrf` is a readable (non-HttpOnly) random value;
state-changing requests must echo it in `X-CSRF-Token`. Compare with
`crypto.timingSafeEqual`.

## Authorization

One declarative matrix, one enforcement point. Never scatter `if (user.role === ...)`
checks through route handlers.

```ts
// permissions.matrix.ts
const MATRIX: Record<Role, Action[]> = {
  STANDARD_USER:  ['document:read', 'document:create', 'document:delete:own'],
  DOCUMENT_OWNER: ['document:read', 'document:create', 'document:delete:own',
                   'document:update', 'permission:manage', 'share:manage'],
  AUDITOR:        ['audit:read', 'audit:export', 'audit:verify'],
  ADMINISTRATOR:  ['user:manage', 'document:delete:any', 'permission:manage',
                   'audit:read'],
};
```

`authorize(action, resourceType?)` middleware evaluates, in order:

1. Does the role hold the action in the matrix? If not → deny.
2. If the action is resource-scoped, load the resource. Not found → **403, not 404**
   (a 404 leaks the existence of documents belonging to others).
3. Is the caller the owner? → allow.
4. Is there an unexpired `DocumentPermission` granting the needed flag? → allow.
5. Otherwise → deny, and write an `ACCESS_DENIED` audit record.

**Startup assertion.** After registering routes, walk the Express router stack and
throw if any non-public route lacks the `authorize` middleware. Maintain an explicit
allow-list of public routes (`/auth/login`, `/auth/register`, `/auth/refresh`,
`/share/:token`, `/share/:token/download`, `/health`). This single check prevents
the most common real-world failure in systems like this.

## Upload pipeline

Order matters — reject as early as possible:

1. **Multer** to a temp dir outside the storage root. `limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 }`.
2. **Extension allow-list**: `pdf docx xlsx pptx txt csv png jpg jpeg`. Case-insensitive, take the last extension only.
3. **Magic bytes** via `file-type`. If the detected MIME disagrees with the extension, reject. For `txt` and `csv`, `file-type` returns undefined — verify instead that the buffer is valid UTF-8 with no null bytes. **Never trust the client `Content-Type` header** — comment on why.
4. **Filename**: the original is kept as metadata only. The storage key is `crypto.randomUUID()` with no extension. The original is sanitised on output for the `Content-Disposition` header (strip path separators, control characters, quotes; truncate to 100 chars).
5. **Scan** via `scanner.service.ts` — see below.
6. **Encrypt, then write.** Plaintext never touches the storage directory.
7. Delete the temp file in a `finally` block.

Storage root is `STORAGE_PATH`, outside any Express static path. Nothing under it is
ever served directly.

## Scanner stub

Real ClamAV is out of scope for this build. Implement `scanner.service.ts` as an
interface with a signature-matching stub, so the control exists and the architecture
is correct:

```ts
export interface Scanner { scan(buf: Buffer): Promise<{ verdict: ScanVerdict; signature?: string }> }
```

The stub detects the EICAR test string and a small list of script markers
(`<?php`, `#!/bin/sh`, `MZ` at offset 0). Add a comment stating that this stands in
for ClamAV, which would be integrated through the same interface in production.
This is a documented limitation, not a hidden shortcut.

## Encryption

Envelope encryption, Node built-in `crypto` only.

**Upload:** generate a 32-byte DEK (`randomBytes`). Encrypt the file with
`aes-256-gcm`, random 12-byte IV → store `iv` and `authTag`. Wrap the DEK by
encrypting it with `aes-256-gcm` under the KEK (`KEK_MASTER`, 64 hex chars parsed
to 32 bytes), separate random IV → store `wrapIv` and `wrapTag`. Persist only the
wrapped DEK. Compute SHA-256 of the **plaintext** into `Document.sha256`.

**Download:** unwrap the DEK, decrypt, verify SHA-256 matches, stream out. A GCM
authentication failure must abort the response and write `DOC_INTEGRITY_FAILURE`.

**Permanent delete:** delete the `DocumentKey` row and unlink the blob. Comment that
destroying the key alone would render the ciphertext unrecoverable even if the blob
survived in a backup — this is cryptographic erasure.

## Share links

Token: 32 bytes from `crypto.randomBytes`, base64url. Stored as SHA-256 in
`tokenHash`. Returned to the creator once, at creation, and never retrievable again.

Expiry is required, 1–720 hours. Optional Argon2id-hashed password. Optional single
use. Revocation sets `revokedAt`.

Public lookup: hash the presented token, look up by hash, compare with
`timingSafeEqual`. **Invalid, expired, revoked, and exhausted all return the same
404 body.** Rate limit: 10 requests per minute per IP.

## Audit log

Write synchronously, in the same transaction as the action where possible.

```
recordHash = SHA256(prevHash + "|" + JSON.stringify({
  sequence, eventType, actorId, targetType, targetId, outcome, createdAt
}))
```

`prevHash` is the previous record's `recordHash`, or 64 zeros for the first.
Because `sequence` is an autoincrement, take an advisory lock (or a serialised
transaction) when appending so concurrent writes can't interleave and break the chain.

`verifyChain()` walks in sequence order and returns the first broken sequence number.

**Never log:** passwords, password hashes, tokens, key material, file contents.
Write a test that asserts no audit row's serialised form contains the seed password
or a known token value.

## Global middleware

`helmet` with CSP: `default-src 'self'`, `script-src 'self'`, `object-src 'none'`,
`frame-ancestors 'none'`. CORS restricted to `WEB_ORIGIN` with credentials.
Rate limits: 10/min on `/auth/login`, 5/min on `/auth/register`, 10/min on `/share/:token`,
100/min globally.

Error handler: log the full error with pino, return the generic contract shape.
In production mode, never include `err.message` in the response.