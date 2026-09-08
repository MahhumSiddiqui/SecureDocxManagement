# Phase 5 — Testing

## Automated tests
12 security tests (`apps/api/src/tests/security.test.ts`), all passing, covering
authentication, enumeration resistance, lockout, refresh rotation and reuse, IDOR,
role denial, upload validation, EICAR, encryption round-trip, GCM tamper detection,
share expiry/revocation, and audit-chain verification.

## Manual testing
Each control was exercised by hand and evidenced with screenshots: Argon2id hashes
in the database, ciphertext on disk with correct decryption on download, CSRF
rejection, upload rejections (extension, content mismatch, EICAR), XSS escaping,
server-side 403 on admin routes via direct API call, and share-link revocation.

## Comparative testing
The attack harness (`tools/attack-harness/attack.mjs`) runs all six attacks against
both modes: **6/6 exploited in vulnerable mode, 0/6 in secure mode**. This isolates
each control''s effect, since the two modes share one codebase and differ only in the
control under test.
