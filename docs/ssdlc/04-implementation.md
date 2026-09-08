# Phase 4 — Implementation

## Secure coding standard
TypeScript strict mode; all database access through Prisma (parameterised); no raw
SQL except the one marked vulnerable path; secrets from environment only; every
security-relevant action writes an audit record.

## Static analysis
TypeScript compiler in strict mode caught real defects during the build, including
a serialiser type mismatch that prevented a raw entity (with `passwordHash`) from
being returned.

## Code review findings (during implementation)
- **Excessive data exposure (CWE-213):** an early upload response returned the full
  owner record including `passwordHash`. Fixed by adding an explicit serialiser layer
  applied to every route.
- **Token in audit log:** a share-access-failure record initially logged the raw
  token; changed to log its hash.
- **Broken startup assertion:** the authorisation self-check initially inspected the
  wrong function name; corrected so it genuinely verifies every route.

## Secret scanning
`.env` is gitignored; `.env.example` documents required variables without values.
