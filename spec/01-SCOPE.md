# 01 — Scope and Stack

## What this system does

Staff in an organisation upload confidential documents, control precisely who can
read each one, share individual documents with outsiders through expiring links,
and review a tamper-evident record of every access. Everything is encrypted at rest.

## Roles

| Role | Can do |
|---|---|
| `STANDARD_USER` | Upload; view, download and delete own documents; view documents shared with them |
| `DOCUMENT_OWNER` | Everything above, plus grant and revoke permissions and create share links |
| `AUDITOR` | Read the audit log and verify its integrity. Cannot read documents. |
| `ADMINISTRATOR` | Manage users and roles. Cannot read document contents. |

Role is a single enum column on `User`. Permissions are resolved from a declarative
matrix in code — see `04-SECURITY.md`.

## In scope

- Registration, login, logout, session refresh
- Document upload with server-side validation and malware-signature scanning
- Document list, detail, download, soft delete
- Per-document permission grants (view / download / reshare)
- Expiring, revocable share links with an unauthenticated public access route
- AES-256-GCM envelope encryption at rest, SHA-256 integrity digests
- Hash-chained append-only audit log with an integrity verification function
- Admin console (users, roles) and auditor console (log search, chain verify)
- Six deliberately vulnerable counterparts, selectable by `SECURE_MODE=false`
- A CLI attack harness proving each vulnerability, run against both modes

## Explicitly out of scope — do not build these

TOTP / MFA · document versioning · folders and hierarchy · password reset by email ·
email sending of any kind · full-text search inside file contents · real ClamAV
(use the stub scanner in `04-SECURITY.md`) · backup and retention automation ·
key rotation · SSO / LDAP · file preview rendering · dark mode · notifications ·
mobile app · production deployment.

If you think one of these is needed, say so and stop. Do not build it.

## Stack — use exactly this, add nothing

**Backend** (`apps/api`)
- Node.js 24, Express 4, TypeScript strict
- Prisma ORM + PostgreSQL 16
- `zod` (validation), `argon2`, `jsonwebtoken`, `cookie-parser`
- `multer` (uploads), `file-type` (magic bytes)
- `helmet`, `cors`, `express-rate-limit`
- `pino` + `pino-pretty`
- Node built-in `crypto` for all encryption. No crypto libraries.

**Frontend** (`apps/web`)
- React 18, Vite, TypeScript, React Router 6
- Tailwind CSS
- `axios` with an interceptor for auth and refresh
- No component library. No state management library — React Context is enough.

**Tooling**
- Docker Compose: `postgres` and `api` and `web` only. No clamav service.
  Map postgres to host port **5433** (`127.0.0.1:5433:5432`) — host port 5432 is
  already in use by an unrelated container on this machine.
- Vitest + Supertest for backend tests
- Root scripts: `dev`, `build`, `test`, `db:migrate`, `db:seed`, `attack`

## Repository layout

```
securedocs/
  AGENTS.md
  docker-compose.yml
  .env.example
  .gitignore
  package.json                 (workspaces)
  spec/                        (this folder — read only, never modify)
  apps/
    api/
      prisma/schema.prisma
      prisma/seed.ts
      src/
        index.ts               entry, mode banner, route registration
        config.ts              env parsing, SECURE_MODE flag
        db.ts                  prisma client
        middleware/            auth, authorize, csrf, errorHandler, rateLimit
        modules/
          auth/                secure/ and vulnerable/ and index.ts factory
          documents/           secure/ and vulnerable/ and index.ts factory
          permissions/
          share/
          audit/
          admin/
        services/
          crypto.service.ts    envelope encryption
          scanner.service.ts   signature stub scanner
          storage.service.ts   blob read/write
        tests/
    web/
      src/
        api/client.ts
        context/AuthContext.tsx
        components/
        pages/
        styles/tokens.css
  tools/attack-harness/
  docs/
  evidence/                    (gitignored)
```

## Environment variables

```
DATABASE_URL=postgresql://securedocs:devpassword@localhost:5433/securedocs
PORT=3000
NODE_ENV=development
SECURE_MODE=true
JWT_SECRET=<32+ random chars>
KEK_MASTER=<64 hex chars = 32 bytes>
STORAGE_PATH=./storage/blobs
MAX_UPLOAD_BYTES=26214400
WEB_ORIGIN=http://127.0.0.1:5173
```

## Seed data

Four users, all with password `Passw0rd!Demo`, plus three synthetic documents owned
by `owner@securedocs.test`, one of which is shared with `user@securedocs.test`.

| Email | Role |
|---|---|
| `admin@securedocs.test` | ADMINISTRATOR |
| `auditor@securedocs.test` | AUDITOR |
| `owner@securedocs.test` | DOCUMENT_OWNER |
| `user@securedocs.test` | STANDARD_USER |