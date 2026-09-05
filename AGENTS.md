# SecureDocs — Agent Instructions

University coursework: a Secure Document Management System for a Secure Software
Design & Development Lab. Two-day build. Read the spec before writing anything.

## Read these first, in order

- `spec/01-SCOPE.md` — what is and isn't being built, and the stack
- `spec/02-DATA-MODEL.md` — the complete Prisma schema. Use it verbatim.
- `spec/03-API-CONTRACT.md` — every endpoint. This contract is fixed. Do not
  rename routes, change response shapes, or add endpoints.
- `spec/04-SECURITY.md` — how each security control must be implemented
- `spec/05-VULNERABLE-MODE.md` — the deliberately insecure counterparts
- `spec/06-FRONTEND.md` — design system and screens
- `spec/07-SESSIONS.md` — which session you are in and where to stop

## Non-negotiable rules

1. **The API contract in `03-API-CONTRACT.md` is law.** Frontend and backend are
   built in separate sessions and only match if both follow it exactly.
2. **Dual mode.** `SECURE_MODE=true` (default) selects hardened code;
   `SECURE_MODE=false` selects the deliberately vulnerable code. Same codebase,
   chosen by a factory at startup. Never duplicate whole files.
3. **Localhost only.** Bind to `127.0.0.1`. Never `0.0.0.0`. Synthetic data only.
4. **Mark every vulnerable path** with a comment block naming the CWE and the
   secure counterpart.
5. **Finish what you start.** No `TODO`, no stub returning mock data. If you are
   running long, tell me what you cut rather than leaving a half-built route.
6. **No unrequested features.** Ask first.
7. **TypeScript strict.** No `any`. All DB access through Prisma except the one
   marked vulnerable raw-SQL path.
8. **Secrets from env only.** Commit `.env.example`, never `.env`.
9. **Every security-relevant action writes an audit record.**
10. **Never run destructive commands.**