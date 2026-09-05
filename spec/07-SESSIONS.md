# 07 — Build Sessions

Three agent sessions. Between them you work manually — running commands, fixing
small things, committing. Manual work costs no prompts.

---

## Session 1 — Backend, secure mode, complete

> Read `AGENTS.md` and all files in `spec/`, then build the complete backend in
> `apps/api`, secure mode only. Do not build the frontend or vulnerable mode.
>
> Scope: the full repo scaffold and `docker-compose.yml` per `spec/01-SCOPE.md`;
> the Prisma schema verbatim from `spec/02-DATA-MODEL.md` plus migrations and the
> seed script; every endpoint in `spec/03-API-CONTRACT.md`; every control in
> `spec/04-SECURITY.md`.
>
> Structure the modules with the `secure/` subfolder and `index.ts` factory layout
> from `spec/05-VULNERABLE-MODE.md` now, with the vulnerable branch importing the
> secure implementation as a temporary placeholder, so session 3 only has to fill
> in files rather than restructure anything.
>
> Write Vitest + Supertest tests covering: login success and failure, enumeration
> resistance, lockout, refresh rotation and reuse detection, IDOR refusal across two
> accounts, role denial on admin and audit routes, upload rejection for a disallowed
> extension and for mismatched magic bytes, EICAR rejection, encryption round-trip,
> GCM tamper detection, share-link expiry and revocation, and audit chain
> verification passing then failing after a manual update.
>
> Work through the whole scope without stopping for permission on routine steps.
> When done, print a summary of what was built, what was skipped, and what I need
> to verify manually.

**Then, manually:**

```bash
docker compose up -d postgres
npm install
npx prisma migrate dev --name init
npm run db:seed
npm run test
npm run dev
```

**Verify before session 2:**

- `npm run test` passes
- Login as `owner@securedocs.test` in Postman returns a token; `users.passwordHash` starts with `$argon2id$`
- Upload a PDF, then open the file in `storage/blobs/` — it must be unreadable binary
- Log in as `user@securedocs.test`, request another user's document ID → **403**
- Request an admin route as a standard user → **403**
- `GET /audit/verify` → `valid: true`. Then `UPDATE "AuditLog" SET outcome='SUCCESS' WHERE sequence=2` in DBeaver and re-run → `valid: false`
- `docker ps` shows ports bound to `127.0.0.1`, not `0.0.0.0`

Commit: `git commit -m "Session 1: backend, secure mode"` then `git push`

---

## Session 2 — Frontend, fully wired

> Read `AGENTS.md`, `spec/03-API-CONTRACT.md` and `spec/06-FRONTEND.md`, then build
> the complete frontend in `apps/web`. The backend is finished and running at
> `http://127.0.0.1:3000`.
>
> Build every screen listed in `spec/06-FRONTEND.md`, wired to the real API. No mock
> data anywhere. Follow the design tokens, the typography rules, and the copy rules
> exactly, including the avoid-list.
>
> Implement the audit chain visualisation as specified — this is the distinctive
> element of the interface and should be the most considered screen in the app.
>
> Meet the quality floor: responsive to 375px, visible focus rings,
> `prefers-reduced-motion` respected, AA contrast, labelled inputs, no
> `dangerouslySetInnerHTML`.
>
> Work through the whole scope without stopping for permission. When done, print a
> summary and list anything I need to verify manually.

**Verify before session 3:**

- Log in, upload, download, grant a permission, create a share link, open the share
  URL in a private window, revoke it, confirm it stops working
- Log in as the auditor — the chain renders and "Verify integrity" works
- Upload a file named `<script>alert(1)</script>.pdf` — it must display as literal text
- Tab through the app with visible focus; check at 375px width

Commit: `git commit -m "Session 2: frontend"` then `git push`

---

## Session 3 — Vulnerable mode, attack harness, documentation

> Read `AGENTS.md`, `spec/05-VULNERABLE-MODE.md` and `spec/04-SECURITY.md`. The
> secure backend and frontend are complete and working. Now implement vulnerable
> mode and the supporting deliverables.
>
> 1. Implement the six vulnerable counterparts (VULN-01 through VULN-06) in the
>    `vulnerable/` folders, selected by the existing factories under
>    `SECURE_MODE=false`. Add the startup banner and the loopback/production guards.
>    Add `docker-compose.vulnerable.yml`. Do not change the API contract.
>
> 2. Build `tools/attack-harness/` — one script per vulnerability, each performing a
>    minimal proof against the local instance, reporting EXPLOITED or BLOCKED, and
>    saving the request and response to `evidence/VULN-nn/`. Keep each proof minimal:
>    enough to establish the flaw, nothing more. For VULN-01, the proof is that a
>    `.js` file uploads and becomes fetchable — not that it executes. For VULN-04,
>    the proof is reading a stored blob and finding plaintext. The runner must
>    hard-refuse any target host other than `localhost` or `127.0.0.1`.
>
> 3. Generate `docs/vulnerability-register.md` and `evidence/comparison-report.md`
>    (vulnerability, result in vulnerable mode, result in secure mode, control
>    responsible).
>
> 4. Write `docs/ssdlc/` — one short file per phase (planning, requirements, design,
>    implementation, testing, deployment, maintenance), each referencing real files
>    and real test results in this repository rather than generic process text. For
>    maintenance, document one worked cycle: an `npm audit` finding, the triage
>    decision, and an incident-response runbook for a leaked share link.
>
> 5. Write `docs/security-controls-matrix.md`: each control, its implementing file,
>    its verifying test, its status. And `docs/known-limitations.md` — include the
>    scanner stub standing in for ClamAV.
>
> Verify that `SECURE_MODE=true` still passes every existing test before you finish.

**Then, manually:**

```bash
npm run attack -- --target http://127.0.0.1:3000 --mode secure      # expect 0/6
docker compose -f docker-compose.yml -f docker-compose.vulnerable.yml up -d
npm run attack -- --target http://127.0.0.1:3000 --mode vulnerable  # expect 6/6
```

Screenshot both runs. That pair is the single most valuable piece of evidence in
your submission.

Commit: `git commit -m "Session 3: vulnerable mode, harness, documentation"` then `git push`

---

## If you run out of prompts

All of this can be done by hand: fixing type errors and import paths · adjusting
colours, spacing and copy · writing the SSDLC documents · screenshots and evidence ·
the final report and slides.

## If a session degrades

If the output starts contradicting itself or producing stubs, stop it. Note what's
complete, commit, and finish by hand. A working system with three vulnerabilities
demonstrated beats a broken one with six.

## Priority if you have to cut

Cut in this order: stretch vulnerabilities (07, 08) → SSDLC documents → attack
harness automation (demo manually in Burp instead) → admin console → audit chain
visualisation (plain table instead).

**Never cut:** encryption at rest, the authorization middleware, the audit log, or
the secure/vulnerable comparison. Those four are the project.