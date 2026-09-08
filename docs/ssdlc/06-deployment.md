# Phase 6 — Deployment

## Hardening checklist
- `SECURE_MODE=true` and `NODE_ENV=production` for any deployment; the vulnerable
  build refuses to start under production conditions.
- Fresh `JWT_SECRET` and `KEK_MASTER` generated for production, never reused from
  development.
- Services bound to loopback / internal network; no public database port.
- Security headers (CSP, HSTS) and CORS restricted to the frontend origin.

## Container review
PostgreSQL runs on an internal Docker network bound to `127.0.0.1:5433`, not exposed
to the host network. Confirmed via `docker ps`.

## Dependency scan
`npm audit` findings are triaged rather than blindly upgraded; see the maintenance
phase for one worked example.
