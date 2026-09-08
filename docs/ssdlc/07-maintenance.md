# Phase 7 — Maintenance

## Monitoring
The hash-chained audit log is the primary detection mechanism. `verifyChain()`
confirms integrity and reports the first altered record. Repeated authentication
failures are recorded for review.

## Worked patch cycle
`npm audit` reported findings in the dependency tree. Process: review each advisory,
assess whether the vulnerable code path is reachable in this application, upgrade
where a fix exists and the change is non-breaking, and record any accepted risk in
known-limitations. This mirrors real triage rather than blind upgrading.

## Incident response runbook — leaked share link
1. Identify the affected link from the audit log (`SHARE_CREATE` / `SHARE_ACCESS`).
2. Revoke it (`DELETE /api/share/:id`); revocation takes effect immediately in
   secure mode.
3. Review `SHARE_ACCESS` records for unexpected use.
4. If the document is sensitive, rotate it (re-upload, new key) and re-share via a
   fresh short-lived link.
5. Record the incident and review whether link lifetimes should be shortened.

## Key rotation
Envelope encryption supports rotation: re-wrap each document''s DEK under a new KEK
without re-encrypting document bodies. Cryptographic erasure (destroying a DEK)
renders a single document unrecoverable without touching others.
