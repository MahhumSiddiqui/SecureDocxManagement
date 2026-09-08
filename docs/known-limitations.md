# Known Limitations — SecureDocs

Deliberate scoping decisions and simplifications, with rationale. Documenting these
is itself a security practice: an honest account of what a system does *not* protect
against is more useful than an overstated claim of completeness.

## Deliberately deferred features

**Password reset by email.** Designed but not implemented. A secure reset requires
an email delivery channel, which is outside the project's local-only scope. The
data model supports it (`PasswordResetToken` with hashed, expiring, single-use
tokens); only the delivery step is absent. Deferring it avoids shipping a
half-working security-sensitive flow.

**Multi-factor authentication (TOTP).** Scoped out to keep the two-day build
focused on the four core concepts (upload security, access control, encryption,
logging). The architecture leaves room for it at the authentication layer.

**Document versioning and folders.** Excluded to concentrate effort on security
rather than document-management breadth.

## Simplified implementations

**Malware scanning is a signature stub, not ClamAV.** `scanner.service.ts` detects
the EICAR test string and common script markers through the same interface a real
scanner would use. Full ClamAV integration was deferred because its signature
database (~300 MB) and startup time are impractical for a short local build. The
control and its integration point exist; only the detection engine is simplified.

**Audit-log immutability is demonstrated, not fully enforced.** The design revokes
UPDATE/DELETE on the audit table from a restricted database role, but the
application runs with broader rights for migration convenience. The hash chain
provides the practical guarantee: any post-hoc modification is detectable via
`verifyChain()`, even if not prevented at the database level.

**Concurrent audit writes.** The secure path serialises audit appends with a
PostgreSQL advisory lock, which is correct for the single-instance deployment used
here. A horizontally-scaled deployment would need a different coordination
mechanism.

**Uploads held in memory.** Files are buffered in memory (25 MB cap) rather than
streamed to a temp directory. Adequate at this scale; a production system handling
large files would stream to disk.

## Scope boundaries the system does not address

**Redistribution of downloaded copies.** Once an authorised user downloads a
document, the system has no further control over it — it can be copied, forwarded,
or printed. This is inherent to any document system: to be read, a file must be
decrypted onto the reader's device. The controls limit *who obtains a copy* (access
control, expiring links), enable *withdrawal of future access* (revocation), and
provide *accountability* (audit trail) — not perpetual control over distributed
copies. DRM and watermarking were excluded for this reason; they raise effort but
cannot prevent capture.

**Deployment.** The system runs in a local laboratory environment. The deliberately
vulnerable build is never deployed; only the secure build (`SECURE_MODE=true`,
`NODE_ENV=production`) would be, and the vulnerable build refuses to start under
production conditions.

## The deliberately vulnerable build

The project ships a vulnerable build for controlled comparison, following
established security-education practice (OWASP Juice Shop, DVWA, WebGoat). Risks are
bounded by: default-secure configuration, an explicit opt-in with a loud startup
warning, loopback-only binding, synthetic data only, a private repository, and a
refusal to start in production. It exists to demonstrate the value of each control,
and is shut down after demonstration.