# Phase 1 — Planning & Initiation

## Security objectives
SecureDocs stores confidential documents, so confidentiality, integrity, and
accountability are core functional requirements, not add-ons. The objective was a
system where each of the four focus areas — upload security, access control,
encryption, and logging — is demonstrably enforced, and where the value of each
control can be shown by comparison against a version without it.

## Risk assessment
A document repository concentrates an organisation''s most sensitive data in one
place; a single flaw in upload handling, authorisation, or sharing can expose every
file. The highest-risk surface is the upload endpoint (arbitrary binary input),
followed by object access (IDOR) and the public share route (unauthenticated).

## Approach
A dual-mode architecture (`SECURE_MODE`) builds both a hardened and a deliberately
vulnerable implementation in one codebase, enabling controlled before/after
comparison. Localhost-only, synthetic data, private repository.
