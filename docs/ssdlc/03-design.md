# Phase 3 — Design

## Threat model (STRIDE summary)
- **Spoofing:** addressed by Argon2id auth, JWT verification, role read from DB.
- **Tampering:** GCM authenticated encryption, SHA-256 digests, hash-chained audit.
- **Repudiation:** append-only audit log recording actor, action, target, outcome.
- **Information disclosure:** encryption at rest, explicit response serialisers,
  generic errors.
- **Denial of service:** upload size caps, rate limiting.
- **Elevation of privilege:** deny-by-default authorisation at a single enforcement
  point, startup assertion that every route carries an authorisation check.

## Key design decisions
- Envelope encryption: a per-document data key (DEK) wrapped by a master key (KEK),
  so key rotation and cryptographic erasure are possible.
- Single authorisation enforcement point rather than scattered per-route checks,
  with a startup assertion to catch any unguarded route.
- Serialiser layer so no route can return a raw database entity.

## Trust boundaries
Client ↔ API (all security decisions server-side); API ↔ database (least-privilege
role); API ↔ blob store (encrypted, outside web root).
