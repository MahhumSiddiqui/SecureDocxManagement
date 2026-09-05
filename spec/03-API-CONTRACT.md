# 03 — API Contract

**This contract is fixed.** The backend and frontend are built in separate sessions
and can only integrate if both follow it exactly. Do not rename a route, change a
field name, or alter a status code.

Base URL: `http://127.0.0.1:3000/api`

## Conventions

- All request and response bodies are JSON, except upload (multipart) and download (binary).
- Authentication: `Authorization: Bearer <accessToken>`. The refresh token lives in
  an HttpOnly cookie named `sd_refresh`.
- CSRF: state-changing requests carry `X-CSRF-Token`, matching the `sd_csrf` cookie.
- Timestamps are ISO 8601 strings.

**Error shape — every error response, without exception:**

```json
{ "error": { "code": "FORBIDDEN", "message": "You do not have access to this document." } }
```

Codes: `VALIDATION_ERROR` (400) · `UNAUTHENTICATED` (401) · `FORBIDDEN` (403) ·
`NOT_FOUND` (404) · `CONFLICT` (409) · `RATE_LIMITED` (429) · `INTERNAL` (500).

Messages are generic. Never include a stack trace, SQL text, filesystem path, or
library version in a response.

---

## Auth

### `POST /auth/register`
Body: `{ email, displayName, password }` — password minimum 12 characters.
→ `201 { user: UserSummary }`
Always returns 201 even if the email exists, to prevent enumeration. Internally,
log the collision and do not create a duplicate.

### `POST /auth/login`
Body: `{ email, password }`
→ `200 { accessToken, user: UserSummary }` and sets `sd_refresh` and `sd_csrf` cookies.
→ `401 UNAUTHENTICATED` for wrong password, unknown user, or locked account — the
response body and timing must be indistinguishable between these three cases.

### `POST /auth/refresh`
No body. Reads `sd_refresh`.
→ `200 { accessToken }` and rotates the cookie.
→ `401` if missing, expired, revoked, or already consumed (reuse revokes the family).

### `POST /auth/logout`
→ `204`. Revokes the refresh family and clears cookies.

### `GET /auth/me`
→ `200 { user: UserSummary }`

```ts
UserSummary = { id, email, displayName, role, status, createdAt, lastLoginAt }
```

---

## Documents

### `GET /documents`
Query: `page` (default 1), `pageSize` (default 20, max 100), `search`, `category`,
`sortBy` (one of `createdAt` | `title` | `sizeBytes`), `sortDir` (`asc` | `desc`),
`scope` (`owned` | `shared` | `all`, default `all`).
→ `200 { items: DocumentSummary[], page, pageSize, total }`

Returns only documents the caller owns or has an unexpired grant on. Never all documents.

### `POST /documents`
`multipart/form-data`: `file` (required), `title`, `description`, `category`.
→ `201 { document: DocumentDetail }`
→ `400 VALIDATION_ERROR` with a message naming the reason: disallowed type,
content does not match extension, too large, or malware signature detected.

### `GET /documents/:id`
→ `200 { document: DocumentDetail, permissions: PermissionEntry[], shareLinks: ShareLinkSummary[] }`
`permissions` and `shareLinks` are returned only to the owner or an administrator;
otherwise they are empty arrays.

### `GET /documents/:id/download`
→ `200` binary stream, `Content-Disposition: attachment; filename="<sanitised>"`,
`X-Content-Type-Options: nosniff`.
→ `403` if the caller lacks `canDownload`.
→ `500 INTERNAL` with an audited integrity alert if the GCM tag fails.

### `PATCH /documents/:id`
Body: `{ title?, description?, category? }` → `200 { document: DocumentDetail }`

### `DELETE /documents/:id`
Soft delete → `204`.

### `DELETE /documents/:id/permanent`
Owner or admin only. Destroys the `DocumentKey` row (cryptographic erasure) and the
blob → `204`.

```ts
DocumentSummary = { id, title, category, originalName, mimeType, sizeBytes,
                    ownerId, ownerEmail, sha256, createdAt, accessLevel }
// accessLevel: "OWNER" | "SHARED" — how this caller reaches the document

DocumentDetail = DocumentSummary & { description, scanVerdict, updatedAt }
```

---

## Permissions

### `GET /documents/:id/permissions` → `200 { permissions: PermissionEntry[] }`

### `POST /documents/:id/permissions`
Body: `{ granteeEmail, canView, canDownload, canReshare, expiresAt? }`
→ `201 { permission: PermissionEntry }` → `404` if the grantee does not exist.

### `PATCH /documents/:id/permissions/:permissionId` → `200 { permission }`

### `DELETE /documents/:id/permissions/:permissionId` → `204`

```ts
PermissionEntry = { id, granteeId, granteeEmail, granteeName, canView,
                    canDownload, canReshare, grantedByEmail, grantedAt, expiresAt }
```

---

## Share links

### `POST /documents/:id/share`
Body: `{ expiresInHours (1–720, required), canDownload, singleUse, password? }`
→ `201 { shareLink: ShareLinkSummary, url, token }`
**`token` is returned exactly once, at creation, and never again.**

### `GET /documents/:id/share` → `200 { shareLinks: ShareLinkSummary[] }`

### `DELETE /share/:shareLinkId` → `204` (revoke)

### `GET /share/:token` — **unauthenticated**
→ `200 { document: { title, originalName, mimeType, sizeBytes }, requiresPassword }`
→ `404 NOT_FOUND` for invalid, expired, revoked, or exhausted tokens — all four
cases return byte-identical responses.

### `POST /share/:token/download` — **unauthenticated**
Body: `{ password? }` → `200` binary stream. Increments `useCount`.

```ts
ShareLinkSummary = { id, documentId, canDownload, hasPassword, expiresAt,
                     singleUse, useCount, revokedAt, createdAt }
```

---

## Audit — AUDITOR and ADMINISTRATOR only

### `GET /audit`
Query: `page`, `pageSize`, `eventType`, `actorEmail`, `outcome`, `from`, `to`
→ `200 { items: AuditEntry[], page, pageSize, total }`

### `GET /audit/verify`
→ `200 { valid: boolean, recordsChecked: number, brokenAtSequence: number | null }`

### `GET /audit/export` → `200` CSV, `Content-Disposition: attachment`

```ts
AuditEntry = { id, sequence, eventType, actorEmail, targetType, targetId,
               outcome, ipAddress, metadata, recordHash, prevHash, createdAt }
```

---

## Admin — ADMINISTRATOR only

### `GET /admin/users` → `200 { users: UserSummary[] }`
### `PATCH /admin/users/:id` — Body: `{ role?, status? }` → `200 { user: UserSummary }`

---

## Event types for the audit log

Use exactly these strings:

`AUTH_REGISTER` · `AUTH_LOGIN` · `AUTH_LOGIN_FAILED` · `AUTH_LOCKOUT` ·
`AUTH_LOGOUT` · `AUTH_REFRESH` · `AUTH_REFRESH_REUSE` · `DOC_UPLOAD` ·
`DOC_UPLOAD_REJECTED` · `DOC_VIEW` · `DOC_DOWNLOAD` · `DOC_UPDATE` ·
`DOC_DELETE` · `DOC_PURGE` · `DOC_INTEGRITY_FAILURE` · `PERM_GRANT` ·
`PERM_UPDATE` · `PERM_REVOKE` · `SHARE_CREATE` · `SHARE_ACCESS` ·
`SHARE_ACCESS_FAILED` · `SHARE_REVOKE` · `ADMIN_USER_UPDATE` ·
`AUDIT_VIEW` · `AUDIT_EXPORT` · `ACCESS_DENIED`