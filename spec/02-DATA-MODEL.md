# 02 — Data Model

Use this schema **verbatim** as `apps/api/prisma/schema.prisma`. Do not rename fields,
add fields, or change types. The API contract and the frontend both depend on these names.

```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

enum Role {
  STANDARD_USER
  DOCUMENT_OWNER
  AUDITOR
  ADMINISTRATOR
}

enum UserStatus {
  ACTIVE
  SUSPENDED
}

enum ScanVerdict {
  CLEAN
  INFECTED
  SKIPPED
}

model User {
  id             String     @id @default(uuid())
  email          String     @unique
  displayName    String
  passwordHash   String
  role           Role       @default(STANDARD_USER)
  status         UserStatus @default(ACTIVE)
  failedAttempts Int        @default(0)
  lockedUntil    DateTime?
  createdAt      DateTime   @default(now())
  lastLoginAt    DateTime?

  documents        Document[]           @relation("DocumentOwner")
  permissionsHeld  DocumentPermission[] @relation("Grantee")
  permissionsGiven DocumentPermission[] @relation("Grantor")
  shareLinks       ShareLink[]
  refreshTokens    RefreshToken[]
  auditLogs        AuditLog[]

  @@index([email])
}

model Document {
  id             String    @id @default(uuid())
  // legacyId exists ONLY to demonstrate VULN-02 (IDOR via enumerable identifier).
  // The secure code path never uses it.
  legacyId       Int       @unique @default(autoincrement())
  title          String
  description    String    @default("")
  category       String    @default("General")
  originalName   String
  mimeType       String
  sizeBytes      Int
  storageKey     String    @unique
  sha256         String
  ownerId        String
  isDeleted      Boolean   @default(false)
  deletedAt      DateTime?
  scanVerdict    ScanVerdict @default(SKIPPED)
  createdAt      DateTime  @default(now())
  updatedAt      DateTime  @updatedAt

  owner       User                 @relation("DocumentOwner", fields: [ownerId], references: [id])
  permissions DocumentPermission[]
  shareLinks  ShareLink[]
  key         DocumentKey?

  @@index([ownerId])
  @@index([isDeleted])
}

model DocumentPermission {
  id           String    @id @default(uuid())
  documentId   String
  granteeId    String
  canView      Boolean   @default(true)
  canDownload  Boolean   @default(false)
  canReshare   Boolean   @default(false)
  grantedById  String
  grantedAt    DateTime  @default(now())
  expiresAt    DateTime?

  document  Document @relation(fields: [documentId], references: [id], onDelete: Cascade)
  grantee   User     @relation("Grantee", fields: [granteeId], references: [id])
  grantedBy User     @relation("Grantor", fields: [grantedById], references: [id])

  @@unique([documentId, granteeId])
  @@index([granteeId])
}

model ShareLink {
  id           String    @id @default(uuid())
  // SHA-256 of the token in secure mode. In vulnerable mode the raw token is
  // stored here — see [VULN-05].
  tokenHash    String    @unique
  documentId   String
  createdById  String
  canDownload  Boolean   @default(true)
  passwordHash String?
  expiresAt    DateTime?
  singleUse    Boolean   @default(false)
  useCount     Int       @default(0)
  revokedAt    DateTime?
  createdAt    DateTime  @default(now())

  document  Document @relation(fields: [documentId], references: [id], onDelete: Cascade)
  createdBy User     @relation(fields: [createdById], references: [id])

  @@index([documentId])
}

model DocumentKey {
  id         String   @id @default(uuid())
  documentId String   @unique
  wrappedDek String            // base64
  kekId      String   @default("kek-v1")
  iv         String            // base64, 12 bytes, for the content cipher
  authTag    String            // base64, 16 bytes, for the content cipher
  wrapIv     String            // base64, 12 bytes, for wrapping the DEK
  wrapTag    String            // base64, 16 bytes, for wrapping the DEK
  createdAt  DateTime @default(now())

  document Document @relation(fields: [documentId], references: [id], onDelete: Cascade)
}

model AuditLog {
  id         String   @id @default(uuid())
  sequence   Int      @unique @default(autoincrement())
  eventType  String
  actorId    String?
  actorEmail String?
  targetType String?
  targetId   String?
  outcome    String            // SUCCESS | FAILURE | DENIED
  ipAddress  String?
  userAgent  String?
  metadata   Json?
  prevHash   String
  recordHash String
  createdAt  DateTime @default(now())

  actor User? @relation(fields: [actorId], references: [id])

  @@index([eventType])
  @@index([actorId])
  @@index([createdAt])
}

model RefreshToken {
  id        String    @id @default(uuid())
  tokenHash String    @unique
  userId    String
  familyId  String
  expiresAt DateTime
  revokedAt DateTime?
  createdAt DateTime  @default(now())

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([userId])
  @@index([familyId])
}

model LoginAttempt {
  id        String   @id @default(uuid())
  email     String
  ipAddress String?
  success   Boolean
  createdAt DateTime @default(now())

  @@index([email, createdAt])
}
```

## Notes for the implementer

**`Document.legacyId`** exists solely so the IDOR demonstration is possible. Secure
routes address documents by UUID; the vulnerable route accepts `legacyId`. Do not
use `legacyId` anywhere in secure-mode code.

**Audit log immutability.** After the initial migration, add a second migration
containing raw SQL that creates a restricted Postgres role and revokes UPDATE and
DELETE on `AuditLog` from it. Document in a comment that in a real deployment the
application would connect as this role; for the lab, note that this is demonstrated
rather than fully enforced, since Prisma migrations need broader rights.

**Genesis hash.** The first audit record's `prevHash` is 64 zeros.