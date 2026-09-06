import type { Prisma } from "@prisma/client";

type DocumentRecord = {
  id: string;
  title: string;
  category: string;
  originalName: string;
  mimeType: string;
  sizeBytes: number;
  ownerId: string;
  sha256: string;
  createdAt: Date;
  description: string;
  scanVerdict: string;
  updatedAt: Date;
  owner: { email: string };
};

type PermissionRecord = {
  id: string;
  documentId: string;
  granteeId: string;
  canView: boolean;
  canDownload: boolean;
  canReshare: boolean;
  grantedAt: Date;
  expiresAt: Date | null;
  grantee: { email: string; displayName: string };
  grantedBy: { email: string };
};

type ShareLinkRecord = {
  id: string;
  documentId: string;
  canDownload: boolean;
  passwordHash: string | null;
  expiresAt: Date | null;
  singleUse: boolean;
  useCount: number;
  revokedAt: Date | null;
  createdAt: Date;
};

type UserRecord = {
  id: string;
  email: string;
  displayName: string;
  role: string;
  status: string;
  createdAt: Date;
  lastLoginAt: Date | null;
};

type AuditRecord = {
  id: string;
  sequence: number;
  eventType: string;
  actorEmail: string | null;
  targetType: string | null;
  targetId: string | null;
  outcome: string;
  ipAddress: string | null;
  metadata: Prisma.JsonValue | null;
  recordHash: string;
  prevHash: string;
  createdAt: Date;
};

export function toDocumentSummary(
  document: DocumentRecord,
  accessLevel: "OWNER" | "SHARED",
) {
  return {
    id: document.id,
    title: document.title,
    category: document.category,
    originalName: document.originalName,
    mimeType: document.mimeType,
    sizeBytes: document.sizeBytes,
    ownerId: document.ownerId,
    ownerEmail: document.owner.email,
    sha256: document.sha256,
    createdAt: document.createdAt,
    accessLevel,
  };
}

export function toDocumentDetail(
  document: DocumentRecord,
  accessLevel: "OWNER" | "SHARED",
) {
  return {
    ...toDocumentSummary(document, accessLevel),
    description: document.description,
    scanVerdict: document.scanVerdict,
    updatedAt: document.updatedAt,
  };
}

export function toPermissionEntry(permission: PermissionRecord) {
  return {
    id: permission.id,
    documentId: permission.documentId,
    granteeId: permission.granteeId,
    granteeEmail: permission.grantee.email,
    granteeName: permission.grantee.displayName,
    canView: permission.canView,
    canDownload: permission.canDownload,
    canReshare: permission.canReshare,
    grantedByEmail: permission.grantedBy.email,
    grantedAt: permission.grantedAt,
    expiresAt: permission.expiresAt,
  };
}

export function toShareLinkSummary(shareLink: ShareLinkRecord) {
  return {
    id: shareLink.id,
    documentId: shareLink.documentId,
    canDownload: shareLink.canDownload,
    hasPassword: Boolean(shareLink.passwordHash),
    expiresAt: shareLink.expiresAt,
    singleUse: shareLink.singleUse,
    useCount: shareLink.useCount,
    revokedAt: shareLink.revokedAt,
    createdAt: shareLink.createdAt,
  };
}

export function toUserSummary(user: UserRecord) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    role: user.role,
    status: user.status,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt,
  };
}

export function toAuditEntry(audit: AuditRecord) {
  return {
    id: audit.id,
    sequence: audit.sequence,
    eventType: audit.eventType,
    actorEmail: audit.actorEmail,
    targetType: audit.targetType,
    targetId: audit.targetId,
    outcome: audit.outcome,
    ipAddress: audit.ipAddress,
    metadata: audit.metadata,
    recordHash: audit.recordHash,
    prevHash: audit.prevHash,
    createdAt: audit.createdAt,
  };
}
