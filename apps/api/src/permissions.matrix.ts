import type { Role } from "@prisma/client";
export type Action =
  | "document:read"
  | "document:create"
  | "document:delete:own"
  | "document:update"
  | "document:delete:any"
  | "permission:manage"
  | "share:manage"
  | "audit:read"
  | "audit:export"
  | "audit:verify"
  | "user:manage";
export const MATRIX: Record<Role, Action[]> = {
  STANDARD_USER: ["document:read", "document:create", "document:delete:own"],
  DOCUMENT_OWNER: [
    "document:read",
    "document:create",
    "document:delete:own",
    "document:update",
    "permission:manage",
    "share:manage",
  ],
  AUDITOR: ["audit:read", "audit:export", "audit:verify"],
  ADMINISTRATOR: [
    "user:manage",
    "document:delete:any",
    "permission:manage",
    "audit:read",
  ],
};
