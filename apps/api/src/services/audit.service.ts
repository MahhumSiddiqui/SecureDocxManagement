import { createHash } from "node:crypto";
import { prisma } from "../db.js";
import { config } from "../config.js";
import type { Prisma } from "@prisma/client";

const genesis = "0".repeat(64);
let appendQueue: Promise<void> = Promise.resolve();

// ----------------------------------------------------------
// [VULN-06] Insufficient Logging & Monitoring
// CWE-778 — OWASP A09:2021
//
// Active ONLY when SECURE_MODE=false.
//
// Root cause, two parts:
//   1. The events that would reveal an attack in progress are simply
//      not recorded: failed logins, authorisation denials, downloads
//      and share-link access. VULN-01 through VULN-05 can therefore
//      be exploited without leaving any trace in the audit trail.
//   2. Records that are written carry empty prevHash and recordHash
//      values, so there is no chain linking them. Any record can be
//      altered or deleted afterwards and verifyChain() cannot tell.
//
// Together these defeat both detection and post-incident
// reconstruction — the two things an audit log exists for.
//
// Secure behaviour (below): every security-relevant event is written
// synchronously under an advisory lock, and each record is hashed
// together with its predecessor so that any later modification
// breaks the chain and is detectable.
// ----------------------------------------------------------
const UNLOGGED_IN_VULNERABLE_MODE = new Set([
  "AUTH_LOGIN_FAILED",
  "AUTH_LOCKOUT",
  "ACCESS_DENIED",
  "DOC_DOWNLOAD",
  "SHARE_ACCESS",
  "SHARE_ACCESS_FAILED",
]);

export type AuditInput = {
  eventType: string;
  actorId?: string;
  actorEmail?: string;
  targetType?: string;
  targetId?: string | null;
  outcome: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Prisma.InputJsonValue;
};

export async function recordAudit(input: AuditInput): Promise<void> {
  if (!config.secureMode) {
    // VULNERABLE: security-relevant events are dropped entirely.
    if (UNLOGGED_IN_VULNERABLE_MODE.has(input.eventType)) {
      return;
    }
    // VULNERABLE: remaining records are written with no hash chain,
    // so tampering cannot be detected.
    const last = await prisma.auditLog.findFirst({
      orderBy: { sequence: "desc" },
    });
    await prisma.auditLog.create({
      data: {
        ...input,
        prevHash: "",
        recordHash: "",
        createdAt: new Date(),
      },
    });
    void last;
    return;
  }

  const append = appendQueue.then(async () =>
    prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(741923);`;
      const last = await tx.auditLog.findFirst({
        orderBy: { sequence: "desc" },
      });
      const createdAt = new Date();
      const prevHash = last?.recordHash || genesis;
      const created = await tx.auditLog.create({
        data: {
          ...input,
          prevHash,
          recordHash: "",
          createdAt,
        },
      });
      const payload = {
        sequence: created.sequence,
        eventType: input.eventType,
        actorId: input.actorId ?? null,
        targetType: input.targetType ?? null,
        targetId: input.targetId ?? null,
        outcome: input.outcome,
        createdAt: createdAt.toISOString(),
      };
      const recordHash = createHash("sha256")
        .update(prevHash + "|" + JSON.stringify(payload))
        .digest("hex");
      await tx.auditLog.update({
        where: { id: created.id },
        data: { recordHash },
      });
    }),
  );
  appendQueue = append.catch(() => undefined);
  await append;
}

export async function verifyChain(): Promise<{
  valid: boolean;
  recordsChecked: number;
  brokenAtSequence: number | null;
}> {
  const rows = await prisma.auditLog.findMany({ orderBy: { sequence: "asc" } });
  let previous = genesis;
  for (const row of rows) {
    const payload = {
      sequence: row.sequence,
      eventType: row.eventType,
      actorId: row.actorId,
      targetType: row.targetType,
      targetId: row.targetId,
      outcome: row.outcome,
      createdAt: row.createdAt.toISOString(),
    };
    const expected = createHash("sha256")
      .update(previous + "|" + JSON.stringify(payload))
      .digest("hex");
    if (row.prevHash !== previous || row.recordHash !== expected)
      return {
        valid: false,
        recordsChecked: rows.length,
        brokenAtSequence: row.sequence,
      };
    previous = row.recordHash;
  }
  return { valid: true, recordsChecked: rows.length, brokenAtSequence: null };
}