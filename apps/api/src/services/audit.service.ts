import { createHash } from "node:crypto";
import { prisma } from "../db.js";
import type { Prisma } from "@prisma/client";
const genesis = "0".repeat(64);
let appendQueue: Promise<void> = Promise.resolve();
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
