import { Router } from "express";
import { prisma } from "../../../db.js";
import { verifyChain, recordAudit } from "../../../services/audit.service.js";
import { toAuditEntry } from "../../../serializers.js";
export function router(): Router {
  const r = Router();
  r.get("/", async (req, res, next) => {
    try {
      const page = Math.max(1, Number(req.query.page ?? 1)),
        pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize ?? 20)));
      const where = {
        ...(req.query.eventType
          ? { eventType: String(req.query.eventType) }
          : {}),
        ...(req.query.actorEmail
          ? { actorEmail: String(req.query.actorEmail) }
          : {}),
        ...(req.query.outcome ? { outcome: String(req.query.outcome) } : {}),
      };
      const [items, total] = await prisma.$transaction([
        prisma.auditLog.findMany({
          where,
          orderBy: { sequence: "desc" },
          skip: (page - 1) * pageSize,
          take: pageSize,
        }),
        prisma.auditLog.count({ where }),
      ]);
      await recordAudit({
        eventType: "AUDIT_VIEW",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        outcome: "SUCCESS",
      });
      return res.json({
        items: items.map(toAuditEntry),
        page,
        pageSize,
        total,
      });
    } catch (e) {
      next(e);
    }
  });
  r.get("/verify", async (req, res, next) => {
    try {
      return res.json(await verifyChain());
    } catch (e) {
      next(e);
    }
  });
  r.get("/export", async (req, res, next) => {
    try {
      const rows = await prisma.auditLog.findMany({
        orderBy: { sequence: "asc" },
      });
      await recordAudit({
        eventType: "AUDIT_EXPORT",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        outcome: "SUCCESS",
      });
      const csv = [
        "id,sequence,eventType,actorEmail,targetType,targetId,outcome,recordHash,prevHash,createdAt",
        ...rows.map((x) =>
          [
            x.id,
            x.sequence,
            x.eventType,
            x.actorEmail ?? "",
            x.targetType ?? "",
            x.targetId ?? "",
            x.outcome,
            x.recordHash,
            x.prevHash,
            x.createdAt.toISOString(),
          ]
            .map((v) => `"${String(v).replaceAll('"', '""')}"`)
            .join(","),
        ),
      ].join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", 'attachment; filename="audit.csv"');
      return res.send(csv);
    } catch (e) {
      next(e);
    }
  });
  return r;
}
