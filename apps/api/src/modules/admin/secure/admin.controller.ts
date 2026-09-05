import { Router } from "express";
import { z } from "zod";
import { prisma } from "../../../db.js";
import { recordAudit } from "../../../services/audit.service.js";
const summary = (u: {
  id: string;
  email: string;
  displayName: string;
  role: string;
  status: string;
  createdAt: Date;
  lastLoginAt: Date | null;
}) => ({
  id: u.id,
  email: u.email,
  displayName: u.displayName,
  role: u.role,
  status: u.status,
  createdAt: u.createdAt,
  lastLoginAt: u.lastLoginAt,
});
export function router(): Router {
  const r = Router();
  r.get("/users", async (_req, res, next) => {
    try {
      return res.json({
        users: (
          await prisma.user.findMany({ orderBy: { createdAt: "asc" } })
        ).map(summary),
      });
    } catch (e) {
      next(e);
    }
  });
  r.patch("/users/:id", async (req, res, next) => {
    try {
      const body = z
        .object({
          role: z
            .enum([
              "STANDARD_USER",
              "DOCUMENT_OWNER",
              "AUDITOR",
              "ADMINISTRATOR",
            ])
            .optional(),
          status: z.enum(["ACTIVE", "SUSPENDED"]).optional(),
        })
        .parse(req.body);
      const u = await prisma.user.update({
        where: { id: req.params.id },
        data: body,
      });
      await recordAudit({
        eventType: "ADMIN_USER_UPDATE",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "User",
        targetId: u.id,
        outcome: "SUCCESS",
        metadata: body,
      });
      return res.json({ user: summary(u) });
    } catch (e) {
      next(e);
    }
  });
  return r;
}
