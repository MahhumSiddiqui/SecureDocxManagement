import { Router } from "express";
import { z } from "zod";
import { prisma } from "../../../db.js";
import { AppError } from "../../../middleware/errors.js";
import { recordAudit } from "../../../services/audit.service.js";
import { toPermissionEntry } from "../../../serializers.js";
async function owner(id: string, userId: string) {
  const d = await prisma.document.findUnique({ where: { id } });
  if (!d || d.ownerId !== userId)
    throw new AppError(
      403,
      "FORBIDDEN",
      "You do not have access to this resource.",
    );
  return d;
}
export function router(): Router {
  const r = Router();
  r.get("/:id/permissions", async (req, res, next) => {
    try {
      await owner(req.params.id, req.user!.id);
      const rows = await prisma.documentPermission.findMany({
        where: { documentId: req.params.id },
        include: { grantee: true, grantedBy: true },
      });
      return res.json({ permissions: rows.map(toPermissionEntry) });
    } catch (e) {
      next(e);
    }
  });
  r.post("/:id/permissions", async (req, res, next) => {
    try {
      await owner(req.params.id, req.user!.id);
      const body = z
        .object({
          granteeEmail: z.string().email(),
          canView: z.boolean(),
          canDownload: z.boolean(),
          canReshare: z.boolean(),
          expiresAt: z.string().datetime().optional(),
        })
        .parse(req.body);
      const grantee = await prisma.user.findUnique({
        where: { email: body.granteeEmail.toLowerCase() },
      });
      if (!grantee)
        throw new AppError(
          404,
          "NOT_FOUND",
          "The requested user was not found.",
        );
      const p = await prisma.documentPermission.create({
        data: {
          documentId: req.params.id,
          granteeId: grantee.id,
          grantedById: req.user!.id,
          canView: body.canView,
          canDownload: body.canDownload,
          canReshare: body.canReshare,
          expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
        },
        include: { grantee: true, grantedBy: true },
      });
      await recordAudit({
        eventType: "PERM_GRANT",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "DocumentPermission",
        targetId: p.id,
        outcome: "SUCCESS",
      });
      return res.status(201).json({ permission: toPermissionEntry(p) });
    } catch (e) {
      next(e);
    }
  });
  r.patch("/:id/permissions/:permissionId", async (req, res, next) => {
    try {
      await owner(req.params.id, req.user!.id);
      const body = z
        .object({
          canView: z.boolean().optional(),
          canDownload: z.boolean().optional(),
          canReshare: z.boolean().optional(),
          expiresAt: z.string().datetime().nullable().optional(),
        })
        .parse(req.body);
      const p = await prisma.documentPermission.update({
        where: { id: req.params.permissionId, documentId: req.params.id },
        data: {
          ...body,
          expiresAt:
            body.expiresAt === undefined
              ? undefined
              : body.expiresAt
                ? new Date(body.expiresAt)
                : null,
        },
        include: { grantee: true, grantedBy: true },
      });
      await recordAudit({
        eventType: "PERM_UPDATE",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "DocumentPermission",
        targetId: p.id,
        outcome: "SUCCESS",
      });
      return res.json({ permission: toPermissionEntry(p) });
    } catch (e) {
      next(e);
    }
  });
  r.delete("/:id/permissions/:permissionId", async (req, res, next) => {
    try {
      await owner(req.params.id, req.user!.id);
      await prisma.documentPermission.delete({
        where: { id: req.params.permissionId, documentId: req.params.id },
      });
      await recordAudit({
        eventType: "PERM_REVOKE",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "DocumentPermission",
        targetId: req.params.permissionId,
        outcome: "SUCCESS",
      });
      return res.status(204).send();
    } catch (e) {
      next(e);
    }
  });
  return r;
}
