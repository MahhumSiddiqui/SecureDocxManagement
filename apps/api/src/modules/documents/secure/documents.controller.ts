import { Router } from "express";
import multer from "multer";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Prisma } from "@prisma/client";
import { prisma } from "../../../db.js";
import { AppError } from "../../../middleware/errors.js";
import { recordAudit } from "../../../services/audit.service.js";
import { encryptBuffer, sha256 } from "../../../services/crypto.service.js";
import {
  writeBlob,
  readBlob,
  deleteBlob,
} from "../../../services/storage.service.js";
import { decryptBuffer } from "../../../services/crypto.service.js";
import { validateUpload, safeFilename } from "./upload.pipeline.js";
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024, files: 1 },
});
const summary = (
  d: {
    id: string;
    title: string;
    category: string;
    originalName: string;
    mimeType: string;
    sizeBytes: number;
    ownerId: string;
    sha256: string;
    createdAt: Date;
    owner: { email: string };
  },
  accessLevel: "OWNER" | "SHARED",
) => ({ ...d, ownerEmail: d.owner.email, accessLevel });
async function findAccess(
  id: string,
  userId: string,
  needed: "view" | "download" | "reshare" = "view",
) {
  const d = await prisma.document.findFirst({
    where: { id, isDeleted: false },
    include: { owner: true, key: true },
  });
  if (!d)
    throw new AppError(
      403,
      "FORBIDDEN",
      "You do not have access to this document.",
    );
  if (d.ownerId === userId) return { d, level: "OWNER" as const };
  const p = await prisma.documentPermission.findFirst({
    where: {
      documentId: id,
      granteeId: userId,
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
    },
    include: { grantee: true },
  });
  if (
    !p ||
    (needed === "view" && !p.canView) ||
    (needed === "download" && !p.canDownload) ||
    (needed === "reshare" && !p.canReshare)
  )
    throw new AppError(
      403,
      "FORBIDDEN",
      "You do not have access to this document.",
    );
  return { d, level: "SHARED" as const };
}
export function router(): Router {
  const r = Router();
  r.get("/", async (req, res, next) => {
    try {
      const user = req.user!;
      const page = Math.max(1, Number(req.query.page ?? 1)),
        pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize ?? 20)));
      const search =
        typeof req.query.search === "string" ? req.query.search : undefined;
      const scope = String(req.query.scope ?? "all");
      const own: Prisma.DocumentWhereInput = { ownerId: user.id };
      const shared: Prisma.DocumentWhereInput = {
        permissions: {
          some: {
            granteeId: user.id,
            OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
          },
        },
      };
      const where: Prisma.DocumentWhereInput = {
        isDeleted: false,
        ...(scope === "owned"
          ? own
          : scope === "shared"
            ? shared
            : { OR: [own, shared] }),
        ...(search
          ? {
              OR: [
                { title: { contains: search, mode: "insensitive" } },
                { originalName: { contains: search, mode: "insensitive" } },
              ],
            }
          : {}),
        ...(req.query.category ? { category: String(req.query.category) } : {}),
      };
      const sortBy = ["createdAt", "title", "sizeBytes"].includes(
        String(req.query.sortBy),
      )
        ? String(req.query.sortBy)
        : "createdAt";
      const [items, total] = await prisma.$transaction([
        prisma.document.findMany({
          where,
          include: { owner: true },
          orderBy: {
            [sortBy]:
              String(req.query.sortDir ?? "desc") === "asc" ? "asc" : "desc",
          },
          skip: (page - 1) * pageSize,
          take: pageSize,
        }),
        prisma.document.count({ where }),
      ]);
      return res.json({
        items: items.map((d) =>
          summary(d, d.ownerId === user.id ? "OWNER" : "SHARED"),
        ),
        page,
        pageSize,
        total,
      });
    } catch (e) {
      next(e);
    }
  });
  r.post("/", upload.single("file"), async (req, res, next) => {
    try {
      if (!req.file)
        throw new AppError(400, "VALIDATION_ERROR", "A file is required.");
      const check = await validateUpload(req.file);
      const encrypted = encryptBuffer(req.file.buffer);
      const storageKey = randomUUID();
      await writeBlob(storageKey, encrypted.ciphertext);
      try {
        const d = await prisma.document.create({
          data: {
            title: String(req.body.title ?? req.file.originalname),
            description: String(req.body.description ?? ""),
            category: String(req.body.category ?? "General"),
            originalName: req.file.originalname,
            mimeType: check.mimeType,
            sizeBytes: req.file.size,
            storageKey,
            sha256: encrypted.sha256,
            ownerId: req.user!.id,
            scanVerdict: "CLEAN",
            key: {
              create: {
                wrappedDek: encrypted.wrappedDek,
                iv: encrypted.iv,
                authTag: encrypted.authTag,
                wrapIv: encrypted.wrapIv,
                wrapTag: encrypted.wrapTag,
              },
            },
          },
          include: { owner: true },
        });
        await recordAudit({
          eventType: "DOC_UPLOAD",
          actorId: req.user!.id,
          actorEmail: req.user!.email,
          targetType: "Document",
          targetId: d.id,
          outcome: "SUCCESS",
        });
        return res
          .status(201)
          .json({
            document: {
              ...summary(d, "OWNER"),
              description: d.description,
              scanVerdict: d.scanVerdict,
              updatedAt: d.updatedAt,
            },
          });
      } catch (e) {
        await deleteBlob(storageKey);
        throw e;
      }
    } catch (e) {
      if (e instanceof AppError)
        await recordAudit({
          eventType: "DOC_UPLOAD_REJECTED",
          actorId: req.user?.id,
          actorEmail: req.user?.email,
          outcome: "FAILURE",
        });
      next(e);
    }
  });
  r.get("/:id", async (req, res, next) => {
    try {
      const { d, level } = await findAccess(req.params.id, req.user!.id);
      const owner =
        d.ownerId === req.user!.id || req.user!.role === "ADMINISTRATOR";
      const permissions = owner
        ? await prisma.documentPermission.findMany({
            where: { documentId: d.id },
            include: { grantee: true, grantedBy: true },
          })
        : [];
      const shareLinks = owner
        ? await prisma.shareLink.findMany({ where: { documentId: d.id } })
        : [];
      await recordAudit({
        eventType: "DOC_VIEW",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "Document",
        targetId: d.id,
        outcome: "SUCCESS",
      });
      return res.json({
        document: {
          ...summary(d, level),
          description: d.description,
          scanVerdict: d.scanVerdict,
          updatedAt: d.updatedAt,
        },
        permissions: permissions.map((p) => ({
          id: p.id,
          documentId: p.documentId,
          granteeId: p.granteeId,
          granteeEmail: p.grantee.email,
          granteeName: p.grantee.displayName,
          canView: p.canView,
          canDownload: p.canDownload,
          canReshare: p.canReshare,
          grantedByEmail: p.grantedBy.email,
          grantedAt: p.grantedAt,
          expiresAt: p.expiresAt,
        })),
        shareLinks: shareLinks.map((s) => ({
          id: s.id,
          documentId: s.documentId,
          canDownload: s.canDownload,
          hasPassword: !!s.passwordHash,
          expiresAt: s.expiresAt,
          singleUse: s.singleUse,
          useCount: s.useCount,
          revokedAt: s.revokedAt,
          createdAt: s.createdAt,
        })),
      });
    } catch (e) {
      next(e);
    }
  });
  r.get("/:id/download", async (req, res, next) => {
    try {
      const { d } = await findAccess(req.params.id, req.user!.id, "download");
      const blob = await readBlob(d.storageKey);
      const plain = decryptBuffer(blob, d.key!);
      if (sha256(plain) !== d.sha256) throw new Error("integrity");
      await recordAudit({
        eventType: "DOC_DOWNLOAD",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "Document",
        targetId: d.id,
        outcome: "SUCCESS",
      });
      res.setHeader("Content-Type", d.mimeType);
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${safeFilename(d.originalName)}"`,
      );
      return res.send(plain);
    } catch (e) {
      if (e instanceof Error && e.message === "integrity")
        await recordAudit({
          eventType: "DOC_INTEGRITY_FAILURE",
          actorId: req.user?.id,
          actorEmail: req.user?.email,
          targetType: "Document",
          targetId: req.params.id,
          outcome: "FAILURE",
        });
      next(
        e instanceof Error && e.message === "integrity"
          ? new AppError(500, "INTERNAL", "An internal error occurred.")
          : e,
      );
    }
  });
  r.patch("/:id", async (req, res, next) => {
    try {
      const { d } = await findAccess(req.params.id, req.user!.id);
      if (d.ownerId !== req.user!.id)
        throw new AppError(
          403,
          "FORBIDDEN",
          "You do not have access to this resource.",
        );
      const body = z
        .object({
          title: z.string().optional(),
          description: z.string().optional(),
          category: z.string().optional(),
        })
        .parse(req.body);
      const updated = await prisma.document.update({
        where: { id: d.id },
        data: body,
        include: { owner: true },
      });
      await recordAudit({
        eventType: "DOC_UPDATE",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "Document",
        targetId: d.id,
        outcome: "SUCCESS",
      });
      return res.json({
        document: {
          ...summary(updated, "OWNER"),
          description: updated.description,
          scanVerdict: updated.scanVerdict,
          updatedAt: updated.updatedAt,
        },
      });
    } catch (e) {
      next(e);
    }
  });
  r.delete("/:id", async (req, res, next) => {
    try {
      const { d } = await findAccess(req.params.id, req.user!.id);
      if (d.ownerId !== req.user!.id)
        throw new AppError(
          403,
          "FORBIDDEN",
          "You do not have access to this resource.",
        );
      await prisma.document.update({
        where: { id: d.id },
        data: { isDeleted: true, deletedAt: new Date() },
      });
      await recordAudit({
        eventType: "DOC_DELETE",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "Document",
        targetId: d.id,
        outcome: "SUCCESS",
      });
      return res.status(204).send();
    } catch (e) {
      next(e);
    }
  });
  r.delete("/:id/permanent", async (req, res, next) => {
    try {
      const d = await prisma.document.findUnique({
        where: { id: req.params.id },
      });
      if (
        !d ||
        (d.ownerId !== req.user!.id && req.user!.role !== "ADMINISTRATOR")
      )
        throw new AppError(
          403,
          "FORBIDDEN",
          "You do not have access to this resource.",
        );
      await prisma.documentKey.deleteMany({ where: { documentId: d.id } });
      await deleteBlob(d.storageKey);
      await prisma.document.delete({ where: { id: d.id } });
      await recordAudit({
        eventType: "DOC_PURGE",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "Document",
        targetId: d.id,
        outcome: "SUCCESS",
      });
      return res.status(204).send();
    } catch (e) {
      next(e);
    }
  });
  return r;
}
