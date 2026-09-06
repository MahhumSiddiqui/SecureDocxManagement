import {
  Router,
  type NextFunction,
  type Request,
  type Response,
} from "express";
import argon2 from "argon2";
import { z } from "zod";
import { prisma } from "../../../db.js";
import { config } from "../../../config.js";
import { AppError } from "../../../middleware/errors.js";
import { authenticate } from "../../../middleware/auth.js";
import {
  randomToken,
  sha256,
  decryptBuffer,
} from "../../../services/crypto.service.js";
import { readBlob } from "../../../services/storage.service.js";
import { recordAudit } from "../../../services/audit.service.js";
import { toShareLinkSummary } from "../../../serializers.js";

const tokenSchema = z.string().regex(/^[A-Za-z0-9_-]{40,50}$/);
// Vulnerable-mode tokens are short and time-derived, so the strict
// length check would reject them before lookup.
const looseTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{4,60}$/);
const uuidSchema = z.string().uuid();

// ----------------------------------------------------------
// [VULN-05] Insecure Share Tokens — CWE-330 / CWE-613 — OWASP A02:2021
//
// Active ONLY when SECURE_MODE=false.
//
// Root cause, three parts:
//   1. Tokens are derived from the current time plus an in-process
//      counter, so an attacker who knows roughly when a link was
//      created can enumerate the small remaining keyspace.
//   2. The raw token is stored in the database instead of a hash,
//      so read access to the table yields working links for every
//      shared document.
//   3. Expiry, revocation and single-use are not enforced on lookup,
//      so a link works forever and revoking it has no effect.
//
// Secure behaviour: 32 bytes from crypto.randomBytes (256 bits of
// entropy), persisted only as a SHA-256 hash, shown to the creator
// exactly once, and checked against expiry, revocation and use count
// on every access.
// ----------------------------------------------------------
let vulnerableTokenCounter = 0;

function shareToken(): string {
  if (!config.secureMode) {
    // VULNERABLE: predictable, time-derived, sequential.
    return Date.now().toString(36) + (vulnerableTokenCounter++).toString(36);
  }
  return randomToken();
}

function storedToken(token: string): string {
  // VULNERABLE: raw token persisted instead of its hash.
  return config.secureMode ? sha256(token) : token;
}

function unavailable(): AppError {
  return new AppError(404, "NOT_FOUND", "This link is not available.");
}

function parseUuid(value: string | string[]): string {
  const parsed = uuidSchema.safeParse(value);
  if (!parsed.success) {
    throw unavailable();
  }
  return parsed.data;
}

function parseToken(value: string | string[]): string {
  const schema = config.secureMode ? tokenSchema : looseTokenSchema;
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw unavailable();
  }
  return parsed.data;
}

async function requireOwner(documentId: string, userId: string) {
  const document = await prisma.document.findUnique({
    where: { id: documentId },
  });
  if (!document || document.ownerId !== userId) {
    throw new AppError(
      403,
      "FORBIDDEN",
      "You do not have access to this resource.",
    );
  }
  return document;
}

async function resolveToken(token: string) {
  const shareLink = await prisma.shareLink.findUnique({
    where: { tokenHash: storedToken(token) },
    include: { document: true },
  });
  if (!shareLink) {
    throw unavailable();
  }

  // VULNERABLE: no expiry, revocation or single-use enforcement.
  if (!config.secureMode) {
    return shareLink;
  }

  if (
    shareLink.revokedAt ||
    !shareLink.expiresAt ||
    shareLink.expiresAt <= new Date() ||
    (shareLink.singleUse && shareLink.useCount > 0) ||
    shareLink.document.isDeleted
  ) {
    throw unavailable();
  }
  return shareLink;
}

async function createShare(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const documentId = parseUuid(req.params.id);
    await requireOwner(documentId, req.user!.id);
    const body = z
      .object({
        expiresInHours: z.number().int().min(1).max(720),
        canDownload: z.boolean(),
        singleUse: z.boolean(),
        password: z.string().min(12).optional(),
      })
      .parse({
        ...req.body,
        password: req.body.password === "" ? undefined : req.body.password,
      });
    const token = shareToken();
    const shareLink = await prisma.shareLink.create({
      data: {
        tokenHash: storedToken(token),
        documentId,
        createdById: req.user!.id,
        expiresAt: new Date(Date.now() + body.expiresInHours * 3_600_000),
        canDownload: body.canDownload,
        singleUse: body.singleUse,
        passwordHash: body.password
          ? await argon2.hash(body.password, {
              type: argon2.argon2id,
              memoryCost: 19456,
              timeCost: 2,
              parallelism: 1,
            })
          : null,
      },
    });
    await recordAudit({
      eventType: "SHARE_CREATE",
      actorId: req.user!.id,
      actorEmail: req.user!.email,
      targetType: "ShareLink",
      targetId: shareLink.id,
      outcome: "SUCCESS",
    });
    res.status(201).json({
      shareLink: toShareLinkSummary(shareLink),
      url: `/share/${token}`,
      token,
    });
  } catch (error) {
    next(error);
  }
}

async function listShares(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const documentId = parseUuid(req.params.id);
    await requireOwner(documentId, req.user!.id);
    const shareLinks = await prisma.shareLink.findMany({
      where: { documentId },
    });
    res.json({ shareLinks: shareLinks.map(toShareLinkSummary) });
  } catch (error) {
    next(error);
  }
}

async function revokeShare(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const shareLinkId = parseUuid(req.params.shareLinkId);
    const shareLink = await prisma.shareLink.findUnique({
      where: { id: shareLinkId },
    });
    if (!shareLink) {
      throw new AppError(
        404,
        "NOT_FOUND",
        "The requested resource was not found.",
      );
    }
    await requireOwner(shareLink.documentId, req.user!.id);
    await prisma.shareLink.update({
      where: { id: shareLink.id },
      data: { revokedAt: new Date() },
    });
    await recordAudit({
      eventType: "SHARE_REVOKE",
      actorId: req.user!.id,
      actorEmail: req.user!.email,
      targetType: "ShareLink",
      targetId: shareLink.id,
      outcome: "SUCCESS",
    });
    res.status(204).send();
  } catch (error) {
    next(error);
  }
}

async function inspectPublicShare(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const token = parseToken(req.params.token);
    const shareLink = await resolveToken(token);
    res.json({
      document: {
        title: shareLink.document.title,
        originalName: shareLink.document.originalName,
        mimeType: shareLink.document.mimeType,
        sizeBytes: shareLink.document.sizeBytes,
      },
      requiresPassword: Boolean(shareLink.passwordHash),
    });
  } catch (error) {
    next(error);
  }
}

async function downloadPublicShare(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  let token: string | undefined;
  try {
    token = parseToken(req.params.token);
    const shareLink = await resolveToken(token);
    if (!shareLink.canDownload) {
      throw unavailable();
    }
    if (
      shareLink.passwordHash &&
      !(
        typeof req.body?.password === "string" &&
        (await argon2.verify(shareLink.passwordHash, req.body.password))
      )
    ) {
      throw unavailable();
    }
    const key = await prisma.documentKey.findUnique({
      where: { documentId: shareLink.documentId },
    });
    const blob = await readBlob(shareLink.document.storageKey);
    // Documents uploaded while SECURE_MODE=false are stored in plaintext
    // and have no DocumentKey row, so there is nothing to decrypt.
    let plaintext: Buffer;
    if (key) {
      plaintext = decryptBuffer(blob, key);
    } else if (!config.secureMode) {
      plaintext = blob;
    } else {
      throw new AppError(500, "INTERNAL", "An internal error occurred.");
    }
    await prisma.shareLink.update({
      where: { id: shareLink.id },
      data: { useCount: { increment: 1 } },
    });
    await recordAudit({
      eventType: "SHARE_ACCESS",
      targetType: "ShareLink",
      targetId: shareLink.id,
      outcome: "SUCCESS",
    });
    res.setHeader("Content-Type", shareLink.document.mimeType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${shareLink.document.originalName.replace(/[\\/"\u0000-\u001f]/g, "_").slice(0, 100)}"`,
    );
    res.send(plaintext);
  } catch (error) {
    if (error instanceof AppError) {
      await recordAudit({
        eventType: "SHARE_ACCESS_FAILED",
        targetType: "ShareLink",
        targetId: token ? sha256(token) : null,
        outcome: "FAILURE",
      });
    }
    next(error);
  }
}

export function router(): Router {
  const router = Router();
  router.post("/documents/:id/share", authenticate, createShare);
  router.get("/documents/:id/share", authenticate, listShares);
  router.delete("/share/:shareLinkId", authenticate, revokeShare);
  router.get("/share/:token", inspectPublicShare);
  router.post("/share/:token/download", downloadPublicShare);
  return router;
}