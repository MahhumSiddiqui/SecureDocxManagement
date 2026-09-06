// ============================================================
// VULNERABLE MODE — apps/api/src/modules/documents/vulnerable
//
// Deliberately insecure implementations for coursework comparison.
// Active ONLY when SECURE_MODE=false. Localhost, synthetic data only.
//
// [VULN-01] Unrestricted File Upload   — CWE-434 — OWASP A04:2021
// [VULN-02] Insecure Direct Object Ref — CWE-639 — OWASP A01:2021
//
// Secure versions: ../secure/documents.controller.ts
//                  ../secure/upload.pipeline.ts
// ============================================================

import { Router } from "express";
import multer from "multer";
import path from "node:path";
import { prisma } from "../../../db.js";
import { AppError } from "../../../middleware/errors.js";
import { recordAudit } from "../../../services/audit.service.js";
import { sha256 } from "../../../services/crypto.service.js";
import { writeBlob, readBlob } from "../../../services/storage.service.js";
import { toDocumentDetail } from "../../../serializers.js";
import { router as secureRouter } from "../secure/documents.controller.js";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024, files: 1 },
});

export function router(): Router {
  const r = Router();

  // ----------------------------------------------------------
  // [VULN-01] Unrestricted File Upload — CWE-434
  //
  // Root cause: the file type is decided from client-supplied data.
  //   - no extension allow-list
  //   - trusts the client's Content-Type header instead of magic bytes
  //   - keeps the original filename as the storage key
  //   - no malware scan
  //   - stores plaintext (no envelope encryption)
  //
  // Secure version: ../secure/upload.pipeline.ts validates extension,
  // verifies magic bytes, scans, then encrypts under a per-file DEK.
  // ----------------------------------------------------------
  r.post("/", upload.single("file"), async (req, res, next) => {
    try {
      if (!req.file) {
        throw new AppError(400, "VALIDATION_ERROR", "A file is required.");
      }

      // VULNERABLE: original filename used directly as the storage key.
      const storageKey = path.basename(req.file.originalname);

      // VULNERABLE: plaintext written to disk — no encryption, no DocumentKey row.
      await writeBlob(storageKey, req.file.buffer);

      const doc = await prisma.document.create({
        data: {
          title: (req.body.title as string) || req.file.originalname,
          description: (req.body.description as string) || "",
          category: (req.body.category as string) || "General",
          originalName: req.file.originalname,
          // VULNERABLE: trusts the client-supplied Content-Type header.
          mimeType: req.file.mimetype,
          sizeBytes: req.file.size,
          storageKey,
          sha256: sha256(req.file.buffer),
          ownerId: req.user!.id,
          scanVerdict: "SKIPPED",
        },
        include: { owner: true },
      });

      await recordAudit({
        eventType: "DOC_UPLOAD",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "Document",
        targetId: doc.id,
        outcome: "SUCCESS",
      });

      return res.status(201).json({ document: toDocumentDetail(doc, "OWNER") });
    } catch (e) {
      next(e);
    }
  });

  // ----------------------------------------------------------
  // [VULN-02] Insecure Direct Object Reference — CWE-639
  //
  // Root cause: authentication is checked, authorisation is not.
  //   - accepts the sequential integer legacyId
  //   - verifies only that a session exists
  //   - no ownership check, no ACL lookup
  //
  // Any authenticated user reads any document by incrementing the id.
  //
  // Secure version: ../secure/documents.controller.ts findAccess(),
  // which requires ownership or an unexpired DocumentPermission grant.
  // ----------------------------------------------------------
  r.get("/legacy/:legacyId/download", async (req, res, next) => {
    try {
      const legacyId = Number(req.params.legacyId);
      if (!Number.isInteger(legacyId)) {
        throw new AppError(400, "VALIDATION_ERROR", "Invalid identifier.");
      }

      // VULNERABLE: no ownership or permission check whatsoever.
      const doc = await prisma.document.findFirst({
        where: { legacyId, isDeleted: false },
      });
      if (!doc) {
        throw new AppError(404, "NOT_FOUND", "Document not found.");
      }

      const bytes = await readBlob(doc.storageKey);

      await recordAudit({
        eventType: "DOC_DOWNLOAD",
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        targetType: "Document",
        targetId: doc.id,
        outcome: "SUCCESS",
      });

      res.setHeader("Content-Type", doc.mimeType);
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${doc.originalName}"`,
      );
      return res.send(bytes);
    } catch (e) {
      next(e);
    }
  });

  // All other document routes reuse the secure implementation, so the
  // only behavioural difference between modes is the vulnerability itself.
  r.use(secureRouter());

  return r;
}