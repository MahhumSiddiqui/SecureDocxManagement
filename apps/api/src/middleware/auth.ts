import type { RequestHandler } from "express";
import jwt from "jsonwebtoken";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { AppError } from "./errors.js";

export const authenticate: RequestHandler = async (req, _res, next) => {
  try {
    const raw = req.headers.authorization?.replace(/^Bearer\s+/i, "");
    if (!raw)
      throw new AppError(401, "UNAUTHENTICATED", "Authentication is required.");
    const claims = jwt.verify(raw, config.JWT_SECRET, {
      algorithms: ["HS256"],
    }) as { sub: string; email: string; role: string; jti: string };
    const user = await prisma.user.findUnique({ where: { id: claims.sub } });
    if (!user || user.status !== "ACTIVE")
      throw new AppError(401, "UNAUTHENTICATED", "Authentication is required.");

    // ----------------------------------------------------------
    // [VULN-03] Broken Access Control — CWE-285 — OWASP A01:2021
    //
    // Active ONLY when SECURE_MODE=false.
    //
    // Root cause: the caller's role is taken from a client-supplied
    // request header instead of the verified database record. Any
    // authenticated user can escalate to ADMINISTRATOR or AUDITOR by
    // sending X-User-Role, because the header is trusted without
    // verification.
    //
    // Secure behaviour (below): the role is read from the User row
    // loaded by primary key from the verified JWT subject, so the
    // client cannot influence it at all.
    // ----------------------------------------------------------
    if (!config.secureMode) {
      const claimedRole = req.headers["x-user-role"];
      if (typeof claimedRole === "string" && claimedRole.length > 0) {
        // VULNERABLE: client-controlled role, no verification.
        req.user = { ...user, role: claimedRole as typeof user.role };
        req.auth = {
          id: user.id,
          email: user.email,
          role: claimedRole as typeof user.role,
          jti: claims.jti,
        };
        return next();
      }
    }

    req.user = user;
    req.auth = {
      id: user.id,
      email: user.email,
      role: user.role,
      jti: claims.jti,
    };
    next();
  } catch (error) {
    next(
      error instanceof AppError
        ? error
        : new AppError(401, "UNAUTHENTICATED", "Authentication is required."),
    );
  }
};