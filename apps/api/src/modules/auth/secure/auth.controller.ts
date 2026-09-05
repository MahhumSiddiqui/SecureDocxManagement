import { randomUUID } from "node:crypto";
import type { Response, Router } from "express";
import { Router as ExpressRouter } from "express";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { prisma } from "../../../db.js";
import { config } from "../../../config.js";
import { randomToken, sha256 } from "../../../services/crypto.service.js";
import { recordAudit } from "../../../services/audit.service.js";
import { AppError } from "../../../middleware/errors.js";

const dummyHash =
  "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const common = new Set([
  "passwordpassword",
  "password123456",
  "123456789012",
  "qwertyuiop12",
  "letmein123456",
  "welcome123456",
  "Passw0rd!Demo".toLowerCase(),
]);
const userSummary = (u: {
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
async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });
}
function accessToken(user: {
  id: string;
  email: string;
  role: string;
}): string {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role, jti: randomUUID() },
    config.JWT_SECRET,
    { algorithm: "HS256", expiresIn: "15m" },
  );
}
function setSessionCookies(res: Response, refresh: string, csrf: string): void {
  res.cookie("sd_refresh", refresh, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/api/auth",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.cookie("sd_csrf", csrf, {
    httpOnly: false,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}
export function router(): Router {
  const r = ExpressRouter();
  r.post("/register", async (req, res, next) => {
    try {
      const body = z
        .object({
          email: z.string().email(),
          displayName: z.string().min(1).max(100),
          password: z.string().min(12),
        })
        .parse(req.body);
      if (common.has(body.password.toLowerCase()))
        throw new AppError(400, "VALIDATION_ERROR", "Password is too common.");
      const email = body.email.toLowerCase();
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing) {
        await recordAudit({
          eventType: "AUTH_REGISTER",
          actorEmail: email,
          outcome: "FAILURE",
          metadata: { collision: true },
        });
        return res.status(201).json({ user: userSummary(existing) });
      }
      const user = await prisma.user.create({
        data: {
          email,
          displayName: body.displayName,
          passwordHash: await hashPassword(body.password),
        },
      });
      await recordAudit({
        eventType: "AUTH_REGISTER",
        actorId: user.id,
        actorEmail: user.email,
        outcome: "SUCCESS",
      });
      return res.status(201).json({ user: userSummary(user) });
    } catch (e) {
      next(e);
    }
  });
  r.post("/login", async (req, res, next) => {
    const email =
      typeof req.body?.email === "string" ? req.body.email.toLowerCase() : "";
    const password =
      typeof req.body?.password === "string" ? req.body.password : "";
    try {
      const user = await prisma.user.findUnique({ where: { email } });
      const hash = user?.passwordHash ?? dummyHash;
      const valid = await argon2.verify(hash, password).catch(() => false);
      const recent = await prisma.loginAttempt.count({
        where: {
          email,
          success: false,
          createdAt: { gte: new Date(Date.now() - 15 * 60_000) },
        },
      });
      const locked = !!user?.lockedUntil && user.lockedUntil > new Date();
      if (
        !user ||
        !valid ||
        locked ||
        user.status !== "ACTIVE" ||
        recent >= 5
      ) {
        await prisma.loginAttempt.create({
          data: { email, ipAddress: req.ip, success: false },
        });
        await recordAudit({
          eventType: locked ? "AUTH_LOCKOUT" : "AUTH_LOGIN_FAILED",
          actorId: user?.id,
          actorEmail: email,
          outcome: "FAILURE",
          ipAddress: req.ip,
        });
        if (user && recent + 1 >= 5 && !locked)
          await prisma.user.update({
            where: { id: user.id },
            data: {
              lockedUntil: new Date(Date.now() + 15 * 60_000),
              failedAttempts: recent + 1,
            },
          });
        throw new AppError(
          401,
          "UNAUTHENTICATED",
          "Invalid email or password.",
        );
      }
      await prisma.loginAttempt.create({
        data: { email, ipAddress: req.ip, success: true },
      });
      const refresh = randomToken(),
        csrf = randomToken(),
        familyId = randomUUID();
      await prisma.refreshToken.create({
        data: {
          tokenHash: sha256(refresh),
          userId: user.id,
          familyId,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60_000),
        },
      });
      const updated = await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date(), failedAttempts: 0, lockedUntil: null },
      });
      await recordAudit({
        eventType: "AUTH_LOGIN",
        actorId: user.id,
        actorEmail: user.email,
        outcome: "SUCCESS",
        ipAddress: req.ip,
      });
      setSessionCookies(res, refresh, csrf);
      return res.json({
        accessToken: accessToken(updated),
        user: userSummary(updated),
      });
    } catch (e) {
      next(e);
    }
  });
  r.post("/refresh", async (req, res, next) => {
    try {
      const raw = req.cookies?.sd_refresh as string | undefined;
      if (!raw)
        throw new AppError(
          401,
          "UNAUTHENTICATED",
          "Authentication is required.",
        );
      const token = await prisma.refreshToken.findUnique({
        where: { tokenHash: sha256(raw) },
        include: { user: true },
      });
      if (!token || token.expiresAt < new Date() || token.revokedAt) {
        if (token?.revokedAt) {
          await prisma.refreshToken.updateMany({
            where: { familyId: token.familyId },
            data: { revokedAt: new Date() },
          });
          await recordAudit({
            eventType: "AUTH_REFRESH_REUSE",
            actorId: token.userId,
            actorEmail: token.user.email,
            outcome: "DENIED",
          });
        }
        throw new AppError(
          401,
          "UNAUTHENTICATED",
          "Authentication is required.",
        );
      }
      const nextRaw = randomToken();
      await prisma.$transaction([
        prisma.refreshToken.update({
          where: { id: token.id },
          data: { revokedAt: new Date() },
        }),
        prisma.refreshToken.create({
          data: {
            tokenHash: sha256(nextRaw),
            userId: token.userId,
            familyId: token.familyId,
            expiresAt: token.expiresAt,
          },
        }),
      ]);
      setSessionCookies(res, nextRaw, randomToken());
      await recordAudit({
        eventType: "AUTH_REFRESH",
        actorId: token.userId,
        actorEmail: token.user.email,
        outcome: "SUCCESS",
      });
      return res.json({ accessToken: accessToken(token.user) });
    } catch (e) {
      next(e);
    }
  });
  r.post("/logout", async (req, res, next) => {
    try {
      const raw = req.cookies?.sd_refresh as string | undefined;
      if (raw) {
        const token = await prisma.refreshToken.findUnique({
          where: { tokenHash: sha256(raw) },
        });
        if (token) {
          await prisma.refreshToken.updateMany({
            where: { familyId: token.familyId },
            data: { revokedAt: new Date() },
          });
          await recordAudit({
            eventType: "AUTH_LOGOUT",
            actorId: token.userId,
            outcome: "SUCCESS",
          });
        }
      }
      res.clearCookie("sd_refresh", { path: "/api/auth" });
      res.clearCookie("sd_csrf", { path: "/" });
      return res.status(204).send();
    } catch (e) {
      next(e);
    }
  });
  r.get("/me", async (req, res, next) => {
    try {
      if (!req.user)
        throw new AppError(
          401,
          "UNAUTHENTICATED",
          "Authentication is required.",
        );
      return res.json({ user: userSummary(req.user) });
    } catch (e) {
      next(e);
    }
  });
  return r;
}
