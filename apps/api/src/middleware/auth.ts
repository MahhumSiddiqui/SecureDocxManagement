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
