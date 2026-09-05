import { timingSafeEqual } from "node:crypto";
import type { RequestHandler } from "express";
import { AppError } from "./errors.js";
const methods = new Set(["POST", "PATCH", "DELETE", "PUT"]);
export const csrf: RequestHandler = (req, _res, next) => {
  if (
    !methods.has(req.method) ||
    req.path === "/api/auth/login" ||
    req.path === "/api/auth/register" ||
    req.path.startsWith("/share/") ||
    req.path.startsWith("/api/share/")
  )
    return next();
  const cookie = req.cookies?.sd_csrf as string | undefined;
  const header = req.header("X-CSRF-Token");
  if (
    !cookie ||
    !header ||
    cookie.length !== header.length ||
    !timingSafeEqual(Buffer.from(cookie), Buffer.from(header))
  )
    return next(new AppError(403, "FORBIDDEN", "CSRF validation failed."));
  next();
};
