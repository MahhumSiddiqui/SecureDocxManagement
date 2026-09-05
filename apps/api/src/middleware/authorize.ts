import type { RequestHandler } from "express";
import { MATRIX, type Action } from "../permissions.matrix.js";
import { AppError } from "./errors.js";
import { recordAudit } from "../services/audit.service.js";

export const authorizationMiddlewareName = "authorize";

export function authorize(action: Action): RequestHandler {
  const middleware: RequestHandler = async (req, _res, next) => {
    const user = req.user;
    if (!user || !MATRIX[user.role].includes(action)) {
      if (user)
        await recordAudit({
          eventType: "ACCESS_DENIED",
          actorId: user.id,
          actorEmail: user.email,
          targetType: "route",
          targetId: req.path,
          outcome: "DENIED",
          ipAddress: req.ip,
        });
      return next(
        new AppError(
          403,
          "FORBIDDEN",
          "You do not have access to this resource.",
        ),
      );
    }
    next();
  };
  Object.defineProperty(middleware, "name", { value: authorizationMiddlewareName });
  return middleware;
}
