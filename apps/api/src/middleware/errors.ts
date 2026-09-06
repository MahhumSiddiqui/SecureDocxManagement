import type { ErrorRequestHandler, RequestHandler } from "express";
import { ZodError } from "zod";
import { logger } from "../services/logger.js";
export class AppError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}
export const notFound: RequestHandler = (_req, _res, next) =>
  next(new AppError(404, "NOT_FOUND", "The requested resource was not found."));
export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  logger.error({ err }, "request failed");
  const app =
    err instanceof AppError
      ? err
      : err instanceof ZodError
        ? new AppError(
            400,
            "VALIDATION_ERROR",
            err.issues
              .map(
                (issue) =>
                  `${issue.path.join(".") || "request"}: ${issue.message}`,
              )
              .join("; "),
          )
        : new AppError(500, "INTERNAL", "An internal error occurred.");
  res.status(app.status).json({
    error: {
      code: app.code,
      message:
        process.env.NODE_ENV === "production" && app.status === 500
          ? "An internal error occurred."
          : app.message,
    },
  });
};
