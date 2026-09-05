import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import cors from "cors";
import { config } from "./config.js";
import { authController } from "./modules/auth/index.js";
import { documentsController } from "./modules/documents/index.js";
import { permissionsController } from "./modules/permissions/index.js";
import { shareController } from "./modules/share/index.js";
import { auditController } from "./modules/audit/index.js";
import { adminController } from "./modules/admin/index.js";
import { authenticate } from "./middleware/auth.js";
import { authorize } from "./middleware/authorize.js";
import { csrf } from "./middleware/csrf.js";
import {
  globalLimit,
  loginLimit,
  registerLimit,
  shareLimit,
} from "./middleware/rateLimit.js";
import { errorHandler, notFound } from "./middleware/errors.js";

const publicRoutes = new Set([
  "/auth/login",
  "/auth/register",
  "/auth/refresh",
  "/share/:token",
  "/share/:token/download",
  "/health",
]);

type StackLayer = {
  name?: string;
  route?: { path?: string | string[] };
  handle?: { stack?: StackLayer[] };
};

function flattenStack(stack: StackLayer[], result: StackLayer[] = []): StackLayer[] {
  for (const layer of stack) {
    result.push(layer);
    if (layer.handle?.stack) {
      flattenStack(layer.handle.stack, result);
    }
  }
  return result;
}

function assertAuthorizationStack(app: express.Application): void {
  const stack = (app as express.Application & { _router?: { stack: StackLayer[] } })._router?.stack ?? [];
  const layers = flattenStack(stack);
  const authorizationLayers = layers.filter((layer) => layer.name === "authorize");
  if (authorizationLayers.length < 3) {
    throw new Error("Authorization startup assertion failed: protected route groups are missing authorize middleware.");
  }
  for (const route of publicRoutes) {
    if (route !== "/health" && !route.startsWith("/auth/") && !route.startsWith("/share/")) {
      throw new Error(`Authorization startup assertion failed: invalid public route ${route}.`);
    }
  }
}

export function createApp() {
  const app = express();
  app.disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
        },
      },
    }),
  );
  app.use(cors({ origin: config.WEB_ORIGIN, credentials: true }));
  app.use(globalLimit);
  app.use(express.json({ limit: "1mb" }));
  app.use(cookieParser());
  app.use(csrf);
  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  app.use("/api/auth/register", registerLimit);
  app.use("/api/auth/login", loginLimit);
  app.use("/api/auth/me", authenticate);
  app.use("/api/auth/logout", authenticate);
  app.use("/api/auth", authController.router());
  app.use("/api/share", shareLimit);
  app.use("/api", shareController.router());
  app.use("/api", authenticate);
  app.use(
    "/api/documents",
    authorize("document:read"),
    documentsController.router(),
  );
  app.use(
    "/api/documents",
    authorize("permission:manage"),
    permissionsController.router(),
  );
  app.use("/api/audit", authorize("audit:read"), auditController.router());
  app.use("/api/admin", authorize("user:manage"), adminController.router());
  app.use(notFound);
  app.use(errorHandler);
  assertAuthorizationStack(app);
  return app;
}
if (process.env.NODE_ENV === "production" && !config.secureMode)
  throw new Error("Vulnerable mode is forbidden in production.");
if (!config.secureMode)
  console.error(
    "WARNING - VULNERABLE MODE ACTIVE\nThis build is for isolated localhost laboratory use only.",
  );
if (process.env.NODE_ENV !== "test")
  createApp().listen(config.PORT, config.host, () =>
    console.log(
      `SecureDocs API listening on http://${config.host}:${config.PORT}`,
    ),
  );
