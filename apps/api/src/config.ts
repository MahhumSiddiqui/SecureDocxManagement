import path from "node:path";
import { z } from "zod";

const schema = z.object({
  DATABASE_URL: z.string().min(1),
  PORT: z.coerce.number().default(3000),
  NODE_ENV: z.string().default("development"),
  SECURE_MODE: z.enum(["true", "false"]).default("true"),
  JWT_SECRET: z.string().min(32),
  KEK_MASTER: z.string().regex(/^[0-9a-fA-F]{64}$/),
  STORAGE_PATH: z.string().default("./storage/blobs"),
  MAX_UPLOAD_BYTES: z.coerce.number().default(26214400),
  WEB_ORIGIN: z.string().url(),
});
const env = schema.parse(process.env);
export const config = {
  ...env,
  secureMode: env.SECURE_MODE === "true",
  storagePath: path.resolve(env.STORAGE_PATH),
  host: "127.0.0.1",
};
