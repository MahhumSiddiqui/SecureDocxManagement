import type { Role, User } from "@prisma/client";

declare global {
  namespace Express {
    interface Request {
      user?: User;
      auth?: { id: string; email: string; role: Role; jti: string };
    }
  }
}
export {};
