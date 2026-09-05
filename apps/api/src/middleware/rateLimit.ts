import rateLimit from "express-rate-limit";

const testBypass = () => process.env.NODE_ENV === "test";

export const globalLimit = rateLimit({
  windowMs: 60_000,
  limit: 100,
  skip: testBypass,
  standardHeaders: true,
  handler: (_req, res) =>
    res
      .status(429)
      .json({ error: { code: "RATE_LIMITED", message: "Too many requests." } }),
});
export const loginLimit = rateLimit({
  windowMs: 60_000,
  limit: 10,
  skip: testBypass,
});
export const registerLimit = rateLimit({
  windowMs: 60_000,
  limit: 5,
  skip: testBypass,
});
export const shareLimit = rateLimit({
  windowMs: 60_000,
  limit: 10,
  skip: testBypass,
});
