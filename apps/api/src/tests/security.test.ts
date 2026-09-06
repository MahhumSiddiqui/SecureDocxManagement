import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { encryptBuffer, decryptBuffer } from "../services/crypto.service.js";
import { scanner } from "../services/scanner.service.js";
import { createApp } from "../index.js";
import { prisma } from "../db.js";

const integration = process.env.RUN_INTEGRATION_TESTS === "true";
const describeIntegration = integration ? describe : describe.skip;

function csrfCookie(response: request.Response): string {
  const cookies = response.headers["set-cookie"];
  const values = Array.isArray(cookies) ? cookies : [cookies];
  const cookie = values.find((value) => value?.startsWith("sd_csrf="));
  return cookie!.split(";")[0].slice("sd_csrf=".length);
}

function cookieHeader(response: request.Response): string[] {
  const cookies = response.headers["set-cookie"];
  const values = Array.isArray(cookies) ? cookies : [cookies];
  return values
    .filter((value): value is string => Boolean(value))
    .map((value) => value.split(";")[0]);
}

function expectNoSensitiveFields(response: request.Response): void {
  const body = JSON.stringify(response.body);
  for (const field of [
    "passwordHash",
    "storageKey",
    "wrappedDek",
    "tokenHash",
  ]) {
    expect(body).not.toContain(field);
  }
}

describe("encryption services", () => {
  it("round-trips encrypted content", () => {
    const plaintext = Buffer.from("confidential test document");
    const encrypted = encryptBuffer(plaintext);
    expect(decryptBuffer(encrypted.ciphertext, encrypted)).toEqual(plaintext);
  });

  it("detects GCM tampering", () => {
    const encrypted = encryptBuffer(Buffer.from("tamper me"));
    encrypted.ciphertext[0] ^= 1;
    expect(() => decryptBuffer(encrypted.ciphertext, encrypted)).toThrow();
  });
});

describe("upload scanner", () => {
  it("rejects the EICAR signature", async () => {
    const result = await scanner.scan(
      Buffer.from(
        "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
      ),
    );
    expect(result.verdict).toBe("INFECTED");
  });
});

describeIntegration("secure API contract", () => {
  const app = createApp();
  let ownerAgent = request.agent(app);
  let userAgent = request.agent(app);
  let documentId = "";
  let shareToken = "";

  beforeAll(async () => {
    await prisma.auditLog.deleteMany();
    await prisma.loginAttempt.deleteMany();
    await prisma.user.updateMany({
      data: { failedAttempts: 0, lockedUntil: null, status: "ACTIVE" },
    });
  });

  it("logs in successfully and rejects a wrong password", async () => {
    const success = await ownerAgent
      .post("/api/auth/login")
      .send({ email: "owner@securedocs.test", password: "Passw0rd!Demo" });
    expect(success.status).toBe(200);
    expect(success.body.accessToken).toEqual(expect.any(String));
    const failure = await request(app)
      .post("/api/auth/login")
      .send({ email: "owner@securedocs.test", password: "wrong-password" });
    expect(failure.status).toBe(401);
    expect(failure.body.error.code).toBe("UNAUTHENTICATED");
  });

  it("resists account enumeration and locks after repeated failures", async () => {
    const unknown = await request(app)
      .post("/api/auth/login")
      .send({ email: "missing@securedocs.test", password: "wrong-password" });
    expect(unknown.status).toBe(401);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await request(app)
        .post("/api/auth/login")
        .send({ email: "user@securedocs.test", password: "wrong-password" });
    }
    const locked = await request(app)
      .post("/api/auth/login")
      .send({ email: "user@securedocs.test", password: "Passw0rd!Demo" });
    expect(locked.status).toBe(401);
    await prisma.loginAttempt.deleteMany({
      where: { email: "user@securedocs.test" },
    });
    await prisma.user.update({
      where: { email: "user@securedocs.test" },
      data: { failedAttempts: 0, lockedUntil: null },
    });
  });

  it("rotates refresh tokens and detects reuse", async () => {
    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "owner@securedocs.test", password: "Passw0rd!Demo" });
    const cookies = login.headers["set-cookie"];
    const cookie = (Array.isArray(cookies) ? cookies : [cookies]).find(
      (value) => value?.startsWith("sd_refresh="),
    );
    expect(cookie).toBeDefined();
    const refreshed = await request(app)
      .post("/api/auth/refresh")
      .set("Cookie", cookieHeader(login))
      .set("X-CSRF-Token", csrfCookie(login));
    expect(refreshed.status).toBe(200);
    const reused = await request(app)
      .post("/api/auth/refresh")
      .set("Cookie", cookieHeader(login))
      .set("X-CSRF-Token", csrfCookie(login));
    expect(reused.status).toBe(401);
  });

  it("refuses IDOR access across accounts", async () => {
    const ownerLogin = await ownerAgent
      .post("/api/auth/login")
      .send({ email: "owner@securedocs.test", password: "Passw0rd!Demo" });
    const userLogin = await userAgent
      .post("/api/auth/login")
      .send({ email: "user@securedocs.test", password: "Passw0rd!Demo" });
    const documents = await ownerAgent
      .get("/api/documents")
      .set("Authorization", `Bearer ${ownerLogin.body.accessToken}`);
    documentId = documents.body.items.find(
      (item: { accessLevel: string }) => item.accessLevel === "OWNER",
    ).id;
    const denied = await userAgent
      .get(`/api/documents/${documentId}`)
      .set("Authorization", `Bearer ${userLogin.body.accessToken}`);
    expect(denied.status).toBe(403);
  });

  it("denies standard users admin and audit routes", async () => {
    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "user@securedocs.test", password: "Passw0rd!Demo" });
    expect(
      (
        await request(app)
          .get("/api/admin/users")
          .set("Authorization", `Bearer ${login.body.accessToken}`)
      ).status,
    ).toBe(403);
    expect(
      (
        await request(app)
          .get("/api/audit")
          .set("Authorization", `Bearer ${login.body.accessToken}`)
      ).status,
    ).toBe(403);
  });

  it("never exposes persistence-only fields in JSON API responses", async () => {
    const ownerLogin = await request(app)
      .post("/api/auth/login")
      .send({ email: "owner@securedocs.test", password: "Passw0rd!Demo" });
    const ownerAuth = {
      Authorization: `Bearer ${ownerLogin.body.accessToken}`,
    };
    const adminLogin = await request(app)
      .post("/api/auth/login")
      .send({ email: "admin@securedocs.test", password: "Passw0rd!Demo" });
    const adminAuth = {
      Authorization: `Bearer ${adminLogin.body.accessToken}`,
    };
    const responses = [
      ownerLogin,
      adminLogin,
      await request(app).get("/api/auth/me").set(ownerAuth),
      await request(app).get("/api/documents").set(ownerAuth),
      await request(app).get(`/api/documents/${documentId}`).set(ownerAuth),
      await request(app)
        .get(`/api/documents/${documentId}/permissions`)
        .set(ownerAuth),
      await request(app)
        .get(`/api/documents/${documentId}/share`)
        .set(ownerAuth),
      await request(app).get("/api/admin/users").set(adminAuth),
      await request(app).get("/api/audit").set(adminAuth),
    ];
    for (const response of responses) {
      expectNoSensitiveFields(response);
    }
  });

  it("rejects disallowed extensions, mismatched magic bytes, and EICAR", async () => {
    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "owner@securedocs.test", password: "Passw0rd!Demo" });
    const auth = { Authorization: `Bearer ${login.body.accessToken}` };
    expect(
      (
        await request(app)
          .post("/api/documents")
          .set(auth)
          .set("Cookie", cookieHeader(login))
          .set("X-CSRF-Token", csrfCookie(login))
          .attach("file", Buffer.from("alert(1)"), "bad.js")
      ).status,
    ).toBe(400);
    expect(
      (
        await request(app)
          .post("/api/documents")
          .set(auth)
          .set("Cookie", cookieHeader(login))
          .set("X-CSRF-Token", csrfCookie(login))
          .attach("file", Buffer.from("not a pdf"), "bad.pdf")
      ).status,
    ).toBe(400);
    expect(
      (
        await request(app)
          .post("/api/documents")
          .set(auth)
          .set("Cookie", cookieHeader(login))
          .set("X-CSRF-Token", csrfCookie(login))
          .attach(
            "file",
            Buffer.from(
              "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            ),
            "bad.txt",
          )
      ).status,
    ).toBe(400);
  });

  it("handles share expiry and revocation", async () => {
    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "owner@securedocs.test", password: "Passw0rd!Demo" });
    const auth = { Authorization: `Bearer ${login.body.accessToken}` };
    const ownerLogin = await request(app)
      .post("/api/auth/login")
      .send({ email: "owner@securedocs.test", password: "Passw0rd!Demo" });
    const created = await request(app)
      .post(`/api/documents/${documentId}/share`)
      .set(auth)
      .set("Cookie", cookieHeader(ownerLogin))
      .set("X-CSRF-Token", csrfCookie(ownerLogin))
      .send({ expiresInHours: 1, canDownload: true, singleUse: false });
    shareToken = created.body.token;
    expect((await request(app).get(`/api/share/${shareToken}`)).status).toBe(
      200,
    );
    expect(
      (
        await request(app)
          .delete(`/api/share/${created.body.shareLink.id}`)
          .set(auth)
          .set("Cookie", cookieHeader(ownerLogin))
          .set("X-CSRF-Token", csrfCookie(ownerLogin))
      ).status,
    ).toBe(204);
    expect((await request(app).get(`/api/share/${shareToken}`)).status).toBe(
      404,
    );
  });

  it("verifies the audit chain, then detects a manual update", async () => {
    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "auditor@securedocs.test", password: "Passw0rd!Demo" });
    const valid = await request(app)
      .get("/api/audit/verify")
      .set("Authorization", `Bearer ${login.body.accessToken}`);
    expect(valid.body.valid).toBe(true);
    expect(valid.body.recordsChecked).toBeGreaterThan(0);
    expect(valid.body.brokenAtSequence).toBeNull();
    const record = await prisma.auditLog.findFirst({
      orderBy: { sequence: "asc" },
    });
    expect(record).toBeTruthy();
    await prisma.auditLog.update({
      where: { id: record!.id },
      data: { outcome: "DENIED" },
    });
    const broken = await request(app)
      .get("/api/audit/verify")
      .set("Authorization", `Bearer ${login.body.accessToken}`);
    expect(broken.body.valid).toBe(false);
  });
});
