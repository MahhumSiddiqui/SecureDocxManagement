import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { config } from "../config.js";
const kek = Buffer.from(config.KEK_MASTER, "hex");
export type EncryptedBlob = {
  ciphertext: Buffer;
  wrappedDek: string;
  iv: string;
  authTag: string;
  wrapIv: string;
  wrapTag: string;
  sha256: string;
};
export function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}
export function encryptBuffer(plain: Buffer): EncryptedBlob {
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const wrapIv = randomBytes(12);
  const wrapper = createCipheriv("aes-256-gcm", kek, wrapIv);
  const wrappedDek = Buffer.concat([wrapper.update(dek), wrapper.final()]);
  return {
    ciphertext,
    wrappedDek: wrappedDek.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    wrapIv: wrapIv.toString("base64"),
    wrapTag: wrapper.getAuthTag().toString("base64"),
    sha256: sha256(plain),
  };
}
export function decryptBuffer(
  blob: Buffer,
  key: {
    wrappedDek: string;
    iv: string;
    authTag: string;
    wrapIv: string;
    wrapTag: string;
  },
): Buffer {
  const unwrap = createDecipheriv(
    "aes-256-gcm",
    kek,
    Buffer.from(key.wrapIv, "base64"),
  );
  unwrap.setAuthTag(Buffer.from(key.wrapTag, "base64"));
  const dek = Buffer.concat([
    unwrap.update(Buffer.from(key.wrappedDek, "base64")),
    unwrap.final(),
  ]);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    dek,
    Buffer.from(key.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(key.authTag, "base64"));
  return Buffer.concat([decipher.update(blob), decipher.final()]);
}
export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}
