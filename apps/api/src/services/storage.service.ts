import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { config } from "../config.js";
export async function writeBlob(key: string, data: Buffer): Promise<void> {
  await mkdir(config.storagePath, { recursive: true });
  await writeFile(path.join(config.storagePath, key), data, { flag: "wx" });
}
export async function readBlob(key: string): Promise<Buffer> {
  return readFile(path.join(config.storagePath, key));
}
export async function deleteBlob(key: string): Promise<void> {
  try {
    await unlink(path.join(config.storagePath, key));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}
