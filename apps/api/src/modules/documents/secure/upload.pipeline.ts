import { fileTypeFromBuffer } from "file-type";
import path from "node:path";
import { AppError } from "../../../middleware/errors.js";
import { config } from "../../../config.js";
import { scanner } from "../../../services/scanner.service.js";
const extMime: Record<string, string[]> = {
  pdf: ["application/pdf"],
  docx: [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/zip",
  ],
  xlsx: [
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/zip",
  ],
  pptx: [
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/zip",
  ],
  txt: ["text/plain"],
  csv: ["text/csv", "application/vnd.ms-excel"],
  png: ["image/png"],
  jpg: ["image/jpeg"],
  jpeg: ["image/jpeg"],
};
export async function validateUpload(
  file: Express.Multer.File,
): Promise<{ extension: string; mimeType: string; verdict: "CLEAN" }> {
  if (file.size > config.MAX_UPLOAD_BYTES)
    throw new AppError(400, "VALIDATION_ERROR", "File is too large.");
  const extension = path.extname(file.originalname).slice(1).toLowerCase();
  if (!Object.hasOwn(extMime, extension))
    throw new AppError(400, "VALIDATION_ERROR", "Disallowed file type.");
  const detected = await fileTypeFromBuffer(file.buffer);
  let mime = detected?.mime ?? "text/plain";
  if (["txt", "csv"].includes(extension)) {
    if (file.buffer.includes(0))
      throw new AppError(
        400,
        "VALIDATION_ERROR",
        "Content does not match extension.",
      );
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(file.buffer);
    } catch {
      throw new AppError(
        400,
        "VALIDATION_ERROR",
        "Content does not match extension.",
      );
    }
    mime = extension === "csv" ? "text/csv" : "text/plain";
  } else if (!detected || !extMime[extension].includes(mime))
    throw new AppError(
      400,
      "VALIDATION_ERROR",
      "Content does not match extension.",
    );
  const scan = await scanner.scan(file.buffer);
  if (scan.verdict === "INFECTED")
    throw new AppError(400, "VALIDATION_ERROR", "Malware signature detected.");
  return { extension, mimeType: mime, verdict: "CLEAN" };
}
export function safeFilename(name: string): string {
  return name.replace(/[\\/\u0000-\u001f\u007f\"]+/g, "_").slice(0, 100);
}
