import type { ScanVerdict } from "@prisma/client";
export interface Scanner {
  scan(buf: Buffer): Promise<{ verdict: ScanVerdict; signature?: string }>;
}
// This signature stub stands in for ClamAV; production can replace it behind the same interface.
export const scanner: Scanner = {
  async scan(buf) {
    const text = buf.toString("latin1");
    if (
      text.includes(
        "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
      )
    )
      return { verdict: "INFECTED", signature: "EICAR-Test-File" };
    if (
      text.includes("<?php") ||
      text.includes("#!/bin/sh") ||
      buf.subarray(0, 2).toString() === "MZ"
    )
      return { verdict: "INFECTED", signature: "script-marker" };
    return { verdict: "CLEAN" };
  },
};
