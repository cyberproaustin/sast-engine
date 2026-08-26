// Nothing in this program imports, re-exports, requires or dynamically loads this file.
// The same call as `preview.ts` makes, and the finding is equally right about the call;
// what it cannot say is that a caller reaches it, because nothing reaches this module.
import crypto from "crypto";

const KEY = Buffer.from(process.env.LEGACY_KEY ?? "", "hex");

export function legacyUrl(id: string): string {
  const c = crypto.createCipheriv("aes-256-cbc", KEY, "fedcba9876543210");
  return `https://legacy.example.com/${c.update(id, "utf8", "hex")}`;
}
