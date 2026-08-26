// Reached: `server.ts` imports it. The IV below is written into the source and the
// finding is anchored, which is what the surface supports.
import crypto from "crypto";

const KEY = Buffer.from(process.env.PREVIEW_KEY ?? "", "hex");

export function previewUrl(id: string): string {
  const c = crypto.createCipheriv("aes-256-cbc", KEY, "0123456789abcdef");
  return `https://preview.example.com/${c.update(id, "utf8", "hex")}`;
}
