// Two weaknesses, and the difference between them is why one gates and one does not.
//
// A broken HASH does not gate, because a hash has honest non-security jobs: cache keys,
// content addressing, and Gravatar, which requires the MD5 of an email by protocol. MD5 is
// only wrong where collision resistance is what makes the thing work, and the call does not
// say which it is.
//
// A broken CIPHER has no such second life. Nothing needs encryption for a purpose that
// does not need encryption, so DES is wrong wherever it appears, and this one gates.
import express from "express";
import { createCipheriv, randomBytes } from "node:crypto";

const app = express();

export function encryptLegacy(plaintext: string, key: Buffer) {
  const c = createCipheriv("des-cbc", key, randomBytes(8));
  return Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
}

export function encrypt(plaintext: string, key: Buffer) {
  const c = createCipheriv("aes-256-gcm", key, randomBytes(12));
  return Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
}

app.get("/search", (req, res) => {
  // The caller writes the pattern. A backtracking engine can be made to take exponential
  // time on a short input, which stops the process without touching it.
  const pattern = new RegExp(String(req.query.q));
  res.json({ matched: pattern.test("haystack") });
});

app.get("/find", (req, res) => {
  // The caller supplies the SUBJECT, not the pattern. Ordinary matching.
  const pattern = new RegExp("^[a-z]+$");
  res.json({ matched: pattern.test(String(req.query.q)) });
});

export default app;
