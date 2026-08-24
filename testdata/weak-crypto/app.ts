// A weakness with no dataflow in it at all.
//
// Nothing reaches this and no caller controls anything: the algorithm is named in the
// source and is broken wherever it is written. A flow analysis cannot express that, and
// bending one into the shape would mean inventing a source for a defect that has none.
//
// Matched only against a LITERAL. An algorithm chosen at runtime is not matched and not
// guessed at, which is what keeps this kind at a precision worth having: a string "md5"
// handed to a hash constructor IS md5, and there is nothing to be wrong about.
import { createHash, createHmac } from "node:crypto";

export function fingerprint(data: string) {
  return createHash("md5").update(data).digest("hex");
}

export function legacyDigest(data: string) {
  return createHash("sha1").update(data).digest("hex");
}

export function digest(data: string) {
  return createHash("sha256").update(data).digest("hex");
}

export function sign(data: string, key: string) {
  // HMAC-SHA1 is not broken the way a bare SHA-1 digest is, and is deliberately absent
  // from the list rather than swept in by association.
  return createHmac("sha1", key).update(data).digest("hex");
}

export function chosen(algorithm: string, data: string) {
  // Not a literal. Unmatched, and not guessed at.
  return createHash(algorithm).update(data).digest("hex");
}
