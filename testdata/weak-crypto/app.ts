// A broken hash algorithm, judged by what the digest is asked to establish.
//
// The algorithm is still named in the source and is still read from a LITERAL: an
// algorithm chosen at runtime is not matched and not guessed at. What changed is that
// naming it is no longer the finding. The same `createHash("md5")` builds a cache key in
// one file and verifies a signature in the next, and only the second place knows which --
// so the call classifies the value and the USE decides.
//
// The negatives here are the point as much as the positives. Every one of them is a
// digest reaching something, and each says a different thing about the boundary: the
// algorithm is not broken, the construction does not rest on collision resistance, the
// algorithm is not knowable, or the digest establishes nothing because it is a name.
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

export function verifyDownload(data: string, recorded: string) {
  // POSITIVE. The comparison is the program saying that the digest STANDS IN for the
  // bytes: anything that hashes the same passes, and finding a second such input is
  // what MD5 no longer prevents. The digest is computed a function away, which is where
  // real code puts it.
  return fingerprint(data) !== recorded;
}

export function verifySignature(payload: string, claimed: string) {
  // POSITIVE. Same judgement, other algorithm, and the check reads as an integrity
  // check rather than as an identity: what makes it one is the comparison, not the word
  // "signature" anywhere in it.
  return legacyDigest(payload) === claimed;
}

export function verifyModern(data: string, recorded: string) {
  // NEGATIVE. The same use exactly, with an algorithm nobody can find collisions in.
  // Nothing here is about the shape of the check.
  return digest(data) === recorded;
}

export function verifyMac(payload: string, key: string, claimed: string) {
  // NEGATIVE, and the one worth stating: this is a signature check on an HMAC, which is
  // what the report is supposed to care about most. HMAC-SHA1's soundness rests on the
  // key and the construction rather than on collision resistance, so a rule about
  // broken digests has nothing to say about it and says nothing.
  return sign(payload, key) === claimed;
}

export function verifyChosen(algorithm: string, data: string, recorded: string) {
  // NEGATIVE. The use decides, but only once the algorithm is known, and here it is a
  // parameter. Not matched, and not guessed at.
  return chosen(algorithm, data) === recorded;
}

export function cacheKey(url: string) {
  // NEGATIVE. The same broken algorithm and no comparison anywhere: a key is a name for
  // a slot, and a collision costs a cache miss rather than a wrong answer about who
  // sent something.
  return `page:${fingerprint(url)}`;
}
