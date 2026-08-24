// A key written into the source, where the contents are beside the point.
//
// Whatever it says, it is in the repository, in every clone of it, and in the history
// after somebody changes it. That last part is what makes rotation insufficient on its own
// and what makes this worth reporting even when the value looks like a placeholder.
//
// The same test is what makes it precise: a secret read from the environment or a vault is
// not a literal and never matches. Nothing here inspects the string, guesses at entropy,
// or keeps a list of what a secret looks like.
import jwt from "jsonwebtoken";
import { createHmac } from "node:crypto";

export function issue(payload: object) {
  return jwt.sign(payload, "s3cr3t-dev-key");
}

export function issueProperly(payload: object) {
  const key = process.env.JWT_SIGNING_KEY;
  if (!key) {
    throw new Error("JWT_SIGNING_KEY is not configured");
  }
  return jwt.sign(payload, key);
}

export function digest(body: string) {
  return createHmac("sha256", "shared-webhook-secret").update(body).digest("hex");
}

export function digestProperly(body: string, key: string) {
  return createHmac("sha256", key).update(body).digest("hex");
}
