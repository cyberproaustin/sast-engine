// A refusal whose condition includes the PRESENCE of the value it refuses on.
//
// `if (claim && expected && claim !== expected) throw` reads as a check and is not one:
// when either side is missing the conjunction is false, the throw does not happen, and
// the caller who supplies one of the two decides whether the comparison runs at all.
//
// The shape is drawn from documenso's embedded-signing presign verifier. The negatives
// are the same idiom written correctly, and the ordinary uses of it that this rule must
// stay quiet about -- all four taken from production code measured on the clean corpus.

import express from "express";

type Claims = { sub: string; scope?: string };

const app = express();

function decodeClaims(token: string): Claims {
  return JSON.parse(Buffer.from(token.split(".")[1], "base64").toString()) as Claims;
}

// EXPECTED FINDING. The verifier takes the expected scope as an OPTIONAL argument and
// tests it only when it is there, so a caller that passes no scope gets no scope check --
// and so does a token minted with no scope claim. Both halves of the guard are the same
// two values the comparison is about.
export function verifyPresignToken(token: string, scope?: string): Claims {
  const claims = decodeClaims(token);

  if (claims.scope && scope && claims.scope !== scope) {
    throw new Error("Presign token scope not matched");
  }

  return claims;
}

// EXPECTED CLEAN. The same verification with nothing to omit. The comparison decides
// whatever arrives on either side of it, including nothing.
export function verifyStrict(token: string, scope: string): Claims {
  const claims = decodeClaims(token);

  if (claims.scope !== scope) {
    throw new Error("Presign token scope not matched");
  }

  return claims;
}

// EXPECTED CLEAN. The correct way to write the conjunctive form: a missing operand is a
// REASON to refuse rather than a reason to skip the refusal. The disjunction is never
// read by this rule, because its truthy side says only that some operand held.
export function verifyRequiringBoth(token: string, scope: string): Claims {
  const claims = decodeClaims(token);

  if (!claims.scope || !scope || claims.scope !== scope) {
    throw new Error("Presign token scope not matched");
  }

  return claims;
}

// EXPECTED CLEAN. The same three-operand conjunction, refusing, and comparing two things
// that are not each other: a request's port against the one the deployment configured.
// Nothing is skipped by omitting either -- there is no check here that the presence test
// is standing in front of, only a narrower condition.
export function assertSamePort(requestPort: string | undefined, configuredPort: string | undefined): void {
  if (requestPort && configuredPort && requestPort !== configuredPort) {
    throw new Error("host does not match");
  }
}

// EXPECTED CLEAN. The commonest form by far, and the one the presence tests exist for: a
// difference test that does WORK on the side where the values differ. Omitting either
// operand skips the move, which is exactly what the guard was written to arrange.
// Measured on ten production repositories, five of the seven occurrences of this shape
// are this.
export function renameIfChanged(oldPath: string | undefined, newPath: string | undefined): string | undefined {
  if (oldPath && newPath && oldPath !== newPath) {
    return `mv ${oldPath} ${newPath}`;
  }
  return undefined;
}

app.get("/documents/:id/file", (req, res) => {
  const token = String(req.query.token ?? "");
  const claims = verifyPresignToken(token, undefined);
  res.json({ sub: claims.sub });
});

app.get("/documents/:id/strict", (req, res) => {
  const token = String(req.query.token ?? "");
  const claims = verifyStrict(token, "document.read");
  res.json({ sub: claims.sub });
});

app.get("/documents/:id/both", (req, res) => {
  const token = String(req.query.token ?? "");
  const claims = verifyRequiringBoth(token, "document.read");
  res.json({ sub: claims.sub });
});

app.get("/host/:port", (req, res) => {
  assertSamePort(String(req.params.port), "8080");
  res.json({ ok: true });
});

app.post("/rename", (req, res) => {
  res.json({ command: renameIfChanged(String(req.body.from), String(req.body.to)) });
});

export default app;
