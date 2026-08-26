// Two directions of one weakness, and they need different evidence.
//
// The engine has always reported a caller who writes the PATTERN. That is rare. What
// actually stops a process is a caller who feeds a long string to a pattern that
// BACKTRACKS -- and that needs two facts at once, neither of which is a finding alone: a
// nested quantifier nobody hostile can reach costs nothing, and an untrusted string
// meeting a linear pattern costs nothing either.

import express from "express";

const app = express();
const db: any = {};

// The shape most email patterns on the internet have, and the one a vulnerable
// application ships: a quantified group whose body is itself quantified, so the engine
// can split one input between the inner and outer repetition exponentially many ways.
const EMAIL = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+$/;

// Linear. It repeats, and nothing can be split between two repetitions.
const SLUG = /^[a-z0-9-]{1,64}$/;

app.post("/subscribe", (req, res) => {
  // POSITIVE. Written inside a negated condition, which is where validation lives -- and
  // which the frontend used to walk straight past, so the call was not in the IR at all.
  if (!EMAIL.test(req.body.mail)) return res.status(400).end();
  res.json({ ok: true });
});

app.get("/page/:slug", (req, res) => {
  // NEGATIVE. The same caller-supplied string against a pattern that cannot churn.
  if (!SLUG.test(req.params.slug)) return res.status(404).end();
  res.json({ ok: true });
});

app.get("/internal", (_req, res) => {
  // NEGATIVE. The dangerous pattern, run on something no caller chose.
  res.json({ ok: EMAIL.test("ops@example.com") });
});

app.post("/search", (req, res) => {
  // POSITIVE, and the spelling the language actually uses: JavaScript reverses the
  // operands, so the SUBJECT is the receiver and the pattern is the argument. The model
  // described only the other direction for a while, which meant the most common shape
  // was invisible.
  const hit = String(req.body.value).match(/^(\w+\s?)*$/);
  res.json({ hit: Boolean(hit) });
});

app.post("/search-linear", (req, res) => {
  // NEGATIVE. The same call against a pattern whose repetitions cannot overlap.
  const hit = String(req.body.value).match(/^[a-z0-9-]{1,64}$/);
  res.json({ hit: Boolean(hit) });
});

app.post("/build", (req, res) => {
  // POSITIVE, and unrelated to patterns: `q += ...` is composition written as a
  // statement, and it was handled by nothing at all -- not the expression lowering,
  // which reads `+` and not `+=`, and not the assignment lowering, which reads `=`.
  let q = "SELECT * FROM notes";
  q += " WHERE title = '" + req.body.title + "'";
  db.query(q);
  res.json({ ok: true });
});

export default app;
