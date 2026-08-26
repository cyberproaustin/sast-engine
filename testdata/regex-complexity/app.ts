// Catastrophic backtracking, and the two ways an application arrives at it.
//
// The first is a match written in the handler: a pattern with a quantified group whose
// body repeats, tested against a string the caller sent. The engine has always been able
// to see that one, because the pattern and the string are arguments to each other.
//
// The second is how a modern application actually validates a request, and there is no
// call anywhere in it where the two meet. The route writes a SCHEMA -- the pattern, a
// length cap, a trim -- and hands it to the framework; the string arrives later and the
// match happens inside the validation library. Nothing flows from the caller to the
// pattern in this file, so a flow analysis has nothing to follow. What is written down is
// the pattern and the route it belongs to, and that is enough: a request schema exists to
// be run against a request.
//
// umami's pre-authentication ReDoS is the second shape exactly -- and its schema runs
// before the shared helper checks any credential, so the caller need not have an account.

import express from "express";
import { z } from "zod";

import { HOSTNAME_LABEL, SAFE_LABEL } from "./patterns";

const app = express();

// A quantified group whose body is itself quantified: a run of word characters can be
// split between the inner `+` and the outer `+` in exponentially many ways.
const TAG_LIST = /^(\w+,?\s*)+$/;

app.post("/tags", (req, res) => {
  // POSITIVE. The pattern is the receiver and the caller's string is the argument, and
  // the test is written inside a negated condition -- which is where validation lives.
  if (!TAG_LIST.test(req.body.tags)) return res.status(400).end();
  res.json({ ok: true });
});

app.post("/websites", (req, res) => {
  // POSITIVE, and the umami shape twice over: the schema is the only place the pattern
  // and the request are connected, and the pattern is catastrophic because the class in
  // front of the group contains the hyphen the group repeats on.
  const schema = z.object({
    domain: z.string().trim().regex(HOSTNAME_LABEL).max(500),
  });
  const parsed = schema.safeParse(req.body);
  res.json({ ok: parsed.success });
});

app.post("/labels", (req, res) => {
  // NEGATIVE. The same schema field, one character different: the class in front of the
  // group has no hyphen in it, so each repetition has exactly one place to start.
  const schema = z.object({
    label: z.string().trim().regex(SAFE_LABEL).max(100),
  });
  res.json({ ok: schema.safeParse(req.body).success });
});

app.get("/slug/:slug", (req, res) => {
  // NEGATIVE. A caller-supplied string against a pattern that repeats and cannot churn.
  if (!SAFE_LABEL.test(req.params.slug)) return res.status(404).end();
  res.json({ ok: true });
});

app.get("/health", (_req, res) => {
  // NEGATIVE. The dangerous pattern, run on a string written in this file. A pattern is
  // only a weakness when somebody else chooses what it runs on.
  res.json({ ok: TAG_LIST.test("alpha, beta") });
});

export default app;
