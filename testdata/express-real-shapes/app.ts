// Shapes taken from real Express codebases, each of which silently dropped taint or
// hid a control before being found by running against code nobody wrote for us.

import express from "express";
import { exec, execSync } from "child_process";
import auth from "./auth";
import { lookup } from "./service";

const app = express();

// EXPECTED FINDING — destructured request data.
app.get("/destructured", auth.required, (req, res) => {
  const { host } = req.query;
  exec(`dig ${host}`);
  res.send("ok");
});

// EXPECTED FINDING — shorthand property. The identifier resolves to the property
// symbol, not the local it reads, so this needs the checker's value accessor.
app.get("/shorthand", auth.required, (req, res) => {
  const host = req.query.host;
  const opts = { host };
  exec(`ping ${opts.host}`);
  res.send("ok");
});

// EXPECTED FINDING — object spread.
app.get("/spread", auth.required, (req, res) => {
  const base = { host: req.query.host };
  const opts = { ...base };
  execSync(`ping ${opts.host}`);
  res.send("ok");
});

// EXPECTED FINDING — nested destructuring through a call into another module.
app.get("/nested", auth.required, (req, res) => {
  const {
    body: { target },
  } = req;
  res.send(lookup(target));
});

// EXPECTED CLEAN — this route is genuinely public, and it is the only one without
// auth.required. Convention analysis should notice; that is advisory, not a defect.
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);

// NEGATIVE CONTROL. `format` is Python's format-string weakness: a caller who writes the
// format chooses the conversions, and Python's format language walks attributes far enough
// to reach module globals. JavaScript has no such method and plenty of objects with a
// `format` of their own -- a date formatter matched the channel exactly, receiver and all,
// and three findings across the clean corpus were `dayjs(when).format("HH:mm")`.
//
// The rule is scoped to the frontend that has the method. Nothing is reported here.
app.get("/when", (req: any, res: any) => {
  res.json({ at: formatter(req.query.when).format("HH:mm") });
});

function formatter(when: string) {
  return { format: (_shape: string) => when };
}

// POSITIVE. Every comparison with NaN is false, the inequality included, because NaN is
// not equal to itself. A branch that tests for one is a branch that never runs -- and in
// a check, a branch that never runs is not a check.
app.get("/score", (req: any, res: any) => {
  const score = Number(req.query.score);
  if (score === NaN) {
    return res.status(400).json({ error: "not a number" });
  }
  res.json({ score });
});

// NEGATIVE, and the way to write it: the language ships a test that works.
app.get("/score-checked", (req: any, res: any) => {
  const score = Number(req.query.score);
  if (Number.isNaN(score)) {
    return res.status(400).json({ error: "not a number" });
  }
  res.json({ score });
});
