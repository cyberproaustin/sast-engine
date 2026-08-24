// A channel nobody wrote a policy for.
//
// `untrusted-to-interpreter` was written against `child_process.exec`. Adding the
// language's own evaluator required describing the channel and nothing else: no policy
// changed, no engine code moved, and the finding names CWE-95 rather than CWE-78 because
// the CHANNEL determines the weakness while the policy determines the judgement
// (ADR-012). This corpus exists to keep that property true.
import express from "express";

const app = express();

app.post("/calculate", (req, res) => {
  // The caller chooses what gets compiled and run.
  const result = eval(req.body.expression);
  res.json({ result });
});

app.post("/compile", (req, res) => {
  const fn = new Function(req.body.source);
  res.json({ ok: typeof fn === "function" });
});

app.post("/report", (req, res) => {
  // Not an interpreter. A template is data.
  res.json({ title: `Report for ${req.body.name}` });
});

export default app;
