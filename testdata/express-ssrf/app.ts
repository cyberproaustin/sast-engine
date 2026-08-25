// Where a request GOES, as opposed to what it carries.
//
// The same axios.post is two destinations depending on which argument is asked about.
// Argument 1 is data leaving the trust boundary; argument 0 is the caller choosing which
// machine the application talks to from inside the network. One call, two judgements.
//
// The discriminator is the mirror image of the SQL one, and the pair is not a coincidence:
// what a destination interprets decides which it needs. A statement is BUILT, so untrusted
// data composed into it is the defect. A destination is CHOSEN, so untrusted data composed
// into one usually is not.
import express from "express";
import axios from "axios";
import needle from "needle";

const app = express();
const BASE = "https://api.internal.example.com";

app.get("/proxy", async (req, res) => {
  // The caller names the machine.
  const r = await axios.get(String(req.query.url));
  res.json({ status: r.status });
});

app.get("/user", async (req, res) => {
  // Fixed host, caller-chosen path segment. They cannot move this to another machine.
  const r = await axios.get(`${BASE}/users/${req.query.id}`);
  res.json({ status: r.status });
});

app.post("/notify", async (req, res) => {
  // A fixed destination carrying caller data. Not this judgement.
  await axios.post("https://hooks.internal.example.com/notify", { note: req.body.note });
  res.json({ ok: true });
});

app.get("/lookup", async (req, res) => {
  // POSITIVE, and the case the whole-value rule used to silence. This is a composition
  // like the one above, and the difference is POSITION: the caller's value comes first,
  // so nothing precedes it and the program named no destination at all. Whoever sends
  // `?base=https://attacker.example/&symbol=x` chooses the machine.
  const r = await needle.get(String(req.query.base) + String(req.query.symbol));
  res.json({ status: r.statusCode });
});

app.get("/quote", async (req, res) => {
  // NEGATIVE, and the reason position rather than "does a literal here name a scheme".
  // A program that keeps its base URL in a constant writes no scheme at the call either,
  // and asking about the literals readmitted two production call sites that are fine.
  const r = await needle.get(BASE + "/quotes/" + String(req.query.symbol));
  res.json({ status: r.statusCode });
});

export default app;
