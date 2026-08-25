const crypto = require("crypto");
const express = require("express");

const app = express();

app.post("/webhook", (req, res) => {
  // POSITIVE. `===` is not required to take the same time whatever it is given, and no
  // engine makes that promise: in practice it returns as soon as two characters differ,
  // so how long it takes says how much of the guess was right.
  const expected = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET).update("body").digest("hex");
  if (req.headers.authorization === expected) {
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: "bad signature" });
});

app.post("/webhook-safe", (req, res) => {
  // NEGATIVE. A constant-time compare is a CALL, so there is no comparison here to match
  // -- which is what makes a fixed program silent rather than differently reported.
  //
  // The length check is not decoration: timingSafeEqual THROWS when the two buffers are
  // different lengths, and the caller chooses the length of the header, so calling it
  // without one hands them a way to make the process raise on demand.
  const expected = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET).update("body").digest("hex");
  const given = Buffer.from(String(req.headers.authorization ?? ""));
  const want = Buffer.from(expected);
  if (given.length === want.length && crypto.timingSafeEqual(given, want)) {
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: "bad signature" });
});

app.post("/present", (req, res) => {
  // NEGATIVE. Comparing a credential to something WRITTEN DOWN is a presence check, a
  // flag test, or a hardcoded credential -- and the last of those is a different weakness
  // with its own number.
  if (req.headers.authorization === undefined) {
    return res.status(401).json({ error: "missing" });
  }
  return res.json({ ok: true });
});

module.exports = app;
