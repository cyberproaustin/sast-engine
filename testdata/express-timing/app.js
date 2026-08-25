const crypto = require("crypto");
const express = require("express");

const app = express();

app.post("/webhook", (req, res) => {
  // POSITIVE. The comparison stops at the first byte that differs, so how long it takes
  // says how much of the guess was right -- and a few thousand guesses recover the rest.
  const expected = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET).update("body").digest("hex");
  if (req.headers.authorization === expected) {
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: "bad signature" });
});

app.post("/webhook-safe", (req, res) => {
  // NEGATIVE. A constant-time compare is a CALL, so there is no comparison here to match
  // -- which is what makes a fixed program silent rather than differently reported.
  const expected = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET).update("body").digest("hex");
  const given = Buffer.from(String(req.headers.authorization ?? ""));
  if (crypto.timingSafeEqual(given, Buffer.from(expected))) {
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
