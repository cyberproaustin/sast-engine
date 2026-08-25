const crypto = require("crypto");
const express = require("express");

const app = express();

app.post("/login", (req, res) => {
  // POSITIVE. Guessing this cookie is being that user, and Math.random's output is
  // reproducible from a handful of samples.
  const sid = Math.random().toString(36).slice(2);
  res.cookie("sid", sid, { httpOnly: true, secure: true });
  res.json({ ok: true });
});

app.post("/login-strong", (req, res) => {
  // NEGATIVE. From a generator built for unpredictability.
  const sid = crypto.randomBytes(32).toString("hex");
  res.cookie("sid", sid, { httpOnly: true, secure: true });
  res.json({ ok: true });
});

app.get("/retry-after", (req, res) => {
  // NEGATIVE. The same call, and nothing about this needs to be unguessable. This is
  // the shape that appears 90 times across the clean corpus.
  const jitter = Math.floor(Math.random() * 1000);
  res.json({ retryInMs: 5000 + jitter });
});

module.exports = app;
