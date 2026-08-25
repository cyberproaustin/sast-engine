const express = require("express");

const app = express();

app.post("/register", (req, res) => {
  // POSITIVE. The same judgement on the other language, written the way JavaScript
  // writes it.
  const password = req.body.password;
  if (password.length < 6) {
    return res.status(400).json({ error: "too short" });
  }
  return res.json({ ok: true });
});

app.post("/register-either-way", (req, res) => {
  // POSITIVE. Which side the constant was written on is not evidence of anything.
  const password = req.body.password;
  if (6 > password.length) {
    return res.status(400).json({ error: "too short" });
  }
  return res.json({ ok: true });
});

app.post("/register-strict", (req, res) => {
  // NEGATIVE. Twelve.
  const password = req.body.password;
  if (password.length < 12) {
    return res.status(400).json({ error: "too short" });
  }
  return res.json({ ok: true });
});

module.exports = app;
