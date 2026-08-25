const express = require("express");

const app = express();

app.post("/login", async (req, res) => {
  // POSITIVE. A password in a log is a password in every aggregator, vendor and backup
  // that log reaches, long after the request it belonged to is gone.
  console.log("login attempt", req.body.email, req.body.password);
  res.json({ ok: true });
});

app.post("/login-safe", async (req, res) => {
  // NEGATIVE. The email is caller-supplied and is not a credential. Logging who tried
  // to sign in is the point of the log.
  console.log("login attempt", req.body.email);
  res.json({ ok: true });
});

app.post("/csrf", async (req, res) => {
  // NEGATIVE. A double-submit CSRF token is a credential nobody hides: the page has to
  // read it back and echo it, so it is already in the browser.
  console.log("csrf check", req.body.csrfToken);
  res.json({ ok: true });
});

module.exports = app;
