const express = require("express");
const { getCookieOpts } = require("./helper");

const app = express();

app.post("/login", (req, res) => {
  // POSITIVE. No options at all, so the absence is not a guess: this cookie carries a
  // session and any script on the origin can read it.
  res.cookie("session", mintSession(req.body.email));
  res.json({ ok: true });
});

app.post("/login-explicit", (req, res) => {
  // POSITIVE. Written down, which makes it a decision rather than an omission.
  res.cookie("jwt", mintSession(req.body.email), { httpOnly: false, path: "/" });
  res.json({ ok: true });
});

app.post("/login-insecure", (req, res) => {
  // POSITIVE. HttpOnly is right and Secure is explicitly off.
  res.cookie("access_token", mintSession(req.body.email), { httpOnly: true, secure: false });
  res.json({ ok: true });
});

app.post("/login-crosssite", (req, res) => {
  // POSITIVE, and deliberately never gating: SameSite=None is what an embedded widget
  // or an OAuth flow legitimately needs.
  res.cookie("refresh_token", mintSession(req.body.email), { httpOnly: true, secure: true, sameSite: "none" });
  res.json({ ok: true });
});

app.post("/login-helper", (req, res) => {
  // NEGATIVE. The attributes are set, in a function this analysis cannot see into.
  // Reporting absence here is the false positive this whole precondition exists for.
  res.cookie("jwt", mintSession(req.body.email), getCookieOpts());
  res.json({ ok: true });
});

app.post("/login-correct", (req, res) => {
  // NEGATIVE. Everything set, and set correctly.
  res.cookie("session", mintSession(req.body.email), { httpOnly: true, secure: true, sameSite: "lax" });
  res.json({ ok: true });
});

app.post("/csrf", (req, res) => {
  // NEGATIVE. A double-submit CSRF cookie is MEANT to be read by script -- the page has
  // to echo it back in a header. HttpOnly would break the protection.
  res.cookie("csrf_token", mintSession(req.body.email));
  res.json({ ok: true });
});

app.post("/theme", (req, res) => {
  // NEGATIVE. Carries no credential, so none of these attributes are required.
  res.cookie("theme", "dark");
  res.json({ ok: true });
});

// The value stored is GENERATED here, which is what a login actually does. Using the
// caller's own submission would be a different weakness in a corpus about a different
// judgement.
function mintSession(email) {
  return `s-${email}-${Date.now()}`;
}

module.exports = app;
