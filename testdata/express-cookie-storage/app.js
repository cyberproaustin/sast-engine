const { randomUUID } = require("crypto");
const express = require("express");
const serveIndex = require("serve-index");

const app = express();

// POSITIVE. Publishing the file names in a directory publishes a map of everything in
// it, including whatever was left there.
app.use("/files", serveIndex("public/files"));

app.post("/remember", (req, res) => {
  // POSITIVE. A credential on a machine the application does not control, sent on every
  // subsequent request to it.
  res.cookie("saved", req.body.password);
  res.json({ ok: true });
});

app.post("/remember-long", (req, res) => {
  // POSITIVE, and a different weakness: the expiry makes the cookie persistent, so it
  // survives the browser closing and sits on disk until the date passes.
  res.cookie("saved", req.body.password, { maxAge: 31536000000 });
  res.json({ ok: true });
});

app.post("/session", (req, res) => {
  // NEGATIVE. The value is generated here, not sent by the caller.
  res.cookie("sid", mintSession(req.body.email), { httpOnly: true, secure: true });
  res.json({ ok: true });
});

function mintSession(email) {
  return `s-${email}-${randomUUID()}`;
}

module.exports = app;
