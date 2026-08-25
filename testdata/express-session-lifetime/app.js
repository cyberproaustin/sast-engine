const { randomUUID } = require("crypto");
const express = require("express");

const app = express();

app.post("/login", (req, res) => {
  // POSITIVE. A credential good for a year is a stolen credential good for a year, and
  // nothing the user does afterwards takes it back.
  res.cookie("session", randomUUID(), { httpOnly: true, secure: true, maxAge: 31536000000 });
  res.json({ ok: true });
});

app.post("/login-short", (req, res) => {
  // NEGATIVE. Fifteen minutes.
  res.cookie("session", randomUUID(), { httpOnly: true, secure: true, maxAge: 900000 });
  res.json({ ok: true });
});

app.post("/theme", (req, res) => {
  // NEGATIVE, and the reason the attribute is only asked about for some cookies: a
  // preference that lasts a year is a feature, not a weakness. The name in argument
  // zero is the only evidence available at the call of what a cookie carries.
  res.cookie("theme", "dark", { maxAge: 31536000000 });
  res.json({ ok: true });
});

function openHelp() {
  // POSITIVE. The opened page keeps a live reference back through window.opener and can
  // navigate the page behind it -- which is how a link to somewhere else replaces the
  // page it came from with a copy that asks for a password.
  window.open("https://docs.example.com/help", "_blank");
}

function openHelpSafely() {
  // NEGATIVE. The third argument is where noopener goes, and it is there.
  window.open("https://docs.example.com/help", "_blank", "noopener,noreferrer");
}

module.exports = { app, openHelp, openHelpSafely };
