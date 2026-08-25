const axios = require("axios");
const express = require("express");

const app = express();

app.post("/verify", async (req, res) => {
  // POSITIVE. A query string is the least private part of a request: it reaches the
  // access log at both ends, the Referer header of whatever loads next, and browser
  // history. TLS does not help with any of those.
  await axios.get("https://auth.internal/check?token=" + req.body.token);
  res.json({ ok: true });
});

app.post("/verify-header", async (req, res) => {
  // NEGATIVE. The same credential, carried where it belongs.
  await axios.get("https://auth.internal/check", {
    headers: { authorization: req.body.token },
  });
  res.json({ ok: true });
});

app.get("/next", (req, res) => {
  // NEGATIVE. Not a credential: an ordinary caller-supplied value in a URL is how
  // pagination works.
  res.redirect("/list?page=" + req.query.page);
});

module.exports = app;
