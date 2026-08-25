const express = require("express");

const app = express();
const ALLOWED = "https://app.example.com";
const ALLOWED_SET = new Set([ALLOWED, "https://admin.example.com"]);

app.get("/data", (req, res) => {
  // POSITIVE. The list is right and the comparison is too generous: a prefix match
  // accepts `https://app.example.com.attacker.net`, which somebody can register this
  // afternoon. What makes it hard to see is that the allowed value is correct.
  const origin = req.headers.origin;
  res.json({ allowed: origin.startsWith(ALLOWED) });
});

app.get("/data-suffix", (req, res) => {
  // POSITIVE, read the other way: a suffix match accepts `https://notexample.com`.
  const origin = req.headers.origin;
  res.json({ allowed: origin.endsWith("example.com") });
});

app.get("/data-exact", (req, res) => {
  // NEGATIVE. A set membership test accepts exactly the values on the list and nothing
  // that extends them, which is what an allow-list is supposed to mean.
  const origin = req.headers.origin;
  res.json({ allowed: ALLOWED_SET.has(origin) });
});

app.get("/route", (req, res) => {
  // NEGATIVE. A partial match on something that is not an origin is how routing is
  // written, and the classification is what keeps this rule away from it: the receiver
  // has to be a value the caller sent AS an origin.
  res.json({ nested: req.path.startsWith("/route/") });
});

module.exports = app;
