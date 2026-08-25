const crypto = require("crypto");
const express = require("express");

const app = express();

app.post("/register", (req, res) => {
  // POSITIVE. Node splits the algorithm and the data across two calls, so `update` on
  // its own says nothing -- what makes this a digest is that the object it was called
  // on came out of createHash, which takes an algorithm and no salt.
  const digest = crypto.createHash("sha256").update(req.body.password).digest("hex");
  res.json({ digest });
});

app.post("/register-stored", (req, res) => {
  // POSITIVE, and the same weakness written across two statements. Following the
  // assignment back is what keeps these one rule instead of two shapes.
  const hash = crypto.createHash("sha512");
  hash.update(req.body.password);
  res.json({ digest: hash.digest("hex") });
});

app.post("/register-salted", (req, res) => {
  // NEGATIVE. Composed with a per-account value before hashing.
  const salted = req.body.salt + req.body.password;
  res.json({ digest: crypto.createHash("sha256").update(salted).digest("hex") });
});

app.post("/etag", (req, res) => {
  // NEGATIVE. A digest of ordinary request data is how caches are keyed.
  res.json({ tag: crypto.createHash("sha256").update(req.body.path).digest("hex") });
});

module.exports = app;
