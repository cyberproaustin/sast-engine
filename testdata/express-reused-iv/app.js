const crypto = require("crypto");
const express = require("express");

const app = express();
const KEY = Buffer.from(process.env.DATA_KEY, "hex");

// Computed once when this file loads. A random number was involved, which is what makes
// it look right; what matters is that it is the SAME random number for every message
// this process ever encrypts.
const IV = crypto.randomBytes(16);

app.post("/store", (req, res) => {
  // POSITIVE. Two messages encrypted under one key and one initialisation vector leak
  // the XOR of their plaintexts, and in counter mode they leak it outright.
  const c = crypto.createCipheriv("aes-256-gcm", KEY, IV);
  res.json({ blob: Buffer.concat([c.update(req.body.note, "utf8"), c.final()]).toString("hex") });
});

app.post("/store-fresh", (req, res) => {
  // NEGATIVE. A new one for every message, which is the whole requirement.
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  res.json({ iv: iv.toString("hex"), blob: Buffer.concat([c.update(req.body.note, "utf8"), c.final()]).toString("hex") });
});

module.exports = app;
