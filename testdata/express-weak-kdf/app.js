const crypto = require("crypto");
const bcrypt = require("bcrypt");
const express = require("express");

const app = express();
const KEY = Buffer.alloc(32);

app.post("/register-cheap", async (req, res) => {
  // POSITIVE. Four rounds is roughly a thousandth of the work the default does.
  const hash = await bcrypt.hash(req.body.password, 4);
  res.json({ hash });
});

app.post("/register", async (req, res) => {
  // NEGATIVE. Ten is the library default. Being AT the floor is not a finding: a rule
  // that fired on current guidance would fire on every codebase forever.
  const hash = await bcrypt.hash(req.body.password, 10);
  res.json({ hash });
});

app.post("/register-configured", async (req, res) => {
  // NEGATIVE. Not a number written in the call, so nothing is claimed about it.
  const hash = await bcrypt.hash(req.body.password, Number(process.env.BCRYPT_ROUNDS));
  res.json({ hash });
});

app.post("/derive-cheap", (req, res) => {
  // POSITIVE. A thousand iterations of PBKDF2 is a rounding error on a GPU.
  crypto.pbkdf2(req.body.password, "salt", 1000, 32, "sha256", () => res.json({}));
});

app.post("/derive", (req, res) => {
  // NEGATIVE.
  crypto.pbkdf2(req.body.password, "salt", 600000, 32, "sha256", () => res.json({}));
});

function encryptFixed(plaintext) {
  // POSITIVE. An IV written into the source is predictable AND reused on every message.
  const cipher = crypto.createCipheriv("aes-256-cbc", KEY, "0000000000000000");
  return cipher.update(plaintext, "utf8", "hex");
}

function encrypt(plaintext) {
  // NEGATIVE. A fresh random IV per message, which is the whole point of one.
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", KEY, iv);
  return cipher.update(plaintext, "utf8", "hex");
}

module.exports = { app, encryptFixed, encrypt };
