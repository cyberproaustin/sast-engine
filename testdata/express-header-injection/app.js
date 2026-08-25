const crypto = require("crypto");
const express = require("express");

const app = express();

app.get("/download", (req, res) => {
  // POSITIVE. A carriage return and a newline end the header and begin whatever the
  // caller writes next: another header, or the body.
  res.setHeader("Content-Disposition", `attachment; filename="${req.query.name}"`);
  res.send("ok");
});

app.get("/download-fixed", (req, res) => {
  // NEGATIVE. Nothing the caller sent reaches the header.
  res.setHeader("Content-Disposition", 'attachment; filename="report.csv"');
  res.send("ok");
});

function encryptLegacy(secret, plaintext) {
  // POSITIVE. createCipher derives its key with a single unsalted MD5 of the
  // passphrase, so two applications sharing a passphrase share a key. Node removed it.
  const cipher = crypto.createCipher("aes-256-cbc", secret);
  return cipher.update(plaintext, "utf8", "hex");
}

module.exports = { app, encryptLegacy };
