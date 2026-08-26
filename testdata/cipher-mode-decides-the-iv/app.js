// The first argument decides what the third one MEANS.
//
// `createCipheriv(alg, key, iv)` holds an initialisation vector in the third slot in
// every mode that has one and holds nothing in ECB, which has none: Node still requires
// the argument and an empty string is the ordinary way to write it. A rule that read the
// third argument without the first was judging an argument whose meaning had not been
// established, and reported an NTLM implementation's `createCipheriv("DES-ECB", key, "")`
// as a predictable IV -- on a line whose real weakness, single-DES in ECB, was already
// being reported correctly one rule over.
//
// The same mistake in the other construction: `createHmac("md5", key)` is not
// `createHash("md5")`. What makes an HMAC sound is the key and the construction, not the
// hash's collision resistance, and HMAC-MD5 has no practical forgery -- so a rule about
// digests broken against collision has nothing to say about it.

const crypto = require("crypto");
const express = require("express");

const app = express();
const KEY = Buffer.from(process.env.DATA_KEY, "hex");

app.post("/ntlm", (req, res) => {
  // NEGATIVE for the IV. ECB has no initialisation vector and the empty third argument
  // is what Node requires; there is nothing predictable about a slot that holds nothing.
  //
  // POSITIVE for the mode, which is the true statement about this line and is made by a
  // rule that reads argument ZERO: single-DES in ECB, where identical plaintext blocks
  // encrypt to identical ciphertext blocks.
  const des = crypto.createCipheriv("DES-ECB", KEY, "");
  res.json({ out: des.update(req.body.message).toString("hex") });
});

app.post("/store", (req, res) => {
  // POSITIVE. CBC takes an IV, this one is written into the source, and it is therefore
  // both predictable and the same for every message.
  const c = crypto.createCipheriv("aes-256-cbc", KEY, "0123456789abcdef");
  res.json({ blob: Buffer.concat([c.update(req.body.note, "utf8"), c.final()]).toString("hex") });
});

app.post("/store-configured", (req, res) => {
  // POSITIVE, and the reason the mode test is written as a veto rather than as a list of
  // the modes that do take an IV. The algorithm is a configuration value and cannot be
  // read here; the IV is still written down. An argument nobody wrote down disqualifies
  // nothing, so the finding stands.
  const c = crypto.createCipheriv(process.env.DATA_ALG, KEY, "0123456789abcdef");
  res.json({ blob: Buffer.concat([c.update(req.body.note, "utf8"), c.final()]).toString("hex") });
});

app.post("/legacy", (req, res) => {
  // NEGATIVE for the IV twice over: the mode has none, and the argument says so.
  const c = crypto.createCipheriv("aes-256-ecb", KEY, null);
  res.json({ blob: Buffer.concat([c.update(req.body.note, "utf8"), c.final()]).toString("hex") });
});

app.post("/verify-hmac", (req, res) => {
  // NEGATIVE. A keyed MAC over MD5. Its security rests on the key, and forging one
  // needs the key rather than a collision -- so the judgement a collision rule makes is
  // not a judgement about this call.
  const mac = crypto.createHmac("md5", KEY).update(req.body.body).digest();
  const ok = crypto.timingSafeEqual(mac, Buffer.from(req.body.signature, "hex"));
  res.json({ ok });
});

app.post("/verify-digest", (req, res) => {
  // POSITIVE, and the contrast that makes the negative above a judgement rather than an
  // exemption. An unkeyed MD5 standing in for the thing it was computed from is the one
  // job that needs collision resistance, and a verification call is the program saying
  // in its own code that this is the job.
  const digest = crypto.createHash("md5").update(req.body.body).digest();
  const ok = crypto.timingSafeEqual(digest, Buffer.from(req.body.signature, "hex"));
  res.json({ ok });
});

module.exports = app;
