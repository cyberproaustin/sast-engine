const crypto = require("crypto");
const express = require("express");
const seedrandom = require("seedrandom");

const app = express();

app.get("/session", (req, res) => {
  // POSITIVE. A value a caller must not be able to guess, built from the clock. An
  // attacker who knows roughly when it was issued has a few thousand candidates.
  res.cookie("session", String(Date.now()), { httpOnly: true, secure: true, sameSite: "lax" });
  res.json({ ok: true });
});

app.get("/issued", (req, res) => {
  // NEGATIVE. The clock is a timestamp here, which is what the clock is for. The
  // classification is at the source and the judgement is at the sink, so an ordinary
  // use of Date.now() is not a finding anywhere.
  res.json({ issuedAt: Date.now() });
});

app.get("/shuffle", (req, res) => {
  // POSITIVE. The seed decides every number that follows it.
  const rng = seedrandom(String(Date.now()));
  res.json({ pick: rng() });
});

app.get("/nonce", (req, res) => {
  // POSITIVE. A good generator asked for too little, and this is the sink that says so:
  // four random bytes are four billion candidates, which is a weekend for anyone who
  // wants the session. The same call four lines down is a filename suffix and is silent.
  res.cookie("sid", crypto.randomBytes(4).toString("hex"), { httpOnly: true, secure: true, sameSite: "lax" });
  res.json({ ok: true });
});

app.get("/upload-name", (req, res) => {
  // NEGATIVE. The identical call, used where the only requirement is uniqueness. Every
  // short random value in the clean corpus was one of these -- a suffix, a parameter
  // name, a temporary table, a slug checked for collisions in a loop -- which is why the
  // length is judged at the sink and never at the call.
  res.json({ name: `upload-${crypto.randomBytes(4).toString("hex")}.bin` });
});

app.get("/token", (req, res) => {
  // NEGATIVE. Thirty-two bytes from a generator built for unpredictability.
  res.json({ token: crypto.randomBytes(32).toString("hex") });
});

// POSITIVE. The project root served whole: the environment file, the version control
// directory, the source, and whatever else was left there.
app.use(express.static("."));

// NEGATIVE. A directory that exists to be served.
app.use(express.static("public"));

module.exports = app;
