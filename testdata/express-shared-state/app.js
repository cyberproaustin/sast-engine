const express = require("express");

const app = express();
let currentUser = null;
const sessions = {};

app.post("/login", (req, res) => {
  // POSITIVE. Every request this process handles reads the same variable, so what one
  // caller put there is what the next caller gets -- under load that means answering one
  // person's request with another person's name.
  currentUser = req.body.email;
  res.json({ ok: true });
});

app.post("/login-keyed", (req, res) => {
  // NEGATIVE for THIS rule and a POSITIVE for the one beside it, which is the division
  // of labour this corpus now asserts. A module-level CONTAINER keyed by something is a
  // cache, and what the next request reads is what it asked for, so the shared-state rule
  // stands aside. That the caller also chooses the KEYS, and can grow this map until the
  // process runs out of memory, is the other rule's question and it has one now.
  sessions[req.body.email] = { at: Date.now() };
  res.json({ ok: true });
});

app.post("/login-local", (req, res) => {
  // NEGATIVE, and the discriminator: the identical statement on a name declared inside
  // the handler touches nothing outside it. The declaration's position is the whole
  // evidence, and there is no guessing in it.
  let currentUser = req.body.email;
  res.json({ ok: !!currentUser });
});

app.get("/whoami", (req, res) => {
  res.json({ user: currentUser });
});

module.exports = app;
