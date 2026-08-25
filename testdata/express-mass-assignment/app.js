const express = require("express");
const db = require("./db");

const app = express();

app.put("/profile", async (req, res) => {
  // POSITIVE. Every key the caller sent is copied onto the record, including the ones
  // nobody meant to expose: `role`, `isAdmin`, `balance`.
  const user = await db.users.find(req.session.userId);
  Object.assign(user, req.body);
  res.json({ ok: true });
});

app.put("/profile-named", async (req, res) => {
  // NEGATIVE. The application names the fields it accepts. The values are just as
  // untrusted and that is fine -- what matters is that the caller cannot choose WHICH
  // fields get written.
  const user = await db.users.find(req.session.userId);
  Object.assign(user, { displayName: req.body.displayName, bio: req.body.bio });
  res.json({ ok: true });
});

app.put("/defaults", async (req, res) => {
  // NEGATIVE. Nothing the caller sent is copied at all.
  const user = await db.users.find(req.session.userId);
  Object.assign(user, { seenTour: true });
  res.json({ ok: true });
});

app.put("/clone", async (req, res) => {
  // NEGATIVE. Copying the caller's data into a FRESH object is making a mutable copy of
  // the request, which four files in one production repository do. Nothing is written
  // to a record, because there is no record: the target was created on this line.
  const params = Object.assign({}, req.body, req.query);
  res.json({ got: Object.keys(params).length });
});

module.exports = app;
