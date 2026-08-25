const express = require("express");
const session = require("express-session");

const app = express();
app.use(session({ secret: process.env.SESSION_SECRET }));

// POSITIVE. The identity is installed and the identifier that names the session is the
// one the browser already had -- which an attacker may have planted before the login.
app.post("/login", (req, res) => {
  const user = lookup(req.body.username, req.body.password);
  req.session.userId = user.id;
  res.json({ ok: true });
});

// POSITIVE, and the reason the rule looks for the rotation rather than for the write: the
// assignment is in a helper, and no rotation happens in the route either.
app.post("/login-helper", (req, res) => {
  markLoggedIn(req.session, lookup(req.body.username, req.body.password));
  res.json({ ok: true });
});

function markLoggedIn(session, user) {
  session.isAdmin = user.isAdmin;
}

// NEGATIVE, and the correct way to write it: the identifier is rotated and the identity is
// installed inside the callback, which is where the new session exists.
app.post("/login-rotated", (req, res) => {
  const user = lookup(req.body.username, req.body.password);
  req.session.regenerate(() => {
    req.session.userId = user.id;
    res.json({ ok: true });
  });
});

// NEGATIVE. The same rotation written as a promise, which is how most code actually does
// it -- the rotation is two functions away from the assignment.
app.post("/login-promise", async (req, res) => {
  const user = lookup(req.body.username, req.body.password);
  await rotate(req);
  req.session.userId = user.id;
  res.json({ ok: true });
});

function rotate(req) {
  return new Promise((resolve) => req.session.regenerate(resolve));
}

// NEGATIVE. Clearing an identity is a logout: the opposite of this weakness, written with
// the same syntax.
app.post("/logout", (req, res) => {
  req.session.userId = null;
  res.json({ ok: true });
});

// NEGATIVE. A session that is not the caller's. An administrative page listing who is
// logged in writes to other people's sessions in a loop, and that is not a login.
app.get("/admin/logins", (req, res) => {
  const rows = allSessions();
  rows.forEach((session) => {
    session.user = describe(session.uid);
  });
  res.json(rows);
});

// NEGATIVE. A session carries more than a principal, and rewriting a basket or a language
// preference is not a change of identity.
app.post("/cart", (req, res) => {
  req.session.basket = req.body.items;
  req.session.locale = req.body.locale;
  res.json({ ok: true });
});

function lookup(u, p) { return { id: 1, isAdmin: false }; }
function allSessions() { return []; }
function describe(uid) { return { uid }; }

module.exports = app;
