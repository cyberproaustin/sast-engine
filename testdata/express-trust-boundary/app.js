const express = require("express");

const app = express();

app.post("/login", (req, res) => {
  // POSITIVE. A session is read back as state the server established. Putting the
  // caller's own claim there launders it across the trust boundary, and by the time
  // anything downstream reads `req.session.role`, the fact that the caller chose it is
  // gone.
  req.session.role = req.body.role;
  res.json({ ok: true });
});

app.post("/login-checked", (req, res) => {
  // NEGATIVE. What goes into the session is what the server decided, not what arrived.
  req.session.role = lookupRole(req.body.email);
  res.json({ ok: true });
});

app.post("/prefs", (req, res) => {
  // NEGATIVE. The caller's own preference is the caller's to choose, and it is not
  // written into the session.
  res.cookie("theme", req.body.theme, { httpOnly: false });
  res.json({ ok: true });
});

function lookupRole(email) {
  return email.endsWith("@example.com") ? "staff" : "user";
}

module.exports = app;
