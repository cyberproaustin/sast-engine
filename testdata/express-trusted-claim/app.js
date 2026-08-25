const express = require("express");

const app = express();

app.post("/admin/purge", (req, res) => {
  // POSITIVE. A field the caller sent is a statement the caller made about themselves,
  // and a branch that trusts it lets them choose which branch runs.
  if (req.body.role === "admin") {
    purgeEverything();
    return res.json({ purged: true });
  }
  res.status(403).json({ error: "forbidden" });
});

app.post("/admin/purge-cookie", (req, res) => {
  // POSITIVE, and its own weakness: a cookie is a value the browser was handed and
  // hands back, and getting it back is no evidence it came from here unchanged.
  if (req.cookies.isAdmin === "true") {
    purgeEverything();
    return res.json({ purged: true });
  }
  res.status(403).json({ error: "forbidden" });
});

app.post("/admin/purge-checked", (req, res) => {
  // NEGATIVE. The privilege is read from the session the server established, not from
  // anything the caller sent.
  if (req.user.role === "admin") {
    purgeEverything();
    return res.json({ purged: true });
  }
  res.status(403).json({ error: "forbidden" });
});

app.get("/search", (req, res) => {
  // NEGATIVE. Caller-supplied and compared, and not a claim about authority: sorting is
  // the caller's to choose.
  if (req.query.sort === "recent") {
    return res.json({ order: "recent" });
  }
  res.json({ order: "default" });
});

function purgeEverything() {}

module.exports = app;
