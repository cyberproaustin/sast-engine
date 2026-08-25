const express = require("express");
const escapeHtml = require("escape-html");

const app = express();
app.set("view engine", "ejs");

app.get("/search", (req, res) => {
  // The handler is not where this is decided. It hands two named values to a view, and
  // the VIEW decides which of them is escaped -- which is why reading only this file
  // reads the half where nothing happens.
  res.render("products", { query: req.query.q, count: 3, rows: req.query.rows });
});

app.get("/profile", (req, res) => {
  res.render("profile", { user: { name: req.query.name } });
});

app.get("/legal", (req, res) => {
  // NEGATIVE. Nothing the caller sent reaches this view.
  res.render("legal", { updatedAt: "2026-01-01" });
});

app.get("/note", (req, res) => {
  // NEGATIVE, and a STATED MISS rather than a safe line. The locals are built in another
  // function, so the map from a template's variable names to the values behind them does
  // not exist here -- and naming a file on a guess is worse than saying nothing.
  res.render("products", buildLocals(req));
});

function buildLocals(req) {
  return { query: req.query.q, count: 1 };
}

app.get("/comment", (req, res) => {
  // NEGATIVE. Escaped before it ever reaches the view, so the unescaped interpolation
  // receives text that can no longer be markup.
  res.render("comment", { body: escapeHtml(req.query.body) });
});

module.exports = app;
