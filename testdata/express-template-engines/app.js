const express = require("express");

const app = express();

app.get("/page", (req, res) => {
  // Pug marks the unsafe form with a `!`: `#{x}` and `= x` escape, `!{x}` and `!= x` do
  // not. One character again, in a different alphabet.
  res.render("page", { bio: req.query.bio, tagline: req.query.tagline, title: req.query.title });
});

app.get("/card", (req, res) => {
  // Handlebars marks it with a third brace, or an ampersand.
  res.render("card", { body: req.query.body, note: req.query.note, heading: req.query.heading });
});

module.exports = app;
