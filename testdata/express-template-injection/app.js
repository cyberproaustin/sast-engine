const express = require("express");
const handlebars = require("handlebars");

const app = express();

const PAGE = handlebars.compile("<h1>{{title}}</h1>");

app.get("/preview", (req, res) => {
  // POSITIVE. The caller's text becomes the template SOURCE. Handlebars compiles to
  // JavaScript, so this is code execution rather than markup injection.
  const template = handlebars.compile(req.query.layout);
  res.send(template({ title: "Preview" }));
});

app.get("/page", (req, res) => {
  // NEGATIVE. A template compiled once from a literal. This is the shape almost all
  // real code has, and it is what keeps this rule usable: three of the production
  // repositories in the corpus call handlebars.compile exactly this way.
  //
  // The render deliberately uses a fixed value rather than caller data. Passing caller
  // data to an already-compiled template is safe for a different reason -- the engine
  // escapes it -- and this engine does not model template auto-escaping, so including
  // it here would test two judgements and fail on the one this corpus is not about.
  res.send(PAGE({ title: "Home" }));
});

module.exports = app;
