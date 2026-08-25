const express = require("express");
const reviews = require("./reviews");

const app = express();

app.get("/reviews/:id", async (req, res) => {
  // POSITIVE. `$where` takes a JavaScript EXPRESSION and MongoDB evaluates it on the
  // server, so the caller's text is the caller's code -- the same judgement as eval, at
  // a different interpreter. What names it is the option rather than the method: `find`,
  // `updateMany` and every wrapper over them accept it.
  res.json(await reviews.find({ $where: `this.id == '${req.params.id}'` }));
});

app.get("/reviews-by-id/:id", async (req, res) => {
  // NEGATIVE. A field equality is data, not an expression: MongoDB compares it and never
  // evaluates it, and the same method call is silent because the option is what matters.
  res.json(await reviews.find({ id: req.params.id }));
});

module.exports = app;
