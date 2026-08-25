const express = require("express");

const app = express();

app.get("/port", (req, res) => {
  // POSITIVE. Radix zero asks the parser to guess the base from the text: `0x10` parses
  // as sixteen and `16` as sixteen, so two different strings the caller may send mean the
  // same number, and one of them was not supposed to be accepted at all. (The leading-zero
  // octal reading is NOT part of this: ES5 removed it, and `010` is ten in any runtime
  // written this century.)
  const port = parseInt(req.query.port, 0);
  res.json({ port });
});

app.get("/port-decimal", (req, res) => {
  // NEGATIVE. The base is stated.
  res.json({ port: parseInt(req.query.port, 10) });
});

app.get("/port-default", (req, res) => {
  // NEGATIVE, and a STATED MISS rather than a safe line. An omitted radix behaves like
  // radix 0 -- `0x10` is still sixteen -- so this has the same defect as the route above.
  // It is not reported because `parseInt(x)` is most of the JavaScript ever written, and a
  // rule that fires on all of it would be read by nobody.
  res.json({ port: parseInt(req.query.port) });
});

module.exports = app;
