const express = require("express");

const app = express();

app.get("/port", (req, res) => {
  // POSITIVE. Radix zero asks the parser to guess the base from the text, so `010` is
  // eight and `0x10` is sixteen -- and the caller writes the text.
  const port = parseInt(req.query.port, 0);
  res.json({ port });
});

app.get("/port-decimal", (req, res) => {
  // NEGATIVE. The base is stated.
  res.json({ port: parseInt(req.query.port, 10) });
});

app.get("/port-default", (req, res) => {
  // NEGATIVE, and a STATED MISS rather than a safe line. An omitted radix is base ten in
  // every runtime since ES5, and reporting it would report most of the JavaScript ever
  // written -- but a very old engine would read `010` as eight here too.
  res.json({ port: parseInt(req.query.port) });
});

module.exports = app;
