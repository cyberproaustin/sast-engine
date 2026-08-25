const express = require("express");
const libxmljs = require("libxmljs");

const app = express();

app.post("/import", (req, res) => {
  // POSITIVE. `noent` tells the parser to resolve entities, so a document the caller
  // supplies can name a file on the server and have its contents inlined.
  const doc = libxmljs.parseXmlString(req.body.xml, { noent: true, noblanks: true });
  res.json({ nodes: doc.root().childNodes().length });
});

app.post("/import-safe", (req, res) => {
  // NEGATIVE. The same parser, not asked to resolve entities. This is the safe way to
  // parse XML and is by far the more common one.
  const doc = libxmljs.parseXmlString(req.body.xml, { noblanks: true });
  res.json({ nodes: doc.root().childNodes().length });
});

app.post("/import-default", (req, res) => {
  // NEGATIVE. No options at all: libxmljs does not resolve entities unless asked.
  const doc = libxmljs.parseXmlString(req.body.xml);
  res.json({ nodes: doc.root().childNodes().length });
});

module.exports = app;
