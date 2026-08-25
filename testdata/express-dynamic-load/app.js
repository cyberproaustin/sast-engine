const express = require("express");
const _ = require("lodash");

const app = express();
const settings = { theme: "light", limits: { rows: 50 } };

app.post("/plugin", (req, res) => {
  // POSITIVE. The caller names a module and the runtime loads and runs it.
  const plugin = require(req.body.module);
  res.json({ name: plugin.name });
});

app.post("/handler", (req, res) => {
  // NEGATIVE. The directory is fixed in the literal, so the caller chooses a leaf name
  // inside it and cannot reach anywhere else. Every plugin loader ever written looks
  // like this, and reporting it would make the rule unusable.
  const handler = require("./handlers/" + req.body.name);
  res.json({ ok: typeof handler });
});

app.post("/settings", (req, res) => {
  // POSITIVE. merge walks nested keys, so a `__proto__` key in the caller's object
  // reaches the prototype every other object inherits from.
  _.merge(settings, req.body);
  res.json(settings);
});

app.post("/settings-named", (req, res) => {
  // NEGATIVE. The application names the field it accepts.
  _.merge(settings, { theme: req.body.theme });
  res.json(settings);
});

module.exports = app;
