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
  // NEGATIVE, and a STATED MISS rather than a safe line. The whole-value requirement
  // means this is not reported, because a fixed base with a variable leaf is what every
  // plugin loader ever written looks like and reporting them all would make the rule
  // unusable. But a leaf containing `../` escapes the directory, so this is not safe --
  // it is a case the rule declines to judge, and saying otherwise would be a comment
  // that lies about the code beneath it.
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
