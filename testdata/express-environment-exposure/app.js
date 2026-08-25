const express = require("express");

const app = express();

app.get("/debug", (req, res) => {
  // POSITIVE. Every secret the process was started with: database URL, API keys,
  // signing keys, all of it.
  res.json(process.env);
});

app.get("/debug-wrapped", (req, res) => {
  // POSITIVE. Wrapping it in an object changes nothing about what is in it.
  res.json({ env: process.env, uptime: process.uptime() });
});

app.get("/config", (req, res) => {
  // NEGATIVE. One value the application chose to publish. Applications publish
  // configuration on purpose all the time, and a rule that could not tell the
  // difference would be reporting the ordinary case.
  res.json({ region: process.env.AWS_REGION, version: process.env.APP_VERSION });
});

module.exports = app;
