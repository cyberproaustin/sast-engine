const http = require("http");
const express = require("express");

const app = express();

app.post("/tools/register", (req, res) => {
  // POSITIVE. The search path decides which binary the next exec actually runs, so a
  // caller who can write to it chooses the program without touching the call that runs
  // it -- and nothing about that call looks wrong afterwards.
  process.env.PATH = req.body.toolDir + ":" + process.env.PATH;
  res.json({ ok: true });
});

app.post("/tools/label", (req, res) => {
  // NEGATIVE. An environment variable that decides nothing about where code comes from.
  process.env.APP_LABEL = req.body.label;
  res.json({ ok: true });
});

app.post("/buffer", (req, res) => {
  // POSITIVE. One request asking for a gigabyte is not a crash the caller had to find;
  // it is one they asked for.
  const buf = Buffer.alloc(req.body.size);
  res.json({ length: buf.length });
});

// POSITIVE. The lenient parser exists for peers that send malformed requests, and
// leniency is what request smuggling needs: two parsers in a chain disagreeing about
// where one request ends and the next begins.
const server = http.createServer({ insecureHTTPParser: true }, app);

// NEGATIVE.
const strict = http.createServer({}, app);

module.exports = { app, server, strict };
