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
  // POSITIVE, at the coarser granularity. This is not a search path, so it is not
  // CWE-427 -- but the environment is inherited by every process this one starts and is
  // where libraries look for their own configuration, so a caller who can write to it
  // reconfigures things that never read the request. Exactly one of the two rules fires
  // on each of these lines, which is what the exclusion is for.
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
