// Cross-site scripting, found by a policy written for operating-system shells.
//
// No policy was added for this corpus. `untrusted-to-interpreter` already says a caller
// must not choose what an interpreter executes, and a browser parsing a response body is
// an interpreter, so describing the channel was the entire change (ADR-012). The finding
// says CWE-79 rather than CWE-78 because the channel carries the weakness identity while
// the policy carries the judgement.
import express from "express";
import escapeHtml from "escape-html";

const app = express();

app.get("/greet", (req, res) => {
  // Express sends a string body as text/html, so this is parsed as markup.
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

app.get("/safe-greet", (req, res) => {
  // Escaped for the context that actually applies.
  res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`);
});

app.get("/api/greet", (req, res) => {
  // A JSON body is not parsed as markup. Same data, different destination.
  res.json({ greeting: req.query.name });
});

app.get("/url-encoded", (req, res) => {
  // A URL encoder is not an HTML encoder. Considered and insufficient, not clearing.
  res.send(`<a href="/x">${encodeURIComponent(req.query.name)}</a>`);
});

export default app;
