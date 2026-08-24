// False-positive corpus. Every route here is safe, and each is safe for a reason a
// naive taint engine gets wrong. Any finding produced against this file is a bug.
//
// Precision claims need a denominator: recall corpora show what a tool catches,
// this shows what it inflicts.

import express from "express";
import { execFile, exec } from "child_process";
import { quote } from "shell-quote";
import { renderStatus, buildReport } from "./report";

const app = express();

const ALLOWED_HOSTS = ["alpha.internal", "beta.internal"];

// Safe: execFile does not spawn a shell. Taint reaches the argument array, and
// that is genuinely not command injection.
app.get("/ping", (req, res) => {
  execFile("ping", ["-c", "1", req.query.host]);
  res.send("queued");
});

// Safe: the tainted value is quoted for exactly the context it lands in.
app.get("/dig", (req, res) => {
  const safe = quote([req.query.domain]);
  exec(`dig ${safe}`);
  res.send("queued");
});

// Safe: untrusted input selects an index, never the command text.
app.get("/probe", (req, res) => {
  const index = Number(req.query.index);
  const host = ALLOWED_HOSTS[index] ?? ALLOWED_HOSTS[0];
  exec(`ping -c 1 ${host}`);
  res.send("queued");
});

// Safe: tainted data flows to a non-dangerous sink. Reaching *a* function is not
// reaching a *sink*.
//
// The destination is res.json rather than res.send deliberately. Express sends a string
// body as text/html, so `res.send(userInput)` is reflected XSS and this corpus -- the
// denominator for every precision number the project reports -- would contain a real
// defect. A JSON body is not parsed as markup, which keeps the point being made here
// (helpers are not sinks) without asserting something false alongside it.
app.get("/echo", (req, res) => {
  const message = buildReport(req.query.note);
  res.json({ status: renderStatus(message) });
});

// Safe: the command is built entirely from literals; the taint goes elsewhere.
app.get("/uptime", (req, res) => {
  const label = req.query.label;
  exec("uptime");
  res.json({ status: renderStatus(label) });
});

// Safe: this helper handles untrusted data but is never registered as a route, so
// nothing untrusted reaches it. Reachability matters, not resemblance.
export function unusedHelper(value: string): void {
  exec(`echo ${value}`);
}

app.listen(3000);
