// Rules the model has shipped for a long time and no fixture had ever exercised.
//
// The companion to flask-symbol-coverage, written after the same diagnostic: for every
// symbol the model names, does any lowered program ever produce it? Most of the ones that
// never had are libraries no corpus happens to use -- which is fine, and unknowable until
// somebody scans a program that uses them. The point of this file is that the description
// and the frontend agree, so a rule that finds nothing is a rule that found nothing rather
// than a rule that could never fire.

import express from "express";
import fetch from "node-fetch";
import * as vm from "vm";
import * as fs from "fs";
import * as http from "http";
import ejs from "ejs";
import nunjucks from "nunjucks";
import escapeHtml from "escape-html";

const app = express();

app.get("/proxy", async (req, res) => {
  // POSITIVE. The caller chooses which host this server talks to.
  const r = await fetch(req.query.url as string);
  res.json({ status: r.status });
});

app.get("/proxy-http", (req, res) => {
  // POSITIVE. The same weakness through the runtime's own client.
  http.get(req.query.url as string, () => res.end());
});

app.post("/run", (req, res) => {
  // POSITIVE. A separate context is not a sandbox: `vm` runs whatever it is given with
  // the host's own globals one prototype away.
  vm.runInNewContext(req.body.code);
  res.json({ ok: true });
});

app.post("/append", (req, res) => {
  // POSITIVE. The caller chooses which file grows.
  fs.appendFile(req.body.path, "entry\n", () => res.end());
});

app.post("/render-ejs", (req, res) => {
  // POSITIVE. A template compiled from a caller's text is a caller's program.
  res.send(ejs.render(req.body.template, {}));
});

app.post("/render-nunjucks", (req, res) => {
  // POSITIVE. The same weakness at a second engine.
  res.send(nunjucks.renderString(req.body.template, {}));
});

app.get("/greet", (req, res) => {
  // NEGATIVE. escape-html neutralizes markup, which is the context this reaches, so the
  // sanitizer is recorded as sufficient and the flow does not survive it.
  res.send("<p>" + escapeHtml(req.query.name as string) + "</p>");
});

app.listen(3000);
