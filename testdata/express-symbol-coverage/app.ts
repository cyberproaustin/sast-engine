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
import * as mathjs from "mathjs";
import { sanitizer } from "./sanitizer";

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

app.post("/calc", (req, res) => {
  // POSITIVE. An expression evaluator is an interpreter. mathjs looks like arithmetic and
  // is not: its expression language reaches the host through function definitions and
  // property access, which is why its own advisories are remote code execution.
  res.json({ value: mathjs.evaluate(req.body.expr) });
});

app.get("/trusted", (req, res) => {
  // POSITIVE. Angular escapes everything it renders and offers exactly one way out,
  // spelled so nobody uses it by accident -- which makes it the clearest possible
  // statement that whatever reaches it goes into the page as markup.
  res.send(sanitizer.bypassSecurityTrustHtml(req.query.note as string));
});

app.get("/render-note", (req, res) => {
  // POSITIVE, and it needs no call at all: the assignment IS the parse. This is the
  // browser-side twin of an unescaped template interpolation, and a rule that watches
  // calls cannot see it.
  const el: any = element();
  el.innerHTML = req.query.note;
  // NEGATIVE. The same assignment with the parsing turned off, which is the fix.
  el.textContent = req.query.note;
  res.end();
});

function element(): any {
  return {};
}
