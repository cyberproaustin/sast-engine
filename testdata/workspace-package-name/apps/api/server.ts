// An Express app in a workspace monorepo, importing its own packages the only way a
// monorepo ever does: by the NAME each package.json publishes. There is no tsconfig
// `paths` table here and no `node_modules` to symlink through -- the manifests in this
// tree are the whole mapping, exactly as in a fresh clone of any pnpm/npm/yarn workspace.
//
// Without reading them every call below lowers as `external`, `req.query` never enters a
// parameter, and four shells one package boundary away are unreachable.

import express from "express";
import { purgeLinks } from "@acme/store";
import { runQuery } from "@acme/store/queries/run";
import { renderReport } from "@acme/build-output";
import { recordAudit } from "@acme/mapped/audit";
import { monthly } from "@acme/mapped/reports/monthly";
// Two packages in this tree publish `@acme/twins`. Nothing says which one the specifier
// means, so it must resolve to NOTHING: picking either invents a call edge into a
// function the program may never have called, and a fabricated flow is worse than a
// missing one.
import { sweep } from "@acme/twins";
// No package.json in this tree declares this name. It is an ordinary dependency the
// checkout does not contain, and it must stay external for the same reason.
import { renderWidget } from "@acme/absent";

export const app = express();

// `main: "./index.ts"` -- the package names its own entry, and it exists.
app.delete("/links", (req, res) => {
  purgeLinks(req.query.ids);
  res.sendStatus(204);
});

// A SUBPATH with no `exports` map: `packages/store/queries/run.ts`, which is how
// documenso writes every one of its 5,646 cross-package calls.
app.get("/query", (req, res) => {
  res.json({ rows: runQuery(req.query.collection) });
});

// Every declared entry names an unbuilt `dist/`, which is medplum's shape: nothing there
// exists in a source checkout, so the package's own `src/index.ts` is what answers.
app.get("/report", (req, res) => {
  res.json({ report: renderReport(req.query.name) });
});

// An `exports` map whose target is NOT where the conventional roots would look:
// `./audit` is `src/checks/audit.ts`. Only the declared mapping can answer it.
app.post("/audit", (req, res) => {
  recordAudit(req.body.entry);
  res.sendStatus(202);
});

// The same map's wildcard: `./reports/*` -> `./src/checks/reports/*.ts`.
app.get("/monthly", (req, res) => {
  res.json({ summary: monthly(req.query.period) });
});

// Negatives. Both callees stay external, so neither shell behind them is reported.
app.post("/sweep", (req, res) => {
  sweep(req.body.pattern);
  res.sendStatus(202);
});

app.get("/widget", (req, res) => {
  res.json({ widget: renderWidget(req.query.view) });
});
