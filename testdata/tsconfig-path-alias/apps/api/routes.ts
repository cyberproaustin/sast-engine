// A second package in the same monorepo, and its tsconfig says something DIFFERENT.
// `apps/api/tsconfig.json` inherits `@shared/*` and `@acme/shared` from the base config
// two directories up and declares no `@/` at all, so `@/lib/db` here is not
// `apps/web/lib/db` -- it is nothing. A mapping is per-directory or it is wrong.

import express from "express";
import { auditLog } from "@shared/audit";
import { runReport } from "@acme/shared";
// The other package's alias, which this package never declared.
import { runQuery } from "@/lib/db";

const app = express();

app.post("/api/audit", (req, res) => {
  auditLog(req.body.entry);
  res.json({ ok: true });
});

app.get("/api/report", (req, res) => {
  runReport(req.query.name);
  res.json({ ok: true });
});

app.get("/api/rows", async (req, res) => {
  res.json({ rows: await runQuery(req.query.collection) });
});

export default app;
