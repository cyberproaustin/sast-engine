/**
 * The request half. Nothing here is a finding; these are the routes that FILL the store
 * the background code later reads, and without them every read below answers with
 * something the program wrote for itself.
 */
import express from "express";

import { db } from "./platform";

const app = express();

// A caller's text goes into one column of the job table.
app.post("/jobs", async (req, res) => {
  await db.job.create({ data: { command: req.body.command, state: "queued" } });
  res.end();
});

// And into one column of the webhook table.
app.post("/webhooks", async (req, res) => {
  await db.webhook.create({ data: { target: req.body.target } });
  res.end();
});

export default app;
