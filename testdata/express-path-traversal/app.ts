// Path traversal is its own judgement, not a spelling of injection.
//
// Nothing is executed here. The caller simply chooses a different file than the one the
// application meant to open, which is why it has its own policy and its own context rather
// than being folded into "untrusted input reaches an interpreter".
import express from "express";
import fs from "node:fs";
import path from "node:path";

const app = express();
const ROOT = "/var/data";

app.get("/download", (req, res) => {
  // The caller names the file. The contents are not sent back to them, so that this
  // corpus tests one judgement rather than two: echoing what was read is a separate
  // question about a separate channel.
  const body = fs.readFileSync(path.join(ROOT, String(req.query.name)), "utf8");
  res.json({ bytes: body.length });
});

app.get("/safe-download", (req, res) => {
  // basename reduces the path to its last segment, so no traversal survives it.
  const name = path.basename(String(req.query.name));
  const body = fs.readFileSync(path.join(ROOT, name), "utf8");
  res.json({ bytes: body.length });
});

app.get("/report", (_req, res) => {
  // A fixed path. Nothing untrusted reaches it.
  const body = fs.readFileSync(path.join(ROOT, "report.txt"), "utf8");
  res.json({ bytes: body.length });
});

app.delete("/purge", (req, res) => {
  fs.unlinkSync(path.join(ROOT, String(req.query.name)));
  res.json({ ok: true });
});

export default app;
