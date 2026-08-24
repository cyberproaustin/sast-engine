// Parameterized queries are not a special case here, and that is the point.
//
// A SQL channel names the argument that is INTERPRETED. `execute(sql, params)` reads its
// first argument as SQL and treats the second as data, so untrusted values arriving in
// the params never reach an interpreter and never match the channel. No allowlist, no
// "does this look parameterized" heuristic, and no exception in the policy: the
// distinction the whole defect turns on falls out of describing the destination
// accurately.
import express from "express";

const app = express();

declare const db: {
  query(sql: string, params?: unknown[]): Promise<unknown>;
  raw(sql: string): Promise<unknown>;
};

app.get("/search", async (req, res) => {
  // The caller's value is concatenated into the statement.
  const sql = "SELECT id, name FROM users WHERE login = '" + req.query.login + "'";
  res.json(await db.query(sql));
});

app.get("/by-id", async (req, res) => {
  // Same data, same API, passed as a parameter. Not a finding.
  res.json(await db.query("SELECT id, name FROM users WHERE id = ?", [req.query.id]));
});

app.get("/report", async (req, res) => {
  // A template is still concatenation.
  res.json(await db.raw(`SELECT * FROM reports WHERE owner = '${req.query.owner}'`));
});

app.get("/all", async (_req, res) => {
  // Nothing untrusted reaches it.
  res.json(await db.query("SELECT id, name FROM users"));
});

export default app;
