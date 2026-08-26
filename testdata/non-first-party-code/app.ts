import express from "express";

const app = express();
const productionKey = "AKIAIOSFODNN7EXAMPLE";

app.get("/application", (_req, res) => res.send(productionKey));

// A handler-shaped function outside the enumerated surface is the completeness signal.
// The matching examples below must not dilute or satisfy that application-only count.
export function applicationInputNotReached(req: { query: { value: string } }) {
  return req.query.value;
}
