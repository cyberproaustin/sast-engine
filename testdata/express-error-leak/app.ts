import express from "express";
import { loadOrder, auditSink } from "./db";

const app = express();

// EXPECTED FINDING — the caught error reaches the response body. Driver messages
// carry schema, query text, and stack detail.
app.get("/api/orders/:id", async (req, res) => {
  try {
    res.json(await loadOrder(req.params.id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// EXPECTED CLEAN — the error is kept server-side and the caller gets a generic
// message. Logging an error is not exposing it.
app.get("/api/health", async (req, res) => {
  try {
    await loadOrder("1");
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "internal error" });
  }
});

// EXPECTED CLEAN — .json() called on something that is not the response object. A
// sink matched by method name alone would flag this; receiver narrowing is what
// makes the response sink mean the response.
app.get("/api/audit", async (req, res) => {
  try {
    await loadOrder("1");
    res.json({ ok: true });
  } catch (err) {
    auditSink.json({ error: err.message });
    res.status(500).json({ error: "internal error" });
  }
});

app.listen(3000);
