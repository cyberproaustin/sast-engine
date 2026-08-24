// A vulnerability class nobody wrote a rule for: internal failure detail forwarded to
// a third-party service. No policy was added for this. The only thing the model
// gained is a DESCRIPTION of what kind of channel an outbound HTTP call is.

import express from "express";
import axios from "axios";
import { loadOrder } from "./db";

const app = express();

app.get("/api/orders/:id", async (req, res) => {
  try {
    res.json(await loadOrder(req.params.id));
  } catch (err) {
    // EXPECTED FINDING — internal-error data reaching a thirdparty-visible channel.
    axios.post("https://hooks.example.com/alerts", { detail: err.message });
    res.status(500).json({ error: "internal error" });
  }
});

// EXPECTED CLEAN — forwarding a caller's own input to a third party is not, by
// itself, a boundary violation. No policy forbids that pairing, and inventing one
// would flag every integration in the codebase.
app.post("/api/forward", (req, res) => {
  axios.post("https://hooks.example.com/ingest", { payload: req.body.note });
  res.json({ ok: true });
});

app.listen(3000);
