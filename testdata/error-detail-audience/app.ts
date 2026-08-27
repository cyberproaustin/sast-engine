import express from "express";
import { verifyUser } from "./auth";
import { loadReport } from "./store";

const app = express();

// EXPECTED FINDING, and the one worth acting on. Nothing on this route asks who the
// caller is, so the driver message describes the system to whoever asked for it.
app.get("/api/status/:id", async (req, res) => {
  try {
    res.json(await loadReport(req.params.id, 0));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// EXPECTED FINDING, and it is not the same claim. The same disclosure, reached only by a
// caller who already holds an account: still worth listing, not worth waking anybody for.
// The engine must report it and must not rank it alongside the route above.
app.get("/api/reports/:id", async (req, res) => {
  const user = await verifyUser(req, res);
  try {
    res.json(await loadReport(req.params.id, user.id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// EXPECTED FINDING, authenticated one hop below the handler. A route that dispatches
// before it does anything is the shape a Next.js page route has, and it is where
// linkwarden's eight adjudicated-true-but-not-worth-reporting disclosures sit: the
// control is not in the handler, it is in the function the handler immediately calls.
app.post("/api/reports", async (req, res) => {
  await createReport(req, res);
});

async function createReport(req: express.Request, res: express.Response) {
  const user = await verifyUser(req, res);
  try {
    res.json(await loadReport(req.body.id, user.id));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
}

// EXPECTED CLEAN — the error is kept server-side and the caller gets a fixed message.
// Present so that the corpus measures the rule and not merely the ranking: an audience
// that changes a rank must not start inventing findings to rank.
app.get("/api/health", async (_req, res) => {
  try {
    await loadReport("1", 0);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "internal error" });
  }
});

app.listen(3000);
