import express from "express";
import { requireAuth, requireAdmin } from "./auth";
import { listOrders, getOrder, createOrder, deleteOrder, adminStats, healthCheck } from "./orders";

const app = express();

// Applies to every route below, so it can never distinguish them and must not
// produce a deviation.
app.use(express.json());

app.get("/api/orders", requireAuth, listOrders);
app.get("/api/orders/:id", requireAuth, getOrder);
app.post("/api/orders", requireAuth, createOrder);

// EXPECTED DEVIATION — every comparable route applies requireAuth. This one does
// not. No pattern is present to match; the defect is what is absent.
app.delete("/api/orders/:id", deleteOrder);

app.get("/api/admin/stats", requireAuth, requireAdmin, adminStats);

// Declared public by design in sast-policy.json. The inferred deviation about the
// missing requireAuth is suppressed — visibly, with the declaration named.
app.get("/api/health", healthCheck);

// Declared to require an authorization control. It has authentication only, so this
// is a DECLARED violation and it gates.
app.get("/api/admin/audit", requireAuth, adminStats);

app.listen(3000);
