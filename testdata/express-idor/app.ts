import express from "express";
import { requireAuth } from "./auth";
import { prisma } from "./prisma";

const app = express();

// EXPECTED FINDING — the caller chooses which order is returned, and this handler
// never consults who the caller is. Authentication is present; authorization is not.
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id } });
  res.json(order);
});

// EXPECTED FINDING — same judgement on a destructive operation. Nothing about the
// policy mentions reads.
app.delete("/api/orders/:id", requireAuth, async (req, res) => {
  await prisma.order.delete({ where: { id: req.params.id } });
  res.json({ ok: true });
});

// EXPECTED CLEAN — the record's owner is compared against the caller.
app.get("/api/orders/:id/detail", requireAuth, async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id } });
  if (order.userId !== req.user.id) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  res.json(order);
});

// EXPECTED CLEAN — the query is scoped by the caller's identity rather than by a
// caller-supplied identifier.
app.get("/api/orders", requireAuth, async (req, res) => {
  res.json(await prisma.order.findMany({ where: { userId: req.user.id } }));
});

// EXPECTED FINDING — the ownership check is present and comes first, but it decides
// nothing: the response happens either way. Position is not enforcement.
app.get("/api/orders/:id/audited", requireAuth, async (req, res) => {
  const order = await prisma.order.findUnique({ where: { id: req.params.id } });
  if (order.userId !== req.user.id) {
    console.warn("cross-user access");
  }
  res.json(order);
});

// EXPECTED CLEAN — same comparison, but this one returns, so the read below is
// reached only when the check passes.
app.get("/api/orders/:id/guarded", requireAuth, async (req, res) => {
  const existing = await prisma.order.findUnique({ where: { id: req.params.id } });
  if (existing.userId !== req.user.id) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  res.json(existing);
});

// EXPECTED CLEAN — a real ownership check where the caller's identity arrives through
// a non-null assertion. A frontend that truncates the property chain at `!` loses the
// identity, fails to recognize the guard, and reports this as unchecked: a false
// positive caused purely by syntax. Found by running against a real codebase.
app.get("/api/orders/:id/asserted", requireAuth, async (req, res) => {
  const found = await prisma.order.findUnique({ where: { id: req.params.id } });
  if (found.userId !== req.user!.id) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  res.json(found);
});

// EXPECTED CLEAN — the ownership check is in the handler and the operation is in a
// private helper. Services are written this way constantly, and a guard check confined
// to the function holding the operation reports this as unchecked: a false positive
// found by running against a real codebase.
app.patch("/api/orders/:id", requireAuth, async (req, res) => {
  const owned = await prisma.order.findUnique({ where: { id: req.params.id } });
  if (owned.userId !== req.user.id) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  await renameOrder(req.params.id);
  res.json({ ok: true });
});

async function renameOrder(id) {
  await prisma.order.update({ where: { id } });
}

// EXPECTED CLEAN, BUT ONLY ONCE DECLARED — registration looks up a user by a
// caller-supplied username to check availability. There is no actor yet, so an
// ownership comparison is incoherent rather than missing. Code cannot tell this from
// an unauthenticated data endpoint, so the team states it (ADR-011).
app.post("/api/auth/register", async (req, res) => {
  const taken = await prisma.user.findUnique({ where: { username: req.body.username } });
  res.json({ available: !taken });
});

app.listen(3000);
