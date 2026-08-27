/**
 * A check about one accessor, and an operation through another.
 *
 * Every handler here authorizes the caller before it does anything, and every one of
 * them authorizes by IDENTITY rather than by record: `isProjectAdmin()` asks whether the
 * caller administers the project their context was built for, and it is handed no
 * identifier at all. The scope that question established is therefore not a value in the
 * request -- it is the context object the authentication layer put the caller inside --
 * which is why the rule beside this one, which relates two request keys, has nothing to
 * compare here and correctly says nothing.
 *
 * What separates the findings from the clean routes is which accessor of that context
 * did the work. `ctx.repo` cannot see outside the caller's project. `ctx.systemRepo`
 * can see everything. A handler that asks the first one for permission and then selects
 * a caller-named record through the second has proved nothing about what it reached.
 *
 * Nothing in this judgement knows which of the two is the privileged one, and nothing
 * needs to: the defect is the swap. Reversing the roles -- asking the elevated
 * repository and operating through the scoped one -- is the same finding, because in
 * both directions the answer belongs to an object the operation did not use.
 */
import express from "express";

import { generateSecret, getAuthenticatedContext, limits } from "./context";

const app = express();

// EXPECTED FINDING. The medplum rotate-secret shape, which is where this came from.
// The check admits any project administrator; the record is then read and rewritten
// through the repository built with the server's own authority, keyed by the id in the
// route, and nothing asks whether that client belongs to the caller's project. An
// administrator of any project reaches a client application in any other.
//
// The operation sits inside a callback, which is where this kind of code lives: the
// handler returned long before the closure was constructed, so the check above still
// governs it.
app.post("/clients/:id/rotate-secret", async (req, res) => {
  const ctx = getAuthenticatedContext();
  if (!(await ctx.repo.isSuperAdmin()) && !(await ctx.repo.isProjectAdmin())) {
    res.status(403).send();
    return;
  }

  const systemRepo = ctx.systemRepo;
  const rotated = await systemRepo.withTransaction(async (tx) => {
    const client = await tx.readResource("ClientApplication", req.params.id);
    return tx.updateResource({ ...client, secret: generateSecret(32) });
  });

  res.json(rotated);
});

// EXPECTED FINDING, and the same weakness with no callback in it. A callback is where
// the shape usually hides, not what makes it a defect.
app.post("/clients/:id/disable", async (req, res) => {
  const ctx = getAuthenticatedContext();
  if (!(await ctx.repo.isProjectAdmin())) {
    res.status(403).send();
    return;
  }

  const client = await ctx.systemRepo.readResource("ClientApplication", req.params.id);
  await ctx.systemRepo.updateResource({ ...client, disabled: true });
  res.json({ ok: true });
});

// EXPECTED CLEAN, and this is the fix for the two above. The record is fetched through
// the very repository the check was about, so it cannot be one the caller's project does
// not hold; the elevated repository then writes a field the caller must not be able to
// set, which is what it is for. The relation is established by the lookup rather than by
// a comparison, which is how this is normally written.
app.post("/clients/:id/retire-secret", async (req, res) => {
  const ctx = getAuthenticatedContext();
  if (!(await ctx.repo.isProjectAdmin())) {
    res.status(403).send();
    return;
  }

  const client = await ctx.repo.readResource("ClientApplication", req.params.id);
  await ctx.systemRepo.updateResource({ ...client, retiringSecret: undefined });
  res.json({ ok: true });
});

// EXPECTED CLEAN. The selection carries the caller's own scope, so it cannot reach a
// record outside it however the caller spells the id. The constraint is in the selection
// rather than in a check above it, and a rule that demanded a comparison would report
// every multi-tenant query ever written.
app.post("/clients/:id/rename", async (req, res) => {
  const ctx = getAuthenticatedContext();
  if (!(await ctx.repo.isProjectAdmin())) {
    res.status(403).send();
    return;
  }

  const client = await ctx.systemRepo.readResource("ClientApplication", req.params.id, ctx.project);
  await ctx.systemRepo.updateResource({ ...client, name: "renamed" });
  res.json({ ok: true });
});

// EXPECTED CLEAN. Asked and acted through the same accessor. There is no second
// authority in this handler and nothing to relate -- and it stays clean whichever
// accessor that is, because the rule is about the swap and not about privilege.
app.post("/clients/:id/touch", async (req, res) => {
  const ctx = getAuthenticatedContext();
  if (!(await ctx.repo.isProjectAdmin())) {
    res.status(403).send();
    return;
  }

  await ctx.repo.updateResource({ id: req.params.id, touched: true });
  res.json({ ok: true });
});

// EXPECTED CLEAN. The check was handed the record. `isAllowedOn(req.params.id)` names
// what it is asking about, so the answer covers the very record the operation reaches
// and which accessor performs it no longer decides anything.
app.post("/clients/:id/archive", async (req, res) => {
  const ctx = getAuthenticatedContext();
  if (!(await ctx.repo.isAllowedOn(req.params.id))) {
    res.status(403).send();
    return;
  }

  await ctx.systemRepo.updateResource({ id: req.params.id, archived: true });
  res.json({ ok: true });
});

// EXPECTED CLEAN, and this is what the name list is for. `cache.has()` is a guard, it
// sits on a sibling accessor of the same context, and the handler leaves from it -- the
// shape is identical to the findings above in every way except that the question is not
// an authorization. A rule that accepted any boolean-returning guard would report this.
app.post("/clients/:id/warm", async (req, res) => {
  const ctx = getAuthenticatedContext();
  if (!ctx.cache.has(req.params.id)) {
    res.status(404).send();
    return;
  }

  await ctx.systemRepo.updateResource({ id: req.params.id, warmed: true });
  res.json({ ok: true });
});

// EXPECTED CLEAN. The check is about something that is not the context at all. Two
// unrelated objects are not two accessors of one thing, and a handler checking a policy
// and then using a repository is every program ever written.
app.post("/clients/:id/quota", async (req, res) => {
  const ctx = getAuthenticatedContext();
  if (!(await limits.policy.isAllowed())) {
    res.status(429).send();
    return;
  }

  await ctx.systemRepo.updateResource({ id: req.params.id, quota: 10 });
  res.json({ ok: true });
});

app.listen(3000);
