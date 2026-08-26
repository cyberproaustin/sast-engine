/**
 * Authorization that happened, and was about something else.
 *
 * Every handler in this file performs a real permission check, and every one of them
 * hands the caller's identity to it. The engine's ownership policy accepts that as the
 * relation it needs -- its own output says so: *a helper receiving actor identity is
 * presumed to enforce* -- so all eight of these read as checked, including the three
 * where the check is about one record and the write is about another.
 *
 * What separates them is not whether a check happened but WHICH KEY it named. A handler
 * authorized for project P and deleting strategy S has proved nothing about S; the fact
 * that `hasPermission` appears above the delete is exactly as true in the safe cases and
 * exactly as uninformative.
 *
 * Three things this corpus insists on, each of which was a real finding or a real false
 * positive on production code:
 *
 *   - Existence is not authorization. `featureExists(id)` proves the row is there and
 *     says nothing about who owns it, so it does not close the relation.
 *   - A key the caller supplied is not a scope. Being told which project to check the
 *     caller against is a parameter; the key has to come from the route or from
 *     established identity for a lookup to be allowed to extend it.
 *   - A selection that carries BOTH keys is scoped by construction and needs no check
 *     above it, which is how multi-tenant code is normally written.
 */
import express from "express";

import { access, DELETE_LINK, DELETE_PROJECT, UPDATE_SEGMENT, UPDATE_STRATEGY } from "./access";
import { requireAuth } from "./auth";
import { featureExists, findStrategyInProject, store } from "./store";

const app = express();

// EXPECTED FINDING. Authorized against the project in the ROUTE, and the write is keyed
// by a strategy id out of the BODY. Whether that strategy belongs to that project is
// never asked, so a caller with rights on any project of their own can delete a strategy
// belonging to somebody else's by naming it in the body. This is unleash's segment
// controller with the names shortened.
app.post("/projects/:projectId/strategies", requireAuth, async (req, res) => {
  const { projectId } = req.params;
  const { strategyId } = req.body;

  if (!(await access.hasPermission(req.user, UPDATE_STRATEGY, projectId))) {
    res.status(403).send();
    return;
  }

  await store.strategy.delete({ where: { id: strategyId } });
  res.json({ ok: true });
});

// EXPECTED FINDING, and the second spelling. There IS a check between the permission
// call and the write, and it establishes the wrong thing: `featureExists` answers whether
// the row is there. Every strategy in the database exists, so this check passes for every
// one of them and the delete still reaches a project the caller has no rights over.
//
// A relation-shaped rule that accepted "some call mentions the key" would call this
// checked, which is why the relating call must carry BOTH keys and not just the one.
app.post("/projects/:projectId/links", requireAuth, async (req, res) => {
  const { projectId } = req.params;
  const { featureId } = req.body;

  if (!(await access.hasPermission(req.user, DELETE_LINK, projectId))) {
    res.status(403).send();
    return;
  }

  if (!(await featureExists(featureId))) {
    res.status(404).send();
    return;
  }

  await store.link.delete({ where: { id: featureId } });
  res.json({ ok: true });
});

// EXPECTED FINDING, and the third shape: the row being written IS the authorized one and
// the field being SET names a different record. The caller may update this project, and
// the update moves it under an organisation nobody checked. umami's report endpoint is
// written exactly this way -- the permission call reads the report's current website and
// the update writes a new one.
app.post("/projects/:projectId", requireAuth, async (req, res) => {
  const { projectId } = req.params;
  const { organisationId, name } = req.body;

  if (!(await access.hasPermission(req.user, DELETE_PROJECT, projectId))) {
    res.status(403).send();
    return;
  }

  await store.project.update({ where: { id: projectId }, data: { organisationId, name } });
  res.json({ ok: true });
});

// EXPECTED CLEAN. The key the write uses IS the key the check named. There is no second
// record in this handler and nothing to relate.
app.delete("/projects/:projectId", requireAuth, async (req, res) => {
  const { projectId } = req.params;

  if (!(await access.hasPermission(req.user, DELETE_PROJECT, projectId))) {
    res.status(403).send();
    return;
  }

  await store.project.delete({ where: { id: projectId } });
  res.json({ ok: true });
});

// EXPECTED CLEAN. A genuine ownership lookup: the call is handed both identifiers, so a
// row it returns is one that belongs to the authorized project, and the handler leaves if
// there is none. The relation is established by the lookup rather than by a comparison,
// which is the shape a service layer usually takes.
app.post("/projects/:projectId/strategies/:strategyId/rename", requireAuth, async (req, res) => {
  const { projectId } = req.params;
  const { strategyId } = req.body;

  if (!(await access.hasPermission(req.user, UPDATE_STRATEGY, projectId))) {
    res.status(403).send();
    return;
  }

  const owned = await findStrategyInProject(strategyId, projectId);
  if (!owned) {
    res.status(404).send();
    return;
  }

  await store.strategy.update({ where: { id: strategyId }, data: req.body.name });
  res.json({ ok: true });
});

// EXPECTED CLEAN. The other way to write the same relation: fetch the record by the
// caller's key and compare its owner against the caller. The comparison never mentions
// the authorized key and it is still an ownership check, because what it relates the
// record to is the actor.
app.post("/segments/:segmentId/strategies", requireAuth, async (req, res) => {
  const { segmentId } = req.params;
  const { strategyId } = req.body;

  if (!(await access.hasPermission(req.user, UPDATE_SEGMENT, segmentId))) {
    res.status(403).send();
    return;
  }

  const found = await store.strategy.findFirst({ where: { id: strategyId } });
  if (found.userId !== req.user.id) {
    res.status(403).send();
    return;
  }

  await store.strategy.delete({ where: { id: strategyId } });
  res.json({ ok: true });
});

// EXPECTED CLEAN. The selection carries both keys, so it cannot reach a strategy outside
// the authorized project however the caller spells the id. No check above it is needed
// and none is written -- this is what most multi-tenant code looks like, and a rule that
// demanded a comparison would report all of it.
app.post("/projects/:projectId/strategies/:strategyId/archive", requireAuth, async (req, res) => {
  const { projectId } = req.params;
  const { strategyId } = req.body;

  if (!(await access.hasPermission(req.user, UPDATE_STRATEGY, projectId))) {
    res.status(403).send();
    return;
  }

  await store.strategy.update({ where: { id: strategyId, projectId }, data: { archived: true } });
  res.json({ ok: true });
});

// EXPECTED CLEAN. The check is about the caller and not about a record: an administrator
// acting on any project by id is what this endpoint is for, so there is no second key the
// check could have named and no relation to state. The presumption the ownership policy
// makes is the right answer here, and this rule stands aside for it.
app.delete("/admin/projects", requireAuth, async (req, res) => {
  const { projectId } = req.body;

  if (!(await access.hasRole(req.user, "admin"))) {
    res.status(403).send();
    return;
  }

  await store.project.delete({ where: { id: projectId } });
  res.json({ ok: true });
});

// EXPECTED CLEAN under THIS rule, and a finding under the ownership policy, which is the
// division of labour the corpus is asserting. No identity reaches this handler at all, so
// there is no check for a scope to be compared against; the missing-ownership rule says
// what there is to say and this one says nothing.
app.post("/public/unsubscribe", async (req, res) => {
  const { subscriptionId } = req.body;
  await store.subscription.delete({ where: { id: subscriptionId } });
  res.json({ ok: true });
});

app.listen(3000);
