import express from "express";

import { requireAuthenticatedSession } from "./auth.ts";
import { prisma } from "./db.ts";
import { completeByToken, revokeApiTokenById, signFieldWithToken } from "./signing.ts";

const router = express.Router();

// --- the population -------------------------------------------------------------
//
// Ten routes that mount the session middleware. This is what the convention analysis
// compares against, and it is the only thing it can compare against: a peer group knows
// what its members MOUNT and nothing about what they do.

router.get("/documents", requireAuthenticatedSession, async (_req, res) => {
  res.json(await prisma.document.findMany({ where: {} }));
});

router.post("/documents", requireAuthenticatedSession, async (req, res) => {
  res.json({ created: req.body.title });
});

router.get("/documents/:documentId", requireAuthenticatedSession, async (req, res) => {
  res.json(await prisma.document.findFirst({ where: { id: req.params.documentId } }));
});

router.patch("/documents/:documentId", requireAuthenticatedSession, async (req, res) => {
  res.json({ patched: req.params.documentId });
});

router.get("/documents/:documentId/recipients", requireAuthenticatedSession, async (req, res) => {
  res.json({ documentId: req.params.documentId });
});

router.post("/documents/:documentId/recipients", requireAuthenticatedSession, async (req, res) => {
  res.json({ added: req.body.email });
});

router.get("/templates", requireAuthenticatedSession, async (_req, res) => {
  res.json({ templates: [] });
});

router.post("/templates", requireAuthenticatedSession, async (req, res) => {
  res.json({ created: req.body.name });
});

router.get("/settings", requireAuthenticatedSession, async (_req, res) => {
  res.json({ settings: {} });
});

router.patch("/settings", requireAuthenticatedSession, async (req, res) => {
  res.json({ saved: req.body.locale });
});

// --- silent: the caller presented a secret --------------------------------------

// The signing link. No session middleware, and none is missing: the caller presents a
// token nobody can guess and the handler resolves the recipient it names. The lookup is
// in this body, which is documenso's `completeDocumentWithToken` shape.
router.post("/sign/status", async (req, res) => {
  const recipient = await prisma.recipient.findFirst({ where: { token: req.body.token } });
  if (!recipient) {
    res.status(404).json({ error: "unknown token" });
    return;
  }
  res.json({ envelopeId: recipient.envelopeId });
});

// The same authentication with the lookup one hop down, which is how the other four of
// documenso's five are written.
router.post("/sign/field", async (req, res) => {
  res.json(await signFieldWithToken({ token: req.body.token, value: req.body.value }));
});

// --- must still fire ------------------------------------------------------------

// Nothing at all. No mounted control, no secret, no lookup: this is the deviation the
// population is for, and the whole point of the fixture is that it survives.
router.post("/documents/archive", async (req, res) => {
  res.json({ archived: req.body.title });
});

// A record selected by a value the caller sent, with no secret anywhere: `documentId` is
// an identifier a caller can count through, so this is an unauthenticated route that
// happens to do a lookup -- the inverse error this rule must not make.
router.delete("/documents/:documentId", async (req, res) => {
  const document = await prisma.document.findFirst({ where: { id: req.params.documentId } });
  await prisma.document.delete({ where: { id: req.params.documentId } });
  res.json({ deleted: document?.id });
});

// SILENT, and a STATED MISS until the binding rule could follow a position. The token is
// handed down as a bare positional argument; kept under this banner, and in place, so the
// diff that closed the miss is the one that moved it. See completeByToken.
router.post("/sign/complete", async (req, res) => {
  res.json(await completeByToken(req.body.token));
});

// The near miss, one hop down. `tokenId` carries a credential word and names a row, and
// the row it names is as enumerable as any other primary key.
router.post("/tokens/revoke", async (req, res) => {
  res.json(await revokeApiTokenById({ tokenId: req.body.tokenId }));
});

export default router;
