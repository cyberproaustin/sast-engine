// A credential that outlives the thing it admits.
//
// The insert half of each call is this program's own statement of what a new record of
// that kind needs. Where it mints a token and the update half beside it rewrites the
// address the token was issued for, the link mailed to the old address still admits its
// holder -- now to the new one. That is the healthchecks weakness, written as a store
// call instead of as a hash seed.
//
// Every negative below is the same call shape with one of the three facts missing.

import express from "express";
import { nanoid } from "nanoid";
import { prisma } from "./db.ts";

const app = express();

// EXPECTED FINDING. `create` says a new recipient needs a freshly minted token; `update`
// rewrites the address and leaves the old one standing.
app.post("/envelopes/:id/recipients", async (req, res) => {
  const recipient = await prisma.recipient.upsert({
    where: { id: Number(req.params.id) },
    update: {
      name: req.body.name,
      email: req.body.email,
      role: req.body.role,
    },
    create: {
      name: req.body.name,
      email: req.body.email,
      role: req.body.role,
      token: nanoid(),
    },
  });

  res.json({ id: recipient.id });
});

// EXPECTED CLEAN. The near miss, and the one that must stay silent for the rule to be
// worth having: the update rewrites the address AND reissues the credential, which is the
// fix. Everything else about the call is identical.
app.post("/invitations", async (req, res) => {
  const invitation = await prisma.invitation.upsert({
    where: { id: Number(req.body.id) },
    update: {
      email: req.body.email,
      token: nanoid(),
    },
    create: {
      email: req.body.email,
      token: nanoid(),
    },
  });

  res.json({ id: invitation.id });
});

// EXPECTED CLEAN. The update leaves the credential alone and changes nothing the
// credential is about. A token still admits the same person to the same thing after its
// row's sort order moves, and rotating it here would be a nuisance rather than a fix.
app.post("/envelopes/:id/order", async (req, res) => {
  const signer = await prisma.signer.upsert({
    where: { id: Number(req.params.id) },
    update: {
      signingOrder: req.body.signingOrder,
      sendStatus: req.body.sendStatus,
    },
    create: {
      signingOrder: req.body.signingOrder,
      sendStatus: req.body.sendStatus,
      token: nanoid(),
    },
  });

  res.json({ id: signer.id });
});

// EXPECTED CLEAN. An ordinary create, with no second half saying anything about an
// existing record. There is nothing here that fails to rotate: the row did not exist.
app.post("/envelopes/:id/add", async (req, res) => {
  const added = await prisma.recipient.create({
    data: {
      name: req.body.name,
      email: req.body.email,
      token: nanoid(),
    },
  });

  res.json({ id: added.id });
});

export default app;
