/**
 * How much a caller may make the server keep, and how much it may make it accept.
 *
 * Two judgements live here and neither is "this loop has no bound", which is true of
 * nearly every loop in every program and is why a rule shaped that way is worthless.
 *
 *   - A container that OUTLIVES the request gains one entry per distinct key. When the
 *     caller chooses the keys, when nothing measures the container against a number, and
 *     when nothing has decided the key names anything real, the number of entries the
 *     process keeps is a number the caller sets.
 *
 *   - A refusal written inside a listener for an event that HAPPENS AGAIN is not a
 *     refusal. `return` ends this invocation and detaches nothing, so the next chunk is
 *     appended to the very buffer the limit was about.
 *
 * The negatives are what make the two usable rather than noisy, and each one removes a
 * population of perfectly ordinary code: a container with a cap, a key written down, a
 * container made inside the handler, an installation that happens only after a lookup,
 * a listener something detaches, an event that happens once, and a fixture.
 *
 * Three of the negatives are about LOOPS, and they are here because the shape that would
 * have reported them was measured and withdrawn. A loop bound by a caller's array is not
 * something this engine can see -- the IR has no repetition in it -- and the two loops
 * that ARE bounded are here so that a future attempt has the discriminator written down.
 */
import express from "express";

import { calculatorFor, findWidget, REGIONS, sessionFor, slowStep } from "./store";

const app = express();

// The state these handlers reach. `sessionByToken` has no cap anywhere in this program;
// `pageCache` has one, and that single comparison is the whole difference between a
// container that is a cache and one that is a leak. Nothing else about the two differs.
const sessionByToken: Record<string, { at: number }> = {};
const pageCache: Record<string, string> = {};
const featureFlags: Record<string, boolean> = {};

// The eviction that makes `pageCache` bounded, written in a different function from the
// insertion -- which is where an eviction usually is, and why the bound has to be looked
// for program-wide rather than beside the write.
function evictIfFull(): void {
  if (Object.keys(pageCache).length > 500) {
    for (const key of Object.keys(pageCache)) delete pageCache[key];
  }
}

// EXPECTED FINDING. The container is module-level, so it outlives every request; the key
// is a token the caller sent; nothing in this program measures `sessionByToken` against
// anything; and nothing has established that the token names a session. One request per
// distinct token is one entry forever.
app.post("/sessions", (req, res) => {
  sessionByToken[req.body.token] = { at: Date.now() };
  res.json({ ok: true });
});

// EXPECTED FINDING, and the shape that needs two functions to see. The write is in
// `calculatorFor` and the decision about whether to make it is here, where there is no
// decision: the handler asks for a calculator for whatever identifier arrived. This is
// uptime-kuma's badge route with the names shortened.
app.get("/widgets/:widgetId/chart", (req, res) => {
  const calculator = calculatorFor(req.params.widgetId);
  res.json({ ok: Boolean(calculator) });
});

// EXPECTED CLEAN, and the discriminator for the rule above: the same installation into
// the same kind of container, reached only after a lookup has answered that the widget
// exists. The container can hold one entry per widget, and the number of widgets is not
// the caller's to choose.
app.get("/widgets/:widgetId/session", async (req, res) => {
  const widget = await findWidget(req.params.widgetId);
  if (!widget) {
    res.status(404).send();
    return;
  }

  sessionFor(req.params.widgetId);
  res.json({ ok: true });
});

// EXPECTED CLEAN. A container with a cap is a cache. The comparison that caps it is in
// another function and it is still the thing that makes this bounded, which is why the
// bound is looked for program-wide.
app.post("/pages", (req, res) => {
  pageCache[req.body.slug] = "rendered";
  evictIfFull();
  res.json({ ok: true });
});

// EXPECTED CLEAN. The key is written down. A container keyed by literals cannot grow past
// the number of literals in the program, however many requests arrive.
app.post("/flags", (req, res) => {
  featureFlags["betaEnabled"] = Boolean(req.body.on);
  res.json({ ok: true });
});

// EXPECTED CLEAN. The identical statement on a container made inside the handler. It dies
// with the handler however many entries it gained, and the declaration's position is the
// whole evidence.
app.post("/tally", (req, res) => {
  const seen: Record<string, number> = {};
  seen[req.body.token] = 1;
  res.json({ ok: Object.keys(seen).length === 1 });
});

// EXPECTED FINDING. The program measures the payload and decides it is too large, and
// then goes on accepting it: the listener is still attached, `chunks.push` runs for the
// next chunk, and the promise it rejected is already rejected. This is linkwarden's
// migration endpoint.
app.post("/import", (req, res) => {
  const parse = new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;

    req.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      total += chunk.length;

      if (total > 1000000) {
        reject(new Error("Payload Too Large"));
      }
    });

    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });

  parse.then(() => res.json({ ok: true })).catch(() => res.status(413).send());
});

// EXPECTED CLEAN, and the discriminator: the same limit in the same listener, with the
// call that makes it real. Destroying the request stops what feeds the callback, so
// there is no next chunk to append.
app.post("/import-bounded", (req, res) => {
  const parse = new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;

    req.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      total += chunk.length;

      if (total > 1000000) {
        req.destroy();
        reject(new Error("Payload Too Large"));
      }
    });

    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });

  parse.then(() => res.json({ ok: true })).catch(() => res.status(413).send());
});

// EXPECTED CLEAN. The refusal is in a listener for an event that happens ONCE. There is
// no next invocation to detach, so there is nothing that a detach would have prevented
// and nothing to report.
app.post("/import-once", (req, res) => {
  const parse = new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];

    req.on("end", () => {
      chunks.push(Buffer.from("x"));
      reject(new Error("Nothing to import"));
    });
  });

  parse.then(() => res.json({ ok: true })).catch(() => res.status(400).send());
});

// EXPECTED CLEAN, and the first of the three loops. An array the caller sent drives a
// loop that costs a round trip per element, and the length was compared against a number
// written down before the loop ran -- so the caller chose the count out of a range the
// program chose. This is the negative a rule about unbounded iteration would have to
// stay silent on, and it is written here because that rule was measured and withdrawn.
app.post("/batch-capped", async (req, res) => {
  const ids: string[] = req.body.ids ?? [];
  if (ids.length > 50) {
    res.status(413).send();
    return;
  }

  for (const id of ids) {
    await slowStep(id);
  }
  res.json({ ok: true });
});

// EXPECTED CLEAN, and the second: a loop over a collection the program wrote down. Its
// length is three whatever arrives.
app.post("/batch-constant", async (req, res) => {
  for (const region of REGIONS) {
    await slowStep(region);
  }
  res.json({ ok: true });
});

// EXPECTED CLEAN TODAY, and the honest half of the withdrawal. This IS unbounded: an
// array the caller sent, a round trip per element, and the only comparison on its length
// is a test for whether anything arrived at all -- which every handler that takes a list
// performs and which bounds nothing. The engine has no repetition in its IR, so there is
// nothing here for a rule to read, and the corpus records the miss rather than hiding it.
// This is linkwarden's bulk delete with the names shortened.
app.post("/batch-uncapped", async (req, res) => {
  const ids: string[] = req.body.ids;
  if (!ids || ids.length === 0) {
    res.status(400).send();
    return;
  }

  for (const id of ids) {
    await slowStep(id);
  }
  res.json({ ok: true });
});

app.listen(3000);
