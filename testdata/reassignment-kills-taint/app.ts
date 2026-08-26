// A variable that is REDEFINED keeps the taint of every value it ever held, because a
// redefinition is lowered as a merge: one value, two edges into it, and no record that
// the second assignment replaced the first. This corpus is the boundary of the fix.
//
// The three POSITIVES are the shapes where a path to the use avoids the reassignment, so
// the first value is still live and reporting it is right. The two NEGATIVES are the
// shapes where it does not, and both of them are ordinary defensive code: verify, then
// carry on with the verified thing; escape, then carry on with the escaped thing. The
// engine used to report the value that was thrown away, with a path pointing at the line
// that threw it away.
import express from "express";
import escapeHtml from "escape-html";
import Stripe from "stripe";

const app = express();

declare const db: { query(sql: string, params?: unknown[]): Promise<unknown> };
declare function rawBody(req: express.Request): Promise<Buffer>;
declare function defaultFilter(): string;

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);
const SAFE_SORTS = ["created_at", "title"];

// POSITIVE — the control. One definition, one use, nothing in between. Whatever the
// reaching-definition analysis does to the cases below, it must not touch this one.
app.get("/api/notes", async (req, res) => {
  const order = req.query.order as string;
  res.json(await db.query("SELECT id FROM notes ORDER BY " + order));
});

// POSITIVE — reassigned inside an `if`. The caller decides whether the replacement
// happens, so a path from the first assignment to the query avoids the second one
// entirely and the caller's value is still what arrives. A killing definition has to be
// UNAVOIDABLE, and this one is not.
app.get("/api/notes/filtered", async (req, res) => {
  let where = req.query.where as string;
  if (req.query.strict === "1") {
    where = defaultFilter();
  }
  res.json(await db.query("SELECT id FROM notes WHERE " + where));
});

// POSITIVE — reassigned inside a loop body. A loop that runs zero times leaves the
// caller's value in place, and neither frontend emits the back edge that would make
// that visible in the block graph. So neither frontend claims a position for a flow
// lowered here, and the analysis declines to reason about one: the taint survives
// because the engine cannot prove it does not.
app.get("/api/notes/sorted", async (req, res) => {
  let sort = req.query.sort as string;
  for (const candidate of SAFE_SORTS) {
    sort = candidate;
  }
  res.json(await db.query("SELECT id FROM notes ORDER BY " + sort));
});

// NEGATIVE — the shape this was built for, copied from linkwarden's Stripe webhook. The
// unsigned body is what `event` holds for ten lines and it never leaves the handler: the
// verification either replaces it or throws, and the catch returns. The log reads the
// verified event, and the engine used to call it log injection with a path back to the
// `req.body` on the first line.
app.post("/api/webhooks/stripe", async (req, res) => {
  let event = req.body;
  const signature = req.headers["stripe-signature"] as string;

  try {
    event = stripe.webhooks.constructEvent(
      await rawBody(req),
      signature,
      process.env.STRIPE_WEBHOOK_SECRET as string
    );
  } catch (err) {
    return res.status(400).send("Webhook signature verification failed.");
  }

  console.log(`stripe event ${event.type}`);
  return res.json({ received: true });
});

// NEGATIVE — `let x = req.body.x; x = escape(x);`, which is how a great deal of
// defensive code is written. Both definitions of `comment` are live, and which one is
// live WHERE is the whole question: the read on the escaping line is the unescaped
// value, and the read on the line after it is the escaped one. Reporting the first
// witness for the second read is what made every guarded handler look unguarded.
app.post("/api/comments", (req, res) => {
  let comment = req.body.comment as string;
  comment = escapeHtml(comment);
  res.send("<p>" + comment + "</p>");
});

export default app;
