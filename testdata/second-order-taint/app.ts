/**
 * A store is a place values come from.
 *
 * The engine had no notion of one, and that single missing fact was producing two
 * opposite defects at once. This corpus holds both, because fixing either alone makes the
 * other worse.
 *
 * From one side, a read was assumed to answer with whatever it was HANDED, so
 * `cache.get(id)` returned the caller's identifier rather than the cached row and taint
 * flowed from the key a lookup was given into the value it returned. Anything a caller
 * could NAME became something a caller had WRITTEN, and six false positives across two
 * production repositories rested on exactly that step -- one of them a 49-hop path onto
 * genuinely raw SQL, where the SQL was real and the taint was not there at all.
 *
 * From the other side, a value a request WROTE to a database arrived at a later request
 * looking like something the server established, because taint is intra-request and
 * nothing carried the fact across.
 *
 * Both are the same sentence: a read answers with what was WRITTEN, and what was written
 * is a separate question with a separate provenance.
 *
 * The second half is the one with teeth, and what keeps it usable is that a row is not a
 * value. A row holds columns a caller filled in and columns the store wrote for itself,
 * and the read that answers with it says nothing about which is which. So the connection
 * names the COLUMN on both sides -- the write's option keys say which columns a request
 * reached, and the read carries the class only through those. `note.body` is a caller's
 * and `note.id` is the database's, out of one call.
 */
import express from "express";

import { cache, db, sql } from "./store";

const app = express();

// The WRITE half. A caller's text goes into one column of one table.
app.post("/notes", async (req, res) => {
  await db.note.create({ data: { body: req.body.body, status: "draft" } });
  res.end();
});

// EXPECTED FINDING -- stored cross-site scripting, and both halves of the store model are
// load-bearing in this one route.
//
// The identifier in the path is the KEY. It selects a row and it is not the row: before
// the store was modelled the engine reported this line with `req.params.id` as the source,
// which is the false positive, and it is silent about the key now.
//
// What IS reported is `note.body`, because POST /notes writes that column of that table
// from a request and this route interpolates it into markup. The source is the store and
// the finding says which route filled it.
app.get("/notes/:id", async (req, res) => {
  const note = await db.note.findUnique({ where: { id: req.params.id } });
  res.send(`<article>${note.body}</article>`);
});

// SILENT -- a column of a written table that no request writes.
//
// `status` is set by the program with a literal at the create above, and a column whose
// value was written down in the source is not one a caller reaches. Same table, same
// read, different column.
app.get("/notes/:id/badge", async (req, res) => {
  const note = await db.note.findUnique({ where: { id: req.params.id } });
  res.send(`<span>${note.status}</span>`);
});

// SILENT -- the column the STORE wrote.
//
// `id` is an auto-increment the database produced, and it is never named by any write.
// This is the shape that made the first version of this rule useless: without the column
// on both sides it connected a write of `body` to a read of `id`, and reported a file
// path built out of a primary key.
app.get("/notes/:id/attachments", async (req, res) => {
  const note = await db.note.findUnique({ where: { id: req.params.id } });
  await sql.query(`SELECT * FROM attachment WHERE note = '${note.id}'`);
  res.end();
});

// SILENT -- a lookup key reaching an interpreter. THE side-B case.
//
// A cache answers with what was put in it. The key a caller chose says which entry, and
// the entry is a separate question with a separate provenance -- one this corpus does not
// answer, because nothing here writes to this cache.
app.get("/cached/:key", async (req, res) => {
  const region = cache.get(req.params.key);
  await sql.query(`SELECT * FROM usage WHERE region = '${region}'`);
  res.end();
});

// SILENT -- the same step through an ORM rather than a cache.
//
// Nothing in this program writes to `tenant` from a request, so the row it answers with
// is the store's own and the identifier that selected it is not a column of it.
app.get("/tenants/:id", async (req, res) => {
  const tenant = await db.tenant.findUnique({ where: { id: req.params.id } });
  await sql.query(`SELECT * FROM usage WHERE region = '${tenant.region}'`);
  res.end();
});

// SILENT -- a write and a read of DIFFERENT tables.
//
// `message` is a caller's and it is a column of `audit`. Reading a column of `profile`
// reaches nothing a caller wrote, and a rule that connected any write to any read would
// report this line and every line like it.
app.post("/audit", async (req, res) => {
  await db.audit.create({ data: { message: req.body.message } });
  res.end();
});

app.get("/profile", async (_req, res) => {
  const profile = await db.profile.findFirst();
  res.send(`<b>${profile.nickname}</b>`);
});

// SILENT -- a table written only with literals.
//
// Every column of this write was written down in the source, so every clone of the
// repository has the same page and no caller has ever reached one.
app.post("/pages", async (_req, res) => {
  await db.page.create({ data: { title: "Untitled", body: "" } });
  res.end();
});

app.get("/pages", async (_req, res) => {
  const page = await db.page.findFirst();
  res.send(`<h1>${page.title}</h1>`);
});

export default app;
