// An options object is a parameter list, and a callee that takes it apart is still being
// handed the caller's data.
//
// A function whose only parameter is an object binding pattern declared NO parameters at
// all: the bindings became values with paths and nothing said they were parameters, so
// `Arg.BoundParam` matched none of them and no argument taint entered such a function
// ever. Taint crossed into `run(id: string)` and stopped at `run({ id }: Options)` --
// which is the shape most of a modern TypeScript codebase is written in. Measured on
// documenso, 3239 local call edges landed on a callee declaring no parameters.
//
// The second half is which PART arrives. One argument is passed and several names are
// bound out of it, so handing the whole object to every binding would put the caller's
// search term into `table` as readily as into `term`. Where the call site writes the
// object's keys down, each binding is handed what its own key carries and nothing else.
import express from "express";

const app = express();

declare const db: {
  query(sql: string, params?: unknown[]): Promise<unknown>;
};

interface Search {
  term: string;
  table: string;
}

// The plainest case: the tainted property is the one that reaches the interpreter.
async function search({ term }: Search) {
  return db.query("SELECT * FROM audit WHERE note = '" + term + "'");
}

app.get("/search", async (req, res) => {
  res.json(await search({ term: String(req.query.q), table: "audit" }));
});

// THE PRECISION CASE. The caller's value is filed under `term`, and the binding that
// reaches the interpreter is `table`. Nothing untrusted reaches the sink and this must
// stay silent: handing the whole object to every binding would report it.
async function count({ table }: Search) {
  return db.query("SELECT count(*) FROM " + table);
}

app.get("/count", async (req, res) => {
  res.json(await count({ term: String(req.query.q), table: "audit" }));
});

// A DEFAULTED binding is still a binding. The caller supplies the value, so the default
// decides nothing about where it came from.
async function order({ column = "id" }: { column?: string }) {
  return db.query("SELECT * FROM audit ORDER BY " + column);
}

app.get("/order", async (req, res) => {
  res.json(await order({ column: String(req.query.col) }));
});

// A NESTED and RENAMED binding: `where.note` arrives under the local name `note`.
async function lookup({ where: { note: text } }: { where: { note: string } }) {
  return db.query("SELECT * FROM audit WHERE note = '" + text + "'");
}

app.get("/lookup", async (req, res) => {
  res.json(await lookup({ where: { note: String(req.query.note) } }));
});

// The sibling of the nested case: the tainted property sits beside the one that is read.
// `where.note` is the caller's; the binding reads `where.owner`.
async function byOwner({ where: { owner } }: { where: { note: string; owner: string } }) {
  return db.query("SELECT * FROM audit WHERE owner = '" + owner + "'");
}

app.get("/by-owner", async (req, res) => {
  res.json(await byOwner({ where: { note: String(req.query.note), owner: "system" } }));
});

// A SPREAD leaves keys nobody wrote. No binding can be ruled out, so the whole object is
// handed over and the finding stands -- refusing to report it would be claiming the call
// site said something it did not.
async function report({ table }: Search) {
  return db.query("SELECT * FROM " + table);
}

app.get("/report", async (req, res) => {
  res.json(await report({ ...(req.query as unknown as Search) }));
});

export default app;
