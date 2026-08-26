// The seventh analysis kind, and the one that reads the SHAPE OF THE GRAPH rather than a
// call, a value or a comparison.
//
// Nothing here is a dangerous call. The status is the right status and the creation is
// the right creation; what is wrong is that both of them run. A rule that reads calls
// sees two correct calls, and a rule that reads position sees a check before an
// operation -- which is what correct code looks like too.

const express = require("express");
const db = require("./db");

const app = express();

app.post("/users", (req, res) => {
  // POSITIVE. The program has already said, in its own code, that this request should
  // not proceed. It proceeds. No declared expectation is needed to know that, which is
  // the whole reason this judgement is worth making.
  if (!req.body.name) {
    res.status(400).json({ error: "name required" });
  }
  db.create(req.body.name);
  res.json({ ok: true });
});

app.post("/users-returned", (req, res) => {
  // NEGATIVE, and the fix: one word.
  if (!req.body.name) {
    return res.status(400).json({ error: "name required" });
  }
  db.create(req.body.name);
  res.json({ ok: true });
});

app.post("/users-else", (req, res) => {
  // NEGATIVE, and the shape that made a first attempt at this rule report correct code.
  // The branches reconverge, exactly as the broken one does -- and they reconverge on
  // NOTHING, because everything happened inside them.
  if (!req.body.name) {
    res.status(400).json({ error: "name required" });
  } else {
    db.create(req.body.name);
    res.json({ ok: true });
  }
});

app.post("/users-raised", (req, res) => {
  // NEGATIVE. A helper that always throws ends the request as surely as a return does,
  // and the caller cannot tell from the call site. The function can: every way out of it
  // is a throw.
  if (!req.body.name) {
    refuse("name required");
  }
  db.create(req.body.name);
  res.json({ ok: true });
});

app.post("/users-caught", async (req, res, next) => {
  // NEGATIVE. A catch handler runs INSTEAD of the rest, not after it -- so the call in it
  // is not the handler carrying on. Lowering try/catch as straight-line code reported
  // five of these in one production repository.
  try {
    if (!(await allowed(req))) {
      res.sendStatus(403);
    } else {
      res.sendStatus(200);
    }
  } catch (err) {
    next(err);
  }
});

app.get("/status-ok", (req, res) => {
  // NEGATIVE. A 2xx is the happy path and says nothing about anything.
  res.status(201);
  db.create("seed");
  res.json({ ok: true });
});

function refuse(message) {
  throw new Error(message);
}

async function allowed(req) {
  return Boolean(req.body);
}

app.listen(3000);
