// A `return` inside a `try` goes to the function exit. It does not go to the `catch`.
//
// The catch is reached from the EXCEPTION edges of the try body, and a statement that
// has already left the function raises nothing. Hanging that edge on the first block of
// the body instead makes the catch the one thing that unavoidably follows whatever the
// body ended with -- and when the body ends with `return res.status(405).json(...)`, the
// catch's own response looks like a second response written after a refusal.
//
// That shape is not unusual. `switch (req.method) { ...; default: return res.status(405) }`
// wrapped in a try is how a single-file route handler answers an unsupported verb, and
// every one of them was reported as execution after a response.
//
// The positive at the bottom is the reason this cannot be fixed by ignoring catch blocks:
// a refusal inside a try, with the work it refused still unavoidable after it, is exactly
// as wrong inside a try as outside one.

const express = require("express");
const db = require("./db");

const app = express();

// NEGATIVE. The method check refuses and RETURNS; the catch answers a different path.
// Both responses are real and no execution reaches both.
app.all("/archives", async (req, res) => {
  try {
    switch (req.method) {
      case "POST":
        await handlePost(req, res);
        break;
      default:
        return res.status(405).json({ response: "Method not allowed" });
    }
  } catch (error) {
    return res.status(400).json({ response: error.message });
  }
});

// NEGATIVE, and the check that the exception edge is still there. A `throw` inside the
// try reaches the catch, so the detail the catch writes into the response is reported --
// removing the edge instead of moving it would have made this catch dead code and taken
// a true finding with it.
app.post("/imports", async (req, res) => {
  try {
    if (!req.body.file) {
      throw new Error("no file for " + req.body.name);
    }
    await db.create(req.body.file);
    return res.status(201).json({ ok: true });
  } catch (err) {
    return res.status(422).json({ error: err.message });
  }
});

// NEGATIVE. The same returning switch with a `finally` under it. The finally runs on
// every path and it audits -- it does not answer -- and the refusal above it still
// returns, so no execution reaches two responses here either.
app.all("/exports", async (req, res) => {
  try {
    switch (req.method) {
      case "GET":
        return res.json({ rows: [] });
      default:
        return res.status(405).json({ error: "Method not allowed" });
    }
  } catch (err) {
    return res.status(400).json({ error: "export failed" });
  } finally {
    audit("exports");
  }
});

// POSITIVE, and the shape the fix must leave alone. The refusal is written, nothing
// returns, and the creation it was refusing is unavoidable after it -- being inside a
// `try` changes nothing about that.
app.post("/users", async (req, res, next) => {
  try {
    if (!req.body.name) {
      res.status(400).json({ error: "name required" });
    }
    db.create(req.body.name);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

async function handlePost(req, res) {
  await db.create(req.body.name);
  return res.status(201).json({ ok: true });
}

function audit(what) {
  return what;
}

app.listen(3000);
