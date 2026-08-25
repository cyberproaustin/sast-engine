const express = require("express");

const app = express();
app.set("view engine", "ejs");
app.set("views", __dirname + "/views");

// POSITIVE. An error message is where a program repeats back what it was given -- the
// name it could not find, the value it could not parse -- so writing one into a page
// unescaped is how the caller's own input comes back as script. Distinguished from
// ordinary cross-site scripting by its SOURCE: the engine classifies failure detail
// separately from caller input precisely so it can tell the two apart.
app.get("/search", (req, res) => {
  try {
    lookup(req.query.q);
  } catch (err) {
    res.render("error", { detail: err.message });
  }
});

// NEGATIVE, and the whole of the fix: the same value written into an escaped slot. It is
// still failure detail on a page, which is reported separately and under its own number --
// the two are different weaknesses with different remedies.
app.get("/search-escaped", (req, res) => {
  try {
    lookup(req.query.q);
  } catch (err) {
    res.render("error-escaped", { detail: err.message });
  }
});

function lookup(q) { throw new Error("no such record: " + q); }

app.listen(3000);
