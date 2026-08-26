// The real one. An application binding this file watched being created, registering a
// route that answers requests from the network.
const express = require("express");
const { execSync } = require("child_process");

const app = express();

app.post("/users", (req, res) => {
  // POSITIVE. A route that survives the mock exclusion still gets analysed, which is the
  // other half of what this corpus asserts: the exclusion must be about mocks and not
  // about registrations that look like them.
  execSync("useradd " + req.body.name);
  res.json({ ok: true });
});

app.listen(3000);
