const express = require("express");

const app = express();

app.get("/", (req, res) => res.json({ ok: true }));

function serveEverywhere() {
  // POSITIVE. Node puts the address in the second position rather than in an option, and
  // it means the same thing there.
  app.listen(8000, "0.0.0.0");
}

function serveLocally() {
  // NEGATIVE.
  app.listen(8000, "127.0.0.1");
}

function serveConfigured() {
  // NEGATIVE. Read from the environment, which is how it should be written.
  app.listen(8000, process.env.BIND_HOST);
}

module.exports = { app, serveEverywhere, serveLocally, serveConfigured };
