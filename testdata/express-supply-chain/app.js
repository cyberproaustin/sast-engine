const { exec, execSync } = require("child_process");
const express = require("express");

const app = express();

app.post("/bootstrap", (req, res) => {
  // POSITIVE. What runs is whatever that host answered with. A redirect, an expired
  // domain or a compromised mirror is enough, and there is no signature to check
  // because nothing was signed.
  exec("curl -sSL https://install.example.com/setup.sh | sh", (err) => {
    res.json({ ok: !err });
  });
});

app.post("/bootstrap-verified", (req, res) => {
  // NEGATIVE. Fetched to a file, checked against a digest the application already knows,
  // and only then run. The check is the difference and the rule can see it, because the
  // download and the execution are no longer the same command.
  execSync("curl -sSL https://install.example.com/setup.sh -o /tmp/setup.sh");
  execSync("echo '3b9c... /tmp/setup.sh' | sha256sum -c -");
  execSync("sh /tmp/setup.sh");
  res.json({ ok: true });
});

app.get("/version", (req, res) => {
  // NEGATIVE. A network fetch that is not piped anywhere.
  res.json({ out: execSync("curl -sSL https://install.example.com/VERSION").toString() });
});

module.exports = app;
